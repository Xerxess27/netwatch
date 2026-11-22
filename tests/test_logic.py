import importlib.util, ipaddress, os, sys, tempfile, io, contextlib
spec = importlib.util.spec_from_file_location("nw", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "netwatch.py"))
nw = importlib.util.module_from_spec(spec); sys.modules["nw"] = nw; spec.loader.exec_module(nw)

fails = 0
def check(cond, msg):
    global fails
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: fails += 1

tmp = tempfile.mkdtemp()
store = nw.Store(os.path.join(tmp, "t.db"))
net = nw.Net("wlan0", "192.168.1.50", ipaddress.ip_network("192.168.1.0/24"), "192.168.1.1",
             "d4:3b:04:aa:10:50", "Home", ipaddress.ip_network("192.168.1.0/24"))
ROUTER, PHONE, PLUG, EVIL = "50:c7:bf:12:34:01", "f0:98:9d:3a:21:0e", "24:0a:c4:9e:11:37", "00:c0:ca:b1:7e:66"
world = {"pairs": [], "cache": {}, "ports": {}}
deps = nw.Deps(discover=lambda n: list(world["pairs"]), resolve=lambda ips: {},
               probe=lambda ips: {ip: world["ports"].get(ip, []) for ip in ips},
               vendor=nw.OUI_DB.lookup, arp_cache=lambda: dict(world["cache"]))
def scan(t):
    with contextlib.redirect_stdout(io.StringIO()):
        return nw.process_scan(store, net, deps, now=t)
kinds = lambda r: [(a.level, a.title) for a in r.alerts]

# 1. baseline: router + phone (phone has telnet open -> baseline risky)
world["pairs"] = [("192.168.1.1", ROUTER), ("192.168.1.14", PHONE)]
world["ports"] = {"192.168.1.1": [53, 80], "192.168.1.14": [23]}
r = scan(1000)
check(r.baseline and r.new == 0, "baseline scan records devices without new-device alerts")
check(kinds(r) == [("info", "NetWatch is now watching your network")], f"baseline sends one summary {kinds(r)}")
check(any("Telnet 23" in l for l in r.alerts[0].lines), "baseline summary lists risky Telnet port")
check(store.meta_get(f"gw:{net.key}") == ROUTER, "router MAC learned")
devs = {d["mac"]: d for d in store.devices(net.key)}
check(devs[ROUTER]["dtype"] == "Router / Gateway" and devs[net.self_mac]["dtype"] == "This computer", "router + self typed")
check(store.labels()[net.self_mac]["trusted"], "self auto-trusted")

# 2. unknown IoT plug joins
world["pairs"].append(("192.168.1.137", PLUG)); world["ports"]["192.168.1.137"] = [23, 80]
r = scan(1060)
check(kinds(r) == [("warn", "New device joined your network")], f"new device alert {kinds(r)}")
check(r.new_macs == {PLUG}, "new_macs holds only the newcomer")
check(any("Espressif" in l for l in r.alerts[0].lines) and any("Telnet" in l for l in r.alerts[0].lines), "alert has vendor + telnet risk")
check(devs.get(PLUG) is None and {d['mac']: d for d in store.devices(net.key)}[PLUG]["dtype"] == "IoT device", "plug typed as IoT device")

# 3. same again -> no repeated alerts
r = scan(1120); check(kinds(r) == [], "no repeat alerts on steady state")

# 4. ARP spoof: attacker answers for router IP too
world["pairs"] += [("192.168.1.66", EVIL), ("192.168.1.1", EVIL)]
r = scan(1180)
check(("crit", "Possible man-in-the-middle attack") in kinds(r), f"spoof detected {kinds(r)}")
check(any("192.168.1.66" in l for l in r.alerts[-1].lines), "spoof alert names attacker's own IP")
ev = {d['mac']: d for d in store.devices(net.key)}
check(ev[EVIL]["ip"] == "192.168.1.66" and ev[ROUTER]["dtype"] == "Router / Gateway", "attacker row uses its own IP; router keeps gateway type")
r = scan(1240); check(("crit", "Possible man-in-the-middle attack") not in kinds(r), "spoof alert not repeated")
# 5. attacker leaves -> all clear
world["pairs"] = [p for p in world["pairs"] if p[1] != EVIL]
r = scan(1300); check(("info", "Router back to normal") in kinds(r), f"all-clear sent {kinds(r)}")
check(store.meta_get(f"gwalert:{net.key}") is None, "alert state cleared")

# 6. cache poisoning (only our ARP cache is wrong, active scan is fine)
world["cache"] = {"192.168.1.1": EVIL}
r = scan(1360)
check(any(a.level == "crit" and any("poisoned" in l for l in a.lines) for a in r.alerts), "kernel ARP cache poisoning detected")
world["cache"] = {"192.168.1.1": ROUTER}
r = scan(1420); check(("info", "Router back to normal") in kinds(r), "poisoning cleared")

# 7. IP conflict
world["pairs"].append(("192.168.1.14", "aa:bb:cc:00:11:22"))
r = scan(1480); check(("warn", "IP address conflict") in kinds(r), f"IP conflict {kinds(r)}")
r = scan(1540); check(("warn", "IP address conflict") not in kinds(r), "conflict not repeated")
world["pairs"].pop()
scan(1600); check(store.meta_get(f"dup:{net.key}") is None, "conflict cleared")

# 8. trusted device appearing for the first time -> no alert
store.label_set("11:22:33:44:55:66", name="My tablet", trusted=True)
world["pairs"].append(("192.168.1.200", "11:22:33:44:55:66"))
r = scan(1660); check(not any(a.title.startswith("New device") for a in r.alerts) and r.new == 1, "trusted newcomer: event but no alert")

# 9. risky port opens later on known device (after probe refresh)
world["ports"]["192.168.1.1"] = [53, 80, 5900]
r = scan(1660 + nw.PROBE_REFRESH + 10)
check(("warn", "Risky port opened") in kinds(r), f"new risky port on known device {kinds(r)}")

# 10. IP change event
world["pairs"] = [(("192.168.1.15" if m == PHONE else ip), m) for ip, m in world["pairs"]]
scan(30000)
check(any(e["kind"] == "ip_change" for e in store.events(net.key)), "IP change logged")

# 11. different network = separate baseline, router MAC change there is not a spoof
net2 = nw.Net("wlan0", "10.0.0.5", ipaddress.ip_network("10.0.0.0/24"), "10.0.0.1", net.self_mac, "Cafe", ipaddress.ip_network("10.0.0.0/24"))
world["pairs"] = [("10.0.0.1", "00:11:22:33:44:55")]; world["cache"] = {}
with contextlib.redirect_stdout(io.StringIO()):
    r = nw.process_scan(store, net2, deps, now=31000)
check(r.baseline and not any(a.level == "crit" for a in r.alerts), "new network gets its own baseline, no false spoof")

# 12. helpers
check(nw.norm_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff" and nw.norm_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff", "MAC normalising")
check(nw.norm_mac("kitchen") is None, "names aren't parsed as MACs")
check(nw.clean_hostname("evil<script>.lan", "1.2.3.4") == "evilscript", "hostname sanitised")
check(nw.clean_hostname("\x1b[31mred\x1b[0m.local") == "31mred0m", "ANSI escapes stripped from hostnames")
check(nw.is_private_mac("da:7f:3e:21:9c:73") and not nw.is_private_mac("f0:98:9d:3a:21:0e"), "private MAC detection")
check(nw.OUI_DB.lookup("b8:27:eb:00:00:01").startswith("Raspberry"), "OUI 6-hex lookup")
check(nw.OUI_DB.lookup("00:55:da:12:34:56") == "KoolPOS", "OUI 7-hex (MA-M) lookup")
gt = nw.guess_type
check(gt("Apple", [62078], "f0:98:9d:00:00:01", "", False, False) == "iPhone / iPad", "iPhone by port")
check(gt("Hangzhou Hikvision Digital", [80, 554], "28:57:be:00:00:01", "", False, False) == "IP camera", "camera")
check(gt("Unknown vendor", [], "da:00:00:00:00:01", "Galaxy-S24", False, False) == "Phone", "hostname hint")
check(gt("TP-Link Technologies", [9999], "b0:be:76:00:00:01", "", False, False) == "IoT device", "TP-Link plug")
check(gt("TP-Link Technologies", [80, 443], "b0:be:76:00:00:01", "", False, False) == "Network gear", "TP-Link AP")
check(gt("Private (randomized) MAC", [], "da:00:00:00:00:01", "", False, False) == "Phone / laptop (private MAC)", "private MAC type")
check(all(v in nw.TYPE_CAT for v in [l for _, l in nw.HOST_HINTS] + [l for _, l in nw.VENDOR_RULES if not l.startswith("_")]), "every type label has an icon category")

# 13. telegram formatting + escaping + size
msg = nw.format_telegram([nw.Alert("warn", "New <device>", ["Hostname: <b>x</b>&"])], "Home & co")
check("&lt;device&gt;" in msg and "&lt;b&gt;x&lt;/b&gt;&amp;" in msg and "Home &amp; co" in msg, "telegram HTML escaped")
big = nw.format_telegram([nw.Alert("warn", "t" * 50, ["x" * 200] * 15) for _ in range(30)], "n")
check(len(big) < 4096 and "more" in big, f"telegram message stays under limit ({len(big)})")

print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)

import importlib.util, io, json, os, sys, tempfile, contextlib, urllib.parse
spec = importlib.util.spec_from_file_location("nw", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "netwatch.py"))
nw = importlib.util.module_from_spec(spec); sys.modules["nw"] = nw; spec.loader.exec_module(nw)
TOKEN = "123456789:AAHfakefakefakefakefakefakefakefake1"
calls = []
class Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): pass
def fake_urlopen(req, timeout=None):
    method = req.full_url.rsplit("/", 1)[1]
    params = dict(urllib.parse.parse_qsl(req.data.decode()))
    calls.append((method, params, req.full_url.startswith("https://api.telegram.org/bot" + TOKEN)))
    result = {"getMe": {"username": "my_netwatch_bot"},
              "getUpdates": [{"update_id": 7, "message": {"chat": {"id": 424242, "first_name": "Sam"}}}],
              "sendMessage": {"message_id": 1}}[method]
    return Resp(json.dumps({"ok": True, "result": result}).encode())
nw.urllib.request.urlopen = fake_urlopen
nw.desktop_notify = lambda *a, **k: None
d = tempfile.mkdtemp()
paths = nw.Paths(d)
args = nw.build_parser().parse_args(["telegram-setup", "--token", TOKEN])
with contextlib.redirect_stdout(io.StringIO()) as out:
    nw.cmd_telegram_setup(args, paths)
cfg = json.load(open(paths.config))
ok = True
def check(c, m):
    global ok; print(("PASS " if c else "FAIL ") + m); ok &= c
check(cfg["telegram"] == {"token": TOKEN, "chat_id": 424242}, "setup saved token + chat id")
check(oct(os.stat(paths.config).st_mode & 0o777) == "0o600", "config file is private (600)")
check([c[0] for c in calls] == ["getMe", "getUpdates", "sendMessage"] and all(c[2] for c in calls), f"API call sequence {[c[0] for c in calls]}")
check("Connected to Sam" in out.getvalue(), "tells user which chat it connected to")
calls.clear()
n = nw.Notifier(nw.load_config(paths), desktop=False)
with contextlib.redirect_stdout(io.StringIO()):
    n.send([nw.Alert("crit", "Possible man-in-the-middle attack", ["Impostor: <evil>"])], "Home")
    n.flush()
check(len(calls) == 1 and calls[0][0] == "sendMessage" and calls[0][1]["parse_mode"] == "HTML"
      and "&lt;evil&gt;" in calls[0][1]["text"] and calls[0][1]["chat_id"] == "424242", "alert delivered via sendMessage, escaped")
check(nw.telegram_api("bad/../token", "getMe") == (False, "invalid bot token format"), "malformed token rejected before any request")
print("ALL OK" if ok else "FAILURES"); sys.exit(0 if ok else 1)

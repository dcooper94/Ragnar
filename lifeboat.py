#!/usr/bin/env python3
"""
lifeboat.py - Ragnar Lifeboat
Always-on service swap UI on port 8001. Independent of ragnar.service
and pwnagotchi.service — stays up regardless of which mode is active.
"""

import json
import subprocess
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

PORT = 8001

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ragnar Lifeboat</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0f172a;color:#e2e8f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:1.5rem}
.card{background:rgba(30,41,59,0.9);border:1px solid rgba(100,116,139,0.3);border-radius:1rem;
  padding:2rem;width:100%;max-width:400px;text-align:center;
  box-shadow:0 25px 50px -12px rgba(0,0,0,0.5)}
.anchor{font-size:2.5rem;margin-bottom:0.5rem}
h1{font-size:1.5rem;font-weight:700;letter-spacing:-0.02em}
.sub{color:#64748b;font-size:0.8rem;margin-bottom:2rem;margin-top:0.25rem}
.row{display:flex;gap:0.75rem;margin-bottom:2rem}
.chip{flex:1;background:#1e293b;border:1px solid #334155;border-radius:0.5rem;padding:0.75rem}
.chip-label{font-size:0.65rem;text-transform:uppercase;color:#475569;letter-spacing:0.08em}
.chip-val{font-size:0.95rem;font-weight:700;margin-top:0.2rem}
.on{color:#4ade80}.off{color:#475569}
.btn{display:block;width:100%;padding:0.9rem 1.5rem;border-radius:0.625rem;border:none;
  font-size:1rem;font-weight:700;cursor:pointer;transition:opacity 0.15s,transform 0.1s;
  margin-bottom:0.625rem;letter-spacing:-0.01em}
.btn:last-of-type{margin-bottom:0}
.btn:hover:not(:disabled){opacity:0.88;transform:translateY(-1px)}
.btn:active:not(:disabled){transform:translateY(0)}
.btn:disabled{opacity:0.35;cursor:not-allowed}
.btn-r{background:linear-gradient(135deg,#6d28d9,#4338ca);color:#fff}
.btn-p{background:linear-gradient(135deg,#a21caf,#7e22ce);color:#fff}
.msg{margin-top:1.25rem;padding:0.625rem 1rem;border-radius:0.375rem;font-size:0.8rem;display:none}
.msg.show{display:block}
.ok{background:#14532d;color:#86efac;border:1px solid #166534}
.er{background:#7f1d1d;color:#fca5a5;border:1px solid #991b1b}
.footer{margin-top:1.75rem;font-size:0.7rem;color:#334155;text-align:center;line-height:1.6}
</style>
</head>
<body>
<div class="card">
  <div class="anchor">&#9875;</div>
  <h1>Ragnar Lifeboat</h1>
  <p class="sub">Always-on service control &middot; port 8001</p>
  <div class="row">
    <div class="chip"><div class="chip-label">Ragnar</div><div id="rs" class="chip-val off">&mdash;</div></div>
    <div class="chip"><div class="chip-label">Pwnagotchi</div><div id="ps" class="chip-val off">&mdash;</div></div>
  </div>
  <button id="br" class="btn btn-r" onclick="swap('ragnar')">&#9876;&#65039; Switch to Ragnar</button>
  <button id="bp" class="btn btn-p" onclick="swap('pwnagotchi')">&#128126; Switch to Pwnagotchi</button>
  <div id="msg" class="msg"></div>
</div>
<div class="footer">
  Ragnar Lifeboat &middot; independent of both services<br>
  Ragnar main UI &rarr; <span id="ragnar-link">port 8000</span>
</div>
<script>
var LABELS={ragnar:'&#9876;&#65039; Switch to Ragnar',pwnagotchi:'&#128126; Switch to Pwnagotchi'};
async function poll(){
  try{
    var d=await(await fetch('/status')).json();
    var rs=document.getElementById('rs'),ps=document.getElementById('ps');
    rs.innerHTML=d.ragnar?'Active':'Stopped';rs.className='chip-val '+(d.ragnar?'on':'off');
    ps.innerHTML=d.pwnagotchi?'Active':'Stopped';ps.className='chip-val '+(d.pwnagotchi?'on':'off');
    document.getElementById('br').disabled=!!d.ragnar;
    document.getElementById('bp').disabled=!!d.pwnagotchi;
    var rl=document.getElementById('ragnar-link');
    if(d.ragnar)rl.innerHTML='<a href="http://'+location.hostname+':8000" style="color:#a78bfa">Open Ragnar UI &rarr;</a>';
    else rl.textContent='port 8000 (currently stopped)';
  }catch(e){}
}
async function swap(t){
  var btn=document.getElementById(t==='ragnar'?'br':'bp'),msg=document.getElementById('msg');
  btn.disabled=true;btn.textContent='Switching…';msg.className='msg';
  try{
    var d=await(await fetch('/swap/'+t,{method:'POST'})).json();
    msg.innerHTML=d.message||(d.success?'Done!':d.error);
    msg.className='msg show '+(d.success?'ok':'er');
    if(d.success)setTimeout(poll,3000);
    else{btn.disabled=false;btn.innerHTML=LABELS[t];}
  }catch(e){
    msg.innerHTML='Request failed — the service may be mid-restart';
    msg.className='msg show er';
    btn.disabled=false;btn.innerHTML=LABELS[t];
  }
}
poll();setInterval(poll,5000);
</script>
</body>
</html>"""


def _svc_active(name: str) -> bool:
    try:
        r = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() == "active"
    except Exception:
        return False


def _swap(target: str):
    if target not in ("ragnar", "pwnagotchi"):
        return False, "Unknown target"
    try:
        if target == "pwnagotchi":
            subprocess.run(["systemctl", "stop", "ragnar.service"], timeout=30, check=False)
            subprocess.run(["systemctl", "start", "bettercap.service"], timeout=30, check=False)
            subprocess.run(["systemctl", "start", "pwnagotchi.service"], timeout=30)
        else:
            subprocess.run(["systemctl", "stop", "pwnagotchi.service"], timeout=30, check=False)
            subprocess.run(["systemctl", "stop", "bettercap.service"], timeout=30, check=False)
            subprocess.run(["systemctl", "start", "ragnar.service"], timeout=30)
        return True, f"Switched to {target}"
    except Exception as exc:
        return False, str(exc)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/status":
            self._json({"ragnar": _svc_active("ragnar"), "pwnagotchi": _svc_active("pwnagotchi")})
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            body = HTML.encode("utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        path = urlparse(self.path).path
        if path in ("/swap/ragnar", "/swap/pwnagotchi"):
            target = path.split("/")[-1]
            ok, msg = _swap(target)
            self._json({"success": ok, "message": msg})
        else:
            self._json({"error": "not found"}, 404)


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), _Handler)
    print(f"Ragnar Lifeboat on port {PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)

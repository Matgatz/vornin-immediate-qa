#!/usr/bin/env python3
"""Start/stop ONLY the separate reviewed QA Caddy process. Never reload a service/admin API."""
import argparse, hashlib, json, os, signal, subprocess, time
from pathlib import Path
from generate import CADDY_SHA256, isolated, render

def start_ticks(pid):
    return Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[19]

def verify_state(state,validation=False):
    state=Path(state).resolve(strict=True)
    manifest=json.loads((state/"runtime.json").read_text())
    if manifest.get("schemaVersion")!=1 or manifest.get("validationOnly")!=validation:raise ValueError("Wrong state mode")
    if validation and not isolated():raise ValueError("Validation requires loopback-only isolated namespace")
    expected=render(manifest['certificate'],manifest['key'],manifest['fleetSource'],manifest['homeSource'],validation)
    actual=(state/"Caddyfile").read_bytes()
    if actual!=expected.encode() or hashlib.sha256(actual).hexdigest()!=manifest['configSha256']:raise ValueError("Configuration does not equal reviewed generator output")
    return state

def verify_process(state,record):
    pid=record['pid']
    if not isinstance(pid,int) or pid<=1:raise ValueError("Unsafe PID")
    if start_ticks(pid)!=record['startTicks']:raise ValueError("PID was reused")
    exe=Path(f"/proc/{pid}/exe").resolve(strict=True)
    if str(exe)!=record['executable'] or hashlib.sha256(exe.read_bytes()).hexdigest()!=CADDY_SHA256:raise ValueError("Process executable does not match qualified Caddy")
    args=Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")[:-1]
    if args!=[str(exe).encode(),b"run",b"--config",str(state/"Caddyfile").encode(),b"--adapter",b"caddyfile"]:raise ValueError("Process is not this exact standalone configuration")
    return pid

def start(state,caddy,validation=False):
    state=verify_state(state,validation)
    binary=Path(caddy).resolve(strict=True)
    if hashlib.sha256(binary.read_bytes()).hexdigest()!=CADDY_SHA256:raise ValueError("Unqualified Caddy binary")
    if (state/"process.json").exists():raise ValueError("Existing process record; inspect/stop it first")
    env=dict(os.environ,XDG_DATA_HOME=str(state/"data"),XDG_CONFIG_HOME=str(state/"config"))
    subprocess.run([str(binary),"validate","--config",str(state/"Caddyfile"),"--adapter","caddyfile"],env=env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    log=(state/"caddy.log").open("ab")
    proc=subprocess.Popen([str(binary),"run","--config",str(state/"Caddyfile"),"--adapter","caddyfile"],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    log.close()
    record=dict(pid=proc.pid,startTicks=start_ticks(proc.pid),executable=str(binary))
    (state/"process.json").write_text(json.dumps(record)+"\n");(state/"process.json").chmod(0o600)
    return proc

def stop(state,validation=False):
    state=verify_state(state,validation)
    record=json.loads((state/"process.json").read_text())
    pid=verify_process(state,record)
    os.kill(pid,signal.SIGTERM)
    for _ in range(100):
        try:
            fields=Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()
            if fields[0]=='Z':break
            if fields[19]!=record['startTicks']:raise ValueError("PID changed during shutdown")
        except FileNotFoundError:break
        time.sleep(.05)
    else:raise TimeoutError("Exact QA process did not stop; no force-kill issued")
    (state/"process.json").unlink()

def main():
    p=argparse.ArgumentParser();p.add_argument("action",choices=['start','stop']);p.add_argument("--apply",action='store_true',required=True);p.add_argument("--state",required=True);p.add_argument("--caddy",default='/usr/bin/caddy');a=p.parse_args()
    if not Path(a.state).is_absolute():raise ValueError("State path must be absolute")
    if a.action=='start':start(a.state,a.caddy)
    else:stop(a.state)
    print("Standalone owned QA process "+a.action+" complete; no service/firewall changes.")
if __name__=='__main__':main()

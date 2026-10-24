#!/usr/bin/env python3
"""Generate only the reviewed static responder. Real source addresses are runtime input, never source data."""
import argparse, hashlib, ipaddress, json, os, re, socket
from pathlib import Path, PurePosixPath
HERE = Path(__file__).resolve().parent
CADDY_SHA256 = "78ce36f1bee55a4c0a99c49842d89cebef4b4007f0fb30ad2078e1d3120e130f"
PORTS = (18445, 18446)

def isolated():
    return os.environ.get("QA_ASSERT_NO_NETWORK") == "1" and {n for _,n in socket.if_nameindex()} == {"lo"}

def source_address(value, validation=False):
    if not isinstance(value,str) or "/" in value or "%" in value or value != value.strip():
        raise ValueError("Source must be one exact IP address, without prefix, zone or whitespace")
    ip = ipaddress.ip_address(value)
    if getattr(ip,"ipv4_mapped",None) or ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        raise ValueError("Source must be a public single address")
    synthetic = ip in ipaddress.ip_network("192.0.2.0/24") if ip.version == 4 else False
    synthetic |= ip in ipaddress.ip_network("198.51.100.0/24") if ip.version == 4 else False
    if not ip.is_global and not (validation and synthetic and isolated()):
        raise ValueError("Non-public source refused outside isolated synthetic validation")
    return str(ip)

def absolute_file(value):
    if not isinstance(value,str) or not re.fullmatch(r"/[A-Za-z0-9_./-]{1,400}",value) or ".." in PurePosixPath(value).parts:
        raise ValueError("Certificate/key path must be an explicit safe absolute Linux path")
    p = Path(value)
    if not p.is_file(): raise ValueError("Explicit certificate/key file is missing")
    return str(p.resolve())

def render(cert,key,fleet,home,validation=False):
    if validation and not isolated(): raise ValueError("Synthetic validation requires a loopback-only network namespace")
    cert,key = absolute_file(cert),absolute_file(key)
    fleet,home=source_address(fleet,validation),source_address(home,validation)
    if fleet==home: raise ValueError("Fleet and home source addresses must be independently specified")
    config=(HERE/"Caddyfile.in").read_text(encoding="utf-8")
    for old,new in {"@@CERT@@":cert,"@@KEY@@":key,"@@ALLOW@@":"127.0.0.1 ::1 "+fleet+" "+home,"@@BIND@@":"bind 127.0.0.1" if validation else ""}.items():
        config=config.replace(old,new)
    if "@@" in config: raise ValueError("Unfilled template field")
    return config

def create(state,cert,key,fleet,home,validation=False):
    state=Path(state)
    if not state.is_absolute() or state.exists(): raise ValueError("Use a fresh explicit absolute QA state directory")
    config=render(cert,key,fleet,home,validation)
    state.mkdir(mode=0o700,parents=False)
    (state/"Caddyfile").write_bytes(config.encode())
    manifest=dict(schemaVersion=1,ports=list(PORTS),certificate=absolute_file(cert),key=absolute_file(key),fleetSource=source_address(fleet,validation),homeSource=source_address(home,validation),validationOnly=validation,configSha256=hashlib.sha256(config.encode()).hexdigest(),caddySha256=CADDY_SHA256,enforcementTested=False)
    (state/"runtime.json").write_bytes((json.dumps(manifest,indent=2)+"\n").encode())
    for p in (state/"Caddyfile",state/"runtime.json"):p.chmod(0o600)
    return manifest

def main():
    p=argparse.ArgumentParser();p.add_argument("--state",required=True);p.add_argument("--certificate",required=True);p.add_argument("--key",required=True);p.add_argument("--fleet-source",required=True);p.add_argument("--home-source",required=True)
    a=p.parse_args();create(a.state,a.certificate,a.key,a.fleet_source,a.home_source)
    print("Generated fixed-port QA configuration; quota headers are advertisement only, enforcement is not tested.")
if __name__=="__main__":main()

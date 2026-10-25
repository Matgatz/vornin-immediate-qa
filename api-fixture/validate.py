#!/usr/bin/env python3
"""Bounded real Caddy plaintext HTTP validation; refuses any network namespace with a non-loopback interface."""
import argparse, hashlib, http.client, json, os, socket, ssl, subprocess, tempfile, time
from pathlib import Path
from generate import CADDY_SHA256, create, isolated, source_address
from manage import start, stop, verify_process

def request(port,path,method='GET',source='127.0.0.1',spoof=False):
    c=http.client.HTTPConnection('127.0.0.1',port,timeout=3,source_address=(source,0))
    try:
        c.request(method,path,headers={'X-Forwarded-For':'127.0.0.1'} if spoof else {})
        r=c.getresponse();return r.status,{k.lower():v for k,v in r.getheaders()},r.read(2048)
    finally:c.close()

def tls_refused(port):
    # Negative control: an unverifying client so that ANY TLS listener would complete and fail this check.
    c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);c.check_hostname=False;c.verify_mode=ssl.CERT_NONE
    with socket.create_connection(('127.0.0.1',port),timeout=3) as s:
        try:c.wrap_socket(s,server_hostname='qa-api.fixture.invalid').close()
        except (ssl.SSLError,OSError):return True
    raise AssertionError('TLS handshake completed on plaintext QA API port')

def main():
    p=argparse.ArgumentParser();p.add_argument('--caddy',required=True);a=p.parse_args()
    if not isolated():raise RuntimeError('Validation requires Docker --network none: only lo may exist')
    caddy=Path(a.caddy).resolve();assert hashlib.sha256(caddy.read_bytes()).hexdigest()==CADDY_SHA256
    checks=[]
    for bad in ('0.0.0.0/0','192.0.2.10/32','192.0.2.0/24','127.0.0.2','::','fe80::1%lo','localhost','192.0.2.10 198.51.100.20','192.0.2.10;anything'):
        try:source_address(bad,True)
        except ValueError:pass
        else:raise AssertionError('Non-single/public source accepted')
    checks.append('strict-exact-source-parser:9-invalid-inputs-refused')
    with tempfile.TemporaryDirectory(prefix='qa-api-') as tmp:
        root=Path(tmp);cert=root/'qa.crt';key=root/'qa.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1','-keyout',str(key),'-out',str(cert),'-subj','/CN=qa-api.fixture.invalid','-addext','subjectAltName=DNS:qa-api.fixture.invalid'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        key.chmod(0o600)
        state=root/'runtime';create(state,str(cert),str(key),'192.0.2.10','198.51.100.20',True)
        adapted=subprocess.run([str(caddy),'adapt','--config',str(state/'Caddyfile'),'--adapter','caddyfile','--pretty'],check=True,capture_output=True,text=True)
        config=json.loads(adapted.stdout);assert config['admin']['disabled'] is True
        servers=config['apps']['http']['servers'];listens=sorted(x for s in servers.values() for x in s['listen']);assert listens==['127.0.0.1:18445','127.0.0.1:18446'],listens
        assert all(s['automatic_https']['disable'] for s in servers.values())
        assert all(s['protocols']==['h1','h2'] for s in servers.values())
        def handlers(x):
            if isinstance(x,dict):
                if 'handler' in x:yield x['handler']
                for v in x.values():yield from handlers(v)
            elif isinstance(x,list):
                for v in x:yield from handlers(v)
        assert set(handlers(config))<={'subroute','static_response','headers'}
        # The unchanged global 'ocsp_stapling off' still emits an apps.tls automation stub; it must hold no certificates.
        assert 'certificates' not in config['apps'].get('tls',{}) and all(not s.get('tls_connection_policies') for s in servers.values()),'Plaintext build must load no certificate and no TLS connection policy'
        checks.append('adapted-config:admin-off-autoHTTPS-off-exact-ports-no-certificate-no-TLS-policy-no-proxy-no-file-server-no-h3')
        proc=start(state,str(caddy),True)
        try:
            deadline=time.monotonic()+5
            while True:
                if proc.poll() is not None:raise RuntimeError('Standalone Caddy exited during isolated startup')
                try:
                    with socket.create_connection(('127.0.0.1',18445),timeout=.2):break
                except OSError:
                    if time.monotonic()>deadline:raise
                    time.sleep(.05)
            for port in (18445,18446):
                for path in ('/','/api/v1'):
                    status,headers,body=request(port,path);assert status==200 and headers.get('content-type')=='application/json'
                    assert 'strict-transport-security' not in headers and 'location' not in headers
                    payload=json.loads(body);assert payload['enforcement_tested'] is False and payload['quota_advertised']==(port==18446)
                    if port==18445:assert not any(k.startswith('ratelimit') or k.startswith('x-ratelimit') for k in headers)
                    else:assert [headers.get(k) for k in ('ratelimit-limit','ratelimit-remaining','ratelimit-reset')]==['100','99','60']
                for path in ('/unknown-owned-qa-path','/api/v1/unknown'):
                    assert request(port,path)[0]==404
                assert request(port,'/','HEAD')[0]==200
                status,headers,body=request(port,'/api/v1','POST');assert status==405 and headers['allow']=='GET, HEAD'
                assert request(port,'/api/v1',source='127.0.0.2',spoof=True)[0]==403
                assert tls_refused(port)
            checks+=['actual-HTTP:both-root-and-api-v1-200-JSON','actual-HTTP:18445-no-quota-headers-18446-advertisement-only','actual-HTTP:unknown-paths-404-no-soft404','actual-HTTP:HEAD-supported-POST405-no-mutation','actual-HTTP:forbidden-source403-even-with-spoofed-XFF','plaintext-only:TLS-handshake-refused-no-HSTS-no-redirect']
            record=json.loads((state/'process.json').read_text());wrong=dict(record,startTicks='0')
            try:verify_process(state,wrong)
            except ValueError:pass
            else:raise AssertionError('PID identity guard accepted reused PID')
            with socket.socket() as s:assert s.connect_ex(('127.0.0.1',2019))!=0
            checks.append('process-boundary:reused-PID-refused-admin-port-absent')
        finally:
            stop(state,True);proc.wait(timeout=5)
        checks.append('exact-standalone-process-stopped-no-service-operation')
    print(json.dumps(dict(status='qualified-in-isolated-Linux-only',networkInterfaces=[n for _,n in socket.if_nameindex()],caddySha256=CADDY_SHA256,checks=checks,productionListenersStarted=False,firewallChanges=False,rateEnforcementTested=False),indent=2))
if __name__=='__main__':main()

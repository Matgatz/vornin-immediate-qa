# Owned API header-advertisement QA responder

Preparation only. This directory is a candidate for the separately reviewed/committed QA repository, **not an application change**. No production listener, Caddy service reload, firewall rule, deployment or scan is authorized by this file. The parent release operator must review and publish the exact committed artifact first.

The responder has two fixed TLS ports: **18445** returns no quota headers; **18446** returns constant `RateLimit-Limit: 100`, `RateLimit-Remaining: 99`, `RateLimit-Reset: 60`. Both return synthetic 2xx JSON only at `/` and `/api/v1`; unknown paths return404, known paths with mutation methods return405. **These headers advertise a quota only. No rate enforcement is implemented, measured or claimed. Do not flood it or infer enforcement from a header.**

Global admin, automatic HTTPS, config persistence and OCSP stapling are disabled. TLS loads explicitly provided self-signed QA certificate/key files. HTTP/3 is disabled. There is no proxy, backend, external URL, filesystem-serving handler or data mutation. Self-signed chain warnings remain expected and separate from the G02 rate-advertisement case.

Only exact independently checked localhost/current fleet NAT/home source addresses may connect. The strict generator adds `127.0.0.1` and `::1`, then requires one public single IP per fleet/home input; it refuses CIDRs, names, zones, metadata/private/loopback sources, whitespace and injection. Actual public IPs are runtime input and must never enter committed source. `remote_ip` checks the real peer; forwarded headers grant nothing. Firewall admission is a separate parent action and is never changed by these helpers.

## Isolated qualification

The existing installed Caddy was inspected read-only: version **v2.11.2**, SHA-256 **78ce36f1bee55a4c0a99c49842d89cebef4b4007f0fb30ad2078e1d3120e130f**. No Caddy binary is part of this source artifact. Supply an explicit trusted copy for validation. The process helper refuses another binary hash.

Run `bash validate_linux.sh /ABSOLUTE/path/to/qualified-linux-caddy` after the digest-pinned Python image is already cached. It uses Docker `--network none`, no published ports, a read-only filesystem and dropped capabilities. Synthetic TEST-NET input is accepted only in a validated loopback-only namespace. Real Caddy HTTPS checks prove root/API JSON, advertised-versus-absent headers,404 paths,405 mutation methods, source403 despite spoofed XFF, absent admin socket and guarded exact-process cleanup. These tests prove fixture behavior only; they do not establish a deployed scanner result.

## Later controlled run and stop (parent only, from reviewed committed source)

Create a dedicated fresh private state parent. Generate a separate self-signed QA certificate with the exact admitted owned hostname, without touching any production certificate or trust store:

```bash
umask 077
QA_PARENT=/ABSOLUTE/dedicated-qa-api-state
QA_HOSTNAME=YOUR_EXACT_ADMITTED_OWNED_HOSTNAME
mkdir -m 700 "$QA_PARENT"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 2 \
  -keyout "$QA_PARENT/qa.key" -out "$QA_PARENT/qa.crt" \
  -subj "/CN=$QA_HOSTNAME" -addext "subjectAltName=DNS:$QA_HOSTNAME"
python3 generate.py --state "$QA_PARENT/runtime" \
  --certificate "$QA_PARENT/qa.crt" --key "$QA_PARENT/qa.key" \
  --fleet-source "$CURRENT_CHECKED_FLEET_NAT_IP" --home-source "$CURRENT_CHECKED_HOME_IP"
python3 manage.py start --apply --state "$QA_PARENT/runtime" --caddy /usr/bin/caddy
```

No automatic interface discovery or broad CIDR is substituted for the two checked source addresses. The generator requires a fresh output directory and writes a private runtime manifest. Keep runtime state, real addresses, keys, certificates, binary copies and logs outside the committed source. Independently verify the two exact ports and finite paths before creating/scanning admitted QA targets. App-box localhost and local-agent home/fleet NAT are distinct source paths; readiness on one does not prove the others.

Cleanup stops only the PID whose start-time, executable hash and full argv match this exact configuration:

```bash
python3 manage.py stop --apply --state "$QA_PARENT/runtime"
```

The helper never calls `caddy reload`, an admin endpoint, `systemctl`, a firewall tool, `pkill` or a force-kill. It preserves state/evidence and refuses reused or mismatched PIDs. The parent separately removes only its exact admitted QA firewall rules and targets after retaining evidence. Do not remove runtime state until the child has stopped and the resolved directory is checked.

Primary references: [Caddy global options](https://caddyserver.com/docs/caddyfile/options), [request matchers](https://caddyserver.com/docs/caddyfile/matchers#remote-ip). This fixture establishes advertisement behavior, not quota enforcement or general API security.

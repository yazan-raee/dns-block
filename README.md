# DNS Blocker

A small DNS forwarder that blocks names found in a SQLite blocklist and
forwards other questions to an upstream DNS resolver.

## Blocklist database

The server creates `blocklist.db` and the `blocked_domains` table on first
start. Add normalized domain names to the `domain` column, for example:

```sql
INSERT INTO blocked_domains(domain) VALUES ('ads.example');
```

Names are matched case-insensitively after normalization. A blocked name also
blocks its subdomains: an entry for `ads.example` blocks
`track.ads.example`, but not `example`.

## Run

Install the dependency and start the server:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe dnsServer.py --upstream 1.1.1.1
```

It listens on `127.0.0.1:8053` over UDP and TCP and forwards allowed queries
to the upstream resolver you provide. Use `--host 0.0.0.0` to accept queries
from other devices on the network, and configure those devices to use this
computer as their DNS server. Restrict access with your firewall; do not expose
the forwarder to the public internet.

Options:

```text
--database PATH       SQLite file (default: blocklist.db)
--host ADDRESS        Listen address (default: 127.0.0.1)
--port PORT           Listen port (default: 8053)
--upstream ADDRESS    Forwarding resolver (required; for example: 1.1.1.1)
--upstream-port PORT  Forwarding resolver port (default: 53)
--timeout SECONDS     Upstream timeout (default: 3)
```

Blocked names receive an `NXDOMAIN` response. Allowed requests are forwarded
unchanged. Queries that cannot be checked or forwarded receive `SERVFAIL`.

Run tests with:

```powershell
.\.venv\Scripts\python.exe -m unittest
```

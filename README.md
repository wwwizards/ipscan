# ipscan

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Poor Man's IP & Port Scanner** — threaded CIDR-range scanner for active hosts and standard service ports. No nmap required.

Scans one or more subnets for live hosts and open ports (21, 22, 25, 53, 80, 443, 3389, WinRM, RDP, SQL, and more). Assumes `/32` if no CIDR is given. Results include responsive IPs with open ports and a summary of unresponsive hosts.

---

## Prerequisites

- Python 3.8+
- No third-party packages required (stdlib only: `socket`, `ipaddress`, `threading`, `subprocess`)

---

## Usage

```bash
python ipscan.py "192.168.1.0/24"
python ipscan.py "10.0.0.0/16 172.16.0.0/12"
python ipscan.py "10.0.0.1"                    # single host, assumes /32
python ipscan.py "10.0.0.0/24" --threads 128   # more threads for large subnets
python ipscan.py "10.0.0.0/24" --output json   # emit JSON for downstream piping
```

---

## Sample output

```
[+] 10.0.0.1     OPEN: 22 80 443
[+] 10.0.0.5     OPEN: 22 3389
[-] 10.0.0.9     no response
...
```

---

## ⚠️ Legal notice

Unauthorized port scanning is illegal in many jurisdictions. This tool is permitted only on networks you own or have **written authorization** to scan. See [nmap.org/book/legal-issues.html](https://nmap.org/book/legal-issues.html) for a full discussion of the legal landscape.

---

## Version history

See [`legacy/`](legacy/) for earlier versions (v0.3 → v0.5 → v0.8 → v0.9 current).

| Version | Notes |
|---|---|
| v0.9 | current — JSON output, Windows port set, modular refactor |
| v0.8 | RPC/WinRM/NetBIOS ports added |
| v0.5 | multi-threaded |
| v0.3 | original scriptlet |

---

## Roadmap

- [ ] `--output csv` mode
- [ ] Service banner grabbing (http title, ssh version string)
- [ ] Integrate with `converters` package for downstream ETL
- [ ] Web UI wrapper (`ipscan-webify` — see old notes)

---

## License

[MIT](LICENSE) © 2023–2026 [wwwizards](https://github.com/wwwizards)

---

*Documented by [wwwizards/pickaxe](https://github.com/wwwizards/pickaxe)*

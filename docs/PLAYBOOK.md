# Hunt & Response Playbook

How to run this pack, what each hit means, and what to do in the first hours after one. Written for a small SOC or a one-person security team. TLP:CLEAR.

**The mindset:** reported ARTEX intrusions reached privileged access in hours to days. Treat this as a speed problem. Decide in advance who can isolate a host or disable an account, so you're not waiting on approvals after a hit.

---

## 1. Before you hunt (30 minutes)

Know what you can see. Every blind spot here is a blind spot the agent will find first.

- [ ] **Egress logging.** Firewall logs record *allowed* outbound connections, not just denies. If you only log denies, the most important hit (an allowed connection) is invisible.
- [ ] **DNS logging.** Resolver or endpoint DNS queries are kept for at least 30 days.
- [ ] **EDR coverage.** Pull a list of hosts with no EDR sensor. VAPOR PANDA told its agents to find exactly those machines. Fix or flag them now.
- [ ] **Domain controller auditing.** Event IDs 4769 (Kerberos service tickets) and 4662 (directory object access) are being collected, or Defender for Identity is deployed.
- [ ] **Zeek or Suricata** (if you have NDR) sees north-south traffic at the internet edge, not only east-west.
- [ ] **A named person** can isolate a host and disable an account without waiting for a change window.

---

## 2. Run order

| Step | What | Where | Time |
|---|---|---|---|
| 1 | Load block lists inbound + outbound, logging on | Firewall | 15 min |
| 2 | Search 30 days of firewall logs for the IOC list, **action = allow** | Firewall / SIEM | 15 min |
| 3 | `01_ioc_hunt_defender.kql` or `02_ioc_hunt_sentinel_asim.kql` | Defender / Sentinel | 10 min |
| 4 | `beacon_hunt.py` over yesterday's conn.log | Zeek / Security Onion | 10 min |
| 5 | B1 (beaconing) and B2 (machine-speed recon) | Defender | 20 min |
| 6 | B3–B5 (ARTEX markers, BLOODALCHEMY, EDR inventory) | Defender | 20 min |
| 7 | B6–B8 / S1–S2 (Kerberoast, DCSync, LSASS) | Defender / Sentinel | 20 min |
| 8 | S3–S5 (spray, spray-then-success, service principal abuse) | Sentinel / Entra | 20 min |
| 9 | B9 on Linux and web servers | Defender | 10 min |

Steps 1–4 are the minimum. If you only have an hour, do those.

---

## 3. What a hit means

Severity is what to do **now**, not how bad the story sounds.

| Hit | Severity | What it means | First move |
|---|---|---|---|
| **Allowed** outbound connection to a `block_and_hunt` IP or domain | 🔴 Incident | A host on your network talked to known attack infrastructure and the connection succeeded | Isolate the host. Go to section 4 |
| **Allowed** inbound connection from an IOC IP | 🔴 Incident | Attack infrastructure reached a service you expose | Check what it hit and whether it got a response. Treat the service as possibly compromised |
| DNS resolution of a BLOODALCHEMY domain | 🔴 Incident | Something tried to reach C2, even if the connection was blocked | Find the process that made the query. Isolate the host |
| SHA256 match in file events | 🔴 Incident | BLOODALCHEMY is on disk | Isolate the host. Collect memory before reboot if you can |
| DCSync (B7 / S2) from a non-DC | 🔴 Incident | Someone is pulling password hashes for the whole domain | Section 4, plus plan a krbtgt double-reset |
| Denied connection to an IOC (any direction) | 🟡 Investigate | Your controls worked. Something still tried | Find the source host and process. Check it for the behaviors in B1–B9 |
| `beacon_hunt.py` / B1 regular beacon, no IOC match | 🟡 Investigate | Could be C2 on new infrastructure, could be a legit agent or updater | Identify the process. Check how new the destination domain or IP is |
| B2 machine-speed recon | 🟡 Investigate | A script or agent ran a burst of discovery commands | Was it your own automation, RMM or admin tooling? If not, escalate |
| B5 EDR-coverage inventory across many hosts | 🟠 Likely hostile | Someone is mapping which hosts lack security tools | Escalate. This is pre-attack staging |
| B6 / S1 Kerberoasting | 🟠 Likely hostile | Service-account passwords are being harvested for offline cracking | Rotate the targeted service-account passwords. Find the source |
| B8 LSASS access | 🟠 Likely hostile | Credential dumping | Isolate. Reset credentials of everyone logged on to that host |
| B9 web server pulling tools with curl/wget/nc | 🟠 Likely hostile | Web shell or RCE followed by tool download | Isolate. Preserve web logs. Look for the initial exploit |
| S4 successful sign-in from a spraying IP | 🔴 Incident | A sprayed password worked | Disable the account, revoke sessions, reset, check MFA registration changes |
| Hit on a `hunt_only` IP (VPN exits) | ⚪ Context | Commercial VPN. Only meaningful on Oct 15–16 2026 with ConnectWise app activity | Correlate. Don't escalate on this alone |

### Common false positives

- **B1 / beacon scorer:** EDR and AV agents, backup software, Windows Update, Teams and Zoom keepalives, monitoring agents. These usually have high fan-in (many of your hosts talk to them). Raise `--max-fanin` or exclude known-good processes.
- **B2:** IT admins running onboarding scripts, RMM tools (ConnectWise, NinjaOne, Kaseya), vulnerability scanners. Learn what your own automation looks like.
- **B4:** OBS Studio and game overlays legitimately load `graphics-hook` DLLs. The tell is a renamed `svchost.exe` outside System32.
- **B5:** Your own asset inventory or EDR deployment tooling. Check the account.
- **Suricata HeadlessChrome / python-requests rules:** uptime monitors, SEO crawlers, your own integration tests. Scope `$HTTP_SERVERS` and suppress known sources.
- **LLM API egress rules:** developers and your own AI tooling. Scope these rules to server subnets only.

---

## 4. First hours after a 🔴 hit

Speed matters more than perfection. Do these in order.

**Hour 0–1: contain**
1. **Isolate the host** with your EDR's network containment. Don't power it off: you lose memory evidence.
2. **Disable the logged-on user's account** and revoke sessions (Entra: *Revoke sessions*; on-prem: disable plus reset).
3. **Block the destination** at the firewall if it isn't already.
4. **Start a timeline** with timestamps: first hit, who did what, when.

**Hour 1–4: scope**

5. **Pivot on the IOC.** Run `01` with `lookback = 90d`. Any other hosts?
6. **Pivot on the account.** Where else did it log on? Run S4 and B5 for that account.
7. **Pivot on behavior.** Run B2, B6, B7 and B8 for the affected host and account.
8. **Check cloud.** Run S5 for new service principal credentials and S6 for AWS. Storm-0940 went straight for cloud control planes.
9. **Collect evidence:** memory image, EDR timeline, firewall and proxy logs, Zeek logs for the host's IP.

**Hour 4–24: eradicate**

10. **Rotate credentials** in widening circles: affected users, then service accounts on the host, then anything that host had access to. If DCSync fired, reset krbtgt twice, 10+ hours apart.
11. **Rotate API keys and secrets,** including old ones in backups and exports. VAPOR PANDA reused a 2022 mail export and a 2024 leaked VPN key.
12. **Rebuild compromised hosts** rather than cleaning them.
13. **Report.** Regulated industries (finance, healthcare) often have notification clocks measured in hours. Talk to counsel early.

---

## 5. Keep it current

The IOCs here rot in days to weeks. The behavior hunts don't.

- **Weekly:** re-run steps 2–5 of the run order.
- **When new reporting drops:** add rows to `iocs.csv` (with source URL and dates), run `python3 build.py`, and reload your firewall feeds, Zeek intel and Suricata rules.
- **Firewall EDLs:** if you host `feeds/edl_block_ipv4.txt` yourself, set your firewall to refresh it hourly.
- **Watch this repo** for updates, or open a PR with indicators you've confirmed.

---

## 6. Contributing

Found a new indicator, a false positive, or a better query?

- **New IOCs:** open a PR that adds rows to `iocs.csv` with a public source URL. No source, no merge.
- **Query fixes:** if a column name differs in your tenant, a PR with the fix helps everyone.
- **False positives:** open an issue describing the benign software. We'll add tuning notes.

Please don't submit indicators from private or TLP:AMBER+ sharing groups.

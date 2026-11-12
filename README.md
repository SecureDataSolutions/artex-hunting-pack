# ARTEX / CyberStrikeAI Hunting Pack

**TLP:CLEAR · Compiled 2026-11-08 by Eddie Espino, [Secure Data Solutions](https://www.sdsitgroup.com) · MIT licensed. Use it, share it, fork it.**

Offensive AI agent frameworks (ARTEX, CyberStrikeAI, PentAGI and others) are in real intrusions now. The agent is new. The traffic isn't. Planning happens on the attacker's server, execution happens on your network, and the implant still has to call home. This pack gives you published indicators in formats your tools already eat, plus behavior hunts that keep working after the IPs rotate.

> **New here? Start with the [Hunt & Response Playbook](docs/PLAYBOOK.md).** It covers what to check before you hunt, the order to run things in, what each hit means, and what to do in the first hours after one.

## What's in here

| Path | What it is | Drop it into |
|---|---|---|
| `iocs.csv` | Every indicator with source, campaign, confidence, first/last seen and a block vs. hunt-only action | Anything. This is the source of truth |
| `feeds/edl_block_ipv4.txt` | 48 single IPs plus 22 CIDR blocks (250 addresses in two Check Point ARTEX C&C ranges), one per line | Palo Alto EDL, FortiGate External Threat Feed, Cisco FMC Security Intelligence |
| `feeds/edl_block_ipv4_ranges.txt` | Same block list, with the CIDR blocks written as first-last ranges (`38.11.173.1-38.11.173.125`) | Check Point Custom Intelligence Feed (its docs list hyphen ranges, not CIDR) or any feed that takes ranges |
| `feeds/edl_block_domains.txt` | BLOODALCHEMY C2 domains | DNS firewall / RPZ, proxy, URL EDL |
| `feeds/hunt_only_ipv4.txt` | 38 IPs. **Do not block.** Commercial VPN exits (only meaningful Oct 15–16, 2026 with ConnectWise app context), a Tor exit, unattributed scan-observed ARTEX hosts, and sources published for hunting only (Datadog, Unit 42) | SIEM lookups |
| `feeds/sha256.txt` | BLOODALCHEMY loader, payload and side-load host | EDR custom IOCs |
| `feeds/artex_intel.dat` | Zeek Intel framework file | Zeek / Security Onion / Corelight |
| `suricata/artex_ioc.rules` | IP reputation (both directions), DNS and TLS SNI for the IOCs | Suricata 7+ (validated: 16 rules load, 0 fail) |
| `suricata/artex_behavior.rules` | Hunting-grade: inbound agent scanners, web servers pulling ELFs, LLM API egress from servers | Suricata 7+ |
| `zeek/artex_intel.zeek` | Loads the intel file, notices on LLM API egress from server subnets | Zeek `local.zeek` |
| `zeek/beacon_hunt.py` | Scores beaconing in conn.log (TSV/JSON/.gz) and flags IOC traffic. No dependencies | Any box with Python 3.8+ |
| `kql/01_ioc_hunt_defender.kql` | IOC hunt across network, DNS and file events. Splits **allowed** from blocked | Defender XDR Advanced Hunting |
| `kql/02_ioc_hunt_sentinel_asim.kql` | Same IOCs across every ASIM network source (firewalls, NSG, Zeek…) | Sentinel |
| `kql/03_behavior_hunts_defender.kql` | 9 behavior hunts: beaconing, machine-speed recon, ARTEX host markers, BLOODALCHEMY side-load, EDR-coverage inventory, Kerberoast, DCSync, LSASS, web servers pulling tools | Defender XDR |
| `kql/04_identity_and_dc_hunts_sentinel.kql` | Raw 4769/4662, spray-then-success, SP credential abuse, AWS ARTEX markers | Sentinel |
| `build.py` | Regenerates every feed, rule and IOC query from `iocs.csv`. Types: `ipv4`, `ipv4_range` (CIDR, or a first-last range that is converted to the exact CIDR cover), `domain`, `sha256`, `user_agent` | Edit the CSV, run this |
| `docs/PLAYBOOK.md` | Pre-hunt checklist, run order, hit severity table, false positives, first-hours response | Your team |

## Quick start (pick your lane)

**Firewall team (15 minutes).** Point your EDL / external feed at `edl_block_ipv4.txt` and `edl_block_domains.txt`. Block **inbound and outbound**, and log every hit. Then search the last 30 days of firewall logs for the same list with action = allow. An allow is an incident. A deny is a good day.

**NDR / Zeek / Security Onion.** Load `artex_intel.dat`, drop both Suricata rule files in, then run the beacon scorer over yesterday's logs:

```bash
python3 zeek/beacon_hunt.py /nsm/zeek/logs/$(date -d yesterday +%F)/conn.*.log.gz
```

It prints IOC traffic first (any direction), then the most regular low-fan-in outbound pairs. Exit code 1 means something was flagged, so you can cron it. On test data it caught a ±10% jittered 60-second beacon and a ±40% jittered 5-minute C2 callback while suppressing 3,000 browsing flows and a 40-host CDN heartbeat.

**Defender XDR.** Run `01` for IOCs, then `03` B1 (beaconing) and B2 (machine-speed recon). Those two find agent activity regardless of which infrastructure it runs from.

**Sentinel without MDI.** Run `02` and `04`.

## Why behavior beats the list

Microsoft says it plainly: these actors rotate through proxies and VPNs, and an agent will change its user agent the moment it gets blocked. The IOCs here have a shelf life of days to weeks. What doesn't change:

- **The implant has to beacon.** Regular rhythm, rare destination, few internal talkers. (`B1`, `beacon_hunt.py`)
- **Agents move at machine speed.** CrowdStrike saw ARTEX run 27 events in 23 seconds. Humans don't run a dozen distinct recon commands in one minute. (`B2`)
- **The end goal is still AD.** Kerberoasting, LSASS dumps, DCSync. Same detections as always, they just have to fire and get worked faster. (`B6`–`B8`, `S1`–`S2`)
- **The operator checks for your EDR.** VAPOR PANDA told its agents to find hosts without CrowdStrike Falcon. Fleet-wide `tasklist` and security-folder listings from one account are a tell. (`B5`) Also: get your sensor coverage gaps closed, because the attacker is already mapping them.
- **Speed is the real change.** Microsoft measured under 3 hours from first targeting to privileged cloud access. Reporting on CyberStrikeAI shows foothold to domain admin in days. Containment playbooks measured in days lose.

## Cheap wins Microsoft and CrowdStrike call out

- MFA and patching on exposed systems. Reporting ties the breaches that *didn't* happen to exactly these.
- Rotate keys and service credentials after any exposure, including ones sitting in old backups and directory exports. VAPOR PANDA used a 2022 mail-server export and a 2024 leaked VPN key.
- Enforce SAML signature validation and IMDSv2. Least-privilege multi-tenant OAuth apps.
- Honeypots, decoys and tarpits. Microsoft found these pull autonomous agents off real assets and burn their token budget, and the hits are high-confidence by definition.

## Check your own exposure

Censys counted 1,465 internet-exposed ARTEX consoles as of Nov 4, 2026, with roughly 650 in two identically configured hosting blocks, and noted some belong to authorized testers. If you run ARTEX or similar for red teaming, it does not need to be internet-facing. Scan your own ranges. The CrowdStrike-linked server exposed its open directory on port 18899, and identical HTTP fingerprints (ETag / Content-Length) across hosts point to a shared image or template.

## Sources

- CrowdStrike: [Unknown Threat Actor Uses AI-Driven ARTEX to Target South Korean Finance](https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/) (Oct 7, 2026)
- CrowdStrike: [VAPOR PANDA Uses AI-Driven ARTEX to Scale a Global Espionage Campaign](https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/) (Oct 29, 2026)
- Microsoft: [AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/) (Oct 21, 2026)
- Microsoft: [ARTEX abuse expands as cybercriminals target financial sector](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/) (Nov 6, 2026)
- Censys: *ARTEX: Agentic Asbestos* (Nov 5, 2026), via [coverage](https://letsdatascience.com/news/censys-finds-1465-exposed-hosts-running-artex-ai-pentesting-58bf3ec9)
- Microsoft: [Threat actors use agentic AI tooling to find and abuse exposed secrets](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/) (Nov 5, 2026)
- Datadog Security Labs: [On the hunt for ARTEX: understanding agentic attacks in AWS environments](https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/) (Nov 9, 2026)
- Palo Alto Unit 42: [Activity using ARTEX agentic AI](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-10-30-activity-using-ARTEX-agentic-AI.txt) (Oct 30, 2026), cited in [ARTEX and AI-Powered Red Teaming Tools](https://unit42.paloaltonetworks.com/artex-and-ai-powered-red-teaming-tools/) (Nov 11, 2026)
- Team Cymru CyberStrikeAI findings, via [BleepingComputer](https://www.bleepingcomputer.com/news/security/cyberstrikeai-tool-adopted-by-hackers-for-ai-powered-attacks/)

## Known caveats

- Microsoft's Nov 6 post lists `178.16.54.129` in its IOC table but `178.15.54.129` in its own ASIM query. Both are in the feed; one is a typo.
- `212.11.64.250` (CyberStrikeAI) was last seen running the tool on Jan 30, 2026. Treat as historical.
- Behavior rules are hunting-grade. Expect noise until you scope `$HOME_NET`, `$HTTP_SERVERS` and the server subnets in `artex_intel.zeek`.
- KQL was reviewed against the published table schemas but not executed against a live tenant. If a column name differs in yours, it's a one-word fix. PRs welcome.

## Need a hand?

Running a hunt like this is straightforward when you have the logging, the sensor coverage and the time. Most teams are missing at least one.

The SDS engineering team does **Threat Exposure & Defense Engineering**. For agentic threats that means:

- **Hunt sweep:** we run this pack and our own behavior analytics across your firewall, NDR, EDR and identity logs, and tell you what we found and what it means
- **Visibility gaps:** where an agent could operate without you seeing it, starting with egress logging, EDR coverage and domain controller auditing
- **Detection engineering:** deploy and tune these rules and queries for your environment so they alert on real activity, not noise
- **Incident support:** if you already have a hit, help with scoping, containment and credential rotation

Based in South Florida, working nationally. **[sdsitgroup.com](https://www.sdsitgroup.com)** · (754) 357-8179

The pack stays free either way. If it helped you, a ⭐ helps other defenders find it.

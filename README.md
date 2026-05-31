# Silent-Firewall-hardened-nftables-host-firewall

> A single-file, idempotent nftables firewall for Debian/Ubuntu hosts. Default-deny inbound, rate-limited SSH, four hardening profiles, and serious lockout protection: timed auto-rollback plus an optional connectivity self-test that reverts automatically if something breaks.

![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-blue)
![Shell](https://img.shields.io/badge/shell-bash-green)
![Firewall](https://img.shields.io/badge/firewall-nftables-orange)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

Run it interactively and it walks you through everything; run it with flags (or `--yes`) for unattended provisioning. It never leaves you locked out of a remote box without a fight — and if it can't confirm you still have access, it puts the old rules back.

---

## Contents

- [Why](#why)
- [Modes](#modes)
- [Lockout protection](#lockout-protection)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [Examples](#examples)
- [What the ruleset does](#what-the-ruleset-does)
- [Operations](#operations)
- [File layout](#file-layout)
- [Uninstall](#uninstall)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Why

`ufw` and raw `nft` both leave gaps: ufw hides the ruleset behind its own abstraction, and hand-written nft files are easy to get subtly wrong (and easy to lock yourself out with). Silent Firewall generates a clean, readable `inet filter` ruleset for a chosen threat profile, validates it in the kernel before applying, and guards every apply with rollback so a bad rule on a remote host doesn't strand you.

---

## Modes

| Mode | Inbound policy | Ping | Notes |
|------|----------------|------|-------|
| **paranoid** | deny all except rate-limited SSH | blocked | Also drops mDNS/SSDP/LLMNR/NetBIOS **inbound and outbound** — the host stops announcing itself |
| **balanced** | deny except SSH | allowed | Sensible default for most hosts |
| **server** | balanced + chosen ports | allowed | Detects listening services and lets you pick which stay open |
| **vpn** | allow only SSH + WireGuard | allowed | Opens a single WireGuard UDP port and nothing else |

Every mode: loopback accepted, established/related accepted, invalid dropped, essential ICMP/ICMPv6 (and IPv6 neighbor discovery) accepted, forward chain default-drop, and SSH rate-limited per source IP.

---

## Lockout protection

This is the point of the tool, so it has several layers:

- **SSH port auto-detection** — reads the port of your current SSH session (`SSH_CONNECTION`) so the rule matches the connection you're actually on.
- **Pre-flight sshd check** — confirms sshd is really listening on the port you're about to open; warns if not (an open port with no daemon is still no access).
- **Kernel validation** — `nft -c` checks the ruleset before anything is applied; a bad ruleset is never committed.
- **Timed auto-rollback** (interactive) — after applying, you have N seconds to type `keep`. No confirmation → the previous ruleset is restored automatically by a background timer.
- **Connectivity self-test** (optional) — measures DNS + outbound TCP (and IPv6 if present) *before* applying, re-tests after, and reverts automatically if something that worked now fails. This is the main safety net for non-interactive runs.
- **SSH source CIDR warnings** — if you restrict SSH by source, it reminds you that your current client IP must fall inside the allowed range.

> In non-interactive mode (`--yes` / no TTY) the timed rollback is disabled — nobody can type `keep` — so the ruleset commits immediately. Validate your flags first, and consider pairing `--yes` with `--health-check`.

---

## Requirements

| | |
|---|---|
| OS | Ubuntu or Debian (or `ID_LIKE=debian`) |
| Privileges | root (`sudo`) |
| Packages | `nftables`, `iproute2` — installed automatically if missing |

`python3` is used opportunistically for strict CIDR validation; if absent, a bounds-checked regex is used instead.

---

## Quick start

```bash
git clone https://github.com/Drejelt/Silent-Firewall-hardened-nftables-host-firewall.git
cd Silent-Firewall-hardened-nftables-host-firewall
sudo ./install.sh
```

Preview without changing anything:

```bash
sudo ./install.sh --dry-run
```

Re-running is safe — it reuses saved config and re-applies the rules.

---

## CLI reference

```
sudo ./install.sh [options]

  -y, --yes               Non-interactive; use flags / saved config / defaults
      --mode MODE         paranoid | balanced | server | vpn
      --ssh-port N        SSH port to keep open
      --ssh-cidr "C ..."  Restrict SSH to source CIDR(s); "any" = open to all
      --keep-tcp "P ..."  Extra TCP ports to open (server mode)
      --keep-udp "P ..."  Extra UDP ports to open (server mode)
      --wg-port N         WireGuard UDP port (vpn mode)
      --rollback N        Auto-rollback seconds (0 disables; interactive only)
      --ssh-rate R        SSH new-connection rate, e.g. 10/minute
      --ssh-burst N       SSH rate burst (packets)
      --allow-dhcp        Allow DHCP/DHCPv6 client traffic
      --no-dhcp           Do not allow DHCP client traffic
      --log-drops         Log dropped inbound packets (rate-limited)
      --no-log-drops      Do not log dropped packets
      --health-check      Post-apply connectivity self-test; auto-revert on regression
      --no-health-check   Disable the connectivity self-test
      --hc-dns NAME       Hostname to resolve for the DNS probe (def: cloudflare.com)
      --hc-tcp HOST:PORT  Outbound TCP probe target (def: 1.1.1.1:443)
      --hc-tcp6 [v6]:PORT IPv6 TCP probe target (def: [2606:4700:4700::1111]:443)
      --dry-run           Build & validate the ruleset, show it; apply nothing
      --report            Print saved/effective config and live status; change nothing
      --uninstall         Flush rules, disable persistence, remove state
  -h, --help              Show this help
```

Precedence for every setting: **CLI flag → saved config (`/etc/silent-firewall.conf`) → built-in default.**

---

## Examples

```bash
# Interactive, guided setup
sudo ./install.sh

# Balanced profile, unattended, with a connectivity self-test
sudo ./install.sh --yes --mode balanced --ssh-port 22 --health-check

# Lock SSH to an office range + your current IP, paranoid profile
sudo ./install.sh --yes --mode paranoid --ssh-cidr "203.0.113.0/24 198.51.100.7/32"

# Server with a web stack open
sudo ./install.sh --yes --mode server --ssh-port 2222 --keep-tcp "80 443"

# VPN box: only SSH + WireGuard on a custom port
sudo ./install.sh --yes --mode vpn --wg-port 51820

# Preview the generated ruleset, change nothing
sudo ./install.sh --dry-run --mode server --keep-tcp "80 443"

# Inspect what's configured and live
sudo ./install.sh --report
```

---

## What the ruleset does

The generated `table inet filter` (single table for IPv4 + IPv6) contains:

- **input** (policy drop): accept loopback; block spoofed loopback addresses arriving on other interfaces; accept established/related; drop invalid; essential ICMP + IPv6 neighbor discovery; ping (allowed except paranoid, rate-limited); SSH on your port, rate-limited per source IP (optionally restricted by CIDR); any extra TCP/UDP ports you opened; paranoid also silently drops discovery multicast; optional rate-limited logging of whatever hits the drop policy.
- **forward** (policy drop): nothing forwarded — this is a host firewall, not a router.
- **output** (policy accept): normally open; paranoid additionally blocks the host's own mDNS/SSDP/LLMNR/NetBIOS and multicast chatter.

The full ruleset is printed before it's applied, validated with `nft -c`, then written to `/etc/nftables.conf` and enabled via `nftables.service` so it survives reboot.

---

## Operations

```bash
# See the live ruleset
sudo nft list ruleset

# Effective config + live status (read-only)
sudo ./install.sh --report

# Watch dropped packets (only if --log-drops was on)
journalctl -k | grep 'silent-fw'

# Re-apply after editing the saved config
sudo ./install.sh --yes
```

Backups of the live ruleset are written to `/var/backups/silent-firewall/` before every apply (timestamped), and each backup is prefixed with `flush ruleset` so restoring it cleanly replaces the current state.

---

## File layout

| Path | Purpose |
|------|---------|
| `/etc/silent-firewall.conf` | Saved settings (mode, ports, options) — mode `600` |
| `/etc/silent-firewall.state` | Idempotency markers |
| `/etc/nftables.conf` | The persisted, active ruleset |
| `/var/backups/silent-firewall/` | Timestamped pre-apply ruleset backups |
| `/var/log/silent-firewall-install.log` | Install log (ANSI stripped) |
| `/run/silent-firewall.committed` | Internal flag that cancels the rollback timer |

---

## Uninstall

```bash
sudo ./install.sh --uninstall
```

This flushes all nftables rules, writes a minimal valid config so a reboot won't re-apply old rules, disables `nftables.service`, and removes the state/config files. Backups and the log are kept.

> After uninstall the host has **no firewall** — all traffic is allowed. The interactive uninstall requires typing `remove` to confirm.

---

## Troubleshooting

**Locked out after restricting SSH by CIDR.**
Your client IP wasn't inside the allowed range. If you used the timed rollback (interactive), it already reverted. Otherwise restore the last backup: `sudo nft -f /var/backups/silent-firewall/<latest>.nft`.

**Non-interactive run reverted my connectivity.**
That's `--health-check` doing its job: something that worked before the apply broke after, so it restored the previous ruleset. Re-check your `--keep-*` / `--ssh-*` flags.

**`--report` shows the table as absent.**
The ruleset isn't loaded. Run the script (or `sudo systemctl start nftables`) and check `journalctl -u nftables`.

**fail2ban is installed.**
It's detected and noted only — there's no integration. The nft SSH rate-limit overlaps harmlessly with fail2ban; you can lower `--ssh-rate`/`--ssh-burst` or rely on fail2ban if you prefer.

**Preview before committing on a remote host.**
Always start with `--dry-run` to read the exact ruleset, then apply interactively so the rollback timer protects you.

---

## License

MIT — see the [LICENSE](LICENSE) file.

> ⚠️ A misconfigured firewall on a remote host can lock you out. Use `--dry-run` first, keep an out-of-band console (provider KVM/serial) available, and prefer interactive runs with rollback when you're not certain. Provided "as is", without warranty.

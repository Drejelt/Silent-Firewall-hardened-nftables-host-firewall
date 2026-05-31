#!/bin/bash
# ============================================================
#  Silent Firewall: hardened nftables host firewall
#  Debian / Ubuntu
#  Idempotent: re-running reuses saved config and re-applies rules.
#
#  Interactive:     sudo ./silent-firewall.sh
#  Non-interactive: sudo ./silent-firewall.sh --yes --mode balanced ...
#  Uninstall:       sudo ./silent-firewall.sh --uninstall
# ============================================================

set -euo pipefail

# ── Config paths ─────────────────────────────────────────────
STATE_FILE="/etc/silent-firewall.state"
CONFIG_FILE="/etc/silent-firewall.conf"
LOG_FILE="/var/log/silent-firewall-install.log"

NFT_CONF="/etc/nftables.conf"
BACKUP_DIR="/var/backups/silent-firewall"
COMMIT_FLAG="/run/silent-firewall.committed"

COMPONENTS="packages ssh_port mode keep_ports options ruleset persist"

# Grace window so the foreground confirm always wins the race with
# the background auto-rollback timer (fix for the equal-timeout race).
ROLLBACK_GRACE=8

# ── Colors ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }
skip()    { echo -e "${CYAN}[~]${NC} $1 — already configured, skipping"; }
header()  { echo -e "\n${BOLD}${BLUE}══ $1 ══${NC}"; }

# ── Validators ───────────────────────────────────────────────
is_uint()    { [[ "$1" =~ ^[0-9]+$ ]]; }
valid_port() {
    is_uint "$1" || return 1
    local n=$((10#$1))            # normalize leading zeros, avoid octal in (( ))
    (( n >= 1 && n <= 65535 ))
}
norm_port()  { is_uint "$1" && echo "$((10#$1))" || echo "$1"; }
is_rate()    { [[ "$1" =~ ^[0-9]+/(second|minute|hour|day)$ ]]; }
valid_cidr() {
    local c="$1"
    # Prefer Python's ipaddress for fully correct host/prefix validation.
    if command -v python3 >/dev/null 2>&1; then
        if python3 - "$c" <<'PY' 2>/dev/null
import ipaddress, sys
s = sys.argv[1]
try:
    ipaddress.ip_network(s, strict=False) if '/' in s else ipaddress.ip_address(s)
except Exception:
    sys.exit(1)
PY
        then return 0; else return 1; fi
    fi
    # Fallback: bounds-checked regex (rejects e.g. 999.999.999.999/99).
    if [[ "$c" == *:* ]]; then
        [[ "$c" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]] || return 1
        local p6="${c#*/}"; [ "$p6" = "$c" ] && p6=128
        [[ "$p6" =~ ^[0-9]+$ ]] && (( 10#$p6 <= 128 ))
    else
        [[ "$c" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(/([0-9]{1,2}))?$ ]] || return 1
        local o p="${BASH_REMATCH[6]:-32}"
        for o in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
            (( 10#$o <= 255 )) || return 1
        done
        (( 10#$p <= 32 ))
    fi
}

# ── Defaults (overridable by saved config, then CLI flags) ───
DEF_MODE="balanced"
DEF_WG_PORT="51820"
DEF_ROLLBACK="60"
DEF_SSH_RATE="10/minute"
DEF_SSH_BURST="5"
DEF_ALLOW_DHCP="no"
DEF_LOG_DROPS="no"
DEF_HEALTH_CHECK="no"
DEF_HC_DNS="cloudflare.com"
DEF_HC_TCP="1.1.1.1:443"
DEF_HC_TCP6="[2606:4700:4700::1111]:443"

# CLI overrides (empty = not provided)
CLI_MODE=""; CLI_SSH_PORT=""; CLI_SSH_CIDR=""; CLI_KEEP_TCP=""; CLI_KEEP_UDP=""
CLI_WG_PORT=""; CLI_ROLLBACK=""; CLI_SSH_RATE=""; CLI_SSH_BURST=""
CLI_ALLOW_DHCP=""; CLI_LOG_DROPS=""
CLI_HEALTH_CHECK=""; CLI_HC_DNS=""; CLI_HC_TCP=""; CLI_HC_TCP6=""
ASSUME_YES=0
DO_UNINSTALL=0
DRY_RUN=0
DO_REPORT=0

usage() {
    cat <<USAGE
Silent Firewall — hardened nftables host firewall (Debian/Ubuntu)

Usage: sudo $0 [options]

  -y, --yes               Non-interactive; use flags / saved config / defaults
      --mode MODE         paranoid | balanced | server | vpn
      --ssh-port N        SSH port to keep open
      --ssh-cidr "C ..."  Restrict SSH to source CIDR(s); "any" = open to all
      --keep-tcp "P ..."  Extra TCP ports to open (server mode)
      --keep-udp "P ..."  Extra UDP ports to open (server mode)
      --wg-port N         WireGuard UDP port (vpn mode)
      --rollback N        Auto-rollback seconds (0 disables; interactive only)
      --ssh-rate R        SSH new-conn rate, e.g. 10/minute
      --ssh-burst N       SSH rate burst (packets)
      --allow-dhcp        Allow DHCP/DHCPv6 client traffic
      --no-dhcp           Do not allow DHCP client traffic
      --log-drops         Log dropped inbound packets (rate-limited)
      --no-log-drops      Do not log dropped packets
      --health-check      Post-apply connectivity self-test; auto-revert on regression
      --no-health-check   Disable the connectivity self-test
      --hc-dns NAME       Hostname to resolve for the DNS probe (def: cloudflare.com)
      --hc-tcp HOST:PORT  Target for the outbound TCP probe (def: 1.1.1.1:443)
      --hc-tcp6 [v6]:PORT Target for the IPv6 TCP probe (def: [2606:4700:4700::1111]:443)
      --dry-run           Detect, build & validate the ruleset, show it; apply nothing
      --report            Print the saved/effective config and live status; change nothing
      --uninstall         Flush rules, disable persistence, remove state
  -h, --help              Show this help

In non-interactive mode the timed rollback is disabled (no one can confirm),
so the ruleset is committed immediately — validate your flags first.
USAGE
}

# ── Parse CLI ────────────────────────────────────────────────
while [ $# -gt 0 ]; do
    case "$1" in
        -y|--yes)        ASSUME_YES=1 ;;
        --mode)          CLI_MODE="${2:-}"; shift ;;
        --ssh-port)      CLI_SSH_PORT="${2:-}"; shift ;;
        --ssh-cidr)      CLI_SSH_CIDR="${2:-}"; shift ;;
        --keep-tcp)      CLI_KEEP_TCP="${2:-}"; shift ;;
        --keep-udp)      CLI_KEEP_UDP="${2:-}"; shift ;;
        --wg-port)       CLI_WG_PORT="${2:-}"; shift ;;
        --rollback)      CLI_ROLLBACK="${2:-}"; shift ;;
        --ssh-rate)      CLI_SSH_RATE="${2:-}"; shift ;;
        --ssh-burst)     CLI_SSH_BURST="${2:-}"; shift ;;
        --allow-dhcp)    CLI_ALLOW_DHCP="yes" ;;
        --no-dhcp)       CLI_ALLOW_DHCP="no" ;;
        --log-drops)     CLI_LOG_DROPS="yes" ;;
        --no-log-drops)  CLI_LOG_DROPS="no" ;;
        --health-check)    CLI_HEALTH_CHECK="yes" ;;
        --no-health-check) CLI_HEALTH_CHECK="no" ;;
        --hc-dns)        CLI_HC_DNS="${2:-}"; shift ;;
        --hc-tcp)        CLI_HC_TCP="${2:-}"; shift ;;
        --hc-tcp6)       CLI_HC_TCP6="${2:-}"; shift ;;
        --dry-run)       DRY_RUN=1 ;;
        --report)        DO_REPORT=1 ;;
        --uninstall)     DO_UNINSTALL=1 ;;
        -h|--help)       usage; exit 0 ;;
        *)               echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
    shift
done

# ── Interactivity: TTY present and not --yes ─────────────────
if [ "$ASSUME_YES" -eq 1 ] || [ ! -t 0 ] || [ "$DRY_RUN" -eq 1 ] || [ "$DO_REPORT" -eq 1 ]; then
    INTERACTIVE=0
else
    INTERACTIVE=1
fi

# ── Logging: color on terminal, ANSI stripped in the log file ─
# Read-only modes (dry-run / report) don't touch the install log.
if [ "$DRY_RUN" -eq 0 ] && [ "$DO_REPORT" -eq 0 ]; then
    mkdir -p "$(dirname "$LOG_FILE")"
    exec > >(tee >(sed -u 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE")) 2>&1
fi
echo ""
echo "════ Start: $(date '+%Y-%m-%d %H:%M:%S') ════"

# ── Cleanup + error traps ────────────────────────────────────
RULES_FILE=""
cleanup() { [ -n "${RULES_FILE:-}" ] && rm -f "$RULES_FILE" 2>/dev/null || true; }
trap cleanup EXIT
trap 'error "Error on line $LINENO: $BASH_COMMAND"' ERR

# ── Root check ───────────────────────────────────────────────
[ "$EUID" -ne 0 ] && error "Run this script as root: sudo $0"

# ── Distro check ─────────────────────────────────────────────
if [ -f /etc/os-release ]; then
    source /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" && "${ID_LIKE:-}" != *"debian"* ]]; then
        error "Only Ubuntu/Debian are supported. Detected: $ID"
    fi
else
    error "Could not determine the distribution"
fi
PRETTY_NAME="${PRETTY_NAME:-${NAME:-$ID}}"

# ── State (atomic, same-filesystem temp) ─────────────────────
[ "$DRY_RUN" -eq 0 ] && [ "$DO_REPORT" -eq 0 ] && { touch "$STATE_FILE"; chmod 600 "$STATE_FILE"; }
is_done()   { grep -q "^$1=done$" "$STATE_FILE" 2>/dev/null; }
mark_done() {
    [ "$DRY_RUN" -eq 1 ] && return 0      # dry-run never mutates state
    local tmp; tmp="$(mktemp "${STATE_FILE}.XXXXXX")"
    grep -v "^$1=" "$STATE_FILE" > "$tmp" 2>/dev/null || true
    echo "$1=done" >> "$tmp"
    chmod 600 "$tmp"
    mv -f "$tmp" "$STATE_FILE"          # atomic: same directory/filesystem
}

# ══════════════════════════════════════════════════════════════
# UNINSTALL
# ══════════════════════════════════════════════════════════════
if [ "$DO_UNINSTALL" -eq 1 ]; then
    header "Uninstall"
    warn "This flushes ALL nftables rules and disables persistence."
    warn "The host will be left with NO firewall (all traffic allowed)."
    if [ "$INTERACTIVE" -eq 1 ]; then
        read -rp "  Type 'remove' to proceed: " _U
        [ "$_U" = "remove" ] || { info "Aborted."; exit 0; }
    fi
    nft flush ruleset 2>/dev/null || true
    success "Live ruleset flushed"
    # Leave a minimal, valid config so a reboot does not re-apply old rules.
    printf '#!/usr/sbin/nft -f\nflush ruleset\n' > "$NFT_CONF"
    chmod 600 "$NFT_CONF"
    systemctl disable nftables >/dev/null 2>&1 || true
    rm -f "$STATE_FILE" "$CONFIG_FILE" "$COMMIT_FLAG"
    success "State, config and persistence removed (backups & log kept)"
    echo "════ Finished: $(date '+%Y-%m-%d %H:%M:%S') ════"
    exit 0
fi

# ── Load saved config ────────────────────────────────────────
[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

SAVED_MODE="${SAVED_MODE:-}"
SAVED_SSH_PORT="${SAVED_SSH_PORT:-}"
SAVED_SSH_CIDR="${SAVED_SSH_CIDR:-}"
SAVED_WG_PORT="${SAVED_WG_PORT:-}"
SAVED_KEEP_TCP="${SAVED_KEEP_TCP:-}"
SAVED_KEEP_UDP="${SAVED_KEEP_UDP:-}"
SAVED_ROLLBACK="${SAVED_ROLLBACK:-}"
SAVED_SSH_RATE="${SAVED_SSH_RATE:-}"
SAVED_SSH_BURST="${SAVED_SSH_BURST:-}"
SAVED_ALLOW_DHCP="${SAVED_ALLOW_DHCP:-}"
SAVED_LOG_DROPS="${SAVED_LOG_DROPS:-}"
SAVED_HEALTH_CHECK="${SAVED_HEALTH_CHECK:-}"
SAVED_HC_DNS="${SAVED_HC_DNS:-}"
SAVED_HC_TCP="${SAVED_HC_TCP:-}"
SAVED_HC_TCP6="${SAVED_HC_TCP6:-}"

# Working values: saved -> default
MODE="${SAVED_MODE:-}"
SSH_PORT="${SAVED_SSH_PORT:-}"
SSH_CIDR="${SAVED_SSH_CIDR:-}"
WG_PORT="${SAVED_WG_PORT:-$DEF_WG_PORT}"
KEEP_TCP="${SAVED_KEEP_TCP:-}"
KEEP_UDP="${SAVED_KEEP_UDP:-}"
ROLLBACK="${SAVED_ROLLBACK:-$DEF_ROLLBACK}"
SSH_RATE="${SAVED_SSH_RATE:-$DEF_SSH_RATE}"
SSH_BURST="${SAVED_SSH_BURST:-$DEF_SSH_BURST}"
ALLOW_DHCP="${SAVED_ALLOW_DHCP:-$DEF_ALLOW_DHCP}"
LOG_DROPS="${SAVED_LOG_DROPS:-$DEF_LOG_DROPS}"
HEALTH_CHECK="${SAVED_HEALTH_CHECK:-$DEF_HEALTH_CHECK}"
HC_DNS="${SAVED_HC_DNS:-$DEF_HC_DNS}"
HC_TCP="${SAVED_HC_TCP:-$DEF_HC_TCP}"
HC_TCP6="${SAVED_HC_TCP6:-$DEF_HC_TCP6}"

# CLI overrides win over saved
[ -n "$CLI_MODE" ]       && MODE="$CLI_MODE"
[ -n "$CLI_SSH_PORT" ]   && SSH_PORT="$CLI_SSH_PORT"
[ -n "$CLI_SSH_CIDR" ]   && SSH_CIDR="$CLI_SSH_CIDR"
[ -n "$CLI_KEEP_TCP" ]   && KEEP_TCP="$CLI_KEEP_TCP"
[ -n "$CLI_KEEP_UDP" ]   && KEEP_UDP="$CLI_KEEP_UDP"
[ -n "$CLI_WG_PORT" ]    && WG_PORT="$CLI_WG_PORT"
[ -n "$CLI_ROLLBACK" ]   && ROLLBACK="$CLI_ROLLBACK"
[ -n "$CLI_SSH_RATE" ]   && SSH_RATE="$CLI_SSH_RATE"
[ -n "$CLI_SSH_BURST" ]  && SSH_BURST="$CLI_SSH_BURST"
[ -n "$CLI_ALLOW_DHCP" ] && ALLOW_DHCP="$CLI_ALLOW_DHCP"
[ -n "$CLI_LOG_DROPS" ]  && LOG_DROPS="$CLI_LOG_DROPS"
[ -n "$CLI_HEALTH_CHECK" ] && HEALTH_CHECK="$CLI_HEALTH_CHECK"
[ -n "$CLI_HC_DNS" ]       && HC_DNS="$CLI_HC_DNS"
[ -n "$CLI_HC_TCP" ]       && HC_TCP="$CLI_HC_TCP"
[ -n "$CLI_HC_TCP6" ]      && HC_TCP6="$CLI_HC_TCP6"

# "any" / empty CIDR both mean unrestricted
[ "$SSH_CIDR" = "any" ] && SSH_CIDR=""

# Validate values that may come from an edited config file or flags
is_rate "$SSH_RATE"   || { warn "Invalid SSH rate '$SSH_RATE'; using $DEF_SSH_RATE"; SSH_RATE="$DEF_SSH_RATE"; }
is_uint "$SSH_BURST"  || { warn "Invalid SSH burst '$SSH_BURST'; using $DEF_SSH_BURST"; SSH_BURST="$DEF_SSH_BURST"; }
is_uint "$ROLLBACK"   || ROLLBACK="$DEF_ROLLBACK"
case "$ALLOW_DHCP" in yes|no) ;; *) ALLOW_DHCP="$DEF_ALLOW_DHCP" ;; esac
case "$LOG_DROPS"  in yes|no) ;; *) LOG_DROPS="$DEF_LOG_DROPS" ;; esac
case "$HEALTH_CHECK" in yes|no) ;; *) HEALTH_CHECK="$DEF_HEALTH_CHECK" ;; esac
[ -n "$HC_DNS" ] || HC_DNS="$DEF_HC_DNS"
[[ "$HC_TCP" =~ ^[^:[:space:]]+:[0-9]+$ ]] || { warn "Invalid health TCP target '$HC_TCP'; using $DEF_HC_TCP"; HC_TCP="$DEF_HC_TCP"; }
[[ "$HC_TCP6" =~ ^\[[0-9a-fA-F:]+\]:[0-9]+$ ]] || { warn "Invalid health IPv6 TCP target '$HC_TCP6'; using $DEF_HC_TCP6"; HC_TCP6="$DEF_HC_TCP6"; }

# ── Prompt helpers ───────────────────────────────────────────
ask() {
    local Q="$1" DEF="${2:-}"
    [ -n "$DEF" ] \
        && echo -e "${YELLOW}[?]${NC} $Q ${GRAY}[$DEF]${NC}: " \
        || echo -e "${YELLOW}[?]${NC} $Q: "
}
# read_val DEFAULT — returns default immediately when non-interactive
read_val() {
    local DEF="${1:-}"
    if [ "$INTERACTIVE" -ne 1 ]; then echo "$DEF"; return; fi
    local _V; read -r _V || true
    echo "${_V:-$DEF}"
}

# Detect the SSH port of the current session (best lockout protection)
detect_ssh_port() {
    if [ -n "${SSH_CONNECTION:-}" ]; then
        awk '{print $4}' <<<"$SSH_CONNECTION"; return
    fi
    local p
    p=$(ss -tlnpH 2>/dev/null | grep -i sshd | grep -oE ':[0-9]+' | tr -d ':' | sort -un | head -n1 || true)
    echo "${p:-22}"
}
# Client IP of the current SSH session (for lockout warnings)
detect_ssh_client() {
    [ -n "${SSH_CONNECTION:-}" ] && awk '{print $1}' <<<"$SSH_CONNECTION" || echo ""
}

# List listening services. Loopback-only binds are flagged "local".
# Prints: proto<TAB>port<TAB>scope<TAB>process
list_listeners() {
    command -v ss >/dev/null 2>&1 || return 0
    ss -tulnpH 2>/dev/null | awk '
        {
            proto=$1; la=$5;
            n=split(la, a, ":"); port=a[n];
            addr=substr(la, 1, length(la)-length(port)-1);
            gsub(/[\[\]]/,"",addr);
            scope = (addr=="127.0.0.1" || addr=="::1") ? "local" : "exposed";
            proc="-";
            if (match($0, /"[^"]+"/)) proc=substr($0, RSTART+1, RLENGTH-2);
            if (port ~ /^[0-9]+$/) print proto"\t"port"\t"scope"\t"proc;
        }' | sort -u
}

# DNS resolve probe — uses the system resolver via NSS; no extra packages needed.
probe_dns() {
    local name="$1"
    if command -v getent >/dev/null 2>&1; then
        timeout 5 getent hosts "$name" >/dev/null 2>&1 && return 0
    fi
    if command -v dig >/dev/null 2>&1; then
        timeout 5 dig +short +time=2 +tries=1 "$name" 2>/dev/null | grep -q . && return 0
    fi
    if command -v python3 >/dev/null 2>&1; then
        timeout 5 python3 -c 'import socket,sys; socket.gethostbyname(sys.argv[1])' "$name" >/dev/null 2>&1 && return 0
    fi
    return 1
}

# Outbound TCP connect probe via the bash /dev/tcp builtin; no curl/wget needed.
# Accepts "host:port" and "[ipv6]:port".
probe_tcp() {
    local hostport="$1" host port
    if [[ "$hostport" == \[*\]:* ]]; then
        host="${hostport%]*}"; host="${host#[}"; port="${hostport##*]:}"
    else
        host="${hostport%:*}"; port="${hostport##*:}"
    fi
    timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" >/dev/null 2>&1
}

# True if the host has a global-scope IPv6 address (worth probing v6 at all).
has_global_ipv6() {
    ip -6 addr show scope global 2>/dev/null | grep -q "inet6"
}


# ══════════════════════════════════════════════════════════════
# REPORT — print effective config + live status, change nothing
# ══════════════════════════════════════════════════════════════
if [ "$DO_REPORT" -eq 1 ]; then
    cfg_state="defaults (not yet configured)"
    [ -f "$CONFIG_FILE" ] && cfg_state="saved"
    live_tbl="absent"; nft list table inet filter >/dev/null 2>&1 && live_tbl="loaded"
    live_pol="n/a"
    if [ "$live_tbl" = loaded ]; then
        nft list chain inet filter input 2>/dev/null | grep -q "policy drop" \
            && live_pol="drop (deny inbound)" || live_pol="not drop"
    fi
    echo -e "${BOLD}${BLUE}Silent Firewall — configuration report${NC}"
    echo "  source        : $cfg_state ($CONFIG_FILE)"
    echo "  mode          : $MODE"
    echo "  ssh port      : $SSH_PORT"
    echo "  ssh source    : ${SSH_CIDR:-any}"
    echo "  open tcp      : ${KEEP_TCP:-none}"
    echo "  open udp      : ${KEEP_UDP:-none}"
    echo "  wireguard     : $([ "$MODE" = vpn ] && echo "udp/$WG_PORT" || echo n/a)"
    echo "  ssh rate      : $SSH_RATE (burst $SSH_BURST)"
    echo "  rollback      : ${ROLLBACK}s"
    echo "  dhcp          : $ALLOW_DHCP"
    echo "  log drops     : $LOG_DROPS"
    echo "  health-check  : $HEALTH_CHECK (dns=$HC_DNS tcp=$HC_TCP tcp6=$HC_TCP6)"
    echo "  --- live ---"
    echo "  table inet filter : $live_tbl"
    echo "  input policy      : $live_pol"
    echo "  persisted ruleset : $([ -f "$NFT_CONF" ] && echo "$NFT_CONF" || echo none)"
    svc_enabled="$(systemctl is-enabled nftables 2>/dev/null || true)"
    echo "  service enabled   : ${svc_enabled:-unknown}"
    if [ "$live_tbl" = loaded ]; then
        echo "  exposed listeners :"
        LINES="$(list_listeners)"
        if [ -n "$LINES" ]; then
            printf '%s\n' "$LINES" | while IFS=$'\t' read -r proto port scope proc; do
                [ "$scope" = exposed ] || continue
                printf "      %-5s %-7s %s\n" "$proto" "$port" "$proc"
            done
        else
            echo "      (none / ss unavailable)"
        fi
    fi
    exit 0
fi


[ "$INTERACTIVE" -eq 1 ] && clear
echo -e "${BOLD}${BLUE}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Silent Firewall — nftables hardening   ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  OS:   ${GREEN}${PRETTY_NAME}${NC}"
echo -e "  Log:  ${GREEN}${LOG_FILE}${NC}"
echo -e "  Mode: ${GREEN}$([ "$INTERACTIVE" -eq 1 ] && echo interactive || echo non-interactive)${NC}"
echo ""
echo -e "  ${BOLD}Component status:${NC}"
for c in $COMPONENTS; do
    is_done "$c" \
        && echo -e "    ${GREEN}[✓]${NC} $c" \
        || echo -e "    ${RED}[ ]${NC} $c"
done
echo ""
[ "$DRY_RUN" -eq 1 ] && warn "DRY-RUN: nothing will be installed, applied or persisted."
if [ "$INTERACTIVE" -eq 1 ]; then
    read -rp "  Continue? (y/n): " _CONFIRM
    [ "$_CONFIRM" != "y" ] && exit 0
else
    info "Non-interactive run — proceeding."
fi

# ══════════════════════════════════════════════════════════════
# 1. PACKAGES
# ══════════════════════════════════════════════════════════════
header "Installing packages"
if [ "$DRY_RUN" -eq 1 ]; then
    if command -v nft >/dev/null 2>&1; then
        success "nftables already present"
    else
        warn "nftables NOT installed — a real run would 'apt install nftables iproute2'"
        warn "Skipping ruleset validation (nft unavailable in dry-run)."
    fi
elif is_done "packages" && command -v nft >/dev/null 2>&1; then
    skip "packages"
else
    apt update -qq
    apt install -y -qq nftables iproute2
    systemctl enable nftables >/dev/null 2>&1 || true
    success "Packages installed (nftables, iproute2)"
    mark_done "packages"
fi
[ "$DRY_RUN" -eq 1 ] || command -v nft >/dev/null 2>&1 || error "nftables still not available after install"

# ══════════════════════════════════════════════════════════════
# 2. SSH PORT — detect / confirm (lockout protection)
# ══════════════════════════════════════════════════════════════
header "SSH port"

if [ -z "$SSH_PORT" ] && is_done "ssh_port" && [ -n "${SAVED_SSH_PORT:-}" ]; then
    SSH_PORT="$SAVED_SSH_PORT"
fi

if is_done "ssh_port" && [ -n "$SSH_PORT" ] && [ "$INTERACTIVE" -ne 1 ] && [ -z "$CLI_SSH_PORT" ]; then
    skip "SSH port ($SSH_PORT)"
elif is_done "ssh_port" && [ -n "$SSH_PORT" ] && [ "$INTERACTIVE" -ne 1 ]; then
    valid_port "$SSH_PORT" || error "Invalid SSH port: $SSH_PORT"
    SSH_PORT="$(norm_port "$SSH_PORT")"
    success "SSH port: $SSH_PORT"
    mark_done "ssh_port"
else
    DETECTED="${SSH_PORT:-$(detect_ssh_port)}"
    [ -n "${SSH_CONNECTION:-}" ] \
        && info "Detected current SSH session on port ${BOLD}$DETECTED${NC}" \
        || info "No SSH session detected; sshd appears to listen on ${BOLD}$DETECTED${NC}"
    ask "SSH port to keep open" "$DETECTED"
    SSH_PORT="$(read_val "$DETECTED")"
    valid_port "$SSH_PORT" || error "Invalid SSH port: $SSH_PORT"
    SSH_PORT="$(norm_port "$SSH_PORT")"
    success "SSH port: $SSH_PORT"
    mark_done "ssh_port"
fi

# ══════════════════════════════════════════════════════════════
# 3. MODE
# ══════════════════════════════════════════════════════════════
header "Firewall mode"

if [ -z "$MODE" ] && is_done "mode" && [ -n "${SAVED_MODE:-}" ]; then
    MODE="$SAVED_MODE"
fi

if is_done "mode" && [ -n "$MODE" ] && [ "$INTERACTIVE" -ne 1 ] && [ -z "$CLI_MODE" ]; then
    skip "mode ($MODE)"
else
    if [ "$INTERACTIVE" -eq 1 ]; then
        echo ""
        echo -e "    1) ${BOLD}Paranoid${NC} — deny all inbound except rate-limited SSH; no ping;"
        echo -e "       ${GRAY}drop mDNS/SSDP/UPnP/LLMNR/NetBIOS inbound AND outbound${NC}"
        echo -e "    2) ${BOLD}Balanced${NC} — deny inbound except SSH; allow ping ${GRAY}(good default)${NC}"
        echo -e "    3) ${BOLD}Server${NC}   — Balanced + choose which detected ports stay open"
        echo -e "    4) ${BOLD}VPN${NC}      — allow only SSH + WireGuard"
        echo ""
        DMODE=2
        case "${MODE:-}" in paranoid) DMODE=1;; balanced) DMODE=2;; server) DMODE=3;; vpn) DMODE=4;; esac
        ask "Select mode (1-4)" "$DMODE"
        MNUM="$(read_val "$DMODE")"
        case "$MNUM" in
            1) MODE="paranoid" ;;
            2) MODE="balanced" ;;
            3) MODE="server" ;;
            4) MODE="vpn" ;;
            *) error "Invalid choice: $MNUM (expected 1..4)" ;;
        esac
    fi
    : "${MODE:=$DEF_MODE}"
    case "$MODE" in paranoid|balanced|server|vpn) ;; *) error "Invalid mode: $MODE" ;; esac

    if [ "$MODE" = "vpn" ]; then
        if [ "$INTERACTIVE" -eq 1 ]; then
            ask "WireGuard port" "$WG_PORT"
            WG_PORT="$(read_val "$WG_PORT")"
        fi
        valid_port "$WG_PORT" || error "Invalid WireGuard port: $WG_PORT"
        WG_PORT="$(norm_port "$WG_PORT")"
    fi
    success "Mode: $MODE$([ "$MODE" = vpn ] && echo "  (WireGuard udp/$WG_PORT)")"
    mark_done "mode"
fi

# ══════════════════════════════════════════════════════════════
# 4. KEEP PORTS — server mode only
# ══════════════════════════════════════════════════════════════
header "Open ports"

if [ "$MODE" != "server" ]; then
    info "Mode '$MODE' manages ports automatically — nothing to choose."
    if [ "$MODE" = "vpn" ]; then KEEP_TCP=""; KEEP_UDP="$WG_PORT"; else KEEP_TCP=""; KEEP_UDP=""; fi
    mark_done "keep_ports"
elif is_done "keep_ports" && [ "$INTERACTIVE" -ne 1 ] \
     && [ -z "$CLI_KEEP_TCP$CLI_KEEP_UDP" ]; then
    skip "open ports (tcp: ${KEEP_TCP:-none}  udp: ${KEEP_UDP:-none})"
elif [ "$INTERACTIVE" -ne 1 ]; then
    # Non-interactive server mode: take ports straight from flags/saved.
    success "Keeping  tcp: ${KEEP_TCP:-none}  udp: ${KEEP_UDP:-none}"
    mark_done "keep_ports"
else
    echo ""
    info "Detected listening services:"
    printf '    %-5s %-7s %-9s %s\n' "PROTO" "PORT" "SCOPE" "PROCESS"
    LINES="$(list_listeners)"
    if [ -n "$LINES" ]; then
        printf '%s\n' "$LINES" | while IFS=$'\t' read -r proto port scope proc; do
            if [ "$scope" = "exposed" ]; then
                printf "    %-5s %-7s ${YELLOW}%-9s${NC} %s\n" "$proto" "$port" "$scope" "$proc"
            else
                printf "    %-5s %-7s ${GRAY}%-9s${NC} %s\n" "$proto" "$port" "$scope" "$proc"
            fi
        done
    else
        warn "No listeners detected."
    fi
    echo ""
    info "SSH/$SSH_PORT is always kept. Enter ports to open (e.g. '80 443'),"
    info "'all' for every ${YELLOW}exposed${NC} port, or blank for none."
    ask "Open which ports?" ""
    ANSWER="$(read_val "")"

    KT=""; KU=""
    if [ "$ANSWER" = "all" ]; then
        while IFS=$'\t' read -r proto port scope _; do
            [ "$scope" = "exposed" ] || continue
            [ "$port" = "$SSH_PORT" ] && continue
            [ "$proto" = "tcp" ] && KT="${KT:+$KT,}$port"
            [ "$proto" = "udp" ] && KU="${KU:+$KU,}$port"
        done < <(printf '%s\n' "$LINES")
    elif [ -n "$ANSWER" ]; then
        for p in $ANSWER; do
            valid_port "$p" || { warn "Skipping invalid port: $p"; continue; }
            p="$(norm_port "$p")"
            PR="$(printf '%s\n' "$LINES" | awk -F'\t' -v P="$p" '$2==P{print $1; exit}')"
            case "${PR:-tcp}" in
                udp) KU="${KU:+$KU,}$p" ;;
                *)   KT="${KT:+$KT,}$p" ;;
            esac
        done
    fi
    KEEP_TCP="$KT"; KEEP_UDP="$KU"
    success "Keeping  tcp: ${KEEP_TCP:-none}  udp: ${KEEP_UDP:-none}"
    mark_done "keep_ports"
fi

# Normalize comma/space-separated KEEP_* (flags may use spaces) to commas
KEEP_TCP="$(echo "$KEEP_TCP" | tr ' ' ',' | sed 's/,,*/,/g; s/^,//; s/,$//')"
KEEP_UDP="$(echo "$KEEP_UDP" | tr ' ' ',' | sed 's/,,*/,/g; s/^,//; s/,$//')"

# ══════════════════════════════════════════════════════════════
# 5. OPTIONS — SSH source restriction, DHCP, drop logging
# ══════════════════════════════════════════════════════════════
header "Hardening options"

if is_done "options" && [ "$INTERACTIVE" -ne 1 ] \
   && [ -z "$CLI_SSH_CIDR$CLI_ALLOW_DHCP$CLI_LOG_DROPS$CLI_HEALTH_CHECK$CLI_HC_DNS$CLI_HC_TCP" ]; then
    skip "options (ssh-cidr: ${SSH_CIDR:-any}  dhcp: $ALLOW_DHCP  log: $LOG_DROPS  health: $HEALTH_CHECK)"
else
    if [ "$INTERACTIVE" -eq 1 ]; then
        CLIENT_IP="$(detect_ssh_client)"
        info "Restrict SSH to specific source networks? Blank = open to all."
        [ -n "$CLIENT_IP" ] && warn "Your current SSH client IP is ${BOLD}$CLIENT_IP${NC} — include it or you may lock yourself out."
        ask "SSH source CIDR(s), space-separated" "${SSH_CIDR:-any}"
        _C="$(read_val "${SSH_CIDR:-any}")"
        [ "$_C" = "any" ] && _C=""
        SSH_CIDR="$_C"

        ask "Allow DHCP client traffic? (yes/no)" "$ALLOW_DHCP"
        ALLOW_DHCP="$(read_val "$ALLOW_DHCP")"

        ask "Log dropped inbound packets? (yes/no)" "$LOG_DROPS"
        LOG_DROPS="$(read_val "$LOG_DROPS")"

        ask "Run a connectivity self-test after applying? (yes/no)" "$HEALTH_CHECK"
        HEALTH_CHECK="$(read_val "$HEALTH_CHECK")"
    fi

    # Validate CIDRs; drop bad tokens with a warning
    if [ -n "$SSH_CIDR" ]; then
        _OK=""
        for c in $SSH_CIDR; do
            if valid_cidr "$c"; then _OK="${_OK:+$_OK }$c"; else warn "Ignoring invalid CIDR: $c"; fi
        done
        SSH_CIDR="$_OK"
        CLIENT_IP="$(detect_ssh_client)"
        [ -n "$CLIENT_IP" ] && info "Reminder: ensure $CLIENT_IP falls within: ${SSH_CIDR:-(none — SSH will be blocked!)}"
    fi
    case "$ALLOW_DHCP" in yes|no) ;; *) ALLOW_DHCP="$DEF_ALLOW_DHCP" ;; esac
    case "$LOG_DROPS"  in yes|no) ;; *) LOG_DROPS="$DEF_LOG_DROPS" ;; esac
    case "$HEALTH_CHECK" in yes|no) ;; *) HEALTH_CHECK="$DEF_HEALTH_CHECK" ;; esac

    success "SSH source: ${SSH_CIDR:-any}   DHCP: $ALLOW_DHCP   Log drops: $LOG_DROPS   Health-check: $HEALTH_CHECK"
    mark_done "options"
fi

# ══════════════════════════════════════════════════════════════
# PRE-FLIGHT CHECKS — sshd liveness, fail2ban awareness
# ══════════════════════════════════════════════════════════════
header "Pre-flight checks"

# Which ports is sshd actually serving? Prefer sshd's own effective config.
SSHD_PORTS=""
if command -v sshd >/dev/null 2>&1; then
    SSHD_PORTS="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -un | tr '\n' ' ' || true)"
fi
if [ -z "$SSHD_PORTS" ]; then
    # Fall back to whatever is listening right now.
    SSHD_PORTS="$(ss -tlnpH 2>/dev/null | grep -i sshd | grep -oE ':[0-9]+' | tr -d ':' | sort -un | tr '\n' ' ' || true)"
fi

if [ -z "$SSHD_PORTS" ]; then
    warn "No running/known sshd detected."
    warn "If you depend on SSH, ensure it is installed AND running — an open port without a live sshd still means no access."
    if [ "$INTERACTIVE" -eq 1 ]; then
        read -rp "  Continue without a verified sshd? (y/n): " _S
        [ "$_S" = "y" ] || error "Aborted: no sshd verified"
    fi
elif grep -qw "$SSH_PORT" <<<"$SSHD_PORTS"; then
    success "sshd is listening on $SSH_PORT"
else
    warn "sshd does not appear to listen on $SSH_PORT (effective: ${SSHD_PORTS% })."
    warn "Opening $SSH_PORT may not actually grant SSH access."
    if [ "$INTERACTIVE" -eq 1 ]; then
        read -rp "  Continue anyway? (y/n): " _S
        [ "$_S" = "y" ] || error "Aborted: SSH port mismatch"
    fi
fi

# fail2ban awareness (detection only — no integration).
if command -v fail2ban-client >/dev/null 2>&1 || systemctl is-active --quiet fail2ban 2>/dev/null; then
    info "fail2ban detected — it already throttles brute force. The nft SSH rate-limit"
    info "overlaps with it: harmless, but rate limiting here may be redundant."
fi

# ══════════════════════════════════════════════════════════════
# Build the nftables ruleset for the chosen mode
# ══════════════════════════════════════════════════════════════
build_ruleset() {
    local out="$1"
    local allow_ping="yes" block_out="no"
    local tcp_set="$KEEP_TCP" udp_set="$KEEP_UDP"

    case "$MODE" in
        paranoid) allow_ping="no"; block_out="yes" ;;
        balanced) : ;;
        server)   : ;;
        vpn)      udp_set="$WG_PORT"; tcp_set="" ;;
    esac

    # Split SSH source CIDRs into v4 / v6 sets
    local cidr4="" cidr6=""
    if [ -n "$SSH_CIDR" ]; then
        local c
        for c in $SSH_CIDR; do
            if [[ "$c" == *:* ]]; then cidr6="${cidr6:+$cidr6, }$c"; else cidr4="${cidr4:+$cidr4, }$c"; fi
        done
    fi

    {
        echo "#!/usr/sbin/nft -f"
        echo "# Generated by silent-firewall.sh  mode=$MODE  ssh=$SSH_PORT  $(date -u +%FT%TZ)"
        echo "flush ruleset"
        echo
        echo "table inet filter {"
        echo "    chain input {"
        echo "        type filter hook input priority 0; policy drop;"
        echo
        echo "        iif \"lo\" accept"
        echo "        iif != \"lo\" ip daddr 127.0.0.0/8 drop"
        echo "        iif != \"lo\" ip6 daddr ::1 drop"
        echo
        echo "        ct state established,related accept"
        echo "        ct state invalid drop"
        echo
        if [ "$ALLOW_DHCP" = "yes" ]; then
            echo "        # DHCP / DHCPv6 client"
            echo "        udp sport 67 udp dport 68 accept"
            echo "        udp sport 547 udp dport 546 accept"
            echo
        fi
        echo "        icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert, nd-router-solicit, nd-redirect } accept"
        echo "        icmp type { destination-unreachable, time-exceeded, parameter-problem } accept"
        echo "        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept"
        if [ "$allow_ping" = "yes" ]; then
            echo "        icmp type echo-request limit rate 5/second accept"
            echo "        icmpv6 type echo-request limit rate 5/second accept"
        else
            echo "        icmp type echo-request drop"
            echo "        icmpv6 type echo-request drop"
        fi
        echo
        echo "        # SSH on $SSH_PORT, rate-limited per source IP"
        if [ -n "$SSH_CIDR" ]; then
            echo "        # restricted to: $SSH_CIDR (other sources fall through to policy drop)"
            if [ -n "$cidr4" ]; then
                echo "        tcp dport $SSH_PORT ip saddr { $cidr4 } ct state new meter ssh4 { ip saddr limit rate over $SSH_RATE burst $SSH_BURST packets } drop"
                echo "        tcp dport $SSH_PORT ip saddr { $cidr4 } accept"
            fi
            if [ -n "$cidr6" ]; then
                echo "        tcp dport $SSH_PORT ip6 saddr { $cidr6 } ct state new meter ssh6 { ip6 saddr limit rate over $SSH_RATE burst $SSH_BURST packets } drop"
                echo "        tcp dport $SSH_PORT ip6 saddr { $cidr6 } accept"
            fi
        else
            echo "        tcp dport $SSH_PORT ct state new meter ssh4 { ip saddr  limit rate over $SSH_RATE burst $SSH_BURST packets } drop"
            echo "        tcp dport $SSH_PORT ct state new meter ssh6 { ip6 saddr limit rate over $SSH_RATE burst $SSH_BURST packets } drop"
            echo "        tcp dport $SSH_PORT accept"
        fi
        if [ -n "$tcp_set" ]; then
            echo "        tcp dport { $tcp_set } accept"
        fi
        if [ -n "$udp_set" ]; then
            echo "        udp dport { $udp_set } accept"
        fi
        if [ "$MODE" = "paranoid" ]; then
            echo
            echo "        # swallow discovery chatter quietly"
            echo "        udp dport { 1900, 5353, 5355, 137, 138 } drop"
            echo "        ip daddr 224.0.0.0/4 drop"
            echo "        ip6 daddr ff00::/8 drop"
        fi
        if [ "$LOG_DROPS" = "yes" ]; then
            echo
            echo "        # log whatever falls through to the drop policy"
            echo "        limit rate 3/second burst 5 packets log prefix \"[silent-fw in] \" level info"
        fi
        echo "    }"
        echo
        echo "    chain forward {"
        echo "        type filter hook forward priority 0; policy drop;"
        echo "    }"
        echo
        echo "    chain output {"
        echo "        type filter hook output priority 0; policy accept;"
        if [ "$block_out" = "yes" ]; then
            echo "        # paranoid: stop this host announcing itself"
            echo "        udp dport { 1900, 5353, 5355, 137, 138 } drop"
            echo "        ip daddr 224.0.0.0/4 drop"
            echo "        ip6 daddr ff00::/8 drop"
        fi
        echo "    }"
        echo "}"
    } > "$out"
}

# ══════════════════════════════════════════════════════════════
# 6. RULESET — build, validate, apply with auto-rollback
# (always runs so re-running re-enforces the firewall)
# ══════════════════════════════════════════════════════════════
header "Building$([ "$DRY_RUN" -eq 1 ] && echo " (dry-run)" || echo " & applying") ruleset"

# Non-interactive runs cannot answer the confirmation prompt, so a timed
# rollback would always revert. Disable it and commit immediately.
if [ "$INTERACTIVE" -ne 1 ] && [ "${ROLLBACK:-0}" -gt 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    warn "Non-interactive: timed rollback disabled (committing immediately)."
    ROLLBACK=0
fi

RULES_FILE="$(mktemp /tmp/silent-firewall.XXXXXX.nft)"
build_ruleset "$RULES_FILE"

echo ""
info "Generated ruleset (mode=${BOLD}$MODE${NC}, SSH=${BOLD}$SSH_PORT${NC}):"
echo -e "${GRAY}"
cat "$RULES_FILE"
echo -e "${NC}"

if command -v nft >/dev/null 2>&1; then
    nft -c -f "$RULES_FILE" || error "Ruleset failed validation; nothing applied"
    success "Ruleset validated"
elif [ "$DRY_RUN" -eq 1 ]; then
    warn "nft not available — skipped kernel validation (dry-run)"
else
    error "nft not available to validate ruleset"
fi

# ── DRY-RUN: detection + profile + ruleset shown; stop before touching anything
if [ "$DRY_RUN" -eq 1 ]; then
    header "Dry-run summary"
    echo "  mode        : $MODE"
    echo "  ssh         : tcp/$SSH_PORT (rate $SSH_RATE, burst $SSH_BURST)"
    echo "  ssh source  : ${SSH_CIDR:-any}"
    echo "  open tcp    : ${KEEP_TCP:-none}"
    echo "  open udp    : ${KEEP_UDP:-none}"
    echo "  dhcp        : $ALLOW_DHCP    log drops: $LOG_DROPS    health-check: $HEALTH_CHECK"
    success "Dry-run complete — no changes were made."
    echo "════ Finished: $(date '+%Y-%m-%d %H:%M:%S') ════"
    exit 0
fi

# Back up the CURRENT live ruleset. Prepend 'flush ruleset' so restoring it
# replaces (rather than fails to merge into) the about-to-be-applied ruleset.
mkdir -p "$BACKUP_DIR"
BACKUP="$BACKUP_DIR/ruleset.$(date -u +%Y%m%dT%H%M%SZ).nft"
{ printf 'flush ruleset\n'; nft list ruleset 2>/dev/null; } > "$BACKUP"
if [ "$(wc -l < "$BACKUP")" -gt 1 ]; then
    success "Current ruleset backed up: $BACKUP"
else
    warn "No prior ruleset; rollback target is an empty (open) ruleset"
fi

rm -f "$COMMIT_FLAG"

# Baseline connectivity BEFORE applying, so we only roll back on a regression
# (a host with no egress at all won't be punished for an already-broken link).
HC_BASE_DNS=0; HC_BASE_TCP=0; HC_BASE_TCP6=0; HC_V6=0
if [ "$HEALTH_CHECK" = "yes" ]; then
    has_global_ipv6 && HC_V6=1 || true
    probe_dns "$HC_DNS" && HC_BASE_DNS=1 || true
    probe_tcp "$HC_TCP" && HC_BASE_TCP=1 || true
    [ $HC_V6 -eq 1 ] && { probe_tcp "$HC_TCP6" && HC_BASE_TCP6=1 || true; }
    info "Baseline — DNS($HC_DNS): $([ $HC_BASE_DNS -eq 1 ] && echo ok || echo n/a)  TCP($HC_TCP): $([ $HC_BASE_TCP -eq 1 ] && echo ok || echo n/a)$([ $HC_V6 -eq 1 ] && echo "  TCP6($HC_TCP6): $([ $HC_BASE_TCP6 -eq 1 ] && echo ok || echo n/a)")"
    [ $((HC_BASE_DNS + HC_BASE_TCP + HC_BASE_TCP6)) -eq 0 ] && warn "No connectivity baseline; self-test will be skipped (nothing to compare against)."
fi

if [ "${ROLLBACK:-0}" -gt 0 ]; then
    # Background timer sleeps a little LONGER than the foreground read, so a
    # last-second "keep" always sets the flag before the timer checks it.
    setsid bash -c '
        sleep '"$((ROLLBACK + ROLLBACK_GRACE))"'
        [ -f "'"$COMMIT_FLAG"'" ] && exit 0
        nft -f "'"$BACKUP"'" 2>/dev/null || nft flush ruleset
    ' >/dev/null 2>&1 < /dev/null &
    info "Auto-rollback armed: reverting in ${BOLD}${ROLLBACK}s${NC} unless confirmed"
fi

nft -f "$RULES_FILE" || error "Apply failed"
success "Ruleset applied (live now)"

# Regression self-test: revert immediately if something that worked before
# is now broken. This is the primary safety net for non-interactive runs.
if [ "$HEALTH_CHECK" = "yes" ]; then
    hc_bad=0
    if [ $HC_BASE_DNS -eq 1 ]; then probe_dns "$HC_DNS" || { warn "DNS resolution regressed after apply"; hc_bad=1; }; fi
    if [ $HC_BASE_TCP -eq 1 ]; then probe_tcp "$HC_TCP" || { warn "Outbound TCP regressed after apply"; hc_bad=1; }; fi
    if [ $HC_BASE_TCP6 -eq 1 ]; then probe_tcp "$HC_TCP6" || { warn "Outbound IPv6 TCP regressed after apply"; hc_bad=1; }; fi
    if [ $hc_bad -eq 1 ]; then
        touch "$COMMIT_FLAG"   # stop any armed background timer from double-reverting
        nft -f "$BACKUP" 2>/dev/null || nft flush ruleset
        error "Connectivity self-test failed — previous ruleset restored"
    fi
    [ $((HC_BASE_DNS + HC_BASE_TCP + HC_BASE_TCP6)) -gt 0 ] && success "Connectivity self-test passed"
fi

if [ "${ROLLBACK:-0}" -gt 0 ]; then
    echo ""
    warn "Confirm you still have access. Type 'keep' within ${ROLLBACK}s to make it permanent."
    REPLY_KEEP=""
    if read -rt "$ROLLBACK" -p "  keep/abort > " REPLY_KEEP; then
        if [ "$REPLY_KEEP" = "keep" ]; then
            touch "$COMMIT_FLAG"
            success "Confirmed"
        else
            info "Aborting; restoring previous ruleset"
            touch "$COMMIT_FLAG"          # stop the background timer from also firing
            nft -f "$BACKUP" 2>/dev/null || nft flush ruleset
            error "Reverted by user"
        fi
    else
        echo ""
        touch "$COMMIT_FLAG"
        nft -f "$BACKUP" 2>/dev/null || nft flush ruleset
        error "No confirmation — previous ruleset restored"
    fi
else
    touch "$COMMIT_FLAG"
fi
mark_done "ruleset"

# ══════════════════════════════════════════════════════════════
# 7. PERSIST
# ══════════════════════════════════════════════════════════════
header "Persisting"

cp "$RULES_FILE" "$NFT_CONF"
chmod 600 "$NFT_CONF"
if systemctl enable --now nftables >/dev/null 2>&1; then
    success "Saved to $NFT_CONF and nftables.service enabled (survives reboot)"
else
    warn "Wrote $NFT_CONF but could not enable nftables.service"
fi
mark_done "persist"

# ══════════════════════════════════════════════════════════════
# SAVE CONFIG
# ══════════════════════════════════════════════════════════════
umask 077
cat > "$CONFIG_FILE" << EOF
# Silent Firewall config — $(date)
SAVED_MODE="$MODE"
SAVED_SSH_PORT="$SSH_PORT"
SAVED_SSH_CIDR="$SSH_CIDR"
SAVED_WG_PORT="$WG_PORT"
SAVED_KEEP_TCP="$KEEP_TCP"
SAVED_KEEP_UDP="$KEEP_UDP"
SAVED_ROLLBACK="$ROLLBACK"
SAVED_SSH_RATE="$SSH_RATE"
SAVED_SSH_BURST="$SSH_BURST"
SAVED_ALLOW_DHCP="$ALLOW_DHCP"
SAVED_LOG_DROPS="$LOG_DROPS"
SAVED_HEALTH_CHECK="$HEALTH_CHECK"
SAVED_HC_DNS="$HC_DNS"
SAVED_HC_TCP="$HC_TCP"
SAVED_HC_TCP6="$HC_TCP6"
EOF
umask 022
chmod 600 "$CONFIG_FILE"

# ══════════════════════════════════════════════════════════════
# VERIFICATION
# ══════════════════════════════════════════════════════════════
header "Verification"

echo ""
info "Active table:"
nft list table inet filter >/dev/null 2>&1 \
    && success "inet filter table is loaded" \
    || warn "inet filter table not found"

echo ""
info "Input policy:"
nft list chain inet filter input 2>/dev/null | grep -q "policy drop" \
    && success "default deny inbound active" \
    || warn "input policy is not drop"

echo ""
info "Still-exposed listeners (should match what you opened):"
LINES="$(list_listeners)"
if [ -n "$LINES" ]; then
    printf '%s\n' "$LINES" | while IFS=$'\t' read -r proto port scope proc; do
        [ "$scope" = "exposed" ] || continue
        printf "    %-5s %-7s %s\n" "$proto" "$port" "$proc"
    done
else
    info "    (none / ss unavailable)"
fi

echo ""
info "Component status:"
for c in $COMPONENTS; do
    is_done "$c" \
        && echo -e "    ${GREEN}[✓]${NC} $c" \
        || echo -e "    ${RED}[ ]${NC} $c"
done

# ══════════════════════════════════════════════════════════════
# DONE
# ══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║       Firewall active!                   ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  Mode      : ${GREEN}$MODE${NC}"
echo -e "  SSH       : ${GREEN}tcp/$SSH_PORT${NC} ${GRAY}(rate $SSH_RATE, burst $SSH_BURST)${NC}"
echo -e "  SSH src   : $([ -n "$SSH_CIDR" ] && echo "${GREEN}$SSH_CIDR${NC}" || echo "${GRAY}any${NC}")"
echo -e "  Open TCP  : $([ -n "$KEEP_TCP" ] && echo "${GREEN}$KEEP_TCP${NC}" || echo "${GRAY}none${NC}")"
echo -e "  Open UDP  : $([ -n "$KEEP_UDP" ] && echo "${GREEN}$KEEP_UDP${NC}" || echo "${GRAY}none${NC}")"
echo -e "  Ping      : $([ "$MODE" = paranoid ] && echo "${GRAY}blocked${NC}" || echo "${GREEN}allowed${NC}")"
echo -e "  DHCP      : $([ "$ALLOW_DHCP" = yes ] && echo "${GREEN}allowed${NC}" || echo "${GRAY}blocked${NC}")"
echo -e "  Log drops : $([ "$LOG_DROPS" = yes ] && echo "${GREEN}on${NC}" || echo "${GRAY}off${NC}")"
echo -e "  Self-test : $([ "$HEALTH_CHECK" = yes ] && echo "${GREEN}on${NC} ${GRAY}(dns $HC_DNS, tcp $HC_TCP)${NC}" || echo "${GRAY}off${NC}")"
echo ""
echo -e "  Re-run            : ${CYAN}sudo $0${NC}"
echo -e "  Preview (no apply): ${CYAN}sudo $0 --dry-run${NC}"
echo -e "  Show config       : ${CYAN}sudo $0 --report${NC}"
echo -e "  Uninstall         : ${CYAN}sudo $0 --uninstall${NC}"
echo -e "  Show live rules   : ${CYAN}nft list ruleset${NC}"
echo -e "  Installer logs    : ${CYAN}$LOG_FILE${NC}"
echo -e "  Ruleset on disk   : ${CYAN}$NFT_CONF${NC}"
echo -e "  Backups           : ${CYAN}$BACKUP_DIR${NC}"
echo -e "  Component status  : ${CYAN}cat $STATE_FILE${NC}"
echo -e "  Config            : ${CYAN}$CONFIG_FILE${NC}"
[ "$LOG_DROPS" = yes ] && echo -e "  Dropped pkts log  : ${CYAN}journalctl -k | grep 'silent-fw'${NC}"
echo ""
echo "════ Finished: $(date '+%Y-%m-%d %H:%M:%S') ════"
exit 0

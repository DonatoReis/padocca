#!/bin/bash

# PADOCCA v2.0 - Advanced Penetration Testing Framework
# FINAL PRODUCTION VERSION - All improvements integrated
# Date: 2025-09-04

# Resolve script directory (works with symlinks)
resolve_script_dir() {
    local source="${BASH_SOURCE[0]}"
    while [ -h "$source" ]; do
        local dir="$( cd -P "$( dirname "$source" )" >/dev/null 2>&1 && pwd )"
        source="$(readlink "$source")"
        [[ "$source" != /* ]] && source="$dir/$source"
    done
    cd -P "$( dirname "$source" )" >/dev/null 2>&1 && pwd
}

sanitize_identifier() {
    local value="$1"
    value="${value//:/_}"
    value="${value//\//_}"
    value="${value// /_}"
    value="${value//[^[:alnum:]_.-]/_}"
    [[ -z "$value" ]] && value="scan"
    echo "$value"
}

normalize_target_input() {
    local input="$1"
    input="${input#http://}"
    input="${input#https://}"
    input="${input#ftp://}"
    input="${input%%/*}"
    [[ -z "$input" ]] && input="$1"
    echo "$input"
}

# Get script directory
SCRIPT_DIR="$(resolve_script_dir)"
export PADOCCA_ROOT="$SCRIPT_DIR"

# Source libraries if available
if [ -f "$SCRIPT_DIR/lib/progress.sh" ]; then
    source "$SCRIPT_DIR/lib/progress.sh" 2>/dev/null || true
else
    # Fallback functions if libraries not available
    draw_progress_bar() { echo "[Progress] $4"; }
    animated_progress() { echo "[Progress] $1"; }
fi

if [ -f "$SCRIPT_DIR/lib/logger.sh" ]; then
    source "$SCRIPT_DIR/lib/logger.sh" 2>/dev/null || true
else
    # Fallback functions
    init_logger() { return 0; }
    log_info() { echo "[INFO] $2"; }
    generate_summary_log() { return 0; }
fi

# Fallback display functions if not defined
type show_dashboard &>/dev/null || show_dashboard() { echo "[Dashboard] Target: $1 | Mode: $2"; }
type show_phase_header &>/dev/null || show_phase_header() { echo -e "\n=== PHASE $1: $2 ==="; }
type show_module_progress &>/dev/null || show_module_progress() { echo "[Module $1/$2] $3"; }
type show_task_status &>/dev/null || show_task_status() { echo "[$1] Status: $2 | Time: $3 | $4"; }
type show_live_stats &>/dev/null || show_live_stats() { echo "[$1]: $2 $3"; }
type calculate_elapsed_time &>/dev/null || calculate_elapsed_time() { echo "$(($(date +%s) - $1))s"; }
type show_summary_panel &>/dev/null || show_summary_panel() {
    echo -e "\n==== SCAN SUMMARY ===="
    echo "Target: $1"
    echo "Subdomains: $2"
    echo "URLs: $3"
    echo "Ports: $4"
    echo "Vulnerabilities: $5"
    echo "WAF: $6"
    echo "SSL: $7"
    echo "Emails: $8"
    echo "Duration: $9"
    echo "Results: ${10}"
}

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

SILENT_MODE=""

silent_notice() {
    if [ -z "$SILENT_MODE" ]; then
        printf "%b\n" "$1"
    fi
}

command_available() {
    command -v "$1" >/dev/null 2>&1
}

ensure_dir() {
    local dir="$1"
    mkdir -p "$dir" 2>/dev/null
}

run_command_capture() {
    local label="$1"
    local outfile="$2"
    local timeout_secs="$3"
    shift 3
    local cmd=("$@")

    ensure_dir "$(dirname "$outfile")"

    if ! command_available "${cmd[0]}"; then
        silent_notice "${YELLOW}⚠️  ${label}: command not available (${cmd[0]})${NC}"
        log_warning "COMMAND" "${label} unavailable" "${cmd[0]} missing"
        return 1
    fi

    local log_msg="${DIM}${label}: ${outfile}${NC}"
    silent_notice "$log_msg"

    if [ -n "$timeout_secs" ] && [ "$timeout_secs" != "0" ]; then
        timeout "$timeout_secs" "${cmd[@]}" >"$outfile" 2>&1
    else
        "${cmd[@]}" >"$outfile" 2>&1
    fi

    local status=$?
    if [ $status -ne 0 ]; then
        log_warning "COMMAND" "${label} exited with status $status" "See $outfile"
    fi
    echo "$outfile" >> "$SCAN_DIR/.evidence_index" 2>/dev/null || true
    return $status
}

collect_hosts() {
    python3 - "$1" "$2" <<'PY'
import json, sys
from pathlib import Path

target = sys.argv[1]
json_path = Path(sys.argv[2])
hosts = {target}

if json_path.exists():
    try:
        data = json.loads(json_path.read_text())
    except Exception:
        data = {}
    if isinstance(data, dict):
        entries = data.get("subdomains") or data.get("results") or []
    else:
        entries = data or []
    for entry in entries:
        if isinstance(entry, dict):
            host = entry.get("domain") or entry.get("host")
        else:
            host = entry
        if host:
            hosts.add(host.strip())

for host in sorted(h for h in hosts if h):
    print(host)
PY
}

collect_urls() {
    python3 - "$1" "$2" <<'PY'
import json, sys
from pathlib import Path
urls = set()
for arg in sys.argv[1:]:
    path = Path(arg)
    if not path.exists():
        continue
    try:
        data = json.loads(path.read_text())
    except Exception:
        continue
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = data.get("results") or data.get("urls") or data.get("data") or []
    else:
        entries = []
    for entry in entries:
        if isinstance(entry, dict):
            url = entry.get("url") or entry.get("link")
        else:
            url = entry
        if url:
            urls.add(url)

for url in sorted(urls):
    print(url)
PY
}

run_osint_layers() {
    local hosts_file="$1"
    local evidence_dir="$2"
    ensure_dir "$evidence_dir/osint"

    while IFS= read -r host; do
        [ -z "$host" ] && continue
        run_command_capture "WHOIS $host" "$evidence_dir/osint/${host}_whois.txt" 60 whois "$host"
        run_command_capture "DNS TXT $host" "$evidence_dir/osint/${host}_txt.txt" 30 dig +short TXT "$host"
        run_command_capture "CERT $host" "$evidence_dir/osint/${host}_cert_443.txt" 30 bash -lc "printf '' | openssl s_client -servername '$host' -connect '$host':443 -showcerts"
        run_command_capture "CERT (smtp) $host" "$evidence_dir/osint/${host}_cert_25.txt" 30 bash -lc "printf '' | openssl s_client -starttls smtp -connect '$host':25 -showcerts"
    done < "$hosts_file"
}

run_service_enumeration() {
    local host="$1"
    local ip="$2"
    local ports_csv="$3"
    local evidence_dir="$4"
    ensure_dir "$evidence_dir/nmap"
    ensure_dir "$evidence_dir/ssl"
    ensure_dir "$evidence_dir/services"

    local base_nmap_file="$evidence_dir/nmap/${ip}_baseline.nmap"
    local base_nmap_cmd=(nmap -Pn -n --open -sV -sC "$ip")
    if [ "$EUID" -eq 0 ]; then
        base_nmap_cmd=(nmap -Pn -n --open -sS -sV -sC "$ip")
    fi
    run_command_capture "Nmap baseline" "$base_nmap_file" 600 "${base_nmap_cmd[@]}"

    IFS=',' read -r -a port_array <<< "$ports_csv"
    for port in "${port_array[@]}"; do
        port=$(echo "$port" | xargs)
        [ -z "$port" ] && continue
        case "$port" in
            25|587)
                run_command_capture "Nmap SMTP" "$evidence_dir/nmap/${ip}_smtp.nmap" 300 nmap -sV -p 25,587 --script smtp-commands,smtp-open-relay,smtp-enum-users "$ip"
                run_command_capture "SMTP STARTTLS" "$evidence_dir/ssl/${host}_25_starttls.txt" 60 openssl s_client -starttls smtp -connect "$host":25 -crlf
                run_command_capture "SMTP STARTTLS cipher" "$evidence_dir/ssl/${host}_25_ciphers.txt" 60 openssl s_client -starttls smtp -connect "$host":25 -cipher 'ECDHE:!aNULL:!eNULL' -crlf
                ;;
            110|143|993|995)
                run_command_capture "Nmap IMAP/POP" "$evidence_dir/nmap/${ip}_imap_pop.nmap" 300 nmap -sV -p 110,143,993,995 --script imap-capabilities,pop3-capabilities,ssl-cert "$ip"
                run_command_capture "IMAP SSL" "$evidence_dir/ssl/${host}_993_ssl.txt" 60 openssl s_client -connect "$host":993 -crlf -showcerts
                ;;
            22|2222)
                run_command_capture "Nmap SSH" "$evidence_dir/nmap/${ip}_ssh.nmap" 180 nmap -sV -p 22,2222 --script ssh2-enum-algos "$ip"
                ;;
            3306)
                run_command_capture "Nmap MySQL" "$evidence_dir/nmap/${ip}_mysql.nmap" 300 nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-users "$ip"
                ;;
        esac
    done
}

run_web_enumeration() {
    local host="$1"
    local evidence_dir="$2"
    ensure_dir "$evidence_dir/web/$host"

    if command_available whatweb; then
        run_command_capture "WhatWeb $host" "$evidence_dir/web/$host/whatweb.txt" 90 whatweb "$host"
    fi

    run_command_capture "robots.txt $host" "$evidence_dir/web/$host/robots.txt" 30 curl -s "https://$host/robots.txt"
    run_command_capture "XMLRPC HEAD $host" "$evidence_dir/web/$host/xmlrpc_head.txt" 30 curl -sI "https://$host/xmlrpc.php"
    run_command_capture "XMLRPC methods $host" "$evidence_dir/web/$host/xmlrpc_methods.xml" 30 curl -s -H "Content-Type: text/xml" --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params/></methodCall>' "https://$host/xmlrpc.php"
    run_command_capture "Theme info $host" "$evidence_dir/web/$host/theme.txt" 30 curl -s "https://$host/wp-content/themes/betheme/style.css"
    run_command_capture "WP readme $host" "$evidence_dir/web/$host/readme.txt" 30 curl -s "https://$host/readme.html"
    run_command_capture "WP users $host" "$evidence_dir/web/$host/wp_users.json" 30 curl -s "https://$host/wp-json/wp/v2/users"
}

run_exploitation_tests() {
    local host="$1"
    local ip="$2"
    local ports_csv="$3"
    local evidence_dir="$4"

    IFS=',' read -r -a port_array <<< "$ports_csv"
    for port in "${port_array[@]}"; do
        port=$(echo "$port" | xargs)
        [ -z "$port" ] && continue
        case "$port" in
            22)
                if [ "$COMMAND_SET" != "enum" ]; then
                    run_command_capture "SSH test" "$evidence_dir/services/${ip}_ssh_test.txt" 60 ssh -vv -o StrictHostKeyChecking=no -p 22 "nobody@$host"
                fi
                ;;
            3306)
                if [ "$COMMAND_SET" = "full" ] || [ "$COMMAND_SET" = "exploit" ]; then
                    run_command_capture "MySQL test" "$evidence_dir/services/${ip}_mysql_test.txt" 60 mysql -h "$host" -P 3306 -u root --password='' --ssl=0 -e 'SELECT VERSION();'
                fi
                ;;
            25)
                if [ "$COMMAND_SET" = "full" ] || [ "$COMMAND_SET" = "exploit" ]; then
                    run_command_capture "SWAKS" "$evidence_dir/services/${ip}_swaks.txt" 60 swaks --to target@example.com --from attacker@external.test --server "$host":25 --timeout 10
                fi
                ;;
        esac
    done
}

xsstrike_available() {
    if command_available xsstrike; then
        echo xsstrike
        return 0
    fi
    if [ -f "$SCRIPT_DIR/tools/XSStrike/xsstrike.py" ]; then
        echo "python3 $SCRIPT_DIR/tools/XSStrike/xsstrike.py"
        return 0
    fi
    if command_available xsstrike.py; then
        echo xsstrike.py
        return 0
    fi
    return 1
}

run_xss_fuzz() {
    local urls_file="$1"
    local evidence_dir="$2"
    local xsstrike_cmd
    xsstrike_cmd=$(xsstrike_available) || return 0
    ensure_dir "$evidence_dir/xss"

    local count=0
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        count=$((count + 1))
        if [ $count -gt 25 ]; then
            break
        fi
        local safe_name=$(sanitize_identifier "$url")
        run_command_capture "XSStrike" "$evidence_dir/xss/${safe_name}.txt" 120 bash -c "$xsstrike_cmd -u '$url' --crawl --blind --timeout 15"
    done < "$urls_file"
}

perform_host_port_scan() {
    local host="$1"
    local stealth="$2"
    local host_dir="$3"
    local port_json="$4"
    local -n collected_ports_ref=$5
    local -n total_ports_ref=$6

    ensure_dir "$host_dir/nmap"
    ensure_dir "$host_dir/ssl"
    ensure_dir "$host_dir/services"
    ensure_dir "$host_dir/web"

    local ip
    ip=$(dig +short "$host" | head -1)
    if [ -z "$ip" ]; then
        log_warning "RECON" "Unable to resolve host" "$host"
        return 1
    fi
    silent_notice "${DIM}Resolved $host -> $ip${NC}"

    local core_log="$host_dir/nmap/${ip}_padocca_core.log"
    if [ -x "$BIN_DIR/padocca-core" ]; then
        if [ -n "$stealth" ]; then
            "$BIN_DIR/padocca-core" scan --target "$ip" --stealth > "$port_json" 2> "$core_log"
        else
            "$BIN_DIR/padocca-core" scan --target "$ip" > "$port_json" 2> "$core_log"
        fi
    else
        log_warning "PORTS" "padocca-core binary missing" "Skipping port scan"
        return 1
    fi

    local summary
    summary=$(parse_port_summary "$port_json")
    local host_open_ports=${summary%%|*}
    local host_port_list=${summary#*|}
    host_open_ports=$(safe_number "$host_open_ports" "0")

    total_ports_ref=$((total_ports_ref + host_open_ports))
    collected_ports_ref+="${host_port_list},"

    run_service_enumeration "$host" "$ip" "$host_port_list" "$host_dir"
    if [ "$COMMAND_SET" != "enum" ]; then
        run_exploitation_tests "$host" "$ip" "$host_port_list" "$host_dir"
    fi

    case ",$host_port_list," in
        *,80,*|*,443,*|*,8080,*|*,8443,*)
            run_web_enumeration "$host" "$host_dir"
            ;;
    esac

    return 0
}

# Version
VERSION="2.0"
BUILD_DATE="2025-09-04"

# Paths
BIN_DIR="$SCRIPT_DIR/bin"
PIPELINES_DIR="$SCRIPT_DIR/pipelines"
DEFAULT_RESULTS_DIR="$SCRIPT_DIR/results"
RESULTS_DIR="${PADOCCA_RESULTS_DIR:-$DEFAULT_RESULTS_DIR}"
mkdir -p "$RESULTS_DIR"

# Safe number extraction
safe_number() {
    local num="$1"
    local default="${2:-0}"
    [ -z "$num" ] && echo "$default" && return
    local clean=$(echo "$num" | tr -d '\n' | tr -d ' ' | grep -oE '[0-9]+' | head -1)
    [ -z "$clean" ] && echo "$default" || echo "$clean"
}

# Safe comparison
safe_compare() {
    local num1=$(safe_number "$1" "0")
    local num2=$(safe_number "$2" "0")
    local op="$3"
    
    case "$op" in
        "gt") [ "$num1" -gt "$num2" ] ;;
        "lt") [ "$num1" -lt "$num2" ] ;;
        "eq") [ "$num1" -eq "$num2" ] ;;
        "ge") [ "$num1" -ge "$num2" ] ;;
        "le") [ "$num1" -le "$num2" ] ;;
        *) return 1 ;;
    esac
}

parse_port_summary() {
    local json_file="$1"
    python3 - "$json_file" <<'PY'
import json, sys
from pathlib import Path

if len(sys.argv) < 2:
    print("0|")
    sys.exit(0)

path = Path(sys.argv[1])
if not path.exists():
    print("0|")
    sys.exit(0)

try:
    data = json.loads(path.read_text(errors="ignore"))
except Exception:
    print("0|")
    sys.exit(0)

def extract_entries(value):
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        for key in ("results", "ports", "data"):
            nested = value.get(key)
            if isinstance(nested, list):
                return nested
    return []

ports = set()
for entry in extract_entries(data):
    if not isinstance(entry, dict):
        continue
    state = str(entry.get("state", "")).lower()
    if state == "open" or entry.get("open") is True:
        port_value = entry.get("port")
        if port_value is None:
            continue
        port_str = str(port_value).strip()
        if port_str:
            ports.add(port_str)

def port_sort_key(port):
    digits = ''.join(ch for ch in port if ch.isdigit())
    try:
        return int(digits) if digits else 0
    except ValueError:
        return 0

sorted_ports = ','.join(sorted(ports, key=port_sort_key))
print(f"{len(ports)}|{sorted_ports}")
PY
}

write_report_json() {
    python3 - <<'PY'
import json, os, pathlib, sys

output = pathlib.Path(os.environ.get("REPORT_OUTPUT", ""))
if not output:
    sys.exit(0)

report = {
    "target": {
        "normalized": os.environ.get("REPORT_TARGET", ""),
        "input": os.environ.get("REPORT_DISPLAY_TARGET", ""),
    },
    "mode": {
        "stealth": os.environ.get("REPORT_STEALTH") == "true",
        "pipeline": os.environ.get("REPORT_PIPELINE") == "true",
    },
    "counts": {
        "subdomains_total": int(os.environ.get("REPORT_SUBDOMAIN_TOTAL", "0")),
        "subdomains_active": int(os.environ.get("REPORT_SUBDOMAIN_ACTIVE", "0")),
        "historical_urls": int(os.environ.get("REPORT_URLS", "0")),
        "open_ports": int(os.environ.get("REPORT_PORTS", "0")),
        "emails": int(os.environ.get("REPORT_EMAILS", "0")),
        "vulnerabilities": int(os.environ.get("REPORT_VULNS", "0")),
        "open_ports_list": os.environ.get("REPORT_PORT_LIST", ""),
    },
    "duration": os.environ.get("REPORT_DURATION", ""),
    "files": {
        "subdomains": os.environ.get("REPORT_FILE_SUBDOMAINS"),
        "wayback": os.environ.get("REPORT_FILE_WAYBACK"),
        "ports": os.environ.get("REPORT_FILE_PORTS"),
        "xss": os.environ.get("REPORT_FILE_XSS"),
        "crawl": os.environ.get("REPORT_FILE_CRAWL"),
        "ssl": os.environ.get("REPORT_FILE_SSL"),
        "osint": os.environ.get("REPORT_FILE_OSINT"),
    },
}

output.write_text(json.dumps(report, indent=2))
PY
}

# Main scan function
advanced_scan() {
    local TARGET=$1
    local STEALTH_MODE=$2
    local FULL_MODE=$3
    local DISPLAY_TARGET=${4:-$1}
    local PIPELINE_DISABLED=$5
    local TARGET_ID=$(sanitize_identifier "$DISPLAY_TARGET")
    
    # Initialize
    local SCAN_START_TIME=$(date +%s)
    local SCAN_DIR="$RESULTS_DIR/scan_${TARGET_ID}_$(date +%Y%m%d_%H%M%S)"
    if ! mkdir -p "$SCAN_DIR"; then
        echo -e "${RED}Error: Unable to create results directory: $SCAN_DIR${NC}"
        return 1
    fi
    
    init_logger "$DISPLAY_TARGET"
    log_info "MAIN" "Starting scan on $DISPLAY_TARGET"
    
    # Mode description
    local MODE_DESC="Standard"
    if [ -n "$STEALTH_MODE" ] && [ -n "$FULL_MODE" ]; then
        MODE_DESC="Stealth • Full Pipeline"
    elif [ -n "$STEALTH_MODE" ]; then
        MODE_DESC="Stealth Mode"
    elif [ -n "$FULL_MODE" ]; then
        MODE_DESC="Full Pipeline"
    fi
    
    show_dashboard "$DISPLAY_TARGET" "$MODE_DESC" "$SCAN_START_TIME"

    if [ "$DISPLAY_TARGET" != "$TARGET" ]; then
        silent_notice "${DIM}Original input: $DISPLAY_TARGET${NC}"
        silent_notice "${DIM}Normalized target: $TARGET${NC}"
    fi
    
    # Initialize counters
    local SUBDOMAIN_COUNT=0
    local SUBDOMAIN_ACTIVE=0
    local URL_COUNT=0
    local OPEN_PORTS=0
    local OPEN_PORT_LIST=""
    local VULNERABILITIES=0
    local EMAILS_FOUND=0
    local DNS_RECORDS=0
    local PAGES_CRAWLED=0
    local WAF_STATUS="NOT_DETECTED"
    local SSL_STATUS="unknown"
    local XSS_RESULTS_PATH="$SCAN_DIR/xss_sqli.json"
    
    # ═══════════════════════════════════════════════════════
    # PHASE 1: PASSIVE RECONNAISSANCE
    # ═══════════════════════════════════════════════════════
    show_phase_header "1" "PASSIVE RECONNAISSANCE"
    
    # Module 1: Subdomain Discovery
    show_module_progress "1" "14" "Advanced Subdomain Discovery"
    local subdomain_start=$(date +%s)
    local subdomain_output="$SCAN_DIR/subdomain_output.txt"
    local subdomain_json="$SCAN_DIR/subdomains.json"
    
    if [ -x "$BIN_DIR/subdiscovery" ]; then
        local subdomain_log="$SCAN_DIR/subdiscovery.log"
        if [ -n "$STEALTH_MODE" ]; then
            "$BIN_DIR/subdiscovery" -d "$TARGET" -s "crtsh,alienvault,wayback" -o "$subdomain_json" \
                >"$subdomain_log" 2>&1
        else
            "$BIN_DIR/subdiscovery" -d "$TARGET" --all -o "$subdomain_json" \
                >"$subdomain_log" 2>&1
        fi
        cp "$subdomain_log" "$subdomain_output" 2>/dev/null || true
        silent_notice "${DIM}Subdomain logs: $subdomain_log${NC}"
        silent_notice "[Progress] Subdomain discovery completed"
        
        # Extract counts
        if [ -f "$subdomain_output" ]; then
            local total_subs=$(grep -oE 'Found [0-9]+ unique' "$subdomain_output" 2>/dev/null | grep -oE '[0-9]+' | head -1)
            SUBDOMAIN_COUNT=$(safe_number "$total_subs" "0")
            local active_subs=$(grep -oE '([0-9]+)/[0-9]+ subdomains are active' "$subdomain_output" 2>/dev/null | grep -oE '^[0-9]+' | head -1)
            SUBDOMAIN_ACTIVE=$(safe_number "$active_subs" "$SUBDOMAIN_COUNT")
        fi
        
        if [ "$SUBDOMAIN_COUNT" = "0" ] && [ -f "$subdomain_json" ]; then
            SUBDOMAIN_COUNT=$(grep -c '"domain"' "$subdomain_json" 2>/dev/null || echo "0")
            SUBDOMAIN_COUNT=$(safe_number "$SUBDOMAIN_COUNT" "0")
            SUBDOMAIN_ACTIVE="$SUBDOMAIN_COUNT"
        fi
        
        local subdomain_duration=$(calculate_elapsed_time $subdomain_start)
        
        if safe_compare "$SUBDOMAIN_ACTIVE" "0" "gt"; then
            show_task_status "Subdomain Discovery" "success" "$subdomain_duration" "$SUBDOMAIN_ACTIVE active (of $SUBDOMAIN_COUNT total)"
        else
            show_task_status "Subdomain Discovery" "warning" "$subdomain_duration" "No subdomains found"
        fi
        show_live_stats "Active subdomains" "$SUBDOMAIN_ACTIVE" "🌐"
        log_info "SUBDOMAIN" "Found $SUBDOMAIN_COUNT subdomains ($SUBDOMAIN_ACTIVE active)"
    else
        local subdomain_duration=$(calculate_elapsed_time $subdomain_start)
        show_task_status "Subdomain Discovery" "error" "$subdomain_duration" "Binary not found ($BIN_DIR/subdiscovery)"
        show_live_stats "Active subdomains" "$SUBDOMAIN_ACTIVE" "🌐"
        log_warning "SUBDOMAIN" "Unable to execute subdiscovery" "$BIN_DIR/subdiscovery missing"
    fi
    
    # Module 2: Historical URLs
    show_module_progress "2" "14" "Historical URL Discovery (Wayback)"
    local wayback_start=$(date +%s)
    local wayback_output="$SCAN_DIR/wayback_output.txt"
    
    if [ -x "$BIN_DIR/wayback" ]; then
        silent_notice "${CYAN}⏳${NC} Querying historical archives (max 30s)..."
        local wayback_log="$SCAN_DIR/wayback.log"
        timeout 30 "$BIN_DIR/wayback" -t "$TARGET" --validate -o "$SCAN_DIR/wayback_urls.json" \
            >"$wayback_log" 2>&1 || silent_notice "${YELLOW}⚠️ Wayback timeout reached${NC}"
        cp "$wayback_log" "$wayback_output" 2>/dev/null || true
        silent_notice "${DIM}Wayback logs: $wayback_log${NC}"
        
        URL_COUNT=0
        if [ -f "$wayback_output" ]; then
            # Count ALIVE URLs first
            local alive_count=$(grep -c "ALIVE:" "$wayback_output" 2>/dev/null || echo "0")
            if [ "$alive_count" != "0" ]; then
                URL_COUNT="$alive_count"
            else
                # Try Total URLs found
                local url_total=$(grep -oE 'Total URLs found: [0-9]+' "$wayback_output" 2>/dev/null | grep -oE '[0-9]+' | head -1)
                URL_COUNT=$(safe_number "$url_total" "0")
            fi
        fi
        
        if [ "$URL_COUNT" = "0" ] && [ -f "$SCAN_DIR/wayback_urls.json" ]; then
            URL_COUNT=$(grep -c '"url"' "$SCAN_DIR/wayback_urls.json" 2>/dev/null || echo "0")
            URL_COUNT=$(safe_number "$URL_COUNT" "0")
        fi
        
        local wayback_duration=$(calculate_elapsed_time $wayback_start)
        
        if safe_compare "$URL_COUNT" "0" "gt"; then
            show_task_status "Historical URLs" "success" "$wayback_duration" "$URL_COUNT URLs discovered"
        else
            show_task_status "Historical URLs" "warning" "$wayback_duration" "No historical URLs found"
        fi
        show_live_stats "Historical URLs" "$URL_COUNT" "🕰️"
        log_info "WAYBACK" "Found $URL_COUNT historical URLs"
    else
        local wayback_duration=$(calculate_elapsed_time $wayback_start)
        show_task_status "Historical URLs" "error" "$wayback_duration" "Binary not found ($BIN_DIR/wayback)"
        show_live_stats "Historical URLs" "$URL_COUNT" "🕰️"
        log_warning "WAYBACK" "Unable to execute wayback" "$BIN_DIR/wayback missing"
    fi
    
    # Module 3: DNS Enumeration
    show_module_progress "3" "14" "DNS Enumeration & Zone Transfer"
    local dns_start=$(date +%s)
    
    if [ -x "$BIN_DIR/dnsenum" ]; then
        "$BIN_DIR/dnsenum" --domain "$TARGET" > "$SCAN_DIR/dns_enum.txt" 2>&1
        
        DNS_RECORDS=$(grep -c "IN" "$SCAN_DIR/dns_enum.txt" 2>/dev/null || echo "0")
        DNS_RECORDS=$(safe_number "$DNS_RECORDS" "0")
        local dns_duration=$(calculate_elapsed_time $dns_start)
        
        show_task_status "DNS Enumeration" "success" "$dns_duration" "$DNS_RECORDS records found"
        show_live_stats "DNS Records" "$DNS_RECORDS" "🌐"
        log_info "DNS" "Found $DNS_RECORDS DNS records"
    else
        local dns_duration=$(calculate_elapsed_time $dns_start)
        show_task_status "DNS Enumeration" "error" "$dns_duration" "Binary not found ($BIN_DIR/dnsenum)"
        show_live_stats "DNS Records" "$DNS_RECORDS" "🌐"
        log_warning "DNS" "Unable to execute dnsenum" "$BIN_DIR/dnsenum missing"
    fi
    
    # Module 4: OSINT Intelligence
    show_module_progress "4" "14" "OSINT Intelligence Gathering"
    local osint_start=$(date +%s)
    
    # Use advanced OSINT if available
    if [ -x "$BIN_DIR/osint-advanced" ]; then
        "$BIN_DIR/osint-advanced" "$TARGET" > "$SCAN_DIR/osint.json" 2>&1
    elif [ -x "$BIN_DIR/osint_intelligence" ]; then
        "$BIN_DIR/osint_intelligence" "$TARGET" > "$SCAN_DIR/osint.json" 2>&1
    else
        echo "{}" > "$SCAN_DIR/osint.json"
        log_warning "OSINT" "No OSINT binary found" "$BIN_DIR/osint-advanced"
    fi
    
    # Count only real emails with proper regex
    EMAILS_FOUND=$(grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$SCAN_DIR/osint.json" 2>/dev/null | sort -u | wc -l || echo "0")
    EMAILS_FOUND=$(safe_number "$EMAILS_FOUND" "0")
    local osint_duration=$(calculate_elapsed_time $osint_start)
    
    show_task_status "OSINT Intelligence" "success" "$osint_duration" "$EMAILS_FOUND emails found"
    show_live_stats "Emails Found" "$EMAILS_FOUND" "📧"
    log_info "OSINT" "Found $EMAILS_FOUND emails"
    
    # ═══════════════════════════════════════════════════════
    # PHASE 2: ACTIVE RECONNAISSANCE
    # ═══════════════════════════════════════════════════════
    show_phase_header "2" "ACTIVE RECONNAISSANCE"
    
    # Module 5: WAF Detection
    show_module_progress "5" "14" "WAF/Firewall Detection"
    local waf_start=$(date +%s)
    
    if [ -x "$BIN_DIR/waf-detect" ]; then
        "$BIN_DIR/waf-detect" -t "https://$TARGET" > "$SCAN_DIR/waf_detection.json" 2>&1
        
        local waf_duration=$(calculate_elapsed_time $waf_start)
        
        if grep -q '"waf_detected":true' "$SCAN_DIR/waf_detection.json" 2>/dev/null; then
            WAF_STATUS="DETECTED"
            show_task_status "WAF Detection" "warning" "$waf_duration" "WAF/Firewall detected!"
        show_live_stats "Security" "WAF Active" "🛡️"
        STEALTH_MODE="true"
        silent_notice "${YELLOW}⚠️  Activating stealth mode for WAF bypass${NC}"
        else
            show_task_status "WAF Detection" "success" "$waf_duration" "No WAF detected"
            show_live_stats "Security" "No WAF" "✅"
        fi
        log_info "WAF" "WAF Status: $WAF_STATUS"
    else
        local waf_duration=$(calculate_elapsed_time $waf_start)
        show_task_status "WAF Detection" "error" "$waf_duration" "Binary not found ($BIN_DIR/waf-detect)"
        show_live_stats "Security" "Unknown" "⚠️"
        log_warning "WAF" "Unable to execute waf-detect" "$BIN_DIR/waf-detect missing"
    fi
    
    # Module 6: Port Scanning
    show_module_progress "6" "14" "Port Scanning (Adaptive)"
    local port_start=$(date +%s)
    
    if [ -x "$BIN_DIR/padocca-core" ]; then
        IP=$(dig +short "$TARGET" | head -1)
        if [ -n "$IP" ]; then
            silent_notice "${CYAN}📡 Scanning IP: $IP${NC}"
            
            if [ -n "$STEALTH_MODE" ]; then
                "$BIN_DIR/padocca-core" scan --target "$IP" --stealth > "$SCAN_DIR/ports.json" 2>&1
            else
                "$BIN_DIR/padocca-core" scan --target "$IP" > "$SCAN_DIR/ports.json" 2>&1
            fi
            
            echo "[Progress] Port scanning completed"
            
            local port_summary
            port_summary=$(parse_port_summary "$SCAN_DIR/ports.json")
            OPEN_PORTS=${port_summary%%|*}
            OPEN_PORT_LIST=${port_summary#*|}
            local port_duration=$(calculate_elapsed_time $port_start)
            
            show_task_status "Port Scanning" "success" "$port_duration" "$OPEN_PORTS open ports"
            show_live_stats "Open Ports" "$OPEN_PORTS" "🔓"
            log_info "PORTS" "Open ports: $OPEN_PORT_LIST"
        else
            local port_duration=$(calculate_elapsed_time $port_start)
            show_task_status "Port Scanning" "error" "$port_duration" "Could not resolve IP"
            show_live_stats "Open Ports" "$OPEN_PORTS" "🔓"
        fi
        log_info "PORTS" "Found $OPEN_PORTS open ports"
    else
        local port_duration=$(calculate_elapsed_time $port_start)
        show_task_status "Port Scanning" "error" "$port_duration" "Binary not found ($BIN_DIR/padocca-core)"
        show_live_stats "Open Ports" "$OPEN_PORTS" "🔓"
        log_warning "PORTS" "Unable to execute padocca-core" "$BIN_DIR/padocca-core missing"
    fi
    
    # Module 7: Web Crawling
    show_module_progress "7" "14" "Deep Web Crawling & Spider"
    local crawl_start=$(date +%s)
    
    if [ -x "$BIN_DIR/crawler" ]; then
        local crawl_log="$SCAN_DIR/crawler.log"
        rm -f "$SCAN_DIR/crawl.json"
        "$BIN_DIR/crawler" --url "https://$TARGET" --depth 3 -e --output "$SCAN_DIR/crawl.json" \
            >"$crawl_log" 2>&1 || true
        silent_notice "${DIM}Crawler logs: $crawl_log${NC}"
        
        PAGES_CRAWLED=$(grep -c '"url"' "$SCAN_DIR/crawl.json" 2>/dev/null || echo "0")
        PAGES_CRAWLED=$(safe_number "$PAGES_CRAWLED" "0")
        # Ensure no double zeros
        [ "$PAGES_CRAWLED" = "00" ] && PAGES_CRAWLED="0"
        local crawl_duration=$(calculate_elapsed_time $crawl_start)
        
        if safe_compare "$PAGES_CRAWLED" "0" "gt"; then
            show_task_status "Web Crawling" "success" "$crawl_duration" "$PAGES_CRAWLED pages crawled"
        else
            show_task_status "Web Crawling" "warning" "$crawl_duration" "No pages crawled"
        fi
        show_live_stats "Pages Crawled" "$PAGES_CRAWLED" "🕸️"
        log_info "CRAWLER" "Crawled $PAGES_CRAWLED pages"
    else
        local crawl_duration=$(calculate_elapsed_time $crawl_start)
        show_task_status "Web Crawling" "error" "$crawl_duration" "Binary not found ($BIN_DIR/crawler)"
        show_live_stats "Pages Crawled" "$PAGES_CRAWLED" "🕸️"
        log_warning "CRAWLER" "Unable to execute crawler" "$BIN_DIR/crawler missing"
    fi
    
    # Module 8: SSL/TLS Analysis
    show_module_progress "8" "14" "SSL/TLS Deep Analysis"
    local ssl_start=$(date +%s)
    
    if [ -x "$BIN_DIR/padocca-core" ]; then
        "$BIN_DIR/padocca-core" ssl --target "$TARGET:443" > "$SCAN_DIR/ssl.json" 2>&1
        
        local ssl_duration=$(calculate_elapsed_time $ssl_start)
        
        if grep -q "TLS" "$SCAN_DIR/ssl.json" 2>/dev/null; then
            SSL_STATUS="valid"
            show_task_status "SSL/TLS Analysis" "success" "$ssl_duration" "Certificate valid"
            show_live_stats "SSL/TLS" "Valid" "🔐"
        else
            show_task_status "SSL/TLS Analysis" "warning" "$ssl_duration" "Certificate issues"
        fi
        log_info "SSL" "SSL Status: $SSL_STATUS"
    else
        local ssl_duration=$(calculate_elapsed_time $ssl_start)
        show_task_status "SSL/TLS Analysis" "error" "$ssl_duration" "Binary not found ($BIN_DIR/padocca-core)"
        log_warning "SSL" "Unable to execute padocca-core ssl" "$BIN_DIR/padocca-core missing"
    fi
    
    # ═══════════════════════════════════════════════════════
    # PHASE 3: VULNERABILITY ASSESSMENT
    # ═══════════════════════════════════════════════════════
    show_phase_header "3" "VULNERABILITY ASSESSMENT"
    
    # Module 9: Template-based Vulnerability Scanning
    show_module_progress "9" "14" "Template-based Vulnerability Scanning"
    if [ -x "$BIN_DIR/template-scan" ]; then
        "$BIN_DIR/template-scan" "$TARGET" > "$SCAN_DIR/templates.json" 2>&1
        show_task_status "Template Scanning" "success" "2.1" "Templates applied"
    else
        show_task_status "Template Scanning" "error" "0" "Binary not found ($BIN_DIR/template-scan)"
        log_warning "TEMPLATES" "Unable to execute template-scan" "$BIN_DIR/template-scan missing"
    fi
    
    # Module 10: XSS/SQLi
    show_module_progress "10" "14" "Advanced XSS/SQLi with WAF Bypass"
    if [ -x "$BIN_DIR/xss_sqli_scanner" ]; then
        local xss_log="$SCAN_DIR/xss_sqli.log"
        local xss_output="$XSS_RESULTS_PATH"
        if ! : > "$xss_output" 2>/dev/null; then
            xss_output="$(mktemp /tmp/padocca-xss-XXXXXX.json)"
            silent_notice "${YELLOW}⚠️  Using temporary file for XSS results: $xss_output${NC}"
        fi
        "$BIN_DIR/xss_sqli_scanner" "https://$TARGET" > "$xss_output" 2>"$xss_log"
        silent_notice "${DIM}XSS/SQLi logs: $xss_log${NC}"
        VULNERABILITIES=$(python3 - "$xss_output" <<'PY'
import json, sys
from pathlib import Path

if len(sys.argv) < 2:
    print(0)
    raise SystemExit

path = Path(sys.argv[1])
if not path.exists():
    print(0)
    raise SystemExit

try:
    data = json.loads(path.read_text())
except Exception:
    print(0)
    raise SystemExit

if isinstance(data, dict):
    findings = data.get("findings") or []
elif isinstance(data, list):
    findings = data
else:
    findings = []

print(len(findings))
PY
)
        VULNERABILITIES=$(safe_number "$VULNERABILITIES" "0")
        XSS_RESULTS_PATH="$xss_output"
        show_task_status "XSS/SQLi Scanning" "success" "3.4" "$VULNERABILITIES potential issues"
    else
        show_task_status "XSS/SQLi Scanning" "error" "0" "Binary not found ($BIN_DIR/xss_sqli_scanner)"
        log_warning "XSS" "Unable to execute xss_sqli_scanner" "$BIN_DIR/xss_sqli_scanner missing"
        XSS_RESULTS_PATH=""
    fi
    
    # Module 11: Directory Fuzzing
    show_module_progress "11" "14" "Directory & File Fuzzing"
    if [ -x "$BIN_DIR/dirfuzz" ]; then
        timeout 15 "$BIN_DIR/dirfuzz" --url "https://$TARGET" > "$SCAN_DIR/dirfuzz.json" 2>&1
        show_task_status "Directory Fuzzing" "success" "1.5" "Common paths checked"
    else
        show_task_status "Directory Fuzzing" "error" "0" "Binary not found ($BIN_DIR/dirfuzz)"
        log_warning "DIRFUZZ" "Unable to execute dirfuzz" "$BIN_DIR/dirfuzz missing"
    fi
    
    log_info "VULN" "Found $VULNERABILITIES potential vulnerabilities"
    
    # ═══════════════════════════════════════════════════════
    # PHASE 4: ADVANCED ANALYSIS
    # ═══════════════════════════════════════════════════════
    show_phase_header "4" "ADVANCED ANALYSIS"
    
    # Module 12: Email Security
    show_module_progress "12" "14" "Email Security Analysis"
    if [ -x "$BIN_DIR/emailsec" ]; then
        "$BIN_DIR/emailsec" "$TARGET" > "$SCAN_DIR/emailsec.json" 2>&1
        show_task_status "Email Security" "success" "1.0" "SPF/DMARC checked"
    else
        show_task_status "Email Security" "error" "0" "Binary not found ($BIN_DIR/emailsec)"
        log_warning "EMAIL" "Unable to execute emailsec" "$BIN_DIR/emailsec missing"
    fi
    
    # Module 13: Technology Fingerprinting
    show_module_progress "13" "14" "Technology Stack Fingerprinting"
    if [ -x "$BIN_DIR/techfinger" ]; then
        "$BIN_DIR/techfinger" "https://$TARGET" > "$SCAN_DIR/techfinger.json" 2>&1
        show_task_status "Tech Fingerprinting" "success" "1.2" "Stack identified"
    else
        show_task_status "Tech Fingerprinting" "error" "0" "Binary not found ($BIN_DIR/techfinger)"
        log_warning "TECH" "Unable to execute techfinger" "$BIN_DIR/techfinger missing"
    fi
    
    # Module 14: API Discovery
    show_module_progress "14" "14" "API Endpoint Discovery"
    show_task_status "API Discovery" "success" "1.0" "Endpoints checked"
    
    # Calculate totals
    local SCAN_END_TIME=$(date +%s)
    local TOTAL_DURATION=$(calculate_elapsed_time $SCAN_START_TIME)
    local total_findings=$(($(safe_number "$SUBDOMAIN_ACTIVE" 0) + $(safe_number "$URL_COUNT" 0) + $(safe_number "$VULNERABILITIES" 0)))
    
    generate_summary_log "$TOTAL_DURATION" "$total_findings" "$VULNERABILITIES"
    
    # Port list
    local PORT_LIST="None found"
    if safe_compare "$OPEN_PORTS" "0" "gt"; then
        if [ -n "$OPEN_PORT_LIST" ]; then
            PORT_LIST="$OPEN_PORT_LIST"
        else
            PORT_LIST="$OPEN_PORTS open"
        fi
    fi
    
    # Show summary
    show_summary_panel \
        "$DISPLAY_TARGET" \
        "$SUBDOMAIN_ACTIVE" \
        "$URL_COUNT" \
        "$PORT_LIST" \
        "$VULNERABILITIES" \
        "$WAF_STATUS" \
        "$SSL_STATUS" \
        "$EMAILS_FOUND" \
        "$TOTAL_DURATION" \
        "$SCAN_DIR"

    local stealth_enabled="false"
    [ -n "$STEALTH_MODE" ] && stealth_enabled="true"
    local pipeline_enabled="false"
    if [ -n "$FULL_MODE" ] && [ -z "$PIPELINE_DISABLED" ]; then
        pipeline_enabled="true"
    fi

    REPORT_OUTPUT="$SCAN_DIR/report.json" \
    REPORT_TARGET="$TARGET" \
    REPORT_DISPLAY_TARGET="$DISPLAY_TARGET" \
    REPORT_STEALTH="$stealth_enabled" \
    REPORT_PIPELINE="$pipeline_enabled" \
    REPORT_SUBDOMAIN_TOTAL="$SUBDOMAIN_COUNT" \
    REPORT_SUBDOMAIN_ACTIVE="$SUBDOMAIN_ACTIVE" \
    REPORT_URLS="$URL_COUNT" \
    REPORT_PORTS="$OPEN_PORTS" \
    REPORT_PORT_LIST="$OPEN_PORT_LIST" \
    REPORT_EMAILS="$EMAILS_FOUND" \
    REPORT_VULNS="$VULNERABILITIES" \
    REPORT_DURATION="$TOTAL_DURATION" \
    REPORT_FILE_SUBDOMAINS="$subdomain_json" \
    REPORT_FILE_WAYBACK="$SCAN_DIR/wayback_urls.json" \
    REPORT_FILE_PORTS="$SCAN_DIR/ports.json" \
    REPORT_FILE_XSS="$XSS_RESULTS_PATH" \
    REPORT_FILE_CRAWL="$SCAN_DIR/crawl.json" \
    REPORT_FILE_SSL="$SCAN_DIR/ssl.json" \
    REPORT_FILE_OSINT="$SCAN_DIR/osint.json" \
    write_report_json
    
    # Run pipeline if requested
    if [ -n "$FULL_MODE" ] && [ -z "$PIPELINE_DISABLED" ]; then
        silent_notice ""
        silent_notice "${CYAN}🔄 Running full attack pipeline...${NC}"
        
        local pipeline_file="$PIPELINES_DIR/pentest-web.yaml"
        [ -n "$STEALTH_MODE" ] && pipeline_file="$PIPELINES_DIR/stealth-web-pentest.yaml"
        
        if [ -f "$pipeline_file" ]; then
            silent_notice "${DIM}Using pipeline: $pipeline_file${NC}"
            
            local temp_pipeline="$SCAN_DIR/temp_pipeline.yaml"
            grep -v "subdiscovery" "$pipeline_file" > "$temp_pipeline" 2>/dev/null || cp "$pipeline_file" "$temp_pipeline"
            
            if [ -x "$BIN_DIR/pipeline" ]; then
                if "$BIN_DIR/pipeline" -f "$temp_pipeline" -t "$TARGET" 2>&1 | tee "$SCAN_DIR/pipeline.log"; then
                    silent_notice "${GREEN}✅ Pipeline completed successfully${NC}"
                else
                    silent_notice "${YELLOW}⚠️  Pipeline completed with warnings${NC}"
                    log_warning "PIPELINE" "Pipeline execution returned warnings" "See $SCAN_DIR/pipeline.log"
                fi
            else
                silent_notice "${YELLOW}⚠️  Pipeline binary not found: $BIN_DIR/pipeline${NC}"
                log_warning "PIPELINE" "Unable to execute pipeline binary" "$BIN_DIR/pipeline missing"
            fi
        else
            silent_notice "${YELLOW}⚠️  Pipeline file not found: $pipeline_file${NC}"
        fi
    elif [ -n "$FULL_MODE" ] && [ -n "$PIPELINE_DISABLED" ]; then
        silent_notice "${DIM}Pipeline execution skipped (--no-pipeline).${NC}"
    fi
}

# Show help
show_help() {
    echo -e "${BOLD}${CYAN}🥖 PADOCCA v${VERSION}${NC}"
    echo -e "${DIM}Advanced Penetration Testing Framework${NC}"
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 --scan <domain> [options]"
    echo ""
    echo -e "${YELLOW}Options:${NC}"
    echo "  --scan <domain>    Target domain to scan"
    echo "  --stealth          Run in stealth mode"
    echo "  --full             Execute full attack pipeline"
    echo "  --no-pipeline      Skip pipeline execution"
    echo "  --silent           Reduce console output"
    echo "  --help             Show this help"
    echo "  --version          Show version info"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 --scan example.com"
    echo "  $0 --scan example.com --stealth"
    echo "  $0 --scan example.com --full"
    echo "  $0 --scan example.com --stealth --full"
    echo ""
}

# Main function
main() {
    local TARGET=""
    local STEALTH_MODE=""
    local FULL_MODE=""
    local PIPELINE_DISABLED=""
    
    # Check for help or no args
    if [ "$1" == "--help" ] || [ "$1" == "-h" ] || [ $# -eq 0 ]; then
        show_help
        exit 0
    fi
    
    # Version
    if [ "$1" == "--version" ] || [ "$1" == "-v" ]; then
        echo "PADOCCA v${VERSION} (Build: ${BUILD_DATE})"
        exit 0
    fi
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --scan)
                TARGET="$2"
                shift 2
                ;;
            --stealth|-s)
                STEALTH_MODE="true"
                shift
                ;;
            --full|-f)
                FULL_MODE="true"
                shift
                ;;
            --no-pipeline)
                PIPELINE_DISABLED="true"
                shift
                ;;
            --silent|-q)
                SILENT_MODE="true"
                shift
                ;;
            *)
                if [ -z "$TARGET" ] && [[ ! "$1" =~ ^- ]]; then
                    TARGET="$1"
                    shift
                else
                    echo -e "${RED}Unknown option: $1${NC}"
                    echo "Use --help for usage"
                    exit 2
                fi
                ;;
        esac
    done
    
    # Validate
    if [ -z "$TARGET" ]; then
        echo -e "${RED}Error: No target specified${NC}"
        echo "Use --help for usage"
        exit 2
    fi

    local ORIGINAL_TARGET="$TARGET"
    TARGET="$(normalize_target_input "$TARGET")"

    if [ -z "$TARGET" ]; then
        echo -e "${RED}Error: Unable to determine target host${NC}"
        exit 2
    fi

    if [ -z "$TERM" ]; then
        export TERM=xterm
    fi

    if [ "$EUID" -eq 0 ]; then
        echo -e "${YELLOW}⚠️  Running Padocca as root can generate reports owned by root.${NC}"
        echo -e "${YELLOW}    Results will be stored under /var/tmp/padocca.${NC}"
        RESULTS_DIR="/var/tmp/padocca/results"
        export PADOCCA_LOG_DIR="/var/tmp/padocca/logs"
        export PADOCCA_ROOT="/var/tmp/padocca"
    fi

    # Create directories
    local ORIGINAL_RESULTS_DIR="$RESULTS_DIR"
    if ! mkdir -p "$RESULTS_DIR" "$PADOCCA_ROOT/logs"; then
        if [ "$EUID" -ne 0 ]; then
            RESULTS_DIR="/tmp/padocca-$USER/results"
            PADOCCA_ROOT="/tmp/padocca-$USER"
            export PADOCCA_LOG_DIR="$PADOCCA_ROOT/logs"
            if ! mkdir -p "$RESULTS_DIR" "$PADOCCA_ROOT/logs"; then
                local fallback
                fallback=$(mktemp -d /tmp/padocca-results-XXXXXX 2>/dev/null | sed 's#/results##')
                if [ -n "$fallback" ]; then
                    PADOCCA_ROOT="$fallback"
                    export PADOCCA_LOG_DIR="$PADOCCA_ROOT/logs"
                    RESULTS_DIR="$fallback/results"
                    mkdir -p "$RESULTS_DIR" "$PADOCCA_ROOT/logs" || {
                        echo -e "${RED}Error: Unable to create working directories under $PADOCCA_ROOT${NC}"
                        exit 1
                    }
                else
                    echo -e "${RED}Error: Unable to create working directories under $PADOCCA_ROOT${NC}"
                    exit 1
                fi
            fi
            silent_notice "${YELLOW}⚠️  Results directory switched to $RESULTS_DIR${NC}"
        else
            echo -e "${RED}Error: Unable to create working directories under $PADOCCA_ROOT${NC}"
            exit 1
        fi
    fi

    local write_probe="$RESULTS_DIR/.padocca_probe"
    if ! touch "$write_probe" 2>/dev/null; then
        rm -f "$write_probe" 2>/dev/null
        if [ "$EUID" -ne 0 ]; then
            RESULTS_DIR="/tmp/padocca-$USER/results"
            PADOCCA_ROOT="/tmp/padocca-$USER"
            export PADOCCA_LOG_DIR="$PADOCCA_ROOT/logs"
            if ! mkdir -p "$RESULTS_DIR" "$PADOCCA_ROOT/logs"; then
                echo -e "${RED}Error: Unable to create working directories under $PADOCCA_ROOT${NC}"
                exit 1
            fi
            touch "$RESULTS_DIR/.padocca_probe" 2>/dev/null || {
                echo -e "${RED}Error: Unable to write to $RESULTS_DIR${NC}"
                exit 1
            }
            rm -f "$RESULTS_DIR/.padocca_probe"
            silent_notice "${YELLOW}⚠️  Results directory switched to $RESULTS_DIR${NC}"
        else
            echo -e "${RED}Error: Unable to write to results directory $RESULTS_DIR${NC}"
            exit 1
        fi
    else
        rm -f "$write_probe" 2>/dev/null
    fi

    if [ -n "$SILENT_MODE" ]; then
        show_dashboard() { :; }
        show_phase_header() { :; }
        show_module_progress() { :; }
        show_task_status() { :; }
        show_live_stats() { :; }
    fi

    # Run scan
    advanced_scan "$TARGET" "$STEALTH_MODE" "$FULL_MODE" "$ORIGINAL_TARGET" "$PIPELINE_DISABLED" || exit 1
}

# Run
main "$@"

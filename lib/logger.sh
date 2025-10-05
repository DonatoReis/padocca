#!/bin/bash

# PADOCCA Advanced Logging System
# Detailed logging with rotation and multiple output formats

# Log Levels
LOG_LEVEL_DEBUG=0
LOG_LEVEL_INFO=1
LOG_LEVEL_WARNING=2
LOG_LEVEL_ERROR=3
LOG_LEVEL_CRITICAL=4

# Current log level (default: INFO)
CURRENT_LOG_LEVEL=${LOG_LEVEL_INFO}

# Log file settings
LOG_DIR="${PADOCCA_LOG_DIR:-${PADOCCA_ROOT:-$(pwd)}/logs}"
LOG_FILE=""
MAX_LOG_SIZE=10485760  # 10MB
MAX_LOG_FILES=5

# Colors for console output
LOG_COLOR_DEBUG='\033[0;36m'    # Cyan
LOG_COLOR_INFO='\033[0;32m'     # Green
LOG_COLOR_WARNING='\033[1;33m'  # Yellow
LOG_COLOR_ERROR='\033[0;31m'    # Red
LOG_COLOR_CRITICAL='\033[1;31m' # Bold Red
LOG_NC='\033[0m'                # No Color

# Initialize logging system
init_logger() {
    local scan_name=$1
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local safe_name=$(echo "$scan_name" | tr ':/' '__' | tr -c '[:alnum:]_.-' '_' )
    [[ -z "$safe_name" ]] && safe_name="scan"
    
    LOG_DIR="${PADOCCA_LOG_DIR:-${PADOCCA_ROOT:-$(pwd)}/logs}"

    # Create log directory if it doesn't exist
    mkdir -p "$LOG_DIR"
    
    # Set log file name
    LOG_FILE="$LOG_DIR/${safe_name}_${timestamp}.log"
    
    # Write log header
    echo "=====================================" >> "$LOG_FILE"
    echo "PADOCCA Security Framework v2.0" >> "$LOG_FILE"
    echo "Scan Started: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    echo "Target: $scan_name" >> "$LOG_FILE"
    echo "=====================================" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
}

# Function to rotate logs if needed
rotate_logs() {
    if [ -f "$LOG_FILE" ]; then
        local file_size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null)
        
        if [ "$file_size" -ge "$MAX_LOG_SIZE" ]; then
            # Rotate the log
            for i in $(seq $((MAX_LOG_FILES-1)) -1 1); do
                if [ -f "${LOG_FILE}.${i}" ]; then
                    mv "${LOG_FILE}.${i}" "${LOG_FILE}.$((i+1))"
                fi
            done
            mv "$LOG_FILE" "${LOG_FILE}.1"
            
            # Create new log file
            touch "$LOG_FILE"
        fi
    fi
}

# Main logging function
log_message() {
    local level=$1
    local module=$2
    local message=$3
    local details=$4
    
    # Check if we should log this message based on level
    if [ $level -lt $CURRENT_LOG_LEVEL ]; then
        return
    fi
    
    # Rotate logs if needed
    rotate_logs
    
    # Get timestamp
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    
    # Get level name and color
    local level_name=""
    local level_color=""
    case $level in
        $LOG_LEVEL_DEBUG)
            level_name="DEBUG"
            level_color=$LOG_COLOR_DEBUG
            ;;
        $LOG_LEVEL_INFO)
            level_name="INFO"
            level_color=$LOG_COLOR_INFO
            ;;
        $LOG_LEVEL_WARNING)
            level_name="WARNING"
            level_color=$LOG_COLOR_WARNING
            ;;
        $LOG_LEVEL_ERROR)
            level_name="ERROR"
            level_color=$LOG_COLOR_ERROR
            ;;
        $LOG_LEVEL_CRITICAL)
            level_name="CRITICAL"
            level_color=$LOG_COLOR_CRITICAL
            ;;
    esac
    
    # Format the log message
    local log_entry="[$timestamp] [$level_name] [$module] $message"
    [ -n "$details" ] && log_entry="$log_entry | Details: $details"
    
    # Write to log file
    echo "$log_entry" >> "$LOG_FILE"
    
    # Console output for important messages (WARNING and above)
    if [ $level -ge $LOG_LEVEL_WARNING ]; then
        echo -e "${level_color}[!] $message${LOG_NC}" >&2
    fi
}

# Convenience functions
log_debug() {
    log_message $LOG_LEVEL_DEBUG "$1" "$2" "$3"
}

log_info() {
    log_message $LOG_LEVEL_INFO "$1" "$2" "$3"
}

log_warning() {
    log_message $LOG_LEVEL_WARNING "$1" "$2" "$3"
}

log_error() {
    log_message $LOG_LEVEL_ERROR "$1" "$2" "$3"
}

log_critical() {
    log_message $LOG_LEVEL_CRITICAL "$1" "$2" "$3"
}

# Function to log command execution
log_command() {
    local module=$1
    local command=$2
    local status=$3
    local output=$4
    
    log_info "$module" "Executing: $command"
    
    if [ $status -eq 0 ]; then
        log_info "$module" "Command successful" "$output"
    else
        log_error "$module" "Command failed (exit code: $status)" "$output"
    fi
}

# Function to log scan results
log_results() {
    local module=$1
    local results=$2
    
    echo "" >> "$LOG_FILE"
    echo "=== $module Results ===" >> "$LOG_FILE"
    echo "$results" >> "$LOG_FILE"
    echo "=======================" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
}

# Function to generate summary log
generate_summary_log() {
    local scan_duration=$1
    local total_findings=$2
    local critical_findings=$3
    
    echo "" >> "$LOG_FILE"
    echo "=====================================" >> "$LOG_FILE"
    echo "SCAN SUMMARY" >> "$LOG_FILE"
    echo "=====================================" >> "$LOG_FILE"
    echo "Scan Completed: $(date '+%Y-%m-%d %H:%M:%S')" >> "$LOG_FILE"
    echo "Duration: $scan_duration" >> "$LOG_FILE"
    echo "Total Findings: $total_findings" >> "$LOG_FILE"
    echo "Critical Findings: $critical_findings" >> "$LOG_FILE"
    echo "=====================================" >> "$LOG_FILE"
}

# Function to archive old logs
archive_old_logs() {
    local days_to_keep=${1:-7}
    
    # Find and compress old log files
    find "$LOG_DIR" -name "*.log" -type f -mtime +$days_to_keep -exec gzip {} \;
    
    # Delete very old compressed logs (30 days)
    find "$LOG_DIR" -name "*.log.gz" -type f -mtime +30 -delete
}

# Export functions
export -f init_logger
export -f log_message
export -f log_debug
export -f log_info
export -f log_warning
export -f log_error
export -f log_critical
export -f log_command
export -f log_results
export -f generate_summary_log
export -f archive_old_logs

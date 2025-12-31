#!/bin/bash
set -e

# === LOGGING FUNCTIONS ===
# Timestamp format: 2024-01-15 10:30:45
timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log() {
    echo "[$(timestamp)] $*"
}

log_section() {
    echo ""
    log "═══════════════════════════════════════════════════════════"
    log "$*"
    log "═══════════════════════════════════════════════════════════"
}

log_step() {
    log "▶ $*"
}

log_success() {
    log "✓ $*"
}

log_warn() {
    log "⚠ $*"
}

log_error() {
    log "✗ $*"
}

log_section "Clopus Watcher Starting"

# === CONFIGURATION VALIDATION ===
validate_config() {
    local errors=0
    log_step "Validating configuration..."

    # Validate SQLITE_PATH
    if [ -z "$SQLITE_PATH" ]; then
        log_warn "SQLITE_PATH not set, using default /data/watcher.db"
        SQLITE_PATH="/data/watcher.db"
    fi

    # Validate SQLITE_PATH directory exists
    SQLITE_DIR=$(dirname "$SQLITE_PATH")
    if [ ! -d "$SQLITE_DIR" ]; then
        log_error "SQLite directory does not exist: $SQLITE_DIR"
        log "  SQLITE_PATH: $SQLITE_PATH"
        log "  Parent directory contents:"
        ls -la "$(dirname "$SQLITE_DIR")" 2>&1 | sed 's/^/    /' || log "    (parent directory also missing)"
        log "  Tip: Ensure the volume is mounted correctly"
        errors=$((errors + 1))
    elif [ ! -w "$SQLITE_DIR" ]; then
        log_error "SQLite directory is not writable: $SQLITE_DIR"
        log "  SQLITE_PATH: $SQLITE_PATH"
        log "  Directory permissions:"
        ls -la "$SQLITE_DIR" 2>&1 | head -5 | sed 's/^/    /'
        log "  Running as user: $(id)"
        log "  Tip: Check volume mount permissions or run with appropriate user"
        errors=$((errors + 1))
    else
        log_success "SQLite directory exists and is writable: $SQLITE_DIR"
    fi

    # Validate kubectl is available
    log_step "Checking kubectl..."
    if ! command -v kubectl >/dev/null 2>&1; then
        log_error "kubectl not found in PATH"
        log "  PATH: $PATH"
        log "  Tip: Ensure kubectl is installed in the container image"
        errors=$((errors + 1))
    else
        log_success "kubectl found: $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>&1 | head -1)"
    fi

    # Validate kubectl can connect to cluster (only if kubectl exists)
    # Note: We use 'kubectl get --raw /healthz' instead of 'cluster-info' because
    # cluster-info requires listing services in kube-system which the watcher doesn't need
    if command -v kubectl >/dev/null 2>&1; then
        log_step "Testing cluster connectivity..."
        if ! kubectl get --raw /healthz >/dev/null 2>&1; then
            log_error "Cannot connect to Kubernetes cluster"
            log "  KUBECONFIG: ${KUBECONFIG:-not set (using default)}"
            log "  Current context: $(kubectl config current-context 2>&1 || echo 'none')"
            log "  Available contexts: $(kubectl config get-contexts -o name 2>&1 | tr '\n' ', ' | sed 's/,$//')"
            log "  Connectivity check error:"
            kubectl get --raw /healthz 2>&1 | sed 's/^/    /'
            errors=$((errors + 1))
        else
            log_success "Cluster API connected: $(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo 'in-cluster')"
        fi
    fi

    # Validate sqlite3 is available
    log_step "Checking sqlite3..."
    if ! command -v sqlite3 >/dev/null 2>&1; then
        log_error "sqlite3 not found in PATH"
        log "  PATH: $PATH"
        log "  Tip: Install sqlite3 package in the container image"
        errors=$((errors + 1))
    else
        log_success "sqlite3 found: $(sqlite3 --version 2>&1 | head -1)"
    fi

    # Validate claude is available
    log_step "Checking Claude CLI..."
    if ! command -v claude >/dev/null 2>&1; then
        log_error "Claude CLI not found in PATH"
        log "  PATH: $PATH"
        log "  Expected location: $(which claude 2>&1 || echo 'not found')"
        log "  Tip: Ensure Claude Code CLI is installed (npm install -g @anthropic-ai/claude-code)"
        errors=$((errors + 1))
    else
        log_success "Claude CLI found: $(claude --version 2>&1 | head -1)"
    fi

    if [ $errors -gt 0 ]; then
        log_section "Configuration validation FAILED with $errors error(s)"
        exit 1
    fi

    log_success "Configuration validation passed"
}

validate_config
log "SQLite path: $SQLITE_PATH"

# === SQL SAFETY FUNCTIONS ===
# Escape single quotes for SQL strings (prevents SQL injection)
sql_escape() {
    echo "$1" | sed "s/'/''/g"
}

# Validate numeric value (prevents SQL injection in numeric fields)
validate_numeric() {
    local value="$1"
    local default="${2:-0}"
    if [[ "$value" =~ ^[0-9]+$ ]]; then
        echo "$value"
    else
        echo "$default"
    fi
}

# === WATCHER MODE ===
log_section "Configuration"
WATCHER_MODE="${WATCHER_MODE:-autonomous}"
# Validate watcher mode
case "$WATCHER_MODE" in
    autonomous|report) ;;
    *)
        log_error "Invalid WATCHER_MODE: $WATCHER_MODE (use 'autonomous' or 'report')"
        exit 1
        ;;
esac
log "Watcher mode: $WATCHER_MODE"

# === PROACTIVE CHECKS ===
PROACTIVE_CHECKS="${PROACTIVE_CHECKS:-false}"
if [ "$PROACTIVE_CHECKS" = "true" ]; then
    log_success "Proactive checks: ENABLED (will scan for potential issues)"
else
    log "Proactive checks: disabled"
fi

# === NAMESPACE RESOLUTION ===
log_section "Namespace Resolution"
TARGET_NAMESPACES="${TARGET_NAMESPACES:-default}"
EXCLUDE_NAMESPACES="${EXCLUDE_NAMESPACES:-kube-system,kube-public,kube-node-lease}"

log "Target namespace patterns: $TARGET_NAMESPACES"
log "Exclude namespace patterns: $EXCLUDE_NAMESPACES"

# Get all cluster namespaces
log_step "Fetching cluster namespaces..."
ALL_NAMESPACES=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}')
log_success "Found $(echo $ALL_NAMESPACES | wc -w | xargs) namespaces in cluster"

# Function to match namespace against pattern (supports * wildcard)
matches_pattern() {
    local ns="$1"
    local pattern="$2"
    # Convert glob pattern to regex: * becomes .*
    local regex="^$(echo "$pattern" | sed 's/\*/.*/')$"
    [[ "$ns" =~ $regex ]]
}

# Resolve target namespaces (expand wildcards)
RESOLVED_NAMESPACES=""
IFS=',' read -ra TARGET_PATTERNS <<< "$TARGET_NAMESPACES"
for pattern in "${TARGET_PATTERNS[@]}"; do
    pattern=$(echo "$pattern" | xargs)  # trim whitespace
    for ns in $ALL_NAMESPACES; do
        if matches_pattern "$ns" "$pattern"; then
            if [ -z "$RESOLVED_NAMESPACES" ]; then
                RESOLVED_NAMESPACES="$ns"
            else
                # Only add if not already in list
                if ! echo ",$RESOLVED_NAMESPACES," | grep -q ",$ns,"; then
                    RESOLVED_NAMESPACES="$RESOLVED_NAMESPACES,$ns"
                fi
            fi
        fi
    done
done

# Apply exclusions
IFS=',' read -ra EXCLUDE_PATTERNS <<< "$EXCLUDE_NAMESPACES"
FINAL_NAMESPACES=""
IFS=',' read -ra RESOLVED_LIST <<< "$RESOLVED_NAMESPACES"
for ns in "${RESOLVED_LIST[@]}"; do
    excluded=false
    for pattern in "${EXCLUDE_PATTERNS[@]}"; do
        pattern=$(echo "$pattern" | xargs)  # trim whitespace
        if matches_pattern "$ns" "$pattern"; then
            excluded=true
            break
        fi
    done
    if [ "$excluded" = false ]; then
        if [ -z "$FINAL_NAMESPACES" ]; then
            FINAL_NAMESPACES="$ns"
        else
            FINAL_NAMESPACES="$FINAL_NAMESPACES,$ns"
        fi
    fi
done

# Fallback to default if no namespaces resolved
if [ -z "$FINAL_NAMESPACES" ]; then
    log_warn "No namespaces matched patterns, falling back to 'default'"
    FINAL_NAMESPACES="default"
fi

NAMESPACE_COUNT=$(echo "$FINAL_NAMESPACES" | tr ',' '\n' | wc -l | xargs)
log_success "Resolved $NAMESPACE_COUNT namespace(s): $FINAL_NAMESPACES"

# === AUTHENTICATION SETUP ===
log_section "Authentication"
AUTH_MODE="${AUTH_MODE:-api-key}"
log "Auth mode: $AUTH_MODE"

if [ "$AUTH_MODE" = "credentials" ]; then
    log_step "Checking for credentials file..."
    if [ -f "$HOME/.claude/.credentials.json" ]; then
        log_success "Using mounted credentials.json at $HOME/.claude/.credentials.json"
    elif [ -f /secrets/credentials.json ]; then
        log_step "Copying credentials from /secrets/"
        mkdir -p "$HOME/.claude"
        cp /secrets/credentials.json "$HOME/.claude/.credentials.json"
        log_success "Credentials copied to $HOME/.claude/.credentials.json"
    else
        log_error "AUTH_MODE=credentials but no credentials.json found"
        log "  Checked locations:"
        log "    - $HOME/.claude/.credentials.json"
        log "    - /secrets/credentials.json"
        log "  Tip: Mount credentials.json via a Secret volume"
        log "  For Claude Pro/subscription, extract from keychain:"
        log "    security find-generic-password -s 'Claude Code-credentials' -a 'USERNAME' -w"
        exit 1
    fi
elif [ "$AUTH_MODE" = "api-key" ]; then
    log_step "Checking for API key..."
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        log_error "AUTH_MODE=api-key but ANTHROPIC_API_KEY not set"
        log "  Tip: Set ANTHROPIC_API_KEY environment variable via Secret"
        log "  Example: kubectl create secret generic anthropic-api-key --from-literal=ANTHROPIC_API_KEY=sk-..."
        exit 1
    fi
    log_success "API key authentication configured (key length: ${#ANTHROPIC_API_KEY} chars)"
else
    log_error "Invalid AUTH_MODE: $AUTH_MODE (use 'api-key' or 'credentials')"
    log "  Valid options:"
    log "    - api-key: Use ANTHROPIC_API_KEY environment variable"
    log "    - credentials: Use mounted credentials.json file (for Claude Pro/subscription)"
    exit 1
fi

# === DATABASE SETUP ===
log_section "Database Setup"
log_step "Initializing database tables..."

# Ensure tables exist
sqlite3 "$SQLITE_PATH" "CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    namespace TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'autonomous',
    status TEXT NOT NULL DEFAULT 'running',
    pod_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    fix_count INTEGER DEFAULT 0,
    proactive_checks INTEGER DEFAULT 0,
    report TEXT,
    log TEXT
);"

sqlite3 "$SQLITE_PATH" "CREATE TABLE IF NOT EXISTS fixes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    timestamp TEXT NOT NULL,
    namespace TEXT NOT NULL,
    pod_name TEXT NOT NULL,
    error_type TEXT NOT NULL,
    error_message TEXT,
    fix_applied TEXT,
    status TEXT DEFAULT 'pending',
    FOREIGN KEY (run_id) REFERENCES runs(id)
);"

# Add columns if missing (migrations for existing DBs)
sqlite3 "$SQLITE_PATH" "ALTER TABLE fixes ADD COLUMN run_id INTEGER;" 2>/dev/null || true
sqlite3 "$SQLITE_PATH" "ALTER TABLE runs ADD COLUMN proactive_checks INTEGER DEFAULT 0;" 2>/dev/null || true

log_success "Database initialized at $SQLITE_PATH"

# === CREATE RUN RECORD ===
log_step "Creating run record..."
ESCAPED_NAMESPACES=$(sql_escape "$FINAL_NAMESPACES")
ESCAPED_MODE=$(sql_escape "$WATCHER_MODE")
PROACTIVE_VALUE=$( [ "$PROACTIVE_CHECKS" = "true" ] && echo "1" || echo "0" )
RUN_ID=$(sqlite3 "$SQLITE_PATH" "INSERT INTO runs (started_at, namespace, mode, status, proactive_checks) VALUES (datetime('now'), '$ESCAPED_NAMESPACES', '$ESCAPED_MODE', 'running', $PROACTIVE_VALUE); SELECT last_insert_rowid();")
RUN_ID=$(validate_numeric "$RUN_ID" "0")
if [ "$RUN_ID" = "0" ]; then
    log_error "Failed to create run record"
    exit 1
fi
log_success "Created run #$RUN_ID"

# === GET LAST RUN TIME ===
# Get last run time across any of the target namespaces
LAST_RUN_TIME=$(sqlite3 "$SQLITE_PATH" "SELECT COALESCE(MAX(ended_at), '') FROM runs WHERE status != 'running' AND id != $RUN_ID;")
if [ -n "$LAST_RUN_TIME" ]; then
    log "Last run completed: $LAST_RUN_TIME"
else
    log "This is the first run"
fi

# === SELECT PROMPT ===
log_section "Prompt Setup"
if [ "$WATCHER_MODE" = "report" ]; then
    PROMPT_FILE="/app/master-prompt-report.md"
    log "Mode: report (detect and recommend only)"
else
    PROMPT_FILE="/app/master-prompt-autonomous.md"
    log "Mode: autonomous (detect and fix)"
fi

log_step "Loading prompt from $PROMPT_FILE..."
if [ ! -f "$PROMPT_FILE" ]; then
    log_error "Prompt file not found: $PROMPT_FILE"
    sqlite3 "$SQLITE_PATH" "UPDATE runs SET ended_at = datetime('now'), status = 'failed', report = 'Prompt file not found' WHERE id = $(validate_numeric $RUN_ID);"
    exit 1
fi

PROMPT=$(cat "$PROMPT_FILE")
log_success "Prompt loaded ($(echo "$PROMPT" | wc -c | xargs) bytes)"

# Append proactive checks if enabled
if [ "$PROACTIVE_CHECKS" = "true" ]; then
    PROACTIVE_FILE="/app/proactive-checks.md"
    if [ -f "$PROACTIVE_FILE" ]; then
        log_step "Adding proactive checks to prompt..."
        PROMPT="$PROMPT

$(cat "$PROACTIVE_FILE")"
        log_success "Proactive checks appended"
    fi
fi

# Replace environment variables in prompt
log_step "Substituting variables in prompt..."
PROMPT=$(echo "$PROMPT" | sed "s|\$TARGET_NAMESPACES|$FINAL_NAMESPACES|g")
PROMPT=$(echo "$PROMPT" | sed "s|\$SQLITE_PATH|$SQLITE_PATH|g")
PROMPT=$(echo "$PROMPT" | sed "s|\$RUN_ID|$RUN_ID|g")
PROMPT=$(echo "$PROMPT" | sed "s|\$LAST_RUN_TIME|$LAST_RUN_TIME|g")
log_success "Prompt prepared"

# === RUN CLAUDE ===
log_section "Claude Code Execution"
log "Run ID: #$RUN_ID"
log "Mode: $WATCHER_MODE"
log "Namespaces: $FINAL_NAMESPACES"

LOG_FILE="/data/watcher.log"
echo "=== Run #$RUN_ID started at $(date -Iseconds) ===" > "$LOG_FILE"
echo "Mode: $WATCHER_MODE | Namespaces: $FINAL_NAMESPACES" >> "$LOG_FILE"
echo "----------------------------------------" >> "$LOG_FILE"

# Capture output
OUTPUT_FILE="/tmp/claude_output_$RUN_ID.txt"
log_step "Starting Claude Code (this may take several minutes)..."
log "Claude is analyzing pods, checking logs, and $( [ "$WATCHER_MODE" = "autonomous" ] && echo "applying fixes" || echo "generating recommendations")..."
log ""
log "─────────────────────────────────────────────────────────────"
log "                    CLAUDE CODE OUTPUT                        "
log "─────────────────────────────────────────────────────────────"

# Force unbuffered output for real-time streaming
export PYTHONUNBUFFERED=1
export NODE_NO_WARNINGS=1

# Use stream-json format to see tool calls in real-time
# Parse the JSON stream and display human-readable output with timestamps
STREAM_FILE="/tmp/claude_stream_$RUN_ID.jsonl"
TEXT_FILE="/tmp/claude_text_$RUN_ID.txt"

# Initialize text file for capturing all text output (for report parsing)
> "$TEXT_FILE"

claude --dangerously-skip-permissions --output-format stream-json --verbose -p "$PROMPT" 2>&1 | while IFS= read -r line; do
    # Save raw stream for debugging
    echo "$line" >> "$STREAM_FILE"

    # Skip empty lines
    [ -z "$line" ] && continue

    # Try to parse JSON
    if echo "$line" | jq -e '.' >/dev/null 2>&1; then
        MSG_TYPE=$(echo "$line" | jq -r '.type // empty' 2>/dev/null)

        case "$MSG_TYPE" in
            "system")
                # System messages (e.g., initialization)
                SUBTYPE=$(echo "$line" | jq -r '.subtype // empty' 2>/dev/null)
                [ "$SUBTYPE" = "init" ] && log "Claude initialized"
                ;;

            "assistant")
                # Check for tool_use in content array
                TOOLS=$(echo "$line" | jq -r '.message.content[]? | select(.type == "tool_use") | .name' 2>/dev/null)
                for TOOL in $TOOLS; do
                    log_step "▶ Tool call: $TOOL"
                    # Extract and show relevant input based on tool type
                    INPUT=$(echo "$line" | jq -r ".message.content[] | select(.type == \"tool_use\" and .name == \"$TOOL\") | .input" 2>/dev/null)
                    case "$TOOL" in
                        Bash)
                            CMD=$(echo "$INPUT" | jq -r '.command // empty' 2>/dev/null | head -c 150)
                            [ -n "$CMD" ] && log "    $ $CMD"
                            ;;
                        Read)
                            FILE=$(echo "$INPUT" | jq -r '.file_path // empty' 2>/dev/null)
                            [ -n "$FILE" ] && log "    Reading: $FILE"
                            ;;
                        Edit)
                            FILE=$(echo "$INPUT" | jq -r '.file_path // empty' 2>/dev/null)
                            [ -n "$FILE" ] && log "    Editing: $FILE"
                            ;;
                        Write)
                            FILE=$(echo "$INPUT" | jq -r '.file_path // empty' 2>/dev/null)
                            [ -n "$FILE" ] && log "    Writing: $FILE"
                            ;;
                        Grep)
                            PATTERN=$(echo "$INPUT" | jq -r '.pattern // empty' 2>/dev/null)
                            [ -n "$PATTERN" ] && log "    Searching: $PATTERN"
                            ;;
                        Glob)
                            PATTERN=$(echo "$INPUT" | jq -r '.pattern // empty' 2>/dev/null)
                            [ -n "$PATTERN" ] && log "    Finding: $PATTERN"
                            ;;
                        *)
                            log "    (executing...)"
                            ;;
                    esac
                done
                # Also capture any text content from assistant messages
                TEXT=$(echo "$line" | jq -r '.message.content[]? | select(.type == "text") | .text // empty' 2>/dev/null)
                [ -n "$TEXT" ] && echo "$TEXT" >> "$TEXT_FILE"
                ;;

            "user")
                # Tool results coming back
                TOOL_RESULTS=$(echo "$line" | jq -r '.message.content[]? | select(.type == "tool_result") | .tool_use_id' 2>/dev/null | wc -l)
                [ "$TOOL_RESULTS" -gt 0 ] && log "    ✓ Tool completed"
                ;;

            "content_block_start")
                BLOCK_TYPE=$(echo "$line" | jq -r '.content_block.type // empty' 2>/dev/null)
                if [ "$BLOCK_TYPE" = "tool_use" ]; then
                    TOOL_NAME=$(echo "$line" | jq -r '.content_block.name // empty' 2>/dev/null)
                    [ -n "$TOOL_NAME" ] && log_step "▶ Calling: $TOOL_NAME"
                elif [ "$BLOCK_TYPE" = "text" ]; then
                    log "  Claude is responding..."
                fi
                ;;

            "content_block_delta")
                DELTA_TYPE=$(echo "$line" | jq -r '.delta.type // empty' 2>/dev/null)
                if [ "$DELTA_TYPE" = "text_delta" ]; then
                    TEXT=$(echo "$line" | jq -r '.delta.text // empty' 2>/dev/null)
                    # Stream text output (Claude's response) and save for report parsing
                    if [ -n "$TEXT" ]; then
                        printf "%s" "$TEXT"
                        printf "%s" "$TEXT" >> "$TEXT_FILE"
                    fi
                fi
                ;;

            "content_block_stop")
                # End of a content block - add newline if we were streaming text
                echo ""
                echo "" >> "$TEXT_FILE"
                ;;

            "result")
                # Final result
                log_success "Claude finished processing"
                RESULT=$(echo "$line" | jq -r '.result // empty' 2>/dev/null)
                if [ -n "$RESULT" ] && [ "$RESULT" != "null" ]; then
                    echo "$RESULT"
                    echo "$RESULT" >> "$TEXT_FILE"
                fi
                ;;

            "error")
                ERROR_MSG=$(echo "$line" | jq -r '.error.message // .error // "Unknown error"' 2>/dev/null)
                log_error "Error: $ERROR_MSG"
                ;;
        esac
    else
        # Not valid JSON - might be stderr output, show as-is
        [ -n "$line" ] && echo "$line"
    fi
done 2>&1 | tee -a "$LOG_FILE"

# Copy accumulated text to output file for report parsing
[ -f "$TEXT_FILE" ] && cp "$TEXT_FILE" "$OUTPUT_FILE"

log "─────────────────────────────────────────────────────────────"

echo ""
log_success "Claude Code execution completed"

# === PARSE REPORT ===
log_section "Report Parsing"
log_step "Extracting report data from output..."

REPORT=""
if grep -q "===REPORT_START===" "$OUTPUT_FILE" 2>/dev/null; then
    # Extract report - first get raw content between markers
    RAW_REPORT=$(sed -n '/===REPORT_START===/,/===REPORT_END===/p' "$OUTPUT_FILE" | grep -v "===REPORT")

    # Debug: save raw extracted content
    echo "$RAW_REPORT" > /tmp/debug_raw_report_$RUN_ID.txt
    log "  Raw lines extracted: $(echo "$RAW_REPORT" | wc -l)"

    # Clean up the JSON - remove newlines and extra spaces
    REPORT=$(echo "$RAW_REPORT" | tr -d '\n' | tr -s ' ' | sed 's/^ *//' | sed 's/ *$//')

    # Debug: save cleaned report
    echo "$REPORT" > /tmp/debug_clean_report_$RUN_ID.txt
    log_success "Found structured report"
    log "  Report length: ${#REPORT} chars"
    log "  First 300 chars: $(echo "$REPORT" | head -c 300)"
else
    log_warn "No structured report markers found in output"
    log "  Output file size: $(wc -c < "$OUTPUT_FILE" 2>/dev/null || echo 0) bytes"
    log "  Output file lines: $(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)"
    # Debug: show last lines of output file
    log "  Last 10 lines:"
    tail -10 "$OUTPUT_FILE" 2>/dev/null | while read -r line; do
        log "    $(echo "$line" | head -c 100)"
    done
fi

# Extract values from report with defaults
POD_COUNT=0
ERROR_COUNT=0
FIX_COUNT=0
STATUS="ok"

if [ -n "$REPORT" ]; then
    # Validate JSON structure first
    if command -v jq >/dev/null 2>&1; then
        # Check if JSON is valid
        JQ_ERROR=$(echo "$REPORT" | jq empty 2>&1)
        JQ_EXIT=$?
        log "  jq validation exit code: $JQ_EXIT"
        if [ $JQ_EXIT -eq 0 ]; then
            log_step "Parsing report JSON with jq..."

            # Extract values - use jq with error output to debug
            POD_COUNT=$(echo "$REPORT" | jq -r '.pod_count // 0' 2>&1)
            log "  .pod_count = '$POD_COUNT'"

            ERROR_COUNT=$(echo "$REPORT" | jq -r '.error_count // 0' 2>&1)
            log "  .error_count = '$ERROR_COUNT'"

            FIX_COUNT=$(echo "$REPORT" | jq -r '.fix_count // 0' 2>&1)
            log "  .fix_count = '$FIX_COUNT'"

            STATUS=$(echo "$REPORT" | jq -r '.status // "ok"' 2>&1)
            log "  .status = '$STATUS'"

            # Validate numeric values (in case jq returned error text)
            [[ "$POD_COUNT" =~ ^[0-9]+$ ]] || POD_COUNT=0
            [[ "$ERROR_COUNT" =~ ^[0-9]+$ ]] || ERROR_COUNT=0
            [[ "$FIX_COUNT" =~ ^[0-9]+$ ]] || FIX_COUNT=0

            log_success "Report parsed successfully"
        else
            log_warn "Report JSON is invalid (exit $JQ_EXIT): $JQ_ERROR"
            log "  First 200 chars: $(echo "$REPORT" | head -c 200)"
            # Try to show what's at the beginning that might be causing issues
            log "  Hex dump of first 50 bytes:"
            echo "$REPORT" | head -c 50 | xxd 2>/dev/null | head -5 | while read -r line; do
                log "    $line"
            done
        fi
    else
        # Fallback to grep/sed parsing (less robust)
        log_step "Parsing report with grep/sed (jq not available)..."

        # Parse pod_count
        PARSED=$(echo "$REPORT" | grep -o '"pod_count"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
        [ -n "$PARSED" ] && POD_COUNT=$PARSED

        # Parse error_count
        PARSED=$(echo "$REPORT" | grep -o '"error_count"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
        [ -n "$PARSED" ] && ERROR_COUNT=$PARSED

        # Parse fix_count
        PARSED=$(echo "$REPORT" | grep -o '"fix_count"[[:space:]]*:[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
        [ -n "$PARSED" ] && FIX_COUNT=$PARSED

        # Parse status
        PARSED=$(echo "$REPORT" | grep -o '"status"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')
        [ -n "$PARSED" ] && STATUS=$PARSED
        log_success "Report parsed with fallback method"
    fi
fi

# Validate status is one of expected values
case "$STATUS" in
    ok|fixed|failed|issues_found|running) ;;
    *) STATUS="ok" ;;
esac

# Validate parsed numeric values
POD_COUNT=$(validate_numeric "$POD_COUNT" "0")
ERROR_COUNT=$(validate_numeric "$ERROR_COUNT" "0")
FIX_COUNT=$(validate_numeric "$FIX_COUNT" "0")

log "Pods monitored: $POD_COUNT"
log "Errors found: $ERROR_COUNT"
log "Fixes applied: $FIX_COUNT"
log "Status: $STATUS"

# Read full log (limit size to prevent issues) and escape for SQL
log_step "Saving log to database..."
FULL_LOG=$(head -c 100000 "$LOG_FILE")
FULL_LOG_ESCAPED=$(sql_escape "$FULL_LOG")

# Escape report for SQL
REPORT_ESCAPED=$(sql_escape "$REPORT")

# Escape status for SQL
STATUS_ESCAPED=$(sql_escape "$STATUS")

# === UPDATE RUN RECORD ===
log_step "Updating run record #$RUN_ID..."
sqlite3 "$SQLITE_PATH" "UPDATE runs SET
    ended_at = datetime('now'),
    status = '$STATUS_ESCAPED',
    pod_count = $POD_COUNT,
    error_count = $ERROR_COUNT,
    fix_count = $FIX_COUNT,
    report = '$REPORT_ESCAPED',
    log = '$FULL_LOG_ESCAPED'
WHERE id = $(validate_numeric $RUN_ID);"

log_success "Run record updated"

# Cleanup
rm -f "$OUTPUT_FILE" "$STREAM_FILE" "$TEXT_FILE" /tmp/debug_raw_report_$RUN_ID.txt /tmp/debug_clean_report_$RUN_ID.txt

# === FINAL SUMMARY ===
log_section "Run #$RUN_ID Complete"
log "Mode: $WATCHER_MODE$( [ "$PROACTIVE_CHECKS" = "true" ] && echo " + proactive checks" )"
log "Namespaces: $FINAL_NAMESPACES"
log "Status: $STATUS"
log "Pods monitored: $POD_COUNT"
log "Errors found: $ERROR_COUNT"
log "Fixes applied: $FIX_COUNT"
if [ "$ERROR_COUNT" -gt 0 ] && [ "$WATCHER_MODE" = "report" ]; then
    log_warn "Issues were found. Check the dashboard for details."
elif [ "$FIX_COUNT" -gt 0 ]; then
    log_success "Fixes were applied. Check the dashboard for details."
else
    log_success "No issues found - all pods healthy!"
fi

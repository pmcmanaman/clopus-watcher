#!/bin/bash
set -e

echo "=== Clopus Watcher Starting ==="

# === CONFIGURATION VALIDATION ===
validate_config() {
    local errors=0

    # Validate SQLITE_PATH
    if [ -z "$SQLITE_PATH" ]; then
        echo "WARNING: SQLITE_PATH not set, using default /data/watcher.db"
        SQLITE_PATH="/data/watcher.db"
    fi

    # Validate SQLITE_PATH directory exists
    SQLITE_DIR=$(dirname "$SQLITE_PATH")
    if [ ! -d "$SQLITE_DIR" ]; then
        echo "ERROR: SQLite directory does not exist: $SQLITE_DIR"
        echo "  SQLITE_PATH: $SQLITE_PATH"
        echo "  Parent directory contents:"
        ls -la "$(dirname "$SQLITE_DIR")" 2>&1 | sed 's/^/    /' || echo "    (parent directory also missing)"
        echo "  Tip: Ensure the volume is mounted correctly"
        errors=$((errors + 1))
    elif [ ! -w "$SQLITE_DIR" ]; then
        echo "ERROR: SQLite directory is not writable: $SQLITE_DIR"
        echo "  SQLITE_PATH: $SQLITE_PATH"
        echo "  Directory permissions:"
        ls -la "$SQLITE_DIR" 2>&1 | head -5 | sed 's/^/    /'
        echo "  Running as user: $(id)"
        echo "  Tip: Check volume mount permissions or run with appropriate user"
        errors=$((errors + 1))
    fi

    # Validate kubectl is available
    if ! command -v kubectl >/dev/null 2>&1; then
        echo "ERROR: kubectl not found in PATH"
        echo "  PATH: $PATH"
        echo "  Tip: Ensure kubectl is installed in the container image"
        errors=$((errors + 1))
    else
        echo "  kubectl version: $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>&1 | head -1)"
    fi

    # Validate kubectl can connect to cluster (only if kubectl exists)
    # Note: We use 'kubectl get --raw /healthz' instead of 'cluster-info' because
    # cluster-info requires listing services in kube-system which the watcher doesn't need
    if command -v kubectl >/dev/null 2>&1; then
        if ! kubectl get --raw /healthz >/dev/null 2>&1; then
            echo "ERROR: Cannot connect to Kubernetes cluster"
            echo "  KUBECONFIG: ${KUBECONFIG:-not set (using default)}"
            echo "  Current context: $(kubectl config current-context 2>&1 || echo 'none')"
            echo "  Available contexts: $(kubectl config get-contexts -o name 2>&1 | tr '\n' ', ' | sed 's/,$//')"
            echo "  Connectivity check error:"
            kubectl get --raw /healthz 2>&1 | sed 's/^/    /'
            errors=$((errors + 1))
        else
            echo "  Cluster API: $(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || echo 'in-cluster')"
        fi
    fi

    # Validate sqlite3 is available
    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo "ERROR: sqlite3 not found in PATH"
        echo "  PATH: $PATH"
        echo "  Tip: Install sqlite3 package in the container image"
        errors=$((errors + 1))
    else
        echo "  sqlite3 version: $(sqlite3 --version 2>&1 | head -1)"
    fi

    # Validate claude is available
    if ! command -v claude >/dev/null 2>&1; then
        echo "ERROR: claude CLI not found in PATH"
        echo "  PATH: $PATH"
        echo "  Expected location: $(which claude 2>&1 || echo 'not found')"
        echo "  Tip: Ensure Claude Code CLI is installed (npm install -g @anthropic-ai/claude-code)"
        errors=$((errors + 1))
    else
        echo "  claude version: $(claude --version 2>&1 | head -1)"
    fi

    if [ $errors -gt 0 ]; then
        echo ""
        echo "=== Configuration validation failed with $errors error(s) ==="
        exit 1
    fi

    echo "=== Configuration validation passed ==="
}

validate_config
echo "SQLite path: $SQLITE_PATH"

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
WATCHER_MODE="${WATCHER_MODE:-autonomous}"
# Validate watcher mode
case "$WATCHER_MODE" in
    autonomous|report) ;;
    *)
        echo "ERROR: Invalid WATCHER_MODE: $WATCHER_MODE (use 'autonomous' or 'report')"
        exit 1
        ;;
esac
echo "Watcher mode: $WATCHER_MODE"

# === PROACTIVE CHECKS ===
PROACTIVE_CHECKS="${PROACTIVE_CHECKS:-false}"
echo "Proactive checks: $PROACTIVE_CHECKS"

# === NAMESPACE RESOLUTION ===
TARGET_NAMESPACES="${TARGET_NAMESPACES:-default}"
EXCLUDE_NAMESPACES="${EXCLUDE_NAMESPACES:-kube-system,kube-public,kube-node-lease}"

echo "Target namespace patterns: $TARGET_NAMESPACES"
echo "Exclude namespace patterns: $EXCLUDE_NAMESPACES"

# Get all cluster namespaces
ALL_NAMESPACES=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}')

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
    echo "WARNING: No namespaces matched patterns, falling back to 'default'"
    FINAL_NAMESPACES="default"
fi

echo "Resolved namespaces: $FINAL_NAMESPACES"
NAMESPACE_COUNT=$(echo "$FINAL_NAMESPACES" | tr ',' '\n' | wc -l | xargs)

# === AUTHENTICATION SETUP ===
AUTH_MODE="${AUTH_MODE:-api-key}"
echo "Auth mode: $AUTH_MODE"

if [ "$AUTH_MODE" = "credentials" ]; then
    if [ -f "$HOME/.claude/.credentials.json" ]; then
        echo "Using mounted credentials.json"
    elif [ -f /secrets/credentials.json ]; then
        echo "Copying credentials from /secrets/"
        mkdir -p "$HOME/.claude"
        cp /secrets/credentials.json "$HOME/.claude/.credentials.json"
    else
        echo "ERROR: AUTH_MODE=credentials but no credentials.json found"
        exit 1
    fi
elif [ "$AUTH_MODE" = "api-key" ]; then
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        echo "ERROR: AUTH_MODE=api-key but ANTHROPIC_API_KEY not set"
        exit 1
    fi
    echo "Using API key authentication"
else
    echo "ERROR: Invalid AUTH_MODE: $AUTH_MODE (use 'api-key' or 'credentials')"
    exit 1
fi

# === DATABASE SETUP ===
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

# Add run_id column if missing (migration)
sqlite3 "$SQLITE_PATH" "ALTER TABLE fixes ADD COLUMN run_id INTEGER;" 2>/dev/null || true

echo "Database initialized"

# === CREATE RUN RECORD ===
ESCAPED_NAMESPACES=$(sql_escape "$FINAL_NAMESPACES")
ESCAPED_MODE=$(sql_escape "$WATCHER_MODE")
RUN_ID=$(sqlite3 "$SQLITE_PATH" "INSERT INTO runs (started_at, namespace, mode, status) VALUES (datetime('now'), '$ESCAPED_NAMESPACES', '$ESCAPED_MODE', 'running'); SELECT last_insert_rowid();")
RUN_ID=$(validate_numeric "$RUN_ID" "0")
if [ "$RUN_ID" = "0" ]; then
    echo "ERROR: Failed to create run record"
    exit 1
fi
echo "Created run #$RUN_ID"

# === GET LAST RUN TIME ===
# Get last run time across any of the target namespaces
LAST_RUN_TIME=$(sqlite3 "$SQLITE_PATH" "SELECT COALESCE(MAX(ended_at), '') FROM runs WHERE status != 'running' AND id != $RUN_ID;")
echo "Last run time: ${LAST_RUN_TIME:-'(first run)'}"

# === SELECT PROMPT ===
if [ "$WATCHER_MODE" = "report" ]; then
    PROMPT_FILE="/app/master-prompt-report.md"
else
    PROMPT_FILE="/app/master-prompt-autonomous.md"
fi

if [ ! -f "$PROMPT_FILE" ]; then
    echo "ERROR: Prompt file not found: $PROMPT_FILE"
    sqlite3 "$SQLITE_PATH" "UPDATE runs SET ended_at = datetime('now'), status = 'failed', report = 'Prompt file not found' WHERE id = $(validate_numeric $RUN_ID);"
    exit 1
fi

PROMPT=$(cat "$PROMPT_FILE")

# Append proactive checks if enabled
if [ "$PROACTIVE_CHECKS" = "true" ]; then
    PROACTIVE_FILE="/app/proactive-checks.md"
    if [ -f "$PROACTIVE_FILE" ]; then
        echo "Adding proactive checks to prompt"
        PROMPT="$PROMPT

$(cat "$PROACTIVE_FILE")"
    fi
fi

# Replace environment variables in prompt
PROMPT=$(echo "$PROMPT" | sed "s|\$TARGET_NAMESPACES|$FINAL_NAMESPACES|g")
PROMPT=$(echo "$PROMPT" | sed "s|\$SQLITE_PATH|$SQLITE_PATH|g")
PROMPT=$(echo "$PROMPT" | sed "s|\$RUN_ID|$RUN_ID|g")
PROMPT=$(echo "$PROMPT" | sed "s|\$LAST_RUN_TIME|$LAST_RUN_TIME|g")

# === RUN CLAUDE ===
echo "Starting Claude Code..."

LOG_FILE="/data/watcher.log"
echo "=== Run #$RUN_ID started at $(date -Iseconds) ===" > "$LOG_FILE"
echo "Mode: $WATCHER_MODE | Namespaces: $FINAL_NAMESPACES" >> "$LOG_FILE"
echo "----------------------------------------" >> "$LOG_FILE"

# Capture output
OUTPUT_FILE="/tmp/claude_output_$RUN_ID.txt"
claude --dangerously-skip-permissions --verbose -p "$PROMPT" 2>&1 | tee -a "$LOG_FILE" | tee "$OUTPUT_FILE"

echo "=== Run #$RUN_ID Complete ===" | tee -a "$LOG_FILE"

# === PARSE REPORT ===
REPORT=""
if grep -q "===REPORT_START===" "$OUTPUT_FILE" 2>/dev/null; then
    REPORT=$(sed -n '/===REPORT_START===/,/===REPORT_END===/p' "$OUTPUT_FILE" | grep -v "===REPORT" | tr -d '\n' | tr -s ' ')
    echo "Parsed report: $REPORT"
fi

# Extract values from report with defaults
POD_COUNT=0
ERROR_COUNT=0
FIX_COUNT=0
STATUS="ok"

if [ -n "$REPORT" ]; then
    # Validate JSON structure first
    if command -v jq >/dev/null 2>&1; then
        # Use jq for robust JSON parsing
        if echo "$REPORT" | jq empty 2>/dev/null; then
            echo "Report JSON is valid, parsing with jq"
            PARSED=$(echo "$REPORT" | jq -r '.pod_count // 0' 2>/dev/null)
            [ -n "$PARSED" ] && [ "$PARSED" != "null" ] && POD_COUNT=$PARSED

            PARSED=$(echo "$REPORT" | jq -r '.error_count // 0' 2>/dev/null)
            [ -n "$PARSED" ] && [ "$PARSED" != "null" ] && ERROR_COUNT=$PARSED

            PARSED=$(echo "$REPORT" | jq -r '.fix_count // 0' 2>/dev/null)
            [ -n "$PARSED" ] && [ "$PARSED" != "null" ] && FIX_COUNT=$PARSED

            PARSED=$(echo "$REPORT" | jq -r '.status // "ok"' 2>/dev/null)
            [ -n "$PARSED" ] && [ "$PARSED" != "null" ] && STATUS=$PARSED
        else
            echo "WARNING: Report JSON is invalid, skipping parse"
        fi
    else
        # Fallback to grep/sed parsing (less robust)
        echo "jq not available, using grep/sed fallback"

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

echo "Final values: pods=$POD_COUNT errors=$ERROR_COUNT fixes=$FIX_COUNT status=$STATUS"

# Read full log (limit size to prevent issues) and escape for SQL
FULL_LOG=$(head -c 100000 "$LOG_FILE")
FULL_LOG_ESCAPED=$(sql_escape "$FULL_LOG")

# Escape report for SQL
REPORT_ESCAPED=$(sql_escape "$REPORT")

# Escape status for SQL
STATUS_ESCAPED=$(sql_escape "$STATUS")

# === UPDATE RUN RECORD ===
sqlite3 "$SQLITE_PATH" "UPDATE runs SET
    ended_at = datetime('now'),
    status = '$STATUS_ESCAPED',
    pod_count = $POD_COUNT,
    error_count = $ERROR_COUNT,
    fix_count = $FIX_COUNT,
    report = '$REPORT_ESCAPED',
    log = '$FULL_LOG_ESCAPED'
WHERE id = $(validate_numeric $RUN_ID);"

echo "Run #$RUN_ID completed with status: $STATUS"

# Cleanup
rm -f "$OUTPUT_FILE"

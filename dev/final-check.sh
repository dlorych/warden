#!/bin/sh
# final-check.sh runs the reproducible issue-8 acceptance gate. It never
# removes volumes or rows from the main retained Audit Log; only the generated
# isolated migration verification database is disposed of by this command.
set -eu

# Keep the acceptance command self-checking when invoked directly or through
# make, including after edits to this executable gate.
sh -n "$0"

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

for command in curl jq openssl docker go npm; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "final-check: required command is missing: $command" >&2
        exit 1
    }
done

COMPOSE="docker compose --env-file .dev/compose.env -f compose.yaml"
BASE_URL=${WARDEN_BASE_URL:-http://localhost:8080}
KEYCLOAK_URL=${KEYCLOAK_URL:-http://localhost:8180}
MOCK_URL=${GITHUBMOCK_URL:-http://localhost:8090}
REALM_URL="$KEYCLOAK_URL/realms/warden"
TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/warden-final-check.XXXXXX")
MIGRATION_DB_NAME=""
cleaned=0
cleanup() {
    status=$?
    if [ "$cleaned" -eq 0 ]; then
        cleaned=1
        if [ -n "$MIGRATION_DB_NAME" ]; then
            # The identifier is generated below from only a fixed prefix and
            # the shell PID. Never use a broad or caller-provided target here.
            $COMPOSE exec -T -e PGPASSWORD=warden-dev-password postgres \
                psql -h 127.0.0.1 -U warden -d postgres -v ON_ERROR_STOP=1 \
                -c "DROP DATABASE IF EXISTS \"$MIGRATION_DB_NAME\" WITH (FORCE)" >/dev/null 2>&1 || true
        fi
        rm -rf "$TMPDIR"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

step() { echo "==> $*"; }
fail() { echo "final-check: $*" >&2; exit 1; }
urlencode() { jq -nr --arg value "$1" '$value|@uri'; }
header_location() { awk 'BEGIN{IGNORECASE=1} /^Location:/{sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit}' "$1"; }

wait_for() {
    url=$1
    i=0
    while [ "$i" -lt 60 ]; do
        if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
        i=$((i + 1))
        sleep 2
    done
    fail "timed out waiting for $url"
}

# Perform a real authorization-code login against Keycloak and establish a
# Warden BFF session.  This follows the same login form a browser submits.
bff_login() {
    username=$1
    password=$2
    jar=$3
    login_headers="$TMPDIR/$username-login.headers"
    login_html="$TMPDIR/$username-login.html"
    form_headers="$TMPDIR/$username-form.headers"
    curl -fsS -D "$login_headers" -c "$jar" -o /dev/null "$BASE_URL/bff/login"
    auth_url=$(header_location "$login_headers")
    [ -n "$auth_url" ] || fail "BFF login did not return an authorization redirect"
    curl -fsS -D "$form_headers" -b "$jar" -c "$jar" -o "$login_html" "$auth_url"
    form_action=$(sed -n 's/.*<form id="kc-form-login"[^>]* action="\([^"]*\)".*/\1/p' "$login_html" | head -n 1 | sed 's/&amp;/\&/g')
    [ -n "$form_action" ] || fail "Keycloak login form was not found for $username"
    curl -fsS -D "$form_headers" -b "$jar" -c "$jar" -o /dev/null -X POST "$form_action" \
        --data-urlencode "username=$username" \
        --data-urlencode "password=$password" \
        --data-urlencode 'credentialId=' \
        --data-urlencode 'login=Sign In'
    callback_url=$(header_location "$form_headers")
    case "$callback_url" in
        "$BASE_URL"/*) : ;;
        *) fail "Keycloak login for $username did not return to Warden" ;;
    esac
    curl -fsS -b "$jar" -c "$jar" -o /dev/null "$callback_url"
    session=$(curl -fsS -b "$jar" "$BASE_URL/bff/session")
    echo "$session" | jq -e '.authenticated == true' >/dev/null || fail "BFF session was not established for $username"
}

# Obtain a bearer token using the public CLI client and the same real
# authorization-code flow.  The callback is consumed in-process by this gate.
cli_token() {
    username=$1
    password=$2
    jar=$3
    verifier=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')
    challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=\n')
    state=$(openssl rand -base64 18 | tr '+/' '-_' | tr -d '=\n')
    nonce=$(openssl rand -base64 18 | tr '+/' '-_' | tr -d '=\n')
    endpoint="$REALM_URL/protocol/openid-connect/auth"
    auth_url="$endpoint?client_id=$(urlencode warden-cli)&response_type=code&redirect_uri=$(urlencode http://127.0.0.1:18765/callback)&scope=$(urlencode 'openid warden:decide')&audience=$(urlencode warden-cli)&code_challenge=$(urlencode "$challenge")&code_challenge_method=S256&state=$(urlencode "$state")&nonce=$(urlencode "$nonce")"
    html="$TMPDIR/$username-cli.html"
    headers="$TMPDIR/$username-cli.headers"
    curl -fsS -b "$jar" -c "$jar" -o "$html" "$auth_url"
    form_action=$(sed -n 's/.*<form id="kc-form-login"[^>]* action="\([^"]*\)".*/\1/p' "$html" | head -n 1 | sed 's/&amp;/\&/g')
    [ -n "$form_action" ] || fail "Keycloak CLI login form was not found for $username"
    curl -fsS -D "$headers" -b "$jar" -c "$jar" -o /dev/null -X POST "$form_action" \
        --data-urlencode "username=$username" \
        --data-urlencode "password=$password" \
        --data-urlencode 'credentialId=' \
        --data-urlencode 'login=Sign In'
    callback_url=$(header_location "$headers")
    code=$(printf '%s' "$callback_url" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
    returned_state=$(printf '%s' "$callback_url" | sed -n 's/.*[?&]state=\([^&]*\).*/\1/p')
    [ -n "$code" ] && [ "$returned_state" = "$state" ] || fail "Keycloak CLI authorization callback was invalid"
    token_json="$TMPDIR/$username-token.json"
    curl -fsS -X POST "$REALM_URL/protocol/openid-connect/token" \
        --data-urlencode 'grant_type=authorization_code' \
        --data-urlencode 'client_id=warden-cli' \
        --data-urlencode 'redirect_uri=http://127.0.0.1:18765/callback' \
        --data-urlencode "code=$code" \
        --data-urlencode "code_verifier=$verifier" >"$token_json"
    jq -er '.access_token' "$token_json"
}

expect_http() {
    expected=$1
    shift
    actual=$("$@" -o "$TMPDIR/http-body" -w '%{http_code}')
    [ "$actual" = "$expected" ] || {
        echo "response body:" >&2
        sed -n '1,80p' "$TMPDIR/http-body" >&2
        fail "expected HTTP $expected, got $actual"
    }
}

step "Docker-independent tests, web build, and Compose validation"
./devinit >/dev/null
npm --prefix web ci --ignore-scripts --no-audit --no-fund
npm --prefix web run build
go test ./...
$COMPOSE config --quiet

step "Start the real Compose stack"
make dev >/dev/null
wait_for "$BASE_URL/healthz"
wait_for "$KEYCLOAK_URL/realms/warden/.well-known/openid-configuration"
wait_for "$MOCK_URL/healthz"
run_started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_started_from=$(urlencode "$run_started_at")

step "Create a signed GitHub deployment-protection webhook"
request_json="$TMPDIR/request.json"
curl -fsS -X POST "$MOCK_URL/mock/requests" -H 'Content-Type: application/json' \
    -d '{"repository":"acme/final-gate","environment":"production","commit_sha":"0123456789abcdef0123456789abcdef01234567","requester":"requester@example.test","reason":"Issue 8 final gate"}' >"$request_json"
request_id=$(jq -er '.id' "$request_json")

step "Real Keycloak auditor authorization-code login and authorization boundaries"
auditor_jar="$TMPDIR/auditor.cookies"
bff_login auditor auditor-dev-password "$auditor_jar"
auditor_session=$(curl -fsS -b "$auditor_jar" "$BASE_URL/bff/session")
auditor_subject=33333333-3333-4333-8333-333333333333
echo "$auditor_session" | jq -e --arg subject "$auditor_subject" '
    .authenticated == true and .user.subject == $subject and
    (.user.roles | index("auditor") != null) and
    (.user.roles | index("reader") == null) and
    (.user.roles | index("reviewer") == null)
' >/dev/null || fail "auditor fixture did not establish an auditor-only session"
expect_http 403 curl -sS -b "$auditor_jar" "$BASE_URL/bff/requests"
expect_http 403 curl -sS -b "$auditor_jar" "$BASE_URL/bff/decisions"
expect_http 200 curl -sS -b "$auditor_jar" "$BASE_URL/bff/audit?limit=10"
# Invalid Audit Log input proves the validation outcome is observable without
# making any protected-resource payload available.
expect_http 400 curl -sS -b "$auditor_jar" "$BASE_URL/bff/audit?action=not-a-semantic-action"

step "Reviewer authorization-code token, signed decision, and Rekor inclusion"
reviewer_jar="$TMPDIR/reviewer.cookies"
bff_login reviewer reviewer-dev-password "$reviewer_jar"
reviewer_token=$(cli_token reviewer reviewer-dev-password "$TMPDIR/reviewer-cli.cookies")
cli_bin="$TMPDIR/warden"
go build -o "$cli_bin" ./cmd/warden
printf 'approved\nIssue 8 final gate approval\ny\n' | "$cli_bin" decide "$request_id" --access-token "$reviewer_token" >"$TMPDIR/decide.log"
bundle="$TMPDIR/$request_id.bundle.json"
deadline=$(( $(date +%s) + 90 ))
while :; do
    state=$(curl -fsS "$MOCK_URL/mock/requests/$request_id")
    outcome=$(echo "$state" | jq -r '.outcome')
    delivery_status=$(echo "$state" | jq -r '.delivery_status')
    # The GitHub mock tracks the source callback outcome, while Warden owns
    # the durable log_status.  Verify both independently below.
    if [ "$outcome" = approved ] && [ "$delivery_status" = delivered ]; then break; fi
    [ "$(date +%s)" -lt "$deadline" ] || fail "request did not reach published/delivered state: $state"
    sleep 2
done
db_log_status=$($COMPOSE exec -T -e PGPASSWORD=warden-dev-password postgres psql -h 127.0.0.1 -U warden -d warden -Atqc "SELECT log_status FROM requests WHERE id = '$request_id'")
[ "$db_log_status" = published ] || fail "Warden request log_status is $db_log_status, want published"
curl -fsS -H "Authorization: Bearer $reviewer_token" "$BASE_URL/api/v1/requests/$request_id/evidence" >"$bundle"
"$cli_bin" verify "$bundle" --trust .dev/trust.json
echo "$state" | jq -e '.callback_comment | contains("/evidence/")' >/dev/null || fail "GitHub callback lacked the evidence link"

step "Audit Log lifecycle events and auditor visibility"
# The first query appends its own audit.read event after its result snapshot;
# query again so that successful Audit Log reads are themselves visible.
curl -fsS -b "$auditor_jar" "$BASE_URL/bff/audit?limit=10" >/dev/null
auth_auditor_json="$TMPDIR/audit-auth-auditor.json"
curl -fsS -b "$auditor_jar" "$BASE_URL/bff/audit?action=auth.login&actor_id=$auditor_subject&outcome=success&from=$run_started_from&limit=100" >"$auth_auditor_json"
jq -e --arg subject "$auditor_subject" '
    .items | any(.[]; .actor_id == $subject and
        .action_code == "auth.login" and .outcome == "success" and
        .auth_method == "oidc" and .route == "/bff/callback" and
        .reason == "session_created" and (.actor_roles | index("auditor") != null) and
        (.actor_roles | index("reader") == null) and (.actor_roles | index("reviewer") == null))
' "$auth_auditor_json" >/dev/null || fail "current auditor authorization was not successfully audited"
auth_reviewer_json="$TMPDIR/audit-auth-reviewer.json"
reviewer_subject=22222222-2222-4222-8222-222222222222
curl -fsS -b "$auditor_jar" "$BASE_URL/bff/audit?action=auth.login&actor_id=$reviewer_subject&outcome=success&from=$run_started_from&limit=100" >"$auth_reviewer_json"
jq -e --arg subject "$reviewer_subject" '
    .items | any(.[]; .actor_id == $subject and
        .action_code == "auth.login" and .outcome == "success" and
        .auth_method == "oidc" and .route == "/bff/callback" and
        .reason == "session_created" and (.actor_roles | index("reviewer") != null))
' "$auth_reviewer_json" >/dev/null || fail "current reviewer authorization was not successfully audited"
audit_read_json="$TMPDIR/audit-read-current.json"
curl -fsS -b "$auditor_jar" "$BASE_URL/bff/audit?action=audit.read&actor_id=$auditor_subject&outcome=success&from=$run_started_from&limit=100" >"$audit_read_json"
jq -e --arg subject "$auditor_subject" '
    .items | any(.[]; .actor_id == $subject and
        .action_code == "audit.read" and .outcome == "success" and
        .auth_method == "cookie" and .route == "/bff/audit" and
        .reason == "read" and (.actor_roles | index("auditor") != null))
' "$audit_read_json" >/dev/null || fail "current auditor Audit Log read was not successfully audited"
request_add_json="$TMPDIR/audit-request.add.json"
curl -fsS -b "$auditor_jar" "$BASE_URL/bff/audit?action=request.add&resource_id=$request_id&limit=100" >"$request_add_json"
jq -e --arg rid "$request_id" '.items | any(.[]; .resource_id == $rid and .actor_id == "source:github" and .actor_type == "webhook" and .outcome == "success" and .reason == "request_accepted") and all(.[]; .outcome != "failed" and .outcome != "invalid")' "$request_add_json" >/dev/null || fail "signed GitHub webhook event for this request was not a successful source event"
decision_add_json="$TMPDIR/audit-decision.add.json"
curl -fsS -b "$auditor_jar" "$BASE_URL/bff/audit?action=decision.add&resource_id=$request_id&actor_id=22222222-2222-4222-8222-222222222222&limit=100" >"$decision_add_json"
jq -e --arg rid "$request_id" '.items | any(.[]; .resource_id == $rid and .actor_id == "22222222-2222-4222-8222-222222222222" and .actor_type == "user" and .outcome == "success" and .reason == "decision_committed") and all(.[]; .outcome != "failed" and .outcome != "invalid")' "$decision_add_json" >/dev/null || fail "Reviewer decision event for this request was not successful"
for action in transparency.publish source.recheck source.deliver; do
    phase_json="$TMPDIR/audit-$action-$request_id.json"
    curl -fsS -b "$auditor_jar" "$BASE_URL/bff/audit?action=$action&resource_id=$request_id&limit=100" >"$phase_json"
    jq -e --arg rid "$request_id" --arg action "$action" '
        [ .items[] | select(.resource_id == $rid and .action_code == $action) ] as $events |
        ([ $events[] | select(.outcome == "started") | .operation_id ] | unique) as $started |
        ([ $events[] | select(.outcome == "success") | .operation_id ] | unique) as $terminal |
        ($events | length > 0) and ($started | length == 1) and ($terminal | length == 1) and
        ($started[0] == $terminal[0]) and
        ([ $events[] | select(.outcome == "failed" or .outcome == "invalid") ] | length == 0)
    ' "$phase_json" >/dev/null || fail "$action events for this request lacked a successful started/terminal pair"
done
denied_json="$TMPDIR/audit-denied.json"
curl -fsS -b "$auditor_jar" "$BASE_URL/bff/audit?actor_id=$auditor_subject&action=request.list&outcome=denied&from=$run_started_from&limit=100" >"$denied_json"
jq -e '.items | any(.[]; .actor_id == "33333333-3333-4333-8333-333333333333" and .action_code == "request.list" and .route == "/bff/requests" and .outcome == "denied" and .reason == "role_missing")' "$denied_json" >/dev/null || fail "this run's auditor request denial was not audited"
invalid_json="$TMPDIR/audit-invalid.json"
curl -fsS -b "$auditor_jar" "$BASE_URL/bff/audit?actor_id=$auditor_subject&action=audit.read&outcome=invalid&from=$run_started_from&limit=100" >"$invalid_json"
jq -e '.items | any(.[]; .actor_id == "33333333-3333-4333-8333-333333333333" and .action_code == "audit.read" and .route == "/bff/audit" and .outcome == "invalid" and .reason == "invalid audit action")' "$invalid_json" >/dev/null || fail "this run's auditor validation failure was not audited"

step "Runtime role cannot update, delete, or truncate Audit Events"
runtime_password=$(sed -n 's/^RUNTIME_PASSWORD=//p' .dev/compose.env | head -n 1)
runtime_password=${runtime_password:-warden-runtime-dev-password}
admin_count=$($COMPOSE exec -T postgres sh -ec 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U warden -d warden -Atqc "SELECT count(*) FROM audit_events"')
expect_db_denied() {
    sql=$1
    set +e
    $COMPOSE exec -T -e "PGPASSWORD=$runtime_password" postgres psql -h 127.0.0.1 -U warden_runtime -d warden -v ON_ERROR_STOP=1 -c "$sql" >/dev/null 2>&1
    status=$?
    set -e
    [ "$status" -ne 0 ] || fail "runtime role unexpectedly executed: $sql"
}
expect_db_denied "UPDATE audit_events SET reason = 'tampered' WHERE false"
expect_db_denied "DELETE FROM audit_events WHERE false"
expect_db_denied "TRUNCATE audit_events"
final_count=$($COMPOSE exec -T postgres sh -ec 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U warden -d warden -Atqc "SELECT count(*) FROM audit_events"')

[ "$final_count" -ge "$admin_count" ] || fail "Audit Event count decreased during final check"

step "Repeat migrations and verify schema-version-gated startup"
main_audit_before=$($COMPOSE exec -T postgres sh -ec 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U warden -d warden -Atqc "SELECT count(*) FROM audit_events"')
main_initialized_before=$($COMPOSE exec -T postgres sh -ec 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U warden -d warden -Atqc "SELECT count(*) FROM audit_events WHERE action_code = '\''audit.initialized'\''"')
[ "$main_initialized_before" = 1 ] || fail "main Audit Log has $main_initialized_before audit.initialized events before repeat migration"
$COMPOSE run --rm migrate >/dev/null
$COMPOSE run --rm migrate >/dev/null
version=$($COMPOSE exec -T postgres sh -ec 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U warden -d warden -Atqc "SELECT coalesce(max(version_id) FILTER (WHERE is_applied), 0) FROM goose_db_version"')
[ "$version" = 3 ] || fail "migration version is $version, want 3"
main_audit_after=$($COMPOSE exec -T postgres sh -ec 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U warden -d warden -Atqc "SELECT count(*) FROM audit_events"')
main_initialized_after=$($COMPOSE exec -T postgres sh -ec 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U warden -d warden -Atqc "SELECT count(*) FROM audit_events WHERE action_code = '\''audit.initialized'\''"')
[ "$main_audit_after" = "$main_audit_before" ] || fail "repeat migration changed the main Audit Event count"
[ "$main_initialized_after" = 1 ] || fail "repeat migration changed audit.initialized count"

step "Fresh isolated migration upgrade, repeat, and refusal below current version"
migrator_password=$(sed -n 's/^MIGRATOR_PASSWORD=//p' .dev/compose.env | head -n 1)
migrator_password=${migrator_password:-warden-migrator-dev-password}
MIGRATION_DB_NAME="warden_final_check_$$"
encoded_migrator_password=$(urlencode "$migrator_password")
isolated_url="postgres://warden_migrator:${encoded_migrator_password}@postgres:5432/$MIGRATION_DB_NAME?sslmode=disable"
$COMPOSE exec -T -e PGPASSWORD=warden-dev-password postgres psql -h 127.0.0.1 -U warden -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE \"$MIGRATION_DB_NAME\" OWNER warden_migrator" >/dev/null
isolated_owner=$($COMPOSE exec -T -e PGPASSWORD=warden-dev-password postgres psql -h 127.0.0.1 -U warden -d postgres -Atqc "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '$MIGRATION_DB_NAME'")
[ "$isolated_owner" = warden_migrator ] || fail "isolated migration database owner is $isolated_owner, want warden_migrator"
$COMPOSE run --rm -e MIGRATION_DATABASE_URL="$isolated_url" migrate >/dev/null
isolated_version=$($COMPOSE exec -T -e PGPASSWORD=warden-dev-password postgres psql -h 127.0.0.1 -U warden -d "$MIGRATION_DB_NAME" -Atqc "SELECT coalesce(max(version_id) FILTER (WHERE is_applied), 0) FROM goose_db_version")
isolated_initialized=$($COMPOSE exec -T -e PGPASSWORD=warden-dev-password postgres psql -h 127.0.0.1 -U warden -d "$MIGRATION_DB_NAME" -Atqc "SELECT count(*) FROM audit_events WHERE action_code = 'audit.initialized'")
[ "$isolated_version" = 3 ] && [ "$isolated_initialized" = 1 ] || fail "fresh isolated migration did not produce version 3 and one audit.initialized"
$COMPOSE run --rm -e MIGRATION_DATABASE_URL="$isolated_url" migrate >/dev/null
isolated_repeat_version=$($COMPOSE exec -T -e PGPASSWORD=warden-dev-password postgres psql -h 127.0.0.1 -U warden -d "$MIGRATION_DB_NAME" -Atqc "SELECT coalesce(max(version_id) FILTER (WHERE is_applied), 0) FROM goose_db_version")
isolated_repeat_initialized=$($COMPOSE exec -T -e PGPASSWORD=warden-dev-password postgres psql -h 127.0.0.1 -U warden -d "$MIGRATION_DB_NAME" -Atqc "SELECT count(*) FROM audit_events WHERE action_code = 'audit.initialized'")
[ "$isolated_repeat_version" = 3 ] && [ "$isolated_repeat_initialized" = 1 ] || fail "repeated isolated migration changed version or audit.initialized count"
$COMPOSE exec -T -e PGPASSWORD=warden-dev-password postgres psql -h 127.0.0.1 -U warden -d "$MIGRATION_DB_NAME" -v ON_ERROR_STOP=1 -c "UPDATE goose_db_version SET is_applied = false WHERE version_id = 3" >/dev/null
encoded_runtime_password=$(urlencode "$runtime_password")
isolated_runtime_url="postgres://warden_runtime:${encoded_runtime_password}@postgres:5432/$MIGRATION_DB_NAME?sslmode=disable"
set +e
$COMPOSE run --rm --no-deps -e DATABASE_URL="$isolated_runtime_url" warden >"$TMPDIR/schema-refusal.log" 2>&1
schema_status=$?
set -e
[ "$schema_status" -ne 0 ] || fail "Warden unexpectedly started below the current schema version"
grep -Eq 'schema check failed|below required version' "$TMPDIR/schema-refusal.log" || {
    cat "$TMPDIR/schema-refusal.log" >&2
    fail "schema-gated startup refusal did not report the schema check"
}
$COMPOSE restart warden >/dev/null
wait_for "$BASE_URL/healthz"

echo "final-check: PASS (Audit Events retained; count $final_count, schema version $version)"

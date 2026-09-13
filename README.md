# Warden local development

Warden is a deployment approval service. The local stack runs the Go service, PostgreSQL, Keycloak, the real Rekor v2 POSIX filesystem log, and a stateful GitHub App/API mock. The React browser UI is served by Warden at `http://localhost:8080`.

The implemented boundaries and security invariants are described in
[docs/architecture.md](docs/architecture.md).

## Run the end-to-end flow

The first command creates ignored development trust material, builds the React and Go images, starts the stack, and waits for health checks:

```sh
make dev
```

The seeded Keycloak users are `requester` / `requester-dev-password` and `reviewer` / `reviewer-dev-password`. Keycloak is at `http://localhost:8180`; the mock admin API is at `http://localhost:8090`.

Create a deployment request. Copy the request ID and the review URL printed by the command:

```sh
make demo-request
```

Open the printed URL (`http://localhost:8080/requests/<request-id>`), choose **Sign in**, and authenticate as `reviewer`. The browser shows the bound repository, environment, commit, requester, delivery status, transparency-log status, and available evidence. It is the review surface; the decision is signed by the CLI.

Build the CLI once:

```sh
make cli-build
```

Run the decision flow with the request ID from `make demo-request`:

```sh
./bin/warden decide <request-id>
```

The CLI opens the real Keycloak authorization page. Authenticate as `reviewer`, then return to the terminal and answer the decision and reason prompts. The CLI uses the public `warden-cli` client, authorization-code PKCE, and the loopback callback `http://127.0.0.1:18765/callback`. It loads the development reviewer certificate and signing key from `.dev/reviewer.pem` and `.dev/reviewer-key.pem`.

The CLI first fetches the request, asks Warden for a one-time challenge bound to the displayed context, checks the returned statement against the request, decision, reason, and certificate identity, signs it, and submits the certificate-backed bundle. Warden verifies the signature and certificate, records the decision, submits the signed statement to Rekor, verifies the inclusion proof, and only then sends the approved or rejected callback to GitHub.

Poll the mock for the callback outcome:

```sh
while :; do
  state=$(curl -fsS "http://localhost:8090/mock/requests/<request-id>")
  printf '%s\n' "$state" | jq '{decision,outcome,delivery_status}'
  test "$(printf '%s\n' "$state" | jq -r .outcome)" != pending || { sleep 2; continue; }
  break
done
```

Download the authenticated evidence bundle. This launches the same real CLI OIDC flow and writes a local file with mode `0600`:

```sh
./bin/warden evidence download <request-id> --output <request-id>.bundle.json
```

Verify the bundle offline against the generated CA and Rekor checkpoint key. This command makes no network request:

```sh
./bin/warden verify <request-id>.bundle.json --trust .dev/trust.json
```

## Authentication and local controls

The browser uses the confidential `warden-bff` client and PKCE. Its BFF endpoints use an HttpOnly same-origin session cookie; logout requires the CSRF token returned by `/bff/session`. Logout first deletes the Warden session and expires the browser cookie, then the BFF returns a server-generated RP-initiated logout URL. The browser follows that URL to Keycloak, which clears the Keycloak SSO session and redirects to the configured local root. The post-logout redirect is fixed in configuration and allowlisted on the Keycloak client; it is never accepted from a browser request. If the provider's logout metadata is unavailable, Warden still completes local logout and reloads the sign-in page. The browser never receives or stores an OIDC access token or ID token. The CLI uses a bearer access token with the `warden:decide` scope for the decision and evidence API, and signs the decision with the user certificate. Browser and CLI credentials are deliberately separate paths.

The mock sends a signed `deployment_protection_rule` webhook to Warden. Its development controls are useful for exercising source-state handling and retries:

```sh
# Make a GitHub API route fail until cleared.
curl -fsS -X POST http://localhost:8090/mock/failures \
  -H 'Content-Type: application/json' \
  -d '{"endpoint":"actions/runs","status":503}'
curl -fsS -X POST http://localhost:8090/mock/failures \
  -H 'Content-Type: application/json' \
  -d '{"endpoint":"actions/runs","clear":true}'

# Mark a fixture's source workflow cancelled.
curl -fsS -X POST http://localhost:8090/mock/requests/<request-id>/cancel \
  -H 'Content-Type: application/json' -d '{}'
```

`make down` stops containers while preserving local volumes. Use `docker compose -f compose.yaml down -v` for a clean database and Rekor log. `make test` runs the TypeScript production build, Go tests, and Compose validation. The generated `.dev/` directory, `bin/warden`, and build output are ignored and must not be committed.

This is a local MVP: the GitHub mock keeps fixtures in memory, its development admin routes are intentionally unauthenticated, and the seeded users, app installation, certificates, and passwords are for development only. Production deployments must provide real GitHub App/OIDC credentials, managed storage, key custody, and operational access controls.

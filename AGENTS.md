# Local platform guidance

The platform surface consists of `compose.yaml`, `Dockerfile`, `dev/`, `cmd/githubmock`, and `web/`. Keep the local workflow runnable on Linux arm64 and use pinned external image or source versions where practical. The browser talks only to same-origin `/bff` endpoints and must not put credentials or tokens in local storage.

Run `./devinit` (or `make dev`) before Compose so `.dev/rekor-signer.key` and the app trust material exist. Do not mount the `.dev` directory into the service: mount only the Rekor signer file required by the log container. Preserve the fixed Keycloak subject IDs, reviewer group, redirect ports and development passwords documented in `README.md`.

Validation: `npm --prefix web ci --ignore-scripts && npm --prefix web run build`, `go test ./...` and `docker compose --env-file .dev/compose.env -f compose.yaml config --quiet`. Full-stack checks should exercise real Keycloak authorization-code login, signed GitHub webhook delivery and Rekor inclusion.

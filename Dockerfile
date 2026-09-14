# syntax=docker/dockerfile:1.7
FROM node:22.22.1-bookworm-slim@sha256:4f77a690f2f8946ab16fe1e791a3ac0667ae1c3575c3e4d0d4589e9ed5bfaf3d AS web-build
WORKDIR /src/web
COPY web/package*.json ./
RUN npm ci --ignore-scripts
COPY web/ ./
RUN npm run build

FROM golang:1.26.0-bookworm@sha256:2a0ba12e116687098780d3ce700f9ce3cb340783779646aafbabed748fa6677c AS go-build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . ./
COPY --from=web-build /src/web/dist ./web/dist
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/warden ./cmd/server
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/migrate ./cmd/migrate

FROM golang:1.26.0-bookworm@sha256:2a0ba12e116687098780d3ce700f9ce3cb340783779646aafbabed748fa6677c
COPY --from=go-build /out/warden /usr/local/bin/warden
COPY --from=go-build /out/migrate /usr/local/bin/migrate
COPY --from=web-build /src/web/dist /app/web/dist
ENV ADDR=:8080 WEB_DIST=/app/web/dist
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/warden"]

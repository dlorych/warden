FROM golang:1.26.0-bookworm@sha256:2a0ba12e116687098780d3ce700f9ce3cb340783779646aafbabed748fa6677c AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY cmd/githubmock ./cmd/githubmock
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/githubmock ./cmd/githubmock
FROM golang:1.26.0-bookworm@sha256:2a0ba12e116687098780d3ce700f9ce3cb340783779646aafbabed748fa6677c
COPY --from=build /out/githubmock /usr/local/bin/githubmock
EXPOSE 8090
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/githubmock"]

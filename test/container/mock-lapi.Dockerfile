# syntax=docker/dockerfile:1.19.0@sha256:b6afd42430b15f2d2a4c5a02b919e98a525b785b1aaff16747d2f623364e39b6

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build

WORKDIR /src
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local
ARG TARGETOS
ARG TARGETARCH

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    go mod download && go mod verify
COPY internal/ ./internal/
RUN GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
    -o /out/mock-lapi ./internal/lapi/mock/cmd/mock-lapi

# Security note: this disposable internal-only peer is log-readiness-gated and ships no probe utility.
FROM scratch
COPY --from=build --chown=65532:65532 --chmod=0555 /out/mock-lapi /mock-lapi
USER 65532:65532
EXPOSE 8080/tcp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/mock-lapi"]

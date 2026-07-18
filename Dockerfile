# syntax=docker/dockerfile:1.19.0@sha256:b6afd42430b15f2d2a4c5a02b919e98a525b785b1aaff16747d2f623364e39b6

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651 AS build

WORKDIR /src
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=1970-01-01T00:00:00Z
ARG SOURCE_DATE_EPOCH=0

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,target=/root/.cache/go-build,sharing=locked \
    go mod download && go mod verify

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY migrations/ ./migrations/

RUN set -eu; \
    case "$VERSION" in ""|*[!0-9A-Za-z._+-]*) exit 2 ;; esac; \
    case "$REVISION" in \
      unknown) ;; \
      ""|*[!0-9a-f]*) exit 2 ;; \
      *) case "${#REVISION}" in 40|64) ;; *) exit 2 ;; esac ;; \
    esac; \
    case "$BUILD_DATE" in ????-??-??T??:??:??Z) ;; *) exit 2 ;; esac; \
    case "$BUILD_DATE" in *[!0-9TZ:-]*) exit 2 ;; esac; \
    case "$SOURCE_DATE_EPOCH" in ""|*[!0-9]*) exit 2 ;; esac; \
    install -d -m 0750 -o 65532 -g 65532 /out/data; \
    GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
      go build -mod=readonly -trimpath -buildvcs=false \
      -ldflags="-s -w -buildid= \
        -X=crowdshield/internal/buildinfo.Version=${VERSION} \
        -X=crowdshield/internal/buildinfo.Revision=${REVISION} \
        -X=crowdshield/internal/buildinfo.BuildDate=${BUILD_DATE}" \
      -o /out/crowdshield ./cmd/crowdshield; \
    chmod 0555 /out/crowdshield

FROM gcr.io/distroless/static-debian12:nonroot@sha256:aef9602f8710ec12bde19d593fed1f76c708531bb7aba205110f1029786ead7b

ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=1970-01-01T00:00:00Z

LABEL org.opencontainers.image.title="Crowdshield" \
      org.opencontainers.image.description="Safely synchronizes reviewed external threat feeds into owned CrowdSec decisions" \
      org.opencontainers.image.url="https://github.com/harshbaldwa/crowdshield" \
      org.opencontainers.image.source="https://github.com/harshbaldwa/crowdshield" \
      org.opencontainers.image.documentation="https://github.com/harshbaldwa/crowdshield#readme" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$REVISION" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot" \
      org.opencontainers.image.base.digest="sha256:aef9602f8710ec12bde19d593fed1f76c708531bb7aba205110f1029786ead7b"

COPY --from=build --chown=65532:65532 --chmod=0555 /out/crowdshield /crowdshield
COPY --from=build --chown=65532:65532 --chmod=0750 /out/data/ /data/
COPY --chown=65532:65532 --chmod=0444 LICENSE THIRD_PARTY_NOTICES.md /licenses/

WORKDIR /data
USER 65532:65532
EXPOSE 9090/tcp
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/crowdshield", "healthcheck"]
ENTRYPOINT ["/crowdshield"]
CMD ["run"]

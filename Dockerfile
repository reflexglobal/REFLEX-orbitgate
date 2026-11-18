# Exact Go patch version: Dependabot bumps it (Go patch releases carry the security fixes).
FROM --platform=$BUILDPLATFORM golang:1.27.3 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o /orbitgate .

# Nothing but the static binary: no shell, no libc, no CA bundle (the apiserver CA
# comes from the ServiceAccount mount or -apiserver-ca), so no base-image CVEs to patch.
FROM scratch
LABEL org.opencontainers.image.source=https://github.com/reflexglobal/orbitgate \
      org.opencontainers.image.licenses=MIT
COPY --from=build /orbitgate /orbitgate
USER 65532:65532
ENTRYPOINT ["/orbitgate"]

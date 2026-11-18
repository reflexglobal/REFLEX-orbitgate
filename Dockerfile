FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /orbitgate .

# Single static binary, no shell; mirror this image into the airgapped registry.
FROM gcr.io/distroless/static:nonroot
LABEL org.opencontainers.image.source=https://github.com/reflexglobal/REFLEX-orbitgate
COPY --from=build /orbitgate /orbitgate
USER 65532:65532
ENTRYPOINT ["/orbitgate"]

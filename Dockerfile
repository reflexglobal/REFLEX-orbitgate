FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /orbitgate .

# Single static binary, no shell; mirror this base into the airgapped registry.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /orbitgate /orbitgate
USER 65532:65532
ENTRYPOINT ["/orbitgate"]

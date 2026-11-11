# SPDX-License-Identifier: Apache-2.0
# bits-store: the static binary alone, as an unprivileged user; CA roots for https
# volumes (a site CA: mount it and set SSL_CERT_FILE).
FROM golang:1.24.7-bookworm AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOTOOLCHAIN=local go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" -o /bits-store ./cmd/bits-store

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /bits-store /bits-store
USER 65532:65532
EXPOSE 8098
HEALTHCHECK --interval=30s --timeout=5s CMD ["/bits-store", "-health", "http://127.0.0.1:8098/health"]
ENTRYPOINT ["/bits-store"]
CMD ["-config", "/etc/bits-store/config.json"]

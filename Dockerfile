# ---- build stage ----
# Compiles a fully static server binary. Pinned Go version so the build
# is reproducible regardless of what's on the host.
FROM golang:1.27-alpine AS build

WORKDIR /src

# Dependencies first, so this layer is cached unless go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# Then the source.
COPY . .

# CGO disabled -> a truly static binary that runs on scratch/alpine with
# no libc. -mod=readonly: the build uses go.mod/go.sum as committed and
# fails instead of quietly changing dependencies.
RUN CGO_ENABLED=0 GOOS=linux GOFLAGS=-mod=readonly \
    go build -o /out/server ./cmd/server

# No TLS cert in the image: a private key in an image layer leaks to
# anyone who gets the image. The cert comes from the ./devcerts volume
# (see docker-compose.yml), made once on the host with `go run ./cmd/gencert`.

# ---- runtime stage ----
FROM alpine:3.22

# iptables/iproute2: the full-tunnel VPN channel creates its own TUN
# device and needs `ip`/`iptables` on the server to address it and set up
# NAT, see cmd/server/vpn_setup.go. Both iptables backends (nft and
# legacy) are installed, the server picks the one the host already uses.
RUN apk add --no-cache iptables iptables-legacy iproute2

WORKDIR /app
COPY --from=build /out/server /app/server

# No EXPOSE: docker-compose.yml uses host networking, the ports are
# whatever server-config.json says (defaults: reliable 8443, glue 8446,
# vpn 8447; droppable is off).

# No flags baked in — the server reads server-config.json (mounted at
# /app/server-config.json by docker-compose.yml) for everything: ports,
# subnet, authorized_keys_file, all of it. Passing flags at `docker run`/in `command:`
# still works and overrides individual config fields if you ever need
# that, but the normal path is just editing the config and rebuilding.
ENTRYPOINT ["/app/server"]
CMD []

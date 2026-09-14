# ---- build stage ----
# Compiles a fully static server binary. Pinned Go version so the build
# is reproducible regardless of what's on the host.
FROM golang:1.23-alpine AS build

WORKDIR /src

# Dependencies first, so this layer is cached unless go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

# Then the source.
COPY . .

# CGO disabled -> a truly static binary that runs on scratch/alpine with
# no libc. GOFLAGS=-mod=mod tolerates the replace directives in go.mod.
RUN CGO_ENABLED=0 GOOS=linux GOFLAGS=-mod=mod \
    go build -o /out/server ./cmd/server

# Generate dev certs at build time so the image is self-contained for
# testing. For anything real, mount your own certs over /app/devcerts
# instead (see the compose file / run command in the README).
RUN CGO_ENABLED=0 GOOS=linux GOFLAGS=-mod=mod \
    go build -o /out/gencert ./cmd/gencert
RUN cd /out && ./gencert

# ---- runtime stage ----
FROM alpine:3.20

# iptables/iproute2: the full-tunnel VPN channel creates its own TUN
# device and needs `ip`/`iptables` on the server to address it, enable
# forwarding, and set up NAT — see cmd/server/vpn.go.
RUN apk add --no-cache iptables iproute2

WORKDIR /app
COPY --from=build /out/server /app/server
COPY --from=build /out/devcerts /app/devcerts

# reliable, droppable, glue, vpn channels
EXPOSE 8443 8444 8446 8447

# Bind all channels to 0.0.0.0 so they're reachable from outside the
# container. Override the flags at `docker run` time to change ports.
ENTRYPOINT ["/app/server"]
CMD ["-addr", "0.0.0.0:8443", "-drop-addr", "0.0.0.0:8444", "-glue-addr", "0.0.0.0:8446", "-vpn-addr", "0.0.0.0:8447"]

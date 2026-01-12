# Build stage
FROM alpine:latest AS builder
RUN apk add --no-cache build-base zig openssl-dev openssl-libs-static

WORKDIR /app
COPY . .

RUN zig build -Doptimize=ReleaseSmall

# Final stage
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /app/zig-out/bin/zig-nostr-relay /zig-nostr-relay
COPY --from=builder /app/public/ /public/

EXPOSE 7447
ENV DATABASE_URL="postgres://postgres:password@localhost:5432/nostr-relay"
ENTRYPOINT ["/zig-nostr-relay"]

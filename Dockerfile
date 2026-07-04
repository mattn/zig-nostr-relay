# Build stage
# alpine 3.23 ships zig 0.15.2; newer releases ship zig 0.16 which rejects
# the legacy package hashes in build.zig.zon
FROM alpine:3.23 AS builder
RUN apk add --no-cache build-base zig openssl-dev openssl-libs-static

WORKDIR /app
COPY . .

RUN zig build

# Final stage
FROM alpine:3.23
RUN apk add --no-cache openssl ca-certificates

WORKDIR /app
COPY --from=builder /app/zig-out/bin/zig-nostr-relay ./zig-nostr-relay
COPY --from=builder /app/public/ ./public/

EXPOSE 7447
ENV DATABASE_URL="postgres://postgres:password@localhost:5432/nostr-relay"
ENTRYPOINT ["./zig-nostr-relay"]

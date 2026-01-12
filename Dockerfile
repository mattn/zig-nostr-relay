# Build stage
FROM alpine:latest AS builder
RUN apk add --no-cache build-base zig openssl-dev openssl-libs-static

WORKDIR /app
COPY . .

RUN zig build -Doptimize=ReleaseSmall

# Final stage
FROM alpine:latest
RUN apk add --no-cache openssl ca-certificates
COPY --from=builder /app/zig-out/bin/zig-nostr-relay /app/zig-nostr-relay
COPY public/ /app/public/
WORKDIR /app

EXPOSE 7447
ENV DATABASE_URL="postgres://postgres:password@localhost:5432/nostr-relay"
ENTRYPOINT ["/app/zig-nostr-relay"]

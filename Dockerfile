# Build stage
FROM alpine:latest AS builder
RUN apk add --no-cache build-base zig openssl-dev openssl-libs-static

WORKDIR /app
COPY . .

RUN zig build -Doptimize=ReleaseSmall

# Final stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/zig-out/bin/zig-nostr-relay /app/zig-nostr-relay
COPY --from=builder /app/public/ /app/public/
WORKDIR /app

EXPOSE 7447
ENV DATABASE_URL="postgres://postgres:password@localhost:5432/nostr-relay"
ENTRYPOINT ["./zig-nostr-relay"]

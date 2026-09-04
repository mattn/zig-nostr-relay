const std = @import("std");
const websocket = @import("websocket");
const Conn = websocket.Conn;
const Message = websocket.Message;
const Handshake = websocket.Handshake;
const logger = @import("logger.zig");

const Secp256k1 = std.crypto.ecc.Secp256k1;
const Scalar = Secp256k1.scalar.Scalar;
const Sha256 = std.crypto.hash.sha2.Sha256;

const pg = @import("pg");
const struct_env = @import("struct-env");

/// Wraps a pg.Pool created from a URI, owning the parsed connection
/// strings so they outlive the pool.
///
/// pg.zig's `Pool.initUri` (commit 78d52e5) has a use-after-free: it
/// allocates host/username/password/database into a parse-time arena,
/// then `defer po.deinit()`s that arena before storing the opts in the
/// pool. `Pool.init` only shallow-copies the opts, so the pool retains
/// slices into freed memory. Once the underlying memory gets reused by
/// later allocations, the background Reconnector's silent
/// `newConnection(pool, false)` permanently fails to re-auth and the
/// pool sits at `missing == size` forever — server reachable, but no
/// in-pool connection can be restored. We parse the URI ourselves,
/// dupe every string into an arena that lives as long as the pool,
/// and call `Pool.init` directly.
pub const OwnedPool = struct {
    pool: *pg.Pool,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *OwnedPool) void {
        // Stop the pool first — its Reconnector thread reads from the
        // strings in `arena` — then free the strings.
        self.pool.deinit();
        self.arena.deinit();
    }
};

pub fn openPoolFromUri(
    allocator: std.mem.Allocator,
    database_url: []const u8,
    size: u16,
) !OwnedPool {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const aa = arena.allocator();

    const uri = try std.Uri.parse(database_url);
    if (!std.mem.eql(u8, uri.scheme, "postgresql") and !std.mem.eql(u8, uri.scheme, "postgres")) {
        return error.InvalidUriScheme;
    }

    var tls: pg.Conn.Opts.TLS = .off;
    var tcp_user_timeout: ?u32 = null;
    if (uri.query) |qry| {
        const query_string = try qry.toRawMaybeAlloc(aa);
        var it = std.mem.splitScalar(u8, query_string, '&');
        while (it.next()) |param| {
            var it2 = std.mem.splitScalar(u8, param, '=');
            const key = it2.first();
            const val = it2.rest();
            if (std.mem.eql(u8, key, "tcp_user_timeout")) {
                tcp_user_timeout = try std.fmt.parseInt(u32, val, 10);
            } else if (std.mem.eql(u8, key, "sslmode")) {
                if (std.mem.eql(u8, val, "require")) {
                    tls = .require;
                } else if (std.mem.eql(u8, val, "verify-full")) {
                    tls = .{ .verify_full = null };
                } else if (!std.mem.eql(u8, val, "disable")) {
                    return error.UnsupportedSSLModeValue;
                }
            } else {
                return error.UnsupportedConnectionParam;
            }
        }
    }

    // Always dupe so the pool never aliases the caller's URL buffer.
    const path_raw = try uri.path.toRawMaybeAlloc(aa);
    const path = std.mem.trimLeft(u8, path_raw, "/");
    const host: ?[]const u8 = if (uri.host) |h|
        try aa.dupe(u8, try h.toRawMaybeAlloc(aa))
    else
        null;
    const username = try aa.dupe(u8, if (uri.user) |u|
        try u.toRawMaybeAlloc(aa)
    else
        "postgres");
    const password: ?[]const u8 = if (uri.password) |p|
        try aa.dupe(u8, try p.toRawMaybeAlloc(aa))
    else
        null;
    const database: ?[]const u8 = if (path.len == 0)
        null
    else
        try aa.dupe(u8, path);

    const pool = try pg.Pool.init(allocator, .{
        .size = size,
        .auth = .{
            .username = username,
            .password = password,
            .database = database,
            .timeout = tcp_user_timeout orelse 10_000,
        },
        .connect = .{
            .tls = tls,
            .port = uri.port,
            .host = host,
        },
    });

    return .{ .pool = pool, .arena = arena };
}

/// Periodically run `SELECT 1` on every currently-idle connection in the
/// pool. This keeps NAT / load-balancer / pgbouncer idle reapers from
/// silently severing connections during quiet periods, which would
/// otherwise cause a burst of failed acquires when traffic resumes (all
/// connections discovered dead at the same time → pool marked fully
/// missing → `PoolExhausted`).
///
/// Holds every idle connection at once during a cycle so that pg.zig's
/// LIFO release order doesn't keep us pinging the same hot conn over and
/// over. Cycle is short (one `SELECT 1` round-trip per conn).
pub fn runHeartbeat(
    pool: *pg.Pool,
    shutdown: *std.atomic.Value(bool),
    allocator: std.mem.Allocator,
    database_url: []const u8,
) void {
    const healthy_interval_ns: u64 = 30 * std.time.ns_per_s;
    const degraded_interval_ns: u64 = 15 * std.time.ns_per_s;
    while (true) {
        const interval_ns = if (pool.stats().missing > 0)
            degraded_interval_ns
        else
            healthy_interval_ns;
        sleepInterruptible(interval_ns, shutdown);
        if (shutdown.load(.acquire)) return;
        heartbeatCycle(pool, allocator, database_url) catch |err| {
            logger.warn("DB heartbeat cycle failed: {s}", .{@errorName(err)});
        };
    }
}

fn sleepInterruptible(total_ns: u64, shutdown: *std.atomic.Value(bool)) void {
    const chunk_ns: u64 = 500 * std.time.ns_per_ms;
    var remaining: u64 = total_ns;
    while (remaining > 0) {
        if (shutdown.load(.acquire)) return;
        const sleep_ns = @min(chunk_ns, remaining);
        std.Thread.sleep(sleep_ns);
        remaining -= sleep_ns;
    }
}

fn heartbeatCycle(pool: *pg.Pool, allocator: std.mem.Allocator, database_url: []const u8) !void {
    const s = pool.stats();

    // Surface the pool's recovery progress. When pg.zig's background
    // Reconnector retries fail, they are logged via pg.zig's own logger
    // with `log_failure=false` — i.e. completely silent. Logging stats
    // every heartbeat lets us see whether `missing` is shrinking (=>
    // Reconnector working, just slow) or stuck (=> server unreachable).
    if (s.missing > 0) {
        logger.warn("DB pool degraded: size={d} available={d} missing={d} in_use={d}", .{
            s.size, s.available, s.missing, s.in_use,
        });
        probeFreshConnection(allocator, database_url);
    }

    const idle = s.available;
    if (idle == 0) return;

    var held: std.ArrayList(*pg.Conn) = .{};
    defer {
        var i = held.items.len;
        while (i > 0) {
            i -= 1;
            pool.release(held.items[i]);
        }
        held.deinit(allocator);
    }

    var fail_count: usize = 0;
    var first_logged = false;

    var n: usize = 0;
    while (n < idle) : (n += 1) {
        const conn = pool.acquire() catch |err| {
            if (err == error.PoolExhausted or err == error.Timeout) break;
            return err;
        };
        // On ping failure, release immediately. pg.zig's release will see
        // a non-idle state and swap the connection for a fresh one (or
        // mark it missing for the reconnector).
        _ = conn.exec("SELECT 1", .{}) catch |err| {
            fail_count += 1;
            if (!first_logged) {
                first_logged = true;
                if (conn.err) |pg_err| {
                    logger.warn("DB heartbeat ping failed: {s} [{s} {s}] {s}", .{
                        @errorName(err),
                        pg_err.severity,
                        pg_err.code,
                        pg_err.message,
                    });
                } else {
                    logger.warn("DB heartbeat ping failed: {s}", .{@errorName(err)});
                }
            }
            pool.release(conn);
            continue;
        };
        try held.append(allocator, conn);
    }

    if (fail_count > 1) {
        logger.warn("DB heartbeat: {d} more connections failed the same cycle", .{fail_count - 1});
    }
}

/// Open a brand-new connection outside the pool to surface why the
/// Reconnector keeps failing. pg.zig's Reconnector calls
/// `newConnection(pool, false)`, which swallows the underlying error
/// entirely — without this probe we have no idea whether the server is
/// refusing TCP, failing TLS, rejecting auth, or returning a Postgres
/// FATAL.
fn probeFreshConnection(allocator: std.mem.Allocator, database_url: []const u8) void {
    const uri = std.Uri.parse(database_url) catch |err| {
        logger.warn("DB probe: bad DATABASE_URL: {s}", .{@errorName(err)});
        return;
    };
    var conn = pg.Conn.openAndAuthUri(allocator, uri) catch |err| {
        logger.warn("DB probe failed to open: {s}", .{@errorName(err)});
        return;
    };
    defer conn.deinit();
    _ = conn.exec("SELECT 1", .{}) catch |err| {
        if (conn.err) |pg_err| {
            logger.warn("DB probe SELECT 1 failed: {s} [{s} {s}] {s}", .{
                @errorName(err), pg_err.severity, pg_err.code, pg_err.message,
            });
        } else {
            logger.warn("DB probe SELECT 1 failed: {s}", .{@errorName(err)});
        }
        return;
    };
    logger.info("DB probe ok: server reachable but pool Reconnector stuck", .{});
}

/// Acquire a connection from the pool, retrying when the pool is fully
/// exhausted (all connections marked missing). The background reconnector
/// in pg.zig restores connections serially with a 2s backoff between
/// failures, so this loop must wait long enough for at least one
/// connection to come back. Total budget is ~5s with exponential backoff.
fn acquirePool(pool: *pg.Pool) !*pg.Conn {
    const max_total_ns: u64 = 5 * std.time.ns_per_s;
    var delay_ns: u64 = 50 * std.time.ns_per_ms;
    const max_delay_ns: u64 = 1 * std.time.ns_per_s;
    var waited_ns: u64 = 0;
    while (true) {
        return pool.acquire() catch |err| {
            if (err == error.PoolExhausted and waited_ns < max_total_ns) {
                const sleep_ns = @min(delay_ns, max_total_ns - waited_ns);
                std.Thread.sleep(sleep_ns);
                waited_ns += sleep_ns;
                delay_ns = @min(delay_ns * 2, max_delay_ns);
                continue;
            }
            return err;
        };
    }
}

/// Write a JSON-encoded string (with surrounding quotes) to an ArrayList writer.
/// Escapes \, ", and control characters as required by RFC 8259.
fn writeJsonString(writer: anytype, s: []const u8) !void {
    try writer.writeAll("\"");
    for (s) |c| {
        switch (c) {
            '\\' => try writer.writeAll("\\\\"),
            '"' => try writer.writeAll("\\\""),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x08 => try writer.writeAll("\\b"),
            0x0C => try writer.writeAll("\\f"),
            0x00...0x07, 0x0B, 0x0E...0x1F => {
                try writer.print("\\u{x:0>4}", .{@as(u16, c)});
            },
            else => try writer.writeByte(c),
        }
    }
    try writer.writeAll("\"");
}

const Event = struct {
    id: []u8,
    kind: i32 = 0,
    created_at: i32,
    pubkey: []u8,
    content: []u8,
    sig: []u8,
    tags: [][][]u8,
};

const Filter = struct {
    ids: std.ArrayList([]const u8) = undefined,
    authors: std.ArrayList([]const u8) = undefined,
    kinds: std.ArrayList(i64) = undefined,
    tags: std.ArrayList([][]const u8) = undefined,
    since: i64 = 0,
    until: i64 = 0,
    limit: i64 = 0,
    search: []const u8 = undefined,
    allocator: std.mem.Allocator,

    pub fn empty(self: *const Filter) bool {
        return self.ids.items.len == 0 and
            self.authors.items.len == 0 and
            self.kinds.items.len == 0 and
            self.tags.items.len == 0 and
            self.since == 0 and
            self.until == 0 and
            self.search.len == 0;
    }

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .ids = std.ArrayList([]const u8){},
            .authors = std.ArrayList([]const u8){},
            .tags = std.ArrayList([][]const u8){},
            .kinds = std.ArrayList(i64){},
            .search = "",
            .since = 0,
            .until = 0,
            .limit = 500,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.ids.items) |id| {
            self.allocator.free(id);
        }
        self.ids.deinit(self.allocator);
        for (self.authors.items) |author| {
            self.allocator.free(author);
        }
        self.authors.deinit(self.allocator);
        self.kinds.deinit(self.allocator);
        for (self.tags.items) |tag| {
            for (tag) |item| {
                self.allocator.free(item);
            }
            self.allocator.free(tag);
        }
        self.tags.deinit(self.allocator);
        if (self.search.len > 0) self.allocator.free(self.search);
    }
};

pub const Subscriber = struct {
    sub: []const u8,
    conn: *Conn,
    filters: std.ArrayList(*Filter),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, sub: []const u8, conn: *Conn, filters: std.ArrayList(*Filter)) !Self {
        return .{
            .sub = try allocator.dupe(u8, sub),
            .conn = conn,
            .filters = filters,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.filters.items) |filter| {
            filter.deinit();
            self.allocator.destroy(filter);
        }
        self.filters.deinit(self.allocator);
        if (self.sub.len > 0) self.allocator.free(self.sub);
    }
};

pub const Config = struct {
    relay_name: []const u8,
    relay_description: []const u8,
    relay_url: []const u8,
    relay_pubkey: []const u8,
    relay_contact: []const u8,
    relay_icon: []const u8,
    relay_countries: []const []const u8,
};

pub const Context = struct {
    allocator: std.mem.Allocator,
    subscribers: std.ArrayList(Subscriber),
    subscribers_mutex: std.Thread.Mutex,
    broadcast_count: u32 = 0,
    pool: *pg.Pool,
    config: Config,
};

pub fn initDatabase(pool: *pg.Pool) !void {
    const db = try acquirePool(pool);
    defer pool.release(db);

    _ = try db.exec(
        \\CREATE OR REPLACE FUNCTION tags_to_tagvalues(jsonb) RETURNS text[]
        \\    AS 'SELECT array_agg(t->>1) FROM (SELECT jsonb_array_elements($1) AS t)s WHERE length(t->>0) = 1;'
        \\    LANGUAGE SQL
        \\    IMMUTABLE
        \\    RETURNS NULL ON NULL INPUT;
        \\
        \\CREATE TABLE IF NOT EXISTS event (
        \\  id text NOT NULL,
        \\  pubkey text NOT NULL,
        \\  created_at integer NOT NULL,
        \\  kind integer NOT NULL,
        \\  tags jsonb NOT NULL,
        \\  content text NOT NULL,
        \\  sig text NOT NULL,
        \\
        \\  tagvalues text[] GENERATED ALWAYS AS (tags_to_tagvalues(tags)) STORED
        \\);
        \\
        \\CREATE UNIQUE INDEX IF NOT EXISTS ididx ON event USING btree (id text_pattern_ops);
        \\CREATE INDEX IF NOT EXISTS pubkeyprefix ON event USING btree (pubkey text_pattern_ops);
        \\CREATE INDEX IF NOT EXISTS timeidx ON event (created_at DESC);
        \\CREATE INDEX IF NOT EXISTS kindidx ON event (kind);
        \\CREATE INDEX IF NOT EXISTS kindtimeidx ON event(kind,created_at DESC);
        \\CREATE INDEX IF NOT EXISTS arbitrarytagvalues ON event USING gin (tagvalues);
    , .{});
}

// https://github.com/vitalnodo/bip340/blob/main/bip340.zig
fn taggedHash(tag: []const u8, msg: []const u8) [32]u8 {
    var buf: [32]u8 = undefined;
    Sha256.hash(tag, &buf, .{});

    var sha256 = Sha256.init(.{});
    sha256.update(buf[0..]);
    sha256.update(buf[0..]);
    sha256.update(msg);
    sha256.final(&buf);
    return buf;
}

fn verify(public_key: [32]u8, msg: [32]u8, signature: [64]u8) !bool {
    const Px = try Secp256k1.Fe.fromBytes(public_key, .big);
    const Py = try Secp256k1.recoverY(Px, false);
    const P = try Secp256k1.fromAffineCoordinates(.{ .x = Px, .y = Py });
    const r = try Secp256k1.Fe.fromBytes(signature[0..32].*, .big);
    const s = try Secp256k1.scalar.Scalar.fromBytes(signature[32..64].*, .big);
    var to_hash: [96]u8 = undefined;
    @memcpy(to_hash[0..32], signature[0..32]);
    @memcpy(to_hash[32..64], public_key[0..]);
    @memcpy(to_hash[64..96], msg[0..]);
    const e = try Scalar.fromBytes(
        taggedHash("BIP0340/challenge", to_hash[0..]),
        .big,
    );
    const R = (try Secp256k1.basePoint.mulPublic(
        s.toBytes(.big),
        .big,
    )).sub(try P.mul(e.toBytes(.big), .big));
    if (R.affineCoordinates().y.isOdd()) {
        return false;
    }
    if (!R.affineCoordinates().x.equivalent(r)) {
        return false;
    }
    return true;
}

// NIP-26: Delegated Event Signing
// https://github.com/nostr-protocol/nips/blob/master/26.md
// An event may carry a tag ["delegation", <delegator pubkey>, <conditions>, <sig>]
// where <sig> is a BIP-340 signature by the delegator over
// sha256("nostr:delegation:<delegatee pubkey>:<conditions>").
fn validateDelegation(ev: Event) bool {
    var delegation_tag: ?[][]u8 = null;
    for (ev.tags) |tag| {
        if (tag.len >= 4 and std.mem.eql(u8, tag[0], "delegation")) {
            delegation_tag = tag;
            break;
        }
    }

    // No delegation tag: accept as before
    const tag = delegation_tag orelse return true;
    if (tag.len != 4) return false;

    const delegator_pubkey = tag[1];
    const conditions = tag[2];
    const signature = tag[3];

    if (delegator_pubkey.len == 0 or conditions.len == 0 or signature.len == 0) return false;

    if (delegator_pubkey.len != 64) return false;
    var bytes_pk: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes_pk, delegator_pubkey) catch return false;

    if (!validateDelegationConditions(ev, conditions)) return false;

    if (!verifyDelegationSignature(ev.pubkey, delegator_pubkey, conditions, signature)) return false;

    return true;
}

// Conditions are an &-separated query string: kind=<int> (event kind must
// match one of the listed kinds), created_at<<timestamp> and
// created_at><timestamp> (event timestamp must fall inside the delegated
// window). Unknown fields are ignored.
fn validateDelegationConditions(ev: Event, conditions: []const u8) bool {
    var kind_allowed = false;
    var created_at_valid = true;

    var it = std.mem.splitScalar(u8, conditions, '&');
    while (it.next()) |condition| {
        if (std.mem.startsWith(u8, condition, "kind=")) {
            const allowed_kind = std.fmt.parseInt(i32, condition["kind=".len..], 10) catch continue;
            if (ev.kind == allowed_kind) kind_allowed = true;
        } else if (std.mem.startsWith(u8, condition, "created_at<")) {
            const max_time = std.fmt.parseInt(i64, condition["created_at<".len..], 10) catch continue;
            if (ev.created_at >= max_time) created_at_valid = false;
        } else if (std.mem.startsWith(u8, condition, "created_at>")) {
            const min_time = std.fmt.parseInt(i64, condition["created_at>".len..], 10) catch continue;
            if (ev.created_at <= min_time) created_at_valid = false;
        }
    }

    return kind_allowed and created_at_valid;
}

fn verifyDelegationSignature(delegatee_pubkey: []const u8, delegator_pubkey: []const u8, conditions: []const u8, signature: []const u8) bool {
    if (signature.len != 128) return false;
    var bytes_sig: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes_sig, signature) catch return false;
    var bytes_pk: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes_pk, delegator_pubkey) catch return false;

    var msgbuf: [32]u8 = undefined;
    var sha256 = Sha256.init(.{});
    sha256.update("nostr:delegation:");
    sha256.update(delegatee_pubkey);
    sha256.update(":");
    sha256.update(conditions);
    sha256.final(&msgbuf);

    return verify(bytes_pk, msgbuf, bytes_sig) catch false;
}

// NIP-22: Event created_at Limits
// https://github.com/nostr-protocol/nips/blob/master/22.md
// Events whose created_at is more than `created_at_lower_limit` seconds in
// the past or `created_at_upper_limit` seconds in the future are rejected.
// A limit of 0 disables that side of the check.
const created_at_lower_limit: i64 = 3 * 365 * 24 * 60 * 60; // 3 years in the past
const created_at_upper_limit: i64 = 15 * 60; // 15 minutes in the future

fn createdAtWithinLimits(created_at: i64, now: i64, lower: i64, upper: i64) bool {
    if (lower > 0 and created_at < now - lower) return false;
    if (upper > 0 and created_at > now + upper) return false;
    return true;
}

// NIP-40: Expiration Timestamp
// https://github.com/nostr-protocol/nips/blob/master/40.md
// An event carrying an ["expiration", "<unix timestamp>"] tag must not be
// served to clients after that timestamp.
fn eventIsExpired(ev: Event, now: i64) bool {
    for (ev.tags) |tag| {
        if (tag.len >= 2 and std.mem.eql(u8, tag[0], "expiration")) {
            const ts = std.fmt.parseInt(i64, tag[1], 10) catch continue;
            if (ts <= now) return true;
        }
    }
    return false;
}

// Same check for a stored event whose tags are only available as a JSON
// string (the `tags` column). The cheap substring guard avoids parsing
// JSON for the vast majority of events that carry no expiration tag.
fn tagsJsonExpired(allocator: std.mem.Allocator, tagsj: []const u8, now: i64) bool {
    if (std.mem.indexOf(u8, tagsj, "\"expiration\"") == null) return false;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, tagsj, .{}) catch return false;
    defer parsed.deinit();
    if (parsed.value != .array) return false;
    for (parsed.value.array.items) |tag| {
        if (tag != .array or tag.array.items.len < 2) continue;
        const name = tag.array.items[0];
        const value = tag.array.items[1];
        if (name != .string or value != .string) continue;
        if (!std.mem.eql(u8, name.string, "expiration")) continue;
        const ts = std.fmt.parseInt(i64, value.string, 10) catch continue;
        if (ts <= now) return true;
    }
    return false;
}

// NIP-70: Protected Events
// https://github.com/nostr-protocol/nips/blob/master/70.md
// An event carrying a ["-"] tag may only be published to the relay by its
// author, over a connection authenticated (NIP-42) as that author.
fn eventIsProtected(ev: Event) bool {
    for (ev.tags) |tag| {
        if (tag.len >= 1 and std.mem.eql(u8, tag[0], "-")) return true;
    }
    return false;
}

fn protectedEventAllowed(ev: Event, authed_pubkey: ?[]const u8) bool {
    if (!eventIsProtected(ev)) return true;
    const authed = authed_pubkey orelse return false;
    return std.mem.eql(u8, ev.pubkey, authed);
}

// NIP-42: Authentication of clients to relays
// https://github.com/nostr-protocol/nips/blob/master/42.md
// Verify the challenge and relay tags of a kind 22242 AUTH event
// independently: both must match, so a replayed AUTH event with two "relay"
// tags cannot authenticate without the right challenge. Trailing slashes
// are ignored when comparing relay URLs.
fn trimTrailingSlashes(s: []const u8) []const u8 {
    return std.mem.trimRight(u8, s, "/");
}

fn authChallengeAndRelayMatch(ev: Event, challenge: []const u8, relay_url: []const u8) bool {
    const expected_relay = trimTrailingSlashes(relay_url);
    var challenge_matched = false;
    var relay_matched = false;
    for (ev.tags) |tag| {
        if (tag.len < 2) continue;
        if (std.mem.eql(u8, tag[0], "challenge")) {
            if (challenge.len > 0 and std.mem.eql(u8, tag[1], challenge)) {
                challenge_matched = true;
            }
        } else if (std.mem.eql(u8, tag[0], "relay")) {
            if (expected_relay.len > 0 and std.mem.eql(u8, trimTrailingSlashes(tag[1]), expected_relay)) {
                relay_matched = true;
            }
        }
    }
    return challenge_matched and relay_matched;
}

fn make_tagsj(allocator: std.mem.Allocator, ev: Event) ![]const u8 {
    var result: std.ArrayList(u8) = .{};
    errdefer result.deinit(allocator);
    var writer = result.writer(allocator);

    try writer.writeAll("[");
    for (ev.tags, 0..) |tag, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("[");
        for (tag, 0..) |item, j| {
            if (j > 0) try writer.writeAll(",");
            try writeJsonString(writer, item);
        }
        try writer.writeAll("]");
    }
    try writer.writeAll("]");

    return result.toOwnedSlice(allocator);
}

pub fn handleEventMessage(allocator: std.mem.Allocator, socket: std.posix.socket_t, pool: *pg.Pool, value: std.json.Value) !void {
    const parsedEvent = try std.json.parseFromValue(Event, allocator, value.array.items[1], .{});
    defer parsedEvent.deinit();
    const ev = parsedEvent.value;

    const verified = verifyEvent(allocator, ev) catch |err| {
        logger.warn("Event verification failed: {s}", .{@errorName(err)});
        const notice = "[\"NOTICE\",\"error: verification failed\"]";
        _ = std.posix.write(socket, notice) catch {};
        return;
    };
    if (!verified) {
        logger.warn("Event has invalid signature", .{});
        const notice = "[\"NOTICE\",\"error: invalid signature\"]";
        _ = std.posix.write(socket, notice) catch {};
        return;
    }

    // NIP-70: protected events require a connection authenticated (NIP-42)
    // as the event author; this path carries no auth state, so reject them.
    if (!protectedEventAllowed(ev, null)) {
        logger.warn("Protected event rejected: not authenticated as author", .{});
        var response: [512]u8 = undefined;
        const response_len = try std.fmt.bufPrint(&response, "[\"OK\",\"{s}\",false,\"auth-required: need to authenticate\"]", .{ev.id});
        _ = std.posix.write(socket, response_len) catch {};
        return;
    }

    if (!validateDelegation(ev)) {
        logger.warn("Event has invalid delegation", .{});
        var response: [512]u8 = undefined;
        const response_len = try std.fmt.bufPrint(&response, "[\"OK\",\"{s}\",false,\"invalid: delegation verification failed\"]", .{ev.id});
        _ = std.posix.write(socket, response_len) catch {};
        return;
    }

    const db = try acquirePool(pool);
    defer pool.release(db);

    // Handle deletions based on event kind
    if (ev.kind == 5) {
        // Kind 5: Delete events by ID in tags
        for (ev.tags) |tag| {
            if (tag.len >= 2 and std.mem.eql(u8, tag[0], "e")) {
                _ = db.exec("DELETE FROM event WHERE id = $1 AND pubkey = $2", .{ tag[1], ev.pubkey }) catch |err| {
                    logger.warn("Error deleting event: {s}", .{@errorName(err)});
                };
            }
        }
    } else {
        // Delete existing events based on kind ranges
        if (ev.kind == 0 or ev.kind == 3 or (10000 <= ev.kind and ev.kind < 20000)) {
            // Replaceable events: delete same kind and pubkey
            _ = db.exec("DELETE FROM event WHERE kind = $1 AND pubkey = $2", .{ ev.kind, ev.pubkey }) catch |err| {
                logger.warn("Error deleting replaceable event: {s}", .{@errorName(err)});
            };
        } else if (30000 <= ev.kind and ev.kind < 40000) {
            // Parameterized replaceable events: delete by kind, pubkey, and d tag
            for (ev.tags) |tag| {
                if (tag.len >= 2 and std.mem.eql(u8, tag[0], "d")) {
                    const pattern = try std.fmt.allocPrint(allocator, "%\"d\",\"{s}\"%", .{tag[1]});
                    defer allocator.free(pattern);
                    _ = db.exec("DELETE FROM event WHERE kind = $1 AND pubkey = $2 AND tags::text LIKE $3", .{ ev.kind, ev.pubkey, pattern }) catch |err| {
                        logger.warn("Error deleting parameterized event: {s}", .{@errorName(err)});
                    };
                    break;
                }
            }
        }

        // Convert tags to JSON
        const tagsj = try make_tagsj(allocator, ev);
        defer allocator.free(tagsj);

        // Insert event into database
        _ = db.exec(
            \\INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES ($1, $2, $3, $4, $5, $6, $7)
        , .{ ev.id, ev.pubkey, ev.created_at, ev.kind, tagsj, ev.content, ev.sig }) catch |err| {
            logger.warn("Error inserting event: {s}", .{@errorName(err)});
            var response: [512]u8 = undefined;
            const response_len = try std.fmt.bufPrint(&response, "[\"OK\",\"{s}\",false,\"error: {s}\"]", .{ ev.id, @errorName(err) });
            _ = std.posix.write(socket, response_len) catch {};
            return;
        };
    }

    // Send OK response
    var response: [512]u8 = undefined;
    const response_len = try std.fmt.bufPrint(&response, "[\"OK\",\"{s}\",true,\"\"]", .{ev.id});
    _ = std.posix.write(socket, response_len) catch {};
}

pub fn handleReqMessage(allocator: std.mem.Allocator, socket: std.posix.socket_t, context: *Context, value: std.json.Value) !void {
    if (value.array.items.len < 2) {
        _ = std.posix.write(socket, "[\"NOTICE\",\"error: invalid request\"]") catch {};
        return;
    }

    const sub_id = value.array.items[1];
    if (sub_id != .string) {
        _ = std.posix.write(socket, "[\"NOTICE\",\"error: invalid subscription id\"]") catch {};
        return;
    }

    // Parse filters from value.array.items[2..]
    var filters = std.ArrayList(*Filter){};
    defer {
        for (filters.items) |filter| {
            filter.deinit();
            allocator.destroy(filter);
        }
        filters.deinit(allocator);
    }

    for (value.array.items[2..]) |elem| {
        if (elem != .object) continue;

        var filter = try allocator.create(Filter);
        filter.* = Filter.init(allocator);

        var it = elem.object.iterator();
        while (it.next()) |entry| {
            const key = entry.key_ptr.*;
            const val = entry.value_ptr.*;

            if (std.mem.eql(u8, key, "ids")) {
                if (val != .array) continue;
                for (val.array.items) |id| {
                    if (id != .string) continue;
                    try filter.ids.append(allocator, id.string);
                }
            } else if (std.mem.eql(u8, key, "authors")) {
                if (val != .array) continue;
                for (val.array.items) |author| {
                    if (author != .string) continue;
                    try filter.authors.append(allocator, author.string);
                }
            } else if (std.mem.eql(u8, key, "kinds")) {
                if (val != .array) continue;
                for (val.array.items) |kind| {
                    if (kind != .integer) continue;
                    try filter.kinds.append(allocator, @intCast(kind.integer));
                }
            } else if (std.mem.startsWith(u8, key, "#")) {
                if (val != .array) continue;
                var tag_filter = std.ArrayList([]const u8){};
                try tag_filter.append(allocator, key[1..]);
                for (val.array.items) |tag_val| {
                    if (tag_val != .string) continue;
                    try tag_filter.append(allocator, tag_val.string);
                }
                try filter.tags.append(allocator, try tag_filter.toOwnedSlice());
            } else if (std.mem.eql(u8, key, "since")) {
                if (val != .integer) continue;
                filter.since = @intCast(val.integer);
            } else if (std.mem.eql(u8, key, "until")) {
                if (val != .integer) continue;
                filter.until = @intCast(val.integer);
            } else if (std.mem.eql(u8, key, "limit")) {
                if (val != .integer) continue;
                filter.limit = @intCast(val.integer);
            } else if (std.mem.eql(u8, key, "search")) {
                if (val != .string) continue;
                filter.search = val.string;
            }
        }

        try filters.append(allocator, filter);
    }

    // Build SQL query
    const db = try acquirePool(context.pool);
    defer context.pool.release(db);

    var sql: std.ArrayList(u8) = .{};
    defer sql.deinit(allocator);
    var params = std.ArrayList([]const u8){};
    defer params.deinit(allocator);

    try sql.appendSlice(allocator, "SELECT id, pubkey, created_at, kind, tags, content, sig FROM event WHERE 1=1");

    var limit: i64 = 500;
    for (filters.items) |filter| {
        if (filter.limit >= 0 and filter.limit < limit) {
            limit = filter.limit;
        }

        // Build WHERE conditions
        if (filter.ids.items.len > 0) {
            try sql.appendSlice(allocator, " AND id IN (");
            for (filter.ids.items, 0..) |id, i| {
                if (i > 0) try sql.appendSlice(allocator, ",");
                try sql.writer(allocator).print("${}", .{params.items.len + 1});
                try params.append(allocator, id);
            }
            try sql.appendSlice(allocator, ")");
        }

        if (filter.authors.items.len > 0) {
            try sql.appendSlice(allocator, " AND pubkey IN (");
            for (filter.authors.items, 0..) |author, i| {
                if (i > 0) try sql.appendSlice(allocator, ",");
                try sql.writer(allocator).print("${}", .{params.items.len + 1});
                try params.append(allocator, author);
            }
            try sql.appendSlice(allocator, ")");
        }

        if (filter.kinds.items.len > 0) {
            try sql.appendSlice(allocator, " AND kind IN (");
            for (filter.kinds.items, 0..) |kind, i| {
                if (i > 0) try sql.appendSlice(allocator, ",");
                try sql.writer(allocator).print("{}", .{kind});
            }
            try sql.appendSlice(allocator, ")");
        }

        if (filter.since > 0) {
            try sql.writer(allocator).print(" AND created_at >= {}", .{filter.since});
        }

        if (filter.until > 0) {
            try sql.writer(allocator).print(" AND created_at <= {}", .{filter.until});
        }

        if (filter.search.len > 0) {
            try params.append(allocator, filter.search);
            try sql.writer(allocator).print(" AND content LIKE ('%' || ${} || '%')", .{params.items.len});
        }
    }

    try sql.writer(allocator).print(" ORDER BY created_at DESC LIMIT {}", .{limit});

    // Execute query
    var stmt = try pg.Stmt.init(db, .{});
    errdefer stmt.deinit();

    try stmt.prepare(sql.items, null);

    for (params.items) |param| {
        try stmt.bind(@constCast(param));
    }

    var res = try stmt.execute();
    defer res.deinit();

    // Send matching events
    while (try res.next()) |row| {
        if (row.values.len != 7) continue;

        var response: std.ArrayList(u8) = .{};
        defer response.deinit(allocator);

        const id = try row.get([]u8, 0);
        const pubkey = try row.get([]u8, 1);
        const created_at = try row.get(i32, 2);
        const kind = try row.get(i32, 3);
        const tags = try row.get([]u8, 4);
        const content = try row.get([]u8, 5);
        const sig = try row.get([]u8, 6);

        try response.writer(allocator).print("[\"EVENT\",\"{s}\",{{\"id\":\"{s}\",\"pubkey\":\"{s}\",\"created_at\":{},\"kind\":{},\"tags\":{s},\"content\":", .{ sub_id.string, id, pubkey, created_at, kind, tags });
        try writeJsonString(response.writer(allocator), content);
        try response.writer(allocator).print(",\"sig\":\"{s}\"}}]", .{sig});

        _ = std.posix.write(socket, response.items) catch {};
    }

    // Send EOSE
    var eose_msg: [512]u8 = undefined;
    const eose_len = try std.fmt.bufPrint(&eose_msg, "[\"EOSE\",\"{s}\"]", .{sub_id.string});
    _ = std.posix.write(socket, eose_len) catch {};
}

pub fn handleCloseMessage(_: std.mem.Allocator, _: std.posix.socket_t, context: *Context, value: std.json.Value) !void {
    if (value.array.items.len < 2) return;

    const sub_id = value.array.items[1];
    if (sub_id != .string) return;

    // Remove subscriber from context.subscribers
    var i: usize = 0;
    while (i < context.subscribers.items.len) {
        if (std.mem.eql(u8, context.subscribers.items[i].sub, sub_id.string)) {
            var sub = context.subscribers.orderedRemove(i);
            sub.deinit();
            logger.debug("Subscription {s} closed", .{sub_id.string});
            return;
        }
        i += 1;
    }
}

pub fn verifyEvent(allocator: std.mem.Allocator, ev: Event) !bool {
    var tags = std.json.Array.init(allocator);
    defer tags.deinit();
    for (ev.tags) |tag| {
        var newtag = std.json.Array.init(allocator);
        for (tag) |v| {
            try newtag.append(allocator, std.json.Value{ .string = v });
        }
        try tags.append(allocator, std.json.Value{ .array = newtag });
    }

    var bytes_pk: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes_pk, ev.pubkey);
    var bytes_sig: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bytes_sig, ev.sig);

    // Serialize event to JSON manually for signature verification
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(allocator);
    const writer = buf.writer(allocator);

    try writer.writeAll("[0,\"");
    try writer.writeAll(ev.pubkey);
    try writer.writeAll("\",");
    try writer.print("{}", .{ev.created_at});
    try writer.writeAll(",");
    try writer.print("{}", .{ev.kind});
    try writer.writeAll(",");

    // Write tags array
    try writer.writeAll("[");
    for (ev.tags, 0..) |tag, i| {
        if (i > 0) try writer.writeAll(",");
        try writer.writeAll("[");
        for (tag, 0..) |v, j| {
            if (j > 0) try writer.writeAll(",");
            try writeJsonString(writer, v);
        }
        try writer.writeAll("]");
    }
    try writer.writeAll("]");

    try writer.writeAll(",");
    try writeJsonString(writer, ev.content);
    try writer.writeAll("]");

    var msgbuf: [32]u8 = undefined;
    var sha256 = Sha256.init(.{});
    sha256.update(buf.items);
    sha256.final(&msgbuf);

    return try verify(
        bytes_pk,
        msgbuf,
        bytes_sig,
    );
}

pub const Handler = struct {
    conn: *Conn,
    context: *Context,
    client_ip: []const u8 = "-",
    // NIP-42: per-connection auth state. The challenge is generated when the
    // connection is established and sent to the client as ["AUTH", challenge].
    challenge: [16]u8 = [_]u8{'0'} ** 16,
    authed_pubkey: ?[64]u8 = null,

    pub fn init(h: *const Handshake, conn: *Conn, context: *Context) !Handler {
        _ = h;
        return Handler{
            .conn = conn,
            .context = context,
        };
    }

    pub fn afterInit(_: *Handler) !void {
        // Database initialization moved to main.zig
    }

    fn kindInSlice(haystack: []i64, needle: i64) bool {
        for (haystack) |item| {
            if (item == needle) {
                return true;
            }
        }
        return false;
    }

    fn idInSlice(haystack: [][]const u8, needle: []const u8) bool {
        for (haystack) |item| {
            if (std.mem.eql(u8, item, needle)) {
                return true;
            }
        }
        return false;
    }

    fn tagsInSlice(haystack: [][][]const u8, needle: [][][]u8) bool {
        for (needle) |tag| {
            for (haystack) |item| {
                if (item.len != 2) continue;
                if (std.mem.eql(u8, item[0], tag[0]) and std.mem.eql(u8, item[1], tag[1])) {
                    return true;
                }
            }
        }
        return false;
    }

    fn eventMatched(event: Event, filters: std.ArrayList(*Filter)) bool {
        if (filters.items.len == 0) return true;

        for (filters.items) |filter| {
            if (filterMatches(event, filter)) {
                return true;
            }
        }
        return false;
    }

    fn filterMatches(event: Event, filter: *Filter) bool {
        // Each condition in a filter is AND'd together
        if (filter.ids.items.len > 0 and !idInSlice(filter.ids.items, event.id)) return false;
        if (filter.authors.items.len > 0 and !idInSlice(filter.authors.items, event.pubkey)) return false;
        if (filter.kinds.items.len > 0 and !kindInSlice(filter.kinds.items, event.kind)) return false;
        if (filter.tags.items.len > 0 and !tagsInSlice(filter.tags.items, event.tags)) return false;
        if (filter.since > 0 and event.created_at < filter.since) return false;
        if (filter.until > 0 and event.created_at > filter.until) return false;
        if (filter.search.len > 0) {
            // Simple substring search in content
            if (std.mem.indexOf(u8, event.content, filter.search) == null) return false;
        }
        return true;
    }

    fn sendOk(self: *Handler, id: []const u8, ok: bool, reason: []const u8) !void {
        var buf: std.ArrayList(u8) = .{};
        defer buf.deinit(self.context.allocator);
        var writer = buf.writer(self.context.allocator);
        try writer.writeAll("[\"OK\",\"");
        try writer.writeAll(id);
        try writer.writeAll(if (ok) "\",true,\"" else "\",false,\"");
        try writer.writeAll(reason);
        try writer.writeAll("\"]");
        try self.conn.write(buf.items);
    }

    // NIP-42: restrict filters for kind-4 DMs and kind-1059 gift wraps to
    // authenticated clients that are a party to the conversation. Returns
    // the CLOSED reason when the filter is not allowed, null when it is.
    fn validateFilterAccess(self: *Handler, filter: *Filter) ?[]const u8 {
        const senders = filter.authors.items;
        var receivers: []const []const u8 = &.{};
        for (filter.tags.items) |tag| {
            if (tag.len >= 1 and std.mem.eql(u8, tag[0], "p")) {
                receivers = tag[1..];
                break;
            }
        }
        const authed: ?[]const u8 = if (self.authed_pubkey) |*pk| pk[0..] else null;

        if (kindInSlice(filter.kinds.items, 4)) {
            if (authed == null) {
                return "restricted: this relay does not serve kind-4 to unauthenticated users, does your client implement NIP-42?";
            } else if (senders.len == 1 and receivers.len < 2 and std.mem.eql(u8, senders[0], authed.?)) {
                // sender is the authenticated user
            } else if (receivers.len == 1 and senders.len < 2 and std.mem.eql(u8, receivers[0], authed.?)) {
                // receiver is the authenticated user
            } else {
                return "restricted: authenticated user does not have authorization for requested filters.";
            }
        }

        if (kindInSlice(filter.kinds.items, 1059)) {
            if (authed == null) {
                return "restricted: this relay does not serve gift-wrapped events to unauthenticated users, does your client implement NIP-42?";
            } else if (receivers.len == 1 and std.mem.eql(u8, receivers[0], authed.?)) {
                // receiver is the authenticated user
            } else {
                return "restricted: authenticated user does not have authorization for requested filters.";
            }
        }

        return null;
    }

    // NIP-42: handle the client's ["AUTH", <kind 22242 event>] message.
    pub fn handleAuth(self: *Handler, value: std.json.Value) !void {
        const parsedEvent = try std.json.parseFromValue(Event, self.context.allocator, value.array.items[1], .{});
        defer parsedEvent.deinit();
        const ev = parsedEvent.value;

        const verified = verify_event(self.context.allocator, ev) catch false;
        if (!verified) {
            logger.warn("[{s}] AUTH event has invalid signature", .{self.client_ip});
            try self.sendOk(ev.id, false, "invalid: event id or signature is invalid");
            return;
        }

        if (ev.kind != 22242) {
            try self.sendOk(ev.id, false, "invalid: auth event kind must be 22242");
            return;
        }

        // created_at must be close (within ~10 minutes) to the current time
        // to prevent replay of a previously observed AUTH event.
        const now = std.time.timestamp();
        const diff = now - ev.created_at;
        if (diff > 600 or diff < -600) {
            try self.sendOk(ev.id, false, "invalid: auth event created_at is out of range");
            return;
        }

        if (authChallengeAndRelayMatch(ev, &self.challenge, self.context.config.relay_url) and ev.pubkey.len == 64) {
            self.authed_pubkey = ev.pubkey[0..64].*;
            logger.info("[{s}] Client authenticated: pubkey={s}", .{ self.client_ip, ev.pubkey[0..16] });
            try self.sendOk(ev.id, true, "");
            return;
        }

        try self.sendOk(ev.id, false, "error: failed to authenticate");
    }

    fn delete_record_by_id(self: *Handler, tag: [][]u8) !bool {
        const bindValue = union(enum) {
            number: i64,
            string: []const u8,
        };
        var params = std.ArrayList(bindValue){};
        defer params.deinit(self.context.allocator);
        var parambuf: std.ArrayList(u8) = .{};
        defer parambuf.deinit(self.context.allocator);

        for (tag) |id| {
            try params.append(self.context.allocator, .{ .string = id });
            const s = try std.fmt.allocPrint(self.context.allocator, "${}", .{params.items.len});
            try parambuf.appendSlice(self.context.allocator, s);
            self.context.allocator.free(s);
            try parambuf.append(self.context.allocator, ',');
        }
        if (parambuf.items.len == 0) return false;

        _ = parambuf.pop();

        const sql = try std.fmt.allocPrint(self.context.allocator, "delete from event where id in ({s})", .{parambuf.items});
        defer self.context.allocator.free(sql);

        const db = try acquirePool(self.context.pool);
        defer self.context.pool.release(db);
        var stmt = try pg.Stmt.init(db, .{});
        errdefer stmt.deinit();

        try stmt.prepare(sql, null);
        for (params.items) |param| {
            switch (param) {
                .number => |number| try stmt.bind(number),
                .string => |string| try stmt.bind(@constCast(string)),
            }
        }
        const res = try stmt.execute();
        defer res.deinit();

        return true;
    }

    fn delete_record_by_kind_and_pubkey(self: *Handler, kind: i64, pubkey: []u8) !bool {
        const db = try acquirePool(self.context.pool);
        defer self.context.pool.release(db);
        var stmt = try pg.Stmt.init(db, .{});
        errdefer stmt.deinit();

        try stmt.prepare("delete from event where kind = $1 and pubkey = $2", null);
        try stmt.bind(kind);
        try stmt.bind(pubkey);

        const res = try stmt.execute();
        defer res.deinit();

        return true;
    }

    fn delete_record_by_kind_and_pubkey_and_dtag(self: *Handler, kind: i64, pubkey: []u8, tag: [][]u8) !bool {
        const bindValue = union(enum) {
            number: i64,
            string: []const u8,
        };
        var params = std.ArrayList(bindValue){};
        defer params.deinit(self.context.allocator);
        var parambuf: std.ArrayList(u8) = .{};
        defer parambuf.deinit(self.context.allocator);
        try params.append(self.context.allocator, .{ .number = kind });
        try params.append(self.context.allocator, .{ .string = pubkey });
        for (tag) |id| {
            try params.append(self.context.allocator, .{ .string = id });
            const s = try std.fmt.allocPrint(self.context.allocator, "${}", .{params.items.len});
            try parambuf.appendSlice(self.context.allocator, s);
            self.context.allocator.free(s);
            try parambuf.append(self.context.allocator, ',');
        }
        if (parambuf.items.len == 0) return false;

        _ = parambuf.pop();

        const sql = try std.fmt.allocPrint(self.context.allocator, "delete from event where kind = $1 and pubkey = $2 and id in ({s})", .{parambuf.items});
        defer self.context.allocator.free(sql);

        const db = try acquirePool(self.context.pool);
        defer self.context.pool.release(db);
        var stmt = try pg.Stmt.init(db, .{});
        errdefer stmt.deinit();

        try stmt.prepare(sql, null);
        for (params.items) |param| {
            switch (param) {
                .number => |number| try stmt.bind(number),
                .string => |string| try stmt.bind(@constCast(string)),
            }
        }
        const res = try stmt.execute();
        defer res.deinit();

        return true;
    }

    fn verify_event(allocator: std.mem.Allocator, ev: Event) !bool {
        var bytes_pk: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes_pk, ev.pubkey);
        var bytes_sig: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes_sig, ev.sig);

        // Manually construct JSON for event ID verification
        // Format: [0, pubkey, created_at, kind, tags, content]
        var buf: std.ArrayList(u8) = .{};
        defer buf.deinit(allocator);
        var writer = buf.writer(allocator);

        try writer.writeAll("[0,\"");
        try writer.writeAll(ev.pubkey);
        try writer.writeAll("\",");
        try writer.print("{},", .{ev.created_at});
        try writer.print("{},", .{ev.kind});

        // Write tags array
        try writer.writeAll("[");
        for (ev.tags, 0..) |tag, i| {
            if (i > 0) try writer.writeAll(",");
            try writer.writeAll("[");
            for (tag, 0..) |item, j| {
                if (j > 0) try writer.writeAll(",");
                try writeJsonString(writer, item);
            }
            try writer.writeAll("]");
        }
        try writer.writeAll("],");
        try writeJsonString(writer, ev.content);
        try writer.writeAll("]");

        var msgbuf: [32]u8 = undefined;
        var sha256 = Sha256.init(.{});
        sha256.update(buf.items);
        sha256.final(&msgbuf);

        return try verify(
            bytes_pk,
            msgbuf,
            bytes_sig,
        );
    }

    fn make_filter(allocator: std.mem.Allocator, array: std.json.Array) !std.ArrayList(*Filter) {
        var filters = std.ArrayList(*Filter){};
        for (array.items[2..]) |elem| {
            if (elem != .object) continue;

            var filter = try allocator.create(Filter);
            filter.* = Filter.init(allocator);
            errdefer allocator.destroy(filter);

            for (elem.object.keys()) |key| {
                if (std.mem.eql(u8, key, "ids")) {
                    const ids = elem.object.get(key);
                    if (ids.? != .array) continue;
                    for (ids.?.array.items) |id| {
                        if (id != .string) continue;
                        try filter.ids.append(allocator, try allocator.dupe(u8, id.string));
                    }
                } else if (std.mem.eql(u8, key, "authors")) {
                    const authors = elem.object.get(key);
                    if (authors.? != .array) continue;
                    for (authors.?.array.items) |pubkey| {
                        if (pubkey != .string) continue;
                        try filter.authors.append(allocator, try allocator.dupe(u8, pubkey.string));
                    }
                } else if (std.mem.eql(u8, key, "tags")) {
                    const tags = elem.object.get(key);
                    if (tags.? != .array) continue;
                    for (tags.?.array.items) |tag| {
                        if (tag != .array) continue;
                        var newarr = std.ArrayList([]const u8){};
                        for (tag.array.items) |v| {
                            try newarr.append(allocator, try allocator.dupe(u8, v.string));
                        }
                        try filter.tags.append(allocator, newarr.items);
                    }
                } else if (std.mem.startsWith(u8, key, "#")) {
                    const tag = elem.object.get(key);
                    if (tag.? != .array) continue;
                    var newarr = std.ArrayList([]const u8){};
                    try newarr.append(allocator, try allocator.dupe(u8, key[1..]));
                    for (tag.?.array.items) |v| {
                        try newarr.append(allocator, try allocator.dupe(u8, v.string));
                    }
                    try filter.tags.append(allocator, newarr.items);
                } else if (std.mem.eql(u8, key, "kinds")) {
                    const kinds = elem.object.get(key);
                    if (kinds.? != .array) continue;
                    for (kinds.?.array.items) |kind| {
                        if (kind != .integer) continue;
                        try filter.kinds.append(allocator, kind.integer);
                    }
                } else if (std.mem.eql(u8, key, "since")) {
                    const since = elem.object.get(key);
                    if (since.? != .integer) continue;
                    filter.since = since.?.integer;
                } else if (std.mem.eql(u8, key, "until")) {
                    const until = elem.object.get(key);
                    if (until.? != .integer) continue;
                    filter.until = until.?.integer;
                } else if (std.mem.eql(u8, key, "search")) {
                    const search = elem.object.get(key);
                    if (search.? != .string) continue;
                    filter.search = try allocator.dupe(u8, search.?.string);
                } else if (std.mem.eql(u8, key, "limit")) {
                    const limit = elem.object.get(key);
                    if (limit.? != .integer) continue;
                    filter.limit = limit.?.integer;
                }
            }

            try filters.append(allocator, filter);
        }
        return filters;
    }

    pub fn handleEvent(self: *Handler, value: std.json.Value) !void {
        const parsedEvent = try std.json.parseFromValue(Event, self.context.allocator, value.array.items[1], .{});
        defer parsedEvent.deinit();
        const ev = parsedEvent.value;

        logger.info("[{s}] Received EVENT: id={s}, kind={d}, pubkey={s}", .{ self.client_ip, ev.id[0..16], ev.kind, ev.pubkey[0..16] });

        // NIP-22: reject events whose created_at is outside the accepted window
        if (!createdAtWithinLimits(ev.created_at, std.time.timestamp(), created_at_lower_limit, created_at_upper_limit)) {
            logger.warn("Event created_at out of range: {d}", .{ev.created_at});
            try self.sendOk(ev.id, false, "invalid: created_at is out of the acceptable range");
            return;
        }

        const verified = verify_event(self.context.allocator, ev) catch |err| {
            logger.warn("Event verification failed: {s}", .{@errorName(err)});
            return;
        };
        if (!verified) {
            logger.warn("Event has invalid signature", .{});
            return;
        }
        logger.debug("Event signature verified", .{});

        // NIP-70: protected events may only be published by their author over
        // a connection authenticated (NIP-42) as that author.
        const authed: ?[]const u8 = if (self.authed_pubkey) |*pk| pk[0..] else null;
        if (!protectedEventAllowed(ev, authed)) {
            logger.warn("[{s}] Protected event rejected: not authenticated as author", .{self.client_ip});
            try self.sendOk(ev.id, false, "auth-required: need to authenticate");
            return;
        }

        if (!validateDelegation(ev)) {
            logger.warn("Event has invalid delegation", .{});
            var ng_buf: std.ArrayList(u8) = .{};
            defer ng_buf.deinit(self.context.allocator);
            var ng_writer = ng_buf.writer(self.context.allocator);
            try ng_writer.writeAll("[\"OK\",\"");
            try ng_writer.writeAll(ev.id);
            try ng_writer.writeAll("\",false,\"invalid: delegation verification failed\"]");
            try self.conn.write(ng_buf.items);
            return;
        }

        if (ev.kind == 5) {
            for (ev.tags) |tag| {
                if (tag.len >= 2 and std.mem.eql(u8, tag[0], "e")) {
                    if (!try self.delete_record_by_id(tag[1..])) {
                        try self.conn.write("[\"NOTICE\", \"error: failed to delete record\"]");
                        return;
                    }
                }
            }
        } else if (20000 <= ev.kind and ev.kind < 30000) {
            // NIP-16: ephemeral events are broadcast to subscribers but never stored
        } else {
            if (ev.kind == 0 or ev.kind == 3 or (10000 <= ev.kind and ev.kind < 20000)) {
                if (!try self.delete_record_by_kind_and_pubkey(ev.kind, ev.pubkey)) {
                    try self.conn.write("[\"NOTICE\", \"error: failed to delete record\"]");
                    return;
                }
            } else if (30000 <= ev.kind and ev.kind < 40000) {
                for (ev.tags) |tag| {
                    if (tag.len >= 2 and std.mem.eql(u8, tag[0], "d")) {
                        if (!try self.delete_record_by_kind_and_pubkey_and_dtag(ev.kind, ev.pubkey, tag)) {
                            try self.conn.write("[\"NOTICE\", \"error: failed to delete record\"]");
                            return;
                        }
                    }
                }
            }

            const tagsj = try make_tagsj(self.context.allocator, ev);
            defer self.context.allocator.free(tagsj);
            {
                const db = try acquirePool(self.context.pool);
                defer self.context.pool.release(db);
                _ = db.exec(
                    \\insert into event (id, pubkey, created_at, kind, tags, content, sig) values ($1, $2, $3, $4, $5, $6, $7)
                , .{ ev.id, ev.pubkey, ev.created_at, ev.kind, @constCast(tagsj), ev.content, ev.sig }) catch |err| {
                    logger.warn("Error inserting event: {s}", .{@errorName(err)});
                };
            }
        }

        // Notify subscribers (copy list under mutex, then process outside)
        // Increment broadcast counter to prevent conn from being freed during broadcast
        _ = @atomicRmw(u32, &self.context.broadcast_count, .Add, 1, .acquire);
        defer _ = @atomicRmw(u32, &self.context.broadcast_count, .Sub, 1, .release);

        var subscribers_to_notify = std.ArrayList(Subscriber){};
        defer subscribers_to_notify.deinit(self.context.allocator);

        // NIP-40: events that are already expired are not broadcast
        if (!eventIsExpired(ev, std.time.timestamp())) {
            self.context.subscribers_mutex.lock();
            defer self.context.subscribers_mutex.unlock();

            logger.debug("Broadcasting event kind={d} to {d} subscribers", .{ ev.kind, self.context.subscribers.items.len });
            for (self.context.subscribers.items) |subscriber| {
                if (@atomicLoad(bool, &subscriber.conn._closed, .monotonic)) {
                    logger.debug("  Subscriber {s}: connection closed", .{subscriber.sub});
                    continue;
                }
                if (!eventMatched(ev, subscriber.filters)) {
                    logger.debug("  Subscriber {s}: event doesn't match filters", .{subscriber.sub});
                    continue;
                }
                logger.debug("  Subscriber {s}: event matches, queuing for notification", .{subscriber.sub});
                try subscribers_to_notify.append(self.context.allocator, subscriber);
            }
        }

        // Build event JSON and send to all matching subscribers
        const tags = try make_tagsj(self.context.allocator, ev);
        defer self.context.allocator.free(tags);

        var buf: std.ArrayList(u8) = .{};
        defer buf.deinit(self.context.allocator);

        // Now notify outside the mutex
        for (subscribers_to_notify.items) |subscriber| {
            // Double-check connection is still open (atomic read)
            if (@atomicLoad(bool, &subscriber.conn._closed, .monotonic)) {
                continue;
            }

            buf.clearRetainingCapacity();
            var ew = buf.writer(self.context.allocator);
            try ew.writeAll("[\"EVENT\",\"");
            try ew.writeAll(subscriber.sub);
            try ew.writeAll("\",{\"id\":\"");
            try ew.writeAll(ev.id);
            try ew.writeAll("\",\"kind\":");
            try ew.print("{d}", .{ev.kind});
            try ew.writeAll(",\"created_at\":");
            try ew.print("{d}", .{ev.created_at});
            try ew.writeAll(",\"pubkey\":\"");
            try ew.writeAll(ev.pubkey);
            try ew.writeAll("\",\"content\":");
            try writeJsonString(ew, ev.content);
            try ew.writeAll(",\"sig\":\"");
            try ew.writeAll(ev.sig);
            try ew.writeAll("\",\"tags\":");
            try ew.writeAll(tags);
            try ew.writeAll("}]");
            subscriber.conn.write(buf.items) catch |err| {
                logger.debug("Broadcast write error to subscriber {s}: {s}", .{ subscriber.sub, @errorName(err) });
                continue;
            };
        }

        buf.clearRetainingCapacity();
        var ok_writer = buf.writer(self.context.allocator);
        try ok_writer.writeAll("[\"OK\",\"");
        try ok_writer.writeAll(ev.id);
        try ok_writer.writeAll("\",true,\"\"]");
        try self.conn.write(buf.items);
    }

    pub fn handleReq(self: *Handler, value: std.json.Value) !void {
        if (value.array.items.len < 3) {
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        }
        const sub = value.array.items[1].string;

        var filters = try make_filter(self.context.allocator, value.array);
        logger.info("[{s}] Received REQ: subscription={s}, filters={d}", .{ self.client_ip, sub, filters.items.len });

        // NIP-42: kind-4 DMs and kind-1059 gift wraps are only served to
        // authenticated clients that are a party to the conversation.
        for (filters.items) |filter| {
            if (self.validateFilterAccess(filter)) |reason| {
                for (filters.items) |f| {
                    f.deinit();
                    self.context.allocator.destroy(f);
                }
                filters.deinit(self.context.allocator);

                var closed_buf: std.ArrayList(u8) = .{};
                defer closed_buf.deinit(self.context.allocator);
                var closed_writer = closed_buf.writer(self.context.allocator);
                try closed_writer.writeAll("[\"CLOSED\",\"");
                try closed_writer.writeAll(sub);
                try closed_writer.writeAll("\",\"");
                try closed_writer.writeAll(reason);
                try closed_writer.writeAll("\"]");
                try self.conn.write(closed_buf.items);
                return;
            }
        }

        const subscriber = try Subscriber.init(self.context.allocator, sub, self.conn, filters);

        // Add subscriber with mutex protection
        // Per NIP-01: if subscription_id already exists for this connection, replace it
        {
            self.context.subscribers_mutex.lock();
            defer self.context.subscribers_mutex.unlock();
            var replaced = false;
            for (self.context.subscribers.items, 0..) |*existing, i| {
                if (existing.conn == self.conn and std.mem.eql(u8, existing.sub, sub)) {
                    existing.deinit();
                    self.context.subscribers.items[i] = subscriber;
                    replaced = true;
                    logger.debug("Replaced existing subscriber, total subscribers: {d}", .{self.context.subscribers.items.len});
                    break;
                }
            }
            if (!replaced) {
                try self.context.subscribers.append(self.context.allocator, subscriber);
                logger.debug("Added subscriber, total subscribers: {d}", .{self.context.subscribers.items.len});
            }
        }

        const bindValue = union(enum) {
            number: i64,
            string: []const u8,
        };
        var params = std.ArrayList(bindValue){};
        defer params.deinit(self.context.allocator);

        var sqlbuf: std.ArrayList(u8) = .{};
        defer sqlbuf.deinit(self.context.allocator);
        const sql_writer = sqlbuf.writer(self.context.allocator);

        try sql_writer.writeAll("SELECT id, pubkey, created_at, kind, tags, content, sig FROM event");

        var has_where = false;
        var limit: i64 = 500;
        for (filters.items) |filter| {
            if (filter.ids.items.len > 0) {
                if (!has_where) {
                    try sql_writer.writeAll(" WHERE ");
                    has_where = true;
                } else {
                    try sql_writer.writeAll(" AND ");
                }
                try sql_writer.writeAll("id IN (");
                for (filter.ids.items, 0..) |id, i| {
                    if (i > 0) try sql_writer.writeAll(",");
                    try params.append(self.context.allocator, .{ .string = id });
                    try sql_writer.print("${}", .{params.items.len});
                }
                try sql_writer.writeAll(")");
            }
            if (filter.authors.items.len > 0) {
                if (!has_where) {
                    try sql_writer.writeAll(" WHERE ");
                    has_where = true;
                } else {
                    try sql_writer.writeAll(" AND ");
                }
                try sql_writer.writeAll("pubkey IN (");
                for (filter.authors.items, 0..) |pubkey, i| {
                    if (i > 0) try sql_writer.writeAll(",");
                    try params.append(self.context.allocator, .{ .string = pubkey });
                    try sql_writer.print("${}", .{params.items.len});
                }
                try sql_writer.writeAll(")");
            }
            if (filter.kinds.items.len > 0) {
                if (!has_where) {
                    try sql_writer.writeAll(" WHERE ");
                    has_where = true;
                } else {
                    try sql_writer.writeAll(" AND ");
                }
                try sql_writer.writeAll("kind IN (");
                for (filter.kinds.items, 0..) |kind, i| {
                    if (i > 0) try sql_writer.writeAll(",");
                    try params.append(self.context.allocator, .{ .number = kind });
                    try sql_writer.print("${}", .{params.items.len});
                }
                try sql_writer.writeAll(")");
            }
            if (filter.tags.items.len > 0) {
                if (!has_where) {
                    try sql_writer.writeAll(" WHERE ");
                    has_where = true;
                } else {
                    try sql_writer.writeAll(" AND ");
                }
                try sql_writer.writeAll("tagvalues && ARRAY[");
                for (filter.tags.items) |tag| {
                    for (tag, 0..) |v, i| {
                        if (i > 0) try sql_writer.writeAll(",");
                        try params.append(self.context.allocator, .{ .string = v });
                        try sql_writer.print("${}", .{params.items.len});
                    }
                }
                try sql_writer.writeAll("]");
            }
            if (filter.since > 0) {
                if (!has_where) {
                    try sql_writer.writeAll(" WHERE ");
                    has_where = true;
                } else {
                    try sql_writer.writeAll(" AND ");
                }
                try params.append(self.context.allocator, .{ .number = filter.since });
                try sql_writer.print("created_at >= ${}", .{params.items.len});
            }
            if (filter.until > 0) {
                if (!has_where) {
                    try sql_writer.writeAll(" WHERE ");
                    has_where = true;
                } else {
                    try sql_writer.writeAll(" AND ");
                }
                try params.append(self.context.allocator, .{ .number = filter.until });
                try sql_writer.print("created_at <= ${}", .{params.items.len});
            }
            if (filter.search.len > 0) {
                if (!has_where) {
                    try sql_writer.writeAll(" WHERE ");
                    has_where = true;
                } else {
                    try sql_writer.writeAll(" AND ");
                }
                try params.append(self.context.allocator, .{ .string = filter.search });
                try sql_writer.print("content LIKE ('%' || ${} || '%')", .{params.items.len});
            }

            if (filter.limit < limit) {
                limit = filter.limit;
            }
        }

        try sql_writer.print(" ORDER BY created_at DESC LIMIT {}", .{limit});

        // Collect all event messages in memory first, then release DB connection
        // before writing to the (potentially slow) client socket.
        var messages: std.ArrayList([]u8) = .{};
        defer {
            for (messages.items) |msg| self.context.allocator.free(msg);
            messages.deinit(self.context.allocator);
        }

        {
            const db = acquirePool(self.context.pool) catch |err| {
                const stats = self.context.pool.stats();
                logger.warn("REQ replay DB acquire failed for subscription={s}: {s} (size={d}, available={d}, missing={d}, in_use={d})", .{
                    sub,
                    @errorName(err),
                    stats.size,
                    stats.available,
                    stats.missing,
                    stats.in_use,
                });
                try self.conn.write("[\"NOTICE\", \"error: failed to load stored events\"]");
                return;
            };
            defer self.context.pool.release(db);

            var stmt = try pg.Stmt.init(db, .{});
            errdefer stmt.deinit();

            try stmt.prepare(sqlbuf.items, null);
            for (params.items) |param| {
                switch (param) {
                    .number => |number| try stmt.bind(number),
                    .string => |string| try stmt.bind(@constCast(string)),
                }
            }
            var res = try stmt.execute();
            defer res.deinit();

            const now = std.time.timestamp();
            while (try res.next()) |row| {
                if (row.values.len != 7) break;

                const id = try row.get([]u8, 0);
                const pubkey = try row.get([]u8, 1);
                const created_at = try row.get(i32, 2);
                const kind = try row.get(i32, 3);
                const tagsj = try row.get([]u8, 4);
                const content = try row.get([]u8, 5);
                const sig = try row.get([]u8, 6);

                // NIP-40: expired events are not served to clients
                if (tagsJsonExpired(self.context.allocator, tagsj, now)) continue;

                var buf: std.ArrayList(u8) = .{};
                errdefer buf.deinit(self.context.allocator);
                var event_writer = buf.writer(self.context.allocator);
                try event_writer.writeAll("[\"EVENT\",\"");
                try event_writer.writeAll(sub);
                try event_writer.writeAll("\",{\"id\":\"");
                try event_writer.writeAll(id);
                try event_writer.writeAll("\",\"kind\":");
                try event_writer.print("{d}", .{kind});
                try event_writer.writeAll(",\"created_at\":");
                try event_writer.print("{d}", .{created_at});
                try event_writer.writeAll(",\"pubkey\":\"");
                try event_writer.writeAll(pubkey);
                try event_writer.writeAll("\",\"content\":");
                try writeJsonString(event_writer, content);
                try event_writer.writeAll(",\"sig\":\"");
                try event_writer.writeAll(sig);
                try event_writer.writeAll("\",\"tags\":");
                try event_writer.writeAll(tagsj);
                try event_writer.writeAll("}]");
                try messages.append(self.context.allocator, try buf.toOwnedSlice(self.context.allocator));
            }
        }

        // DB connection released — now write to client
        for (messages.items) |msg| {
            try self.conn.write(msg);
        }

        var buf: std.ArrayList(u8) = .{};
        defer buf.deinit(self.context.allocator);
        var eose_writer = buf.writer(self.context.allocator);
        try eose_writer.writeAll("[\"EOSE\",\"");
        try eose_writer.writeAll(sub);
        try eose_writer.writeAll("\"]");
        try self.conn.write(buf.items);
    }

    pub fn handleCloseMsg(self: *Handler, value: std.json.Value) !void {
        if (value.array.items.len < 2) {
            try self.conn.write("[\"NOTICE\", \"error: invalid CLOSE message\"]");
            return;
        }

        const sub_id = value.array.items[1];
        if (sub_id != .string) {
            try self.conn.write("[\"NOTICE\", \"error: subscription ID must be a string\"]");
            return;
        }

        // Remove subscriber from context.subscribers (with mutex protection)
        self.context.subscribers_mutex.lock();
        defer self.context.subscribers_mutex.unlock();

        var i: usize = 0;
        while (i < self.context.subscribers.items.len) {
            if (std.mem.eql(u8, self.context.subscribers.items[i].sub, sub_id.string) and
                self.context.subscribers.items[i].conn == self.conn)
            {
                var sub = self.context.subscribers.orderedRemove(i);
                sub.deinit();
                return;
            }
            i += 1;
        }
    }

    pub fn clientMessage(self: *Handler, allocator: std.mem.Allocator, data: []const u8) !void {
        _ = allocator;

        // Validate data is not empty and not too large
        if (data.len == 0) {
            self.conn.write("[\"NOTICE\", \"error: empty message\"]") catch |err| {
                return err;
            };
            return;
        }

        // Limit message size to 256KB to avoid websocket frame size issues
        if (data.len > 256 * 1024) {
            try self.conn.write("[\"NOTICE\", \"error: message too large\"]");
            return;
        }

        // Validate JSON structure - must start with [ and end with ]
        if (data[0] != '[' or data[data.len - 1] != ']') {
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        }

        // Validate UTF-8
        if (!std.unicode.utf8ValidateSlice(data)) {
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        }

        // Parse with arena allocator to isolate potential issues
        var arena = std.heap.ArenaAllocator.init(self.context.allocator);
        defer arena.deinit();

        // NOTE: no manual bracket-balance scan here. A naive byte-level count
        // of [ { ] } does not skip JSON string contents, so any event whose
        // content/tags carry unbalanced brackets in a string (e.g. a blurhash
        // like "UJEo[Ht8...NM{00M{...") would be wrongly rejected as "invalid
        // request". std.json.parseFromSlice below already validates structure.
        const parsed = std.json.parseFromSlice(std.json.Value, arena.allocator(), data, .{
            .allocate = .alloc_always,
            .max_value_len = 1024 * 1024, // 1MB max
        }) catch {
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        };

        // Ensure the parsed value is an array
        if (parsed.value != .array) {
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        }

        if (parsed.value.array.items.len < 2) {
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        }
        if (parsed.value.array.items[0] != .string) {
            try self.conn.write("[\"NOTICE\", \"error: invalid message type\"]");
            return;
        }

        const msg_type = parsed.value.array.items[0].string;
        if (std.mem.eql(u8, msg_type, "EVENT")) {
            try self.handleEvent(parsed.value);
        } else if (std.mem.eql(u8, msg_type, "REQ")) {
            try self.handleReq(parsed.value);
        } else if (std.mem.eql(u8, msg_type, "CLOSE")) {
            try self.handleCloseMsg(parsed.value);
        } else if (std.mem.eql(u8, msg_type, "AUTH")) {
            try self.handleAuth(parsed.value);
        }
    }

    pub fn close(self: *Handler) void {
        // Remove all subscriptions for this connection (with mutex protection)
        self.context.subscribers_mutex.lock();
        defer self.context.subscribers_mutex.unlock();

        var i: usize = 0;
        while (i < self.context.subscribers.items.len) {
            if (self.context.subscribers.items[i].conn == self.conn) {
                var sub = self.context.subscribers.orderedRemove(i);
                sub.deinit();
                // Don't increment i because we removed an item
            } else {
                i += 1;
            }
        }
        logger.debug("Connection closed, cleaned up subscriptions", .{});
    }
};

// Test-only BIP-340 signer (deterministic nonce per the BIP, with an
// all-zero aux) used to produce delegation signatures for the tests below.
fn testSchnorrSign(secret: [32]u8, msg: [32]u8) ![64]u8 {
    var d = try Scalar.fromBytes(secret, .big);
    const P = try Secp256k1.basePoint.mul(d.toBytes(.big), .big);
    if (P.affineCoordinates().y.isOdd()) {
        d = d.neg();
    }
    const px = P.affineCoordinates().x.toBytes(.big);

    const aux = [_]u8{0} ** 32;
    const aux_hash = taggedHash("BIP0340/aux", &aux);
    var t = d.toBytes(.big);
    for (&t, aux_hash) |*b, a| b.* ^= a;

    var nonce_input: [96]u8 = undefined;
    @memcpy(nonce_input[0..32], &t);
    @memcpy(nonce_input[32..64], &px);
    @memcpy(nonce_input[64..96], &msg);
    var k_wide = [_]u8{0} ** 64;
    const nonce_hash = taggedHash("BIP0340/nonce", &nonce_input);
    @memcpy(k_wide[32..64], &nonce_hash);
    var k = Scalar.fromBytes64(k_wide, .big);
    if (k.isZero()) return error.IdentityElement;

    const R = try Secp256k1.basePoint.mul(k.toBytes(.big), .big);
    if (R.affineCoordinates().y.isOdd()) {
        k = k.neg();
    }
    const rx = R.affineCoordinates().x.toBytes(.big);

    var challenge_input: [96]u8 = undefined;
    @memcpy(challenge_input[0..32], &rx);
    @memcpy(challenge_input[32..64], &px);
    @memcpy(challenge_input[64..96], &msg);
    var e_wide = [_]u8{0} ** 64;
    const challenge_hash = taggedHash("BIP0340/challenge", &challenge_input);
    @memcpy(e_wide[32..64], &challenge_hash);
    const e = Scalar.fromBytes64(e_wide, .big);

    var sig: [64]u8 = undefined;
    @memcpy(sig[0..32], &rx);
    @memcpy(sig[32..64], &k.add(e.mul(d)).toBytes(.big));
    return sig;
}

fn testXOnlyPubkey(secret: [32]u8) ![64]u8 {
    const P = try Secp256k1.basePoint.mul(secret, .big);
    return std.fmt.bytesToHex(P.affineCoordinates().x.toBytes(.big), .lower);
}

test "validateDelegation accepts events without a delegation tag" {
    var pubkey = [_]u8{'0'} ** 64;
    var no_tags = [_][][]u8{};
    const ev = Event{
        .id = @constCast(""),
        .kind = 1,
        .created_at = 100,
        .pubkey = &pubkey,
        .content = @constCast(""),
        .sig = @constCast(""),
        .tags = &no_tags,
    };
    try std.testing.expect(validateDelegation(ev));
}

test "validateDelegation accepts valid delegation and rejects forged signature" {
    const delegatee_secret = [_]u8{0x11} ** 32;
    const delegator_secret = [_]u8{0x22} ** 32;

    var delegatee_pubkey = try testXOnlyPubkey(delegatee_secret);
    var delegator_pubkey = try testXOnlyPubkey(delegator_secret);
    const conditions = "kind=1&created_at>1&created_at<4102444800";

    // Sign sha256("nostr:delegation:<delegatee>:<conditions>") with the delegator key
    var msgbuf: [32]u8 = undefined;
    var sha256 = Sha256.init(.{});
    sha256.update("nostr:delegation:");
    sha256.update(&delegatee_pubkey);
    sha256.update(":");
    sha256.update(conditions);
    sha256.final(&msgbuf);
    var signature = std.fmt.bytesToHex(try testSchnorrSign(delegator_secret, msgbuf), .lower);

    var tag = [_][]u8{ @constCast("delegation"), &delegator_pubkey, @constCast(conditions), &signature };
    var tags = [_][][]u8{&tag};
    var ev = Event{
        .id = @constCast(""),
        .kind = 1,
        .created_at = 100,
        .pubkey = &delegatee_pubkey,
        .content = @constCast(""),
        .sig = @constCast(""),
        .tags = &tags,
    };
    try std.testing.expect(validateDelegation(ev));

    // Event kind not covered by the delegated conditions
    ev.kind = 2;
    try std.testing.expect(!validateDelegation(ev));
    ev.kind = 1;

    // Event timestamp outside the delegated window
    ev.created_at = 1;
    try std.testing.expect(!validateDelegation(ev));
    ev.created_at = 100;

    // Forged signature
    var forged = [_]u8{'3'} ** 128;
    tag[3] = &forged;
    try std.testing.expect(!validateDelegation(ev));
}

test "createdAtWithinLimits enforces the accepted window" {
    const now: i64 = 1700000000;

    // limits disabled
    try std.testing.expect(createdAtWithinLimits(now - 100000, now, 0, 0));
    try std.testing.expect(createdAtWithinLimits(now + 100000, now, 0, 0));

    // upper boundary
    try std.testing.expect(createdAtWithinLimits(now + 900, now, 0, 900));
    try std.testing.expect(!createdAtWithinLimits(now + 901, now, 0, 900));

    // lower boundary
    try std.testing.expect(createdAtWithinLimits(now - 3600, now, 3600, 900));
    try std.testing.expect(!createdAtWithinLimits(now - 3601, now, 3600, 900));
}

fn testEventWithTags(tags: [][][]u8) Event {
    var pubkey = [_]u8{'0'} ** 64;
    return Event{
        .id = @constCast(""),
        .kind = 1,
        .created_at = 100,
        .pubkey = &pubkey,
        .content = @constCast(""),
        .sig = @constCast(""),
        .tags = tags,
    };
}

test "eventIsExpired honors the expiration tag" {
    var no_tags = [_][][]u8{};
    try std.testing.expect(!eventIsExpired(testEventWithTags(&no_tags), 1700000000));

    var expired_tag = [_][]u8{ @constCast("expiration"), @constCast("1600000000") };
    var expired_tags = [_][][]u8{&expired_tag};
    try std.testing.expect(eventIsExpired(testEventWithTags(&expired_tags), 1700000000));
    // boundary: expired exactly at the expiration timestamp
    try std.testing.expect(eventIsExpired(testEventWithTags(&expired_tags), 1600000000));
    // not yet expired
    try std.testing.expect(!eventIsExpired(testEventWithTags(&expired_tags), 1599999999));

    // malformed timestamps are ignored
    var bogus_tag = [_][]u8{ @constCast("expiration"), @constCast("not-a-number") };
    var bogus_tags = [_][][]u8{&bogus_tag};
    try std.testing.expect(!eventIsExpired(testEventWithTags(&bogus_tags), 1700000000));
}

test "tagsJsonExpired parses the stored tags column" {
    const allocator = std.testing.allocator;
    try std.testing.expect(!tagsJsonExpired(allocator, "[]", 1700000000));
    try std.testing.expect(!tagsJsonExpired(allocator, "[[\"e\",\"abc\"]]", 1700000000));
    try std.testing.expect(tagsJsonExpired(allocator, "[[\"expiration\",\"1600000000\"]]", 1700000000));
    try std.testing.expect(!tagsJsonExpired(allocator, "[[\"expiration\",\"1800000000\"]]", 1700000000));
    // malformed JSON or timestamps never match
    try std.testing.expect(!tagsJsonExpired(allocator, "[[\"expiration\",\"oops\"]]", 1700000000));
    try std.testing.expect(!tagsJsonExpired(allocator, "[[\"expiration\"", 1700000000));
}

test "eventIsProtected detects the \"-\" tag" {
    var no_tags = [_][][]u8{};
    try std.testing.expect(!eventIsProtected(testEventWithTags(&no_tags)));

    var protected_tag = [_][]u8{@constCast("-")};
    var protected_tags = [_][][]u8{&protected_tag};
    try std.testing.expect(eventIsProtected(testEventWithTags(&protected_tags)));

    // other tags do not mark an event as protected
    var e_tag = [_][]u8{ @constCast("e"), @constCast("abc") };
    var other_tags = [_][][]u8{&e_tag};
    try std.testing.expect(!eventIsProtected(testEventWithTags(&other_tags)));

    // the "-" tag counts even when mixed with other tags
    var mixed_tags = [_][][]u8{ &e_tag, &protected_tag };
    try std.testing.expect(eventIsProtected(testEventWithTags(&mixed_tags)));
}

test "protectedEventAllowed requires auth as the event author" {
    var protected_tag = [_][]u8{@constCast("-")};
    var protected_tags = [_][][]u8{&protected_tag};
    var pubkey = [_]u8{'0'} ** 64;
    var ev = testEventWithTags(&protected_tags);
    ev.pubkey = &pubkey;

    // unauthenticated connections cannot publish protected events
    try std.testing.expect(!protectedEventAllowed(ev, null));
    // authenticated as a different pubkey
    const other = [_]u8{'1'} ** 64;
    try std.testing.expect(!protectedEventAllowed(ev, &other));
    // authenticated as the author
    const author = [_]u8{'0'} ** 64;
    try std.testing.expect(protectedEventAllowed(ev, &author));

    // unprotected events pass regardless of auth state
    var no_tags = [_][][]u8{};
    try std.testing.expect(protectedEventAllowed(testEventWithTags(&no_tags), null));
    try std.testing.expect(protectedEventAllowed(testEventWithTags(&no_tags), &other));
}

test "authChallengeAndRelayMatch requires both matching tags" {
    var challenge_tag = [_][]u8{ @constCast("challenge"), @constCast("deadbeefdeadbeef") };
    var relay_tag = [_][]u8{ @constCast("relay"), @constCast("wss://example.com/") };
    var tags = [_][][]u8{ &challenge_tag, &relay_tag };
    var ev = testEventWithTags(&tags);
    ev.kind = 22242;

    try std.testing.expect(authChallengeAndRelayMatch(ev, "deadbeefdeadbeef", "wss://example.com"));
    // trailing slashes on either side are ignored
    try std.testing.expect(authChallengeAndRelayMatch(ev, "deadbeefdeadbeef", "wss://example.com/"));
    // wrong challenge
    try std.testing.expect(!authChallengeAndRelayMatch(ev, "0000000000000000", "wss://example.com"));
    // wrong relay URL
    try std.testing.expect(!authChallengeAndRelayMatch(ev, "deadbeefdeadbeef", "wss://other.example.com"));
    // a second relay tag must not stand in for a matching challenge
    var relay_tag2 = [_][]u8{ @constCast("relay"), @constCast("wss://example.com") };
    var two_relays = [_][][]u8{ &relay_tag, &relay_tag2 };
    ev.tags = &two_relays;
    try std.testing.expect(!authChallengeAndRelayMatch(ev, "deadbeefdeadbeef", "wss://example.com"));
}

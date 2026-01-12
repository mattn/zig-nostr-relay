const std = @import("std");
const websocket = @import("websocket");
const Conn = websocket.Conn;
const Message = websocket.Message;
const Handshake = websocket.Handshake;

const Secp256k1 = std.crypto.ecc.Secp256k1;
const Scalar = Secp256k1.scalar.Scalar;
const Sha256 = std.crypto.hash.sha2.Sha256;

const pg = @import("pg");
const struct_env = @import("struct-env");

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
    kinds: std.ArrayList(i32) = undefined,
    tags: std.ArrayList([][]const u8) = undefined,
    since: i32 = 0,
    until: i32 = 0,
    limit: i32 = 0,
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
            .ids = .{ .items = &.{}, .capacity = 0 },
            .authors = .{ .items = &.{}, .capacity = 0 },
            .tags = .{ .items = &.{}, .capacity = 0 },
            .kinds = .{ .items = &.{}, .capacity = 0 },
            .search = "",
            .since = 0,
            .until = 0,
            .limit = 500,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.ids.deinit(self.allocator);
        self.authors.deinit(self.allocator);
        self.kinds.deinit(self.allocator);
        self.tags.deinit(self.allocator);
        if (self.search.len > 0) self.allocator.free(self.search);
    }
};

const Subscriber = struct {
    sub: []const u8,
    conn: *Conn,
    filters: std.ArrayList(Filter),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, sub: []const u8, conn: *Conn, filters: std.ArrayList(Filter)) !Self {
        return .{
            .sub = try allocator.dupe(u8, sub),
            .conn = conn,
            .filters = filters,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.filters.items) |*filter| {
            filter.deinit();
        }
        self.filters.deinit(self.allocator);
        if (self.sub.len > 0) self.allocator.free(self.sub);
    }
};

const Context = struct {
    allocator: std.mem.Allocator,
    subscribers: std.ArrayList(Subscriber),
    pool: *pg.Pool,
};

const Config = struct {
    database_url: []const u8 = "",
    relay_addr: []const u8 = "0.0.0.0",
    relay_port: u16 = 7447,
    relay_name: []const u8 = "zig-nostr-relay",
    relay_description: []const u8 = "A high-performance Nostr relay written in Zig",
    relay_pubkey: []const u8 = "",
    relay_contact: []const u8 = "",
};

var shutdown_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn signalHandler(_: i32) callconv(.c) void {
    shutdown_flag.store(true, .release);
}

fn serveStaticFile(allocator: std.mem.Allocator, socket: std.posix.socket_t, path: []const u8) !void {
    const file = std.fs.cwd().openFile(path, .{}) catch {
        const not_found = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
        _ = std.posix.write(socket, not_found) catch {};
        return;
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(content);

    const content_type = if (std.mem.endsWith(u8, path, ".html"))
        "text/html; charset=utf-8"
    else if (std.mem.endsWith(u8, path, ".png"))
        "image/png"
    else if (std.mem.endsWith(u8, path, ".svg"))
        "image/svg+xml"
    else if (std.mem.endsWith(u8, path, ".css"))
        "text/css"
    else if (std.mem.endsWith(u8, path, ".js"))
        "application/javascript"
    else
        "application/octet-stream";

    var response: std.ArrayList(u8) = .{};
    defer response.deinit(allocator);
    var writer = response.writer(allocator);

    try writer.print("HTTP/1.1 200 OK\r\n", .{});
    try writer.print("Connection: close\r\n", .{});
    try writer.print("Content-Type: {s}\r\n", .{content_type});
    try writer.print("Content-Length: {}\r\n\r\n", .{content.len});
    try writer.writeAll(content);

    _ = std.posix.write(socket, response.items) catch {};
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

fn handleHTTPRequest(allocator: std.mem.Allocator, socket: std.posix.socket_t, request: []const u8) !void {
    // Check Accept header
    var is_json = false;
    if (std.mem.containsAtLeast(u8, request, 1, "Accept: application/nostr+json") or
        std.mem.containsAtLeast(u8, request, 1, "accept: application/nostr+json"))
    {
        is_json = true;
    }

    if (is_json) {
        // NIP-11 JSON
        var response: std.ArrayList(u8) = .{};
        defer response.deinit(allocator);
        var writer = response.writer(allocator);

        var json: std.ArrayList(u8) = .{};
        defer json.deinit(allocator);
        var j = json.writer(allocator);

        try j.print("{{", .{});
        try j.print("\"name\":\"zig-nostr-relay\"", .{});
        try j.print(",\"description\":\"A high-performance Nostr relay written in Zig\"", .{});
        try j.print(",\"supported_nips\":[1,2,4,9,11,20,22,33,40,42]", .{});
        try j.print(",\"software\":\"https://github.com/mattn/zig-nostr-relay\"", .{});
        try j.print(",\"version\":\"0.1.0\"", .{});
        try j.print(",\"limitation\":{{", .{});
        try j.print("\"max_message_length\":262144", .{});
        try j.print(",\"max_subscriptions\":20", .{});
        try j.print(",\"max_subid_length\":256", .{});
        try j.print(",\"max_limit\":1000", .{});
        try j.print(",\"max_event_tags\":2000", .{});
        try j.print(",\"max_content_length\":140000", .{});
        try j.print(",\"min_pow_difficulty\":0", .{});
        try j.print(",\"auth_required\":false", .{});
        try j.print(",\"payment_required\":false", .{});
        try j.print(",\"restricted_writes\":false", .{});
        try j.print("}}", .{});
        try j.print("}}", .{});

        try writer.print("HTTP/1.1 200 OK\r\n", .{});
        try writer.print("Connection: close\r\n", .{});
        try writer.print("Access-Control-Allow-Origin: *\r\n", .{});
        try writer.print("Content-Type: application/nostr+json\r\n", .{});
        try writer.print("Content-Length: {}\r\n\r\n", .{json.items.len});
        try writer.writeAll(json.items);

        _ = std.posix.write(socket, response.items) catch {};
    } else {
        // Parse request path
        var lines = std.mem.splitScalar(u8, request, '\n');
        const first_line = lines.first();
        var parts = std.mem.splitScalar(u8, first_line, ' ');
        _ = parts.next(); // GET
        const path = parts.next() orelse "/";

        if (std.mem.eql(u8, path, "/")) {
            try serveStaticFile(allocator, socket, "public/index.html");
        } else if (std.mem.startsWith(u8, path, "/")) {
            const file_path = try std.fmt.allocPrint(allocator, "public{s}", .{path});
            defer allocator.free(file_path);
            try serveStaticFile(allocator, socket, file_path);
        }
    }
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Setup signal handlers
    var sa: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
    sa.handler = .{ .handler = signalHandler };
    _ = std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    _ = std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    const env = try struct_env.fromEnv(allocator, Config);
    defer struct_env.free(allocator, env);

    std.debug.print("Initializing PostgreSQL pool with: {s}\n", .{env.database_url});
    var pool = pg.Pool.initUri(allocator, try std.Uri.parse(env.database_url), .{
        .size = 5,
    }) catch |err| {
        std.debug.print("Failed to initialize pool: {s}\n", .{@errorName(err)});
        return;
    };
    defer pool.deinit();
    std.debug.print("Pool initialized\n", .{});

    const context = Context{
        .allocator = allocator,
        .subscribers = std.ArrayList(Subscriber){},
        .pool = pool,
    };
    _ = context;

    // TCPサーバーを起動
    const server_address = try std.net.Address.parseIp(env.relay_addr, env.relay_port);
    const server_socket = try std.posix.socket(server_address.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, 0);
    defer std.posix.close(server_socket);

    try std.posix.setsockopt(server_socket, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, &std.mem.toBytes(@as(c_int, 1)));

    // Set socket timeout to allow signal handling
    const one_sec: c_long = 1;
    const zero_usec: c_long = 0;
    var timeout: std.posix.timeval = .{ .sec = one_sec, .usec = zero_usec };
    try std.posix.setsockopt(server_socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

    const socklen = server_address.getOsSockLen();
    try std.posix.bind(server_socket, &server_address.any, socklen);
    try std.posix.listen(server_socket, 128);

    std.debug.print("Starting Nostr relay on {s}:{}\n", .{ env.relay_addr, env.relay_port });
    std.debug.print("Server initialized, listening...\n", .{});

    while (!shutdown_flag.load(.acquire)) {
        var client_addr: std.net.Address = undefined;
        var client_addr_len: std.posix.socklen_t = @sizeOf(std.net.Address);
        const client_socket = std.posix.accept(server_socket, &client_addr.any, &client_addr_len, 0) catch |err| {
            // EAGAIN/EWOULDBLOCK is expected due to timeout
            if (err == error.WouldBlock) {
                continue;
            }
            std.debug.print("Failed to accept connection: {}\n", .{err});
            continue;
        };
        defer std.posix.close(client_socket);

        var buffer: [4096]u8 = undefined;
        const bytes_read = std.posix.read(client_socket, &buffer) catch |err| {
            std.debug.print("Failed to read from socket: {}\n", .{err});
            continue;
        };

        if (bytes_read == 0) continue;

        const request = buffer[0..bytes_read];

        if (std.mem.startsWith(u8, request, "GET")) {
            if (std.mem.containsAtLeast(u8, request, 1, "Upgrade: websocket") or
                std.mem.containsAtLeast(u8, request, 1, "Sec-WebSocket-Key"))
            {
                continue;
            }
            try handleHTTPRequest(allocator, client_socket, request);
        }
    }

    std.debug.print("\nShutdown signal received, exiting...\n", .{});
}

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
const relay = @import("relay.zig");

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
        try j.print(",\"logo\":\"https://zig-nostr-relay.compile-error.net/logo.png\"", .{});
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
            // Prevent directory traversal
            if (std.mem.containsAtLeast(u8, path, 1, "..")) {
                const not_found = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n";
                _ = std.posix.write(socket, not_found) catch {};
                return;
            }
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

    // Initialize database schema
    std.debug.print("Initializing database schema...\n", .{});
    try relay.initDatabase(pool);
    std.debug.print("Database initialized\n", .{});

    // Create relay context
    var context = relay.Context{
        .allocator = allocator,
        .subscribers = std.ArrayList(relay.Subscriber){},
        .pool = pool,
    };

    std.debug.print("Starting Nostr relay on {s}:{}\n", .{ env.relay_addr, env.relay_port });

    // Start WebSocket server
    var server = try websocket.Server(relay.Handler).init(allocator, .{
        .address = env.relay_addr,
        .port = env.relay_port,
    });
    defer server.deinit();

    try server.listen(&context);
}

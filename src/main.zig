const std = @import("std");
const websocket = @import("websocket");
const Conn = websocket.Conn;
const Message = websocket.Message;
const Handshake = websocket.Handshake;

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
var relay_context: *relay.Context = undefined;

fn signalHandler(_: i32) callconv(.c) void {
    shutdown_flag.store(true, .release);
}

// Custom connection handler that routes to WebSocket or HTTP
fn handleConnection(stream: std.net.Stream, allocator: std.mem.Allocator) void {
    defer stream.close();

    // Peek at the request to determine if it's WebSocket or HTTP (without consuming)
    var buf: [4096]u8 = undefined;
    const bytes_read = std.posix.recv(stream.handle, &buf, std.posix.MSG.PEEK) catch return;
    if (bytes_read == 0) return;

    const request_peek = buf[0..bytes_read];

    // Check if it's a WebSocket upgrade request
    const is_websocket = std.mem.indexOf(u8, request_peek, "Upgrade: websocket") != null or
        std.mem.indexOf(u8, request_peek, "upgrade: websocket") != null;

    if (is_websocket) {
        handleWebSocketUpgrade(stream, allocator) catch |err| {
            std.debug.print("WebSocket error: {}\n", .{err});
        };
    } else {
        // For HTTP, we need to actually read the data
        const bytes_read_actual = stream.read(&buf) catch return;
        if (bytes_read_actual == 0) return;
        const request = buf[0..bytes_read_actual];
        
        handleHttpRequest(stream, request, allocator) catch |err| {
            std.debug.print("HTTP error: {}\n", .{err});
        };
    }
}

fn handleWebSocketUpgrade(stream: std.net.Stream, allocator: std.mem.Allocator) !void {
    // Read the WebSocket upgrade request
    var buf: [4096]u8 = undefined;
    const bytes_read = try stream.read(&buf);
    if (bytes_read == 0) return error.EndOfStream;
    const request = buf[0..bytes_read];

    // Extract Sec-WebSocket-Key (case insensitive)
    const lower_request = try allocator.alloc(u8, request.len);
    defer allocator.free(lower_request);

    for (request, 0..) |c, i| {
        lower_request[i] = std.ascii.toLower(c);
    }

    const key_header = "sec-websocket-key:";
    const key_start_lower = std.mem.indexOf(u8, lower_request, key_header) orelse return error.NoWebSocketKey;

    const key_line_start = key_start_lower + key_header.len;
    const key_line_end = std.mem.indexOfPos(u8, request, key_line_start, "\r\n") orelse
        std.mem.indexOfPos(u8, request, key_line_start, "\n") orelse return error.InvalidKey;

    const key = std.mem.trim(u8, request[key_line_start..key_line_end], &std.ascii.whitespace);

    // Create handshake response
    var reply_buf: [2048]u8 = undefined;
    const handshake_reply = try Handshake.createReply(key, null, false, &reply_buf);

    // Write handshake response (handle partial writes)
    var written: usize = 0;
    while (written < handshake_reply.len) {
        const n = try stream.write(handshake_reply[written..]);
        if (n == 0) return error.EndOfStream;
        written += n;
    }

    // Create a Conn wrapper for the stream (allocate on heap for thread safety)
    var conn = try allocator.create(Conn);
    defer allocator.destroy(conn);
    
    conn.* = Conn{
        ._closed = false,
        .started = @intCast(std.time.timestamp()),
        .stream = stream,
        .address = std.net.Address.initIp4([_]u8{ 127, 0, 0, 1 }, 7447),
        .lock = std.Thread.Mutex{},
        .compression = null,
    };

    // Create Handler
    const handler = relay.Handler{
        .conn = conn,
        .context = relay_context,
    };

    // Handle WebSocket messages
    const buffer_provider = try websocket.bufferProvider(allocator, .{});
    const reader_buf = try allocator.alloc(u8, 4096);
    defer allocator.free(reader_buf);

    var reader = websocket.proto.Reader.init(reader_buf, @constCast(&buffer_provider), null);

    while (true) {
        reader.fill(stream) catch |err| {
            // Connection closed or error, exit gracefully
            if (err == error.EndOfStream) break;
            std.debug.print("WebSocket fill error: {}\n", .{err});
            break;
        };

        const read_result = reader.read() catch |err| {
            // Connection closed or error, exit gracefully
            if (err == error.EndOfStream) break;
            std.debug.print("WebSocket read error: {}\n", .{err});
            break;
        };
        if (read_result == null) break;

        const has_more = read_result.?[0];
        const message = read_result.?[1];
        defer reader.done(message.type);

        switch (message.type) {
            .text, .binary => {
                if (message.data.len > 0) {
                    @constCast(&handler).clientMessage(allocator, message.data) catch |err| {
                        // If connection is broken, exit gracefully
                        if (err == error.EndOfStream or err == error.ConnectionResetByPeer or err == error.BrokenPipe) break;
                        std.debug.print("Handler error: {}\n", .{err});
                        break;
                    };
                }
            },
            .close => break,
            .ping => {
                conn.writePong(message.data) catch |err| {
                    if (err == error.EndOfStream or err == error.ConnectionResetByPeer or err == error.BrokenPipe) break;
                    break;
                };
            },
            .pong => {},
        }

        if (!has_more) break;
    }

    @constCast(&handler).close();
}

fn handleHttpRequest(stream: std.net.Stream, request: []const u8, allocator: std.mem.Allocator) !void {
    // Parse request line
    var lines = std.mem.splitScalar(u8, request, '\n');
    const request_line = lines.next() orelse return error.InvalidRequest;

    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.InvalidRequest;
    const url = parts.next() orelse return error.InvalidRequest;

    // Handle OPTIONS (CORS preflight)
    if (std.mem.eql(u8, method, "OPTIONS")) {
        const response = "HTTP/1.1 204 No Content\r\n" ++
            "Access-Control-Allow-Origin: *\r\n" ++
            "Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n" ++
            "Access-Control-Allow-Headers: Accept, Content-Type, Authorization\r\n" ++
            "\r\n";
        try stream.writeAll(response);
        return;
    }

    // Handle HEAD (same as GET but without body)
    if (std.mem.eql(u8, method, "HEAD")) {
        // Check for NIP-11 request
        if (std.mem.indexOf(u8, request, "application/nostr+json") != null) {
            const json_len = 438; // Precomputed NIP-11 response length
            var response_buf: [512]u8 = undefined;
            const response = try std.fmt.bufPrint(&response_buf, "HTTP/1.1 200 OK\r\n" ++
                "Content-Type: application/nostr+json\r\n" ++
                "Access-Control-Allow-Origin: *\r\n" ++
                "Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n" ++
                "Access-Control-Allow-Headers: Accept, Content-Type, Authorization\r\n" ++
                "Content-Length: {d}\r\n" ++
                "\r\n", .{json_len});
            try stream.writeAll(response);
            return;
        }
        // For files, return headers only
        return serveStaticFileHead(url, stream, allocator);
    }

    if (!std.mem.eql(u8, method, "GET")) {
        const response = "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n";
        try stream.writeAll(response);
        return;
    }

    // Check for NIP-11 request
    if (std.mem.indexOf(u8, request, "application/nostr+json") != null) {
        return serveNip11(stream);
    }

    // Serve static files
    return serveStaticFile(url, stream, allocator);
}

fn serveNip11(stream: std.net.Stream) !void {
    const json =
        \\{"name":"zig-nostr-relay","description":"A high-performance Nostr relay written in Zig","pubkey":"","contact":"","supported_nips":[1,2,4,9,11,20,22,33,40,42],"software":"https://github.com/mattn/zig-nostr-relay","version":"0.1.0","limitation":{"max_message_length":262144,"max_subscriptions":20,"max_subid_length":256,"max_limit":1000,"max_event_tags":2000,"max_content_length":140000,"min_pow_difficulty":0,"auth_required":false,"payment_required":false,"restricted_writes":false}}
    ;

    var response_buf: [2048]u8 = undefined;
    const response = try std.fmt.bufPrint(&response_buf, "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: application/nostr+json\r\n" ++
        "Access-Control-Allow-Origin: *\r\n" ++
        "Access-Control-Allow-Methods: GET, HEAD, OPTIONS\r\n" ++
        "Access-Control-Allow-Headers: Accept, Content-Type, Authorization\r\n" ++
        "Content-Length: {d}\r\n" ++
        "\r\n" ++
        "{s}", .{ json.len, json });

    try stream.writeAll(response);
}

fn serveStaticFile(url: []const u8, stream: std.net.Stream, allocator: std.mem.Allocator) !void {
    var path_buf: [1024]u8 = undefined;

    // Normalize and validate path
    const path = blk: {
        if (std.mem.eql(u8, url, "/")) {
            break :blk "public/index.html";
        }

        // Remove leading slash and trim
        const sanitized = std.mem.trim(u8, url, "/");

        // Check for directory traversal attempts
        if (std.mem.indexOf(u8, sanitized, "..") != null) {
            return error.InvalidPath;
        }

        // Check for absolute paths
        if (sanitized.len > 0 and sanitized[0] == '/') {
            return error.InvalidPath;
        }

        // Additional security: only allow alphanumeric, dash, underscore, dot, and slash
        for (sanitized) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.' and c != '/') {
                return error.InvalidPath;
            }
        }

        const p = try std.fmt.bufPrint(&path_buf, "public/{s}", .{sanitized});

        // Ensure the resolved path is still within public/
        const abs_path = std.fs.cwd().realpathAlloc(allocator, p) catch |err| {
            if (err == error.FileNotFound) {
                const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                try stream.writeAll(not_found);
                return error.FileNotFound;
            }
            return error.InvalidPath;
        };
        defer allocator.free(abs_path);

        const abs_public = std.fs.cwd().realpathAlloc(allocator, "public") catch {
            return error.InvalidPath;
        };
        defer allocator.free(abs_public);

        if (!std.mem.startsWith(u8, abs_path, abs_public)) {
            return error.InvalidPath;
        }

        break :blk p;
    };

    const file = std.fs.cwd().openFile(path, .{}) catch {
        const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        try stream.writeAll(not_found);
        return error.FileNotFound;
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(content);

    const content_type = blk: {
        if (std.mem.endsWith(u8, path, ".html")) break :blk "text/html; charset=utf-8";
        if (std.mem.endsWith(u8, path, ".js")) break :blk "application/javascript; charset=utf-8";
        if (std.mem.endsWith(u8, path, ".css")) break :blk "text/css; charset=utf-8";
        if (std.mem.endsWith(u8, path, ".png")) break :blk "image/png";
        if (std.mem.endsWith(u8, path, ".jpg") or std.mem.endsWith(u8, path, ".jpeg")) break :blk "image/jpeg";
        if (std.mem.endsWith(u8, path, ".svg")) break :blk "image/svg+xml";
        if (std.mem.endsWith(u8, path, ".json")) break :blk "application/json; charset=utf-8";
        break :blk "application/octet-stream";
    };

    var response_buf: [1024]u8 = undefined;
    const header = try std.fmt.bufPrint(&response_buf, "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: {s}\r\n" ++
        "Content-Length: {d}\r\n" ++
        "Cache-Control: public, max-age=3600\r\n" ++
        "Access-Control-Allow-Origin: *\r\n" ++
        "\r\n", .{ content_type, content.len });

    try stream.writeAll(header);
    try stream.writeAll(content);
}

fn serveStaticFileHead(url: []const u8, stream: std.net.Stream, allocator: std.mem.Allocator) !void {
    var path_buf: [1024]u8 = undefined;
    const path = blk: {
        if (std.mem.eql(u8, url, "/")) {
            break :blk "public/index.html";
        }
        const sanitized = std.mem.trim(u8, url, "/");
        if (std.mem.indexOf(u8, sanitized, "..") != null) {
            return error.InvalidPath;
        }
        for (sanitized) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_' and c != '.' and c != '/') {
                return error.InvalidPath;
            }
        }
        const p = try std.fmt.bufPrint(&path_buf, "public/{s}", .{sanitized});
        break :blk p;
    };

    const file = std.fs.cwd().openFile(path, .{}) catch {
        const not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        try stream.writeAll(not_found);
        return error.FileNotFound;
    };
    defer file.close();

    const stat = try file.stat();

    const content_type = blk: {
        if (std.mem.endsWith(u8, path, ".html")) break :blk "text/html; charset=utf-8";
        if (std.mem.endsWith(u8, path, ".js")) break :blk "application/javascript; charset=utf-8";
        if (std.mem.endsWith(u8, path, ".css")) break :blk "text/css; charset=utf-8";
        if (std.mem.endsWith(u8, path, ".png")) break :blk "image/png";
        if (std.mem.endsWith(u8, path, ".jpg") or std.mem.endsWith(u8, path, ".jpeg")) break :blk "image/jpeg";
        if (std.mem.endsWith(u8, path, ".svg")) break :blk "image/svg+xml";
        if (std.mem.endsWith(u8, path, ".json")) break :blk "application/json; charset=utf-8";
        break :blk "application/octet-stream";
    };

    var response_buf: [1024]u8 = undefined;
    const header = try std.fmt.bufPrint(&response_buf, "HTTP/1.1 200 OK\r\n" ++
        "Content-Type: {s}\r\n" ++
        "Content-Length: {d}\r\n" ++
        "Cache-Control: public, max-age=3600\r\n" ++
        "Access-Control-Allow-Origin: *\r\n" ++
        "\r\n", .{ content_type, stat.size });

    try stream.writeAll(header);
    _ = allocator;
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Ignore SIGPIPE to prevent crash when client disconnects
    var sa_pipe: std.posix.Sigaction = std.mem.zeroes(std.posix.Sigaction);
    sa_pipe.handler = .{ .handler = std.posix.SIG.IGN };
    _ = std.posix.sigaction(std.posix.SIG.PIPE, &sa_pipe, null);

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
    relay_context = &context;

    std.debug.print("Starting unified server (WebSocket + HTTP) on {s}:{}\n", .{ env.relay_addr, env.relay_port });

    // Start custom TCP server that routes to WebSocket or HTTP
    const address = try std.net.Address.parseIp(env.relay_addr, env.relay_port);
    var server = try address.listen(.{
        .reuse_address = true,
    });
    defer server.deinit();

    // Set a 1 second timeout on accept so we can check shutdown flag regularly
    try std.posix.setsockopt(server.stream.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, &std.mem.toBytes(std.posix.timeval{
        .sec = 1,
        .usec = 0,
    }));

    while (!shutdown_flag.load(.acquire)) {
        var client = server.accept() catch |err| {
            if (err == error.SocketTimeout) continue;
            continue;
        };
        const thread = std.Thread.spawn(.{}, handleConnection, .{ client.stream, allocator }) catch {
            client.stream.close();
            continue;
        };
        thread.detach();
    }

    std.debug.print("Shutting down server...\n", .{});
}

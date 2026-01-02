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
    //db_host: []const u8 = "localhost",
    //db_port: u16 = 5432,
    //db_database: []const u8 = "zig-nostr-relay",
    //db_username: []const u8 = "postgres",
    //db_password: []const u8 = "postgres",
    //db_use_tls: bool = false,
    //db_timeout: u32 = 10_000,
    database_url: []const u8 = "",
    relay_addr: []const u8 = "0.0.0.0",
    relay_port: u16 = 7447,
};

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

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const env = try struct_env.fromEnv(allocator, Config);
    defer struct_env.free(allocator, env);

    var pool = pg.Pool.initUri(allocator, try std.Uri.parse(env.database_url), .{
        .size = 5,
        //.connect = .{
        //    .port = env.db_port,
        //    .host = env.db_host,
        //    .tls = if (env.db_use_tls) .require else .off,
        //},
    }) catch return;
    defer pool.deinit();

    const subscribers = std.ArrayList(Subscriber){};
    var context = Context{
        .allocator = allocator,
        .subscribers = subscribers,
        .pool = pool,
    };

    var server = try websocket.server.Server(Handler).init(allocator, .{
        .port = env.relay_port,
        .address = env.relay_addr,
        .handshake = .{
            .max_headers = 10,
        },
    });
    defer server.deinit();
    try server.listen(&context);
}

const Handler = struct {
    conn: *Conn,
    context: *Context,

    pub fn init(h: *Handshake, conn: *Conn, context: *Context) !Handler {
        _ = h;

        const db = try context.pool.acquire();
        defer context.pool.release(db);

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

        return Handler{
            .conn = conn,
            .context = context,
        };
    }

    fn kindInSlice(haystack: []i32, needle: i32) bool {
        for (haystack) |item| {
            if (item == needle) {
                return true;
            }
        }
        return false;
    }

    fn idInSlice(haystack: [][]const u8, needle: []u8) bool {
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

    fn eventMatched(event: Event, filters: std.ArrayList(Filter)) bool {
        for (filters.items) |filter| {
            if (filter.empty()) return true;
            if (idInSlice(filter.ids.items, event.id)) return true;
            if (idInSlice(filter.authors.items, event.pubkey)) return true;
            if (tagsInSlice(filter.tags.items, event.tags)) return true;
            if (kindInSlice(filter.kinds.items, event.kind)) return true;
            if (filter.since > 0 and event.created_at >= filter.since) return true;
            if (filter.until > 0 and event.created_at <= filter.until) return true;
        }
        return false;
    }

    fn delete_record_by_id(self: *Handler, tag: [][]u8) !bool {
        const bindValue = union(enum) {
            number: i64,
            string: []const u8,
        };
        var params: std.ArrayList(bindValue) = .{};
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

        const sql = try std.fmt.allocPrint(self.context.allocator, "DELETE FROM event WHERE id IN ({s})", .{parambuf.items});
        defer self.context.allocator.free(sql);

        const db = try self.context.pool.acquire();
        defer self.context.pool.release(db);
        var stmt = try pg.Stmt.init(db, .{});
        defer stmt.deinit();

        _ = stmt.prepare(sql, null) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            return false;
        };
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
        const db = try self.context.pool.acquire();
        defer self.context.pool.release(db);
        var stmt = try pg.Stmt.init(db, .{});
        defer stmt.deinit();

        _ = stmt.prepare("DELETE FROM event WHERE kind = $1 AND pubkey = $2", null) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            return false;
        };
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
        var params: std.ArrayList(bindValue) = .{};
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

        const sql = try std.fmt.allocPrint(self.context.allocator, "DELETE FROM event WHERE kind = $1 AND pubkey = $2 AND id IN ({s})", .{parambuf.items});
        defer self.context.allocator.free(sql);

        const db = try self.context.pool.acquire();
        defer self.context.pool.release(db);
        var stmt = try pg.Stmt.init(db, .{});
        defer stmt.deinit();

        _ = stmt.prepare(sql, null) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            return false;
        };
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

    fn make_tagsj(allocator: std.mem.Allocator, ev: Event) ![]const u8 {
        var tags = std.json.Array.init(allocator);
        defer tags.deinit();
        for (ev.tags) |tag| {
            var tmptag = std.json.Array.init(allocator);
            for (tag) |v| {
                try tmptag.append(std.json.Value{ .string = v });
            }
            try tags.append(std.json.Value{ .array = tmptag });
        }
        var json_buf: std.ArrayList(u8) = .{};
        defer json_buf.deinit(allocator);
        try json_buf.writer(allocator).print("{f}", .{std.json.fmt(tags.items, .{})});
        return try allocator.dupe(u8, json_buf.items);
    }

    fn verify_event(allocator: std.mem.Allocator, ev: Event) !bool {
        var tags = std.json.Array.init(allocator);
        defer tags.deinit();
        for (ev.tags) |tag| {
            var newtag = std.json.Array.init(allocator);
            for (tag) |v| {
                try newtag.append(std.json.Value{ .string = v });
            }
            try tags.append(std.json.Value{ .array = newtag });
        }
        const result = [_]std.json.Value{
            .{ .integer = 0 },
            .{ .string = ev.pubkey },
            .{ .integer = ev.created_at },
            .{ .integer = ev.kind },
            .{ .array = tags },
            .{ .string = ev.content },
        };

        var bytes_pk: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes_pk, ev.pubkey);
        var bytes_sig: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&bytes_sig, ev.sig);

        var json_buf: std.ArrayList(u8) = .{};
        defer json_buf.deinit(allocator);
        try json_buf.writer(allocator).print("{f}", .{std.json.fmt(result, .{})});

        var msgbuf: [32]u8 = undefined;
        var sha256 = Sha256.init(.{});
        sha256.update(json_buf.items);
        sha256.final(&msgbuf);

        return try verify(
            bytes_pk,
            msgbuf,
            bytes_sig,
        );
    }

    fn make_filter(allocator: std.mem.Allocator, array: std.json.Array) !std.ArrayList(Filter) {
        var filters: std.ArrayList(Filter) = .{};
        for (array.items[2..]) |elem| {
            var filter = Filter.init(allocator);
            for (elem.object.keys()) |key| {
                if (std.mem.eql(u8, key, "ids")) {
                    const ids = elem.object.get(key);
                    if (ids.? != .array) continue;
                    for (ids.?.array.items) |id| {
                        if (id != .string) continue;
                        try filter.ids.append(allocator, id.string);
                    }
                } else if (std.mem.eql(u8, key, "authors")) {
                    const authors = elem.object.get(key);
                    if (authors.? != .array) continue;
                    for (authors.?.array.items) |pubkey| {
                        if (pubkey != .string) continue;
                        try filter.authors.append(allocator, pubkey.string);
                    }
                } else if (std.mem.eql(u8, key, "tags")) {
                    const tags = elem.object.get(key);
                    if (tags.? != .array) continue;
                    for (tags.?.array.items) |tag| {
                        if (tag != .array) continue;
                        var newarr: std.ArrayList([]const u8) = .{};
                        for (tag.array.items) |v| {
                            try newarr.append(allocator, v.string);
                        }
                        try filter.tags.append(allocator, newarr.items);
                    }
                } else if (std.mem.startsWith(u8, key, "#")) {
                    const tag = elem.object.get(key);
                    if (tag.? != .array) continue;
                    var newarr: std.ArrayList([]const u8) = .{};
                    try newarr.append(allocator, key[1..]);
                    for (tag.?.array.items) |v| {
                        try newarr.append(allocator, v.string);
                    }
                    try filter.tags.append(allocator, newarr.items);
                } else if (std.mem.eql(u8, key, "kinds")) {
                    const kinds = elem.object.get(key);
                    if (kinds.? != .array) continue;
                    for (kinds.?.array.items) |kind| {
                        if (kind != .integer) continue;
                        try filter.kinds.append(allocator, @intCast(kind.integer));
                    }
                } else if (std.mem.eql(u8, key, "since")) {
                    const since = elem.object.get(key);
                    if (since.? != .integer) continue;
                    filter.since = @intCast(since.?.integer);
                } else if (std.mem.eql(u8, key, "until")) {
                    const until = elem.object.get(key);
                    if (until.? != .integer) continue;
                    filter.until = @intCast(until.?.integer);
                } else if (std.mem.eql(u8, key, "search")) {
                    const search = elem.object.get(key);
                    if (search.? != .string) continue;
                    filter.search = search.?.string;
                } else if (std.mem.eql(u8, key, "limit")) {
                    const limit = elem.object.get(key);
                    if (limit.? != .integer) continue;
                    filter.limit = @intCast(limit.?.integer);
                }
            }

            try filters.append(allocator, filter);
        }
        return filters;
    }

    pub fn handleEvent(self: *Handler, value: std.json.Value) !void {
        const parsedEvent = try std.json.parseFromValue(Event, self.context.allocator, value.array.items[1], .{});
        const ev = parsedEvent.value;

        const verified = verify_event(self.context.allocator, ev) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            return;
        };
        if (!verified) {
            std.debug.print("error: {s}\n", .{"invalid event signature"});
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
        } else {
            if (20000 <= ev.kind and ev.kind < 30000) {} else if (ev.kind == 0 or ev.kind == 3 or (10000 <= ev.kind and ev.kind < 20000)) {
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
            const db = try self.context.pool.acquire();
            defer self.context.pool.release(db);
            _ = db.exec(
                \\INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES ($1, $2, $3, $4, $5, $6, $7)
            , .{ ev.id, ev.pubkey, ev.created_at, ev.kind, @constCast(tagsj), ev.content, ev.sig }) catch |err| {
                std.debug.print("error: {s}\n", .{@errorName(err)});
            };
        }

        for (self.context.subscribers.items) |subscriber| {
            if (!eventMatched(ev, subscriber.filters)) continue;

            var buf: std.ArrayList(u8) = .{};
            defer buf.deinit(self.context.allocator);
            const event_array = .{ "EVENT", subscriber.sub, ev };
            try buf.writer(self.context.allocator).print("{f}", .{std.json.fmt(event_array, .{})});
            try subscriber.conn.write(buf.items);
        }

        const result = [_]std.json.Value{
            .{ .string = "OK" },
            .{ .string = ev.id },
            .{ .bool = true },
            .{ .string = "" },
        };
        var json_buf: std.ArrayList(u8) = .{};
        defer json_buf.deinit(self.context.allocator);
        try json_buf.writer(self.context.allocator).print("{f}", .{std.json.fmt(result, .{})});
        try self.conn.write(json_buf.items);
    }

    pub fn handleReq(self: *Handler, value: std.json.Value) !void {
        if (value.array.items.len < 3) {
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        }
        const sub = value.array.items[1].string;

        const filters = try make_filter(self.context.allocator, value.array);
        const subscriber = try Subscriber.init(self.context.allocator, sub, self.conn, filters);
        try self.context.subscribers.append(self.context.allocator, subscriber);

        const bindValue = union(enum) {
            number: i64,
            string: []const u8,
        };
        var params: std.ArrayList(bindValue) = .{};
        defer params.deinit(self.context.allocator);

        var condbuf: std.ArrayList([]u8) = .{};
        defer condbuf.deinit(self.context.allocator);

        var limit: i64 = 500;
        for (filters.items) |filter| {
            if (filter.empty()) continue;
            if (filter.ids.items.len > 0) {
                var parambuf: std.ArrayList(u8) = .{};
                defer parambuf.deinit(self.context.allocator);
                std.debug.print("{}\n", .{filter.ids.items.len});
                for (filter.ids.items) |id| {
                    try params.append(self.context.allocator, .{ .string = id });
                    const s = try std.fmt.allocPrint(self.context.allocator, "${}", .{params.items.len});
                    try parambuf.appendSlice(self.context.allocator, s);
                    try parambuf.append(self.context.allocator, ',');
                }
                if (parambuf.items.len > 0) {
                    _ = parambuf.pop();
                    const s = try std.fmt.allocPrint(self.context.allocator, "id IN ({s})", .{parambuf.items});
                    try condbuf.append(self.context.allocator, s);
                }
            }
            if (filter.authors.items.len > 0) {
                var parambuf: std.ArrayList(u8) = .{};
                defer parambuf.deinit(self.context.allocator);
                for (filter.authors.items) |pubkey| {
                    try params.append(self.context.allocator, .{ .string = pubkey });
                    const s = try std.fmt.allocPrint(self.context.allocator, "${}", .{params.items.len});
                    try parambuf.appendSlice(self.context.allocator, s);
                    try parambuf.append(self.context.allocator, ',');
                }
                if (parambuf.items.len > 0) {
                    _ = parambuf.pop();
                    const s = try std.fmt.allocPrint(self.context.allocator, "pubkey IN ({s})", .{parambuf.items});
                    try condbuf.append(self.context.allocator, s);
                }
            }
            if (filter.kinds.items.len > 0) {
                var parambuf: std.ArrayList(u8) = .{};
                defer parambuf.deinit(self.context.allocator);
                for (filter.kinds.items) |kind| {
                    try params.append(self.context.allocator, .{ .number = kind });
                    const s = try std.fmt.allocPrint(self.context.allocator, "${}", .{params.items.len});
                    try parambuf.appendSlice(self.context.allocator, s);
                    try parambuf.append(self.context.allocator, ',');
                }
                if (parambuf.items.len > 0) {
                    _ = parambuf.pop();
                    const s = try std.fmt.allocPrint(self.context.allocator, "kind IN ({s})", .{parambuf.items});
                    try condbuf.append(self.context.allocator, s);
                }
            }
            if (filter.tags.items.len > 0) {
                var parambuf: std.ArrayList(u8) = .{};
                defer parambuf.deinit(self.context.allocator);
                for (filter.tags.items) |tag| {
                    for (tag) |v| {
                        try params.append(self.context.allocator, .{ .string = v });
                        const s = try std.fmt.allocPrint(self.context.allocator, "${}", .{params.items.len});
                        try parambuf.appendSlice(self.context.allocator, s);
                        try parambuf.append(self.context.allocator, ',');
                    }
                }
                if (parambuf.items.len > 0) {
                    _ = parambuf.pop();
                    const s = try std.fmt.allocPrint(self.context.allocator, "tagvalues && ARRAY[{s}]", .{parambuf.items});
                    try condbuf.append(self.context.allocator, s);
                }
            }
            if (filter.since > 0) {
                try params.append(self.context.allocator, .{ .number = filter.since });
                const s = try std.fmt.allocPrint(self.context.allocator, "created_at >= ${}", .{params.items.len});
                try condbuf.append(self.context.allocator, s);
            }
            if (filter.until > 0) {
                try params.append(self.context.allocator, .{ .number = filter.until });
                const s = try std.fmt.allocPrint(self.context.allocator, "created_at <= ${}", .{params.items.len});
                try condbuf.append(self.context.allocator, s);
            }
            if (filter.search.len > 0) {
                try params.append(self.context.allocator, .{ .string = try std.fmt.allocPrint(self.context.allocator, "%{s}%", .{filter.search}) });
                const s = try std.fmt.allocPrint(self.context.allocator, "content LIKE ${}", .{params.items.len});
                try condbuf.append(self.context.allocator, s);
            }

            if (filter.limit < limit) {
                limit = filter.limit;
            }
        }

        var sqlbuf: std.ArrayList(u8) = .{};
        defer sqlbuf.deinit(self.context.allocator);
        const writer = sqlbuf.writer(self.context.allocator);

        try writer.print("SELECT id, pubkey, created_at, kind, tags, content, sig FROM event", .{});
        if (condbuf.items.len > 0) {
            try writer.print(" WHERE ", .{});
            for (condbuf.items, 0..) |cond, i| {
                if (i > 0) try writer.print(" AND ", .{});
                try writer.print("{s}", .{cond});
                self.context.allocator.free(cond);
            }
        }
        try writer.print(" order by created_at desc limit {}", .{limit});

        const db = try self.context.pool.acquire();
        defer self.context.pool.release(db);

        var stmt = try pg.Stmt.init(db, .{});
        defer stmt.deinit();

        std.debug.print("{s}\n", .{sqlbuf.items});
        _ = stmt.prepare(sqlbuf.items, null) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            return;
        };
        for (params.items) |param| {
            switch (param) {
                .number => |number| try stmt.bind(number),
                .string => |string| try stmt.bind(@constCast(string)),
            }
        }
        var res = try stmt.execute();
        defer res.deinit();

        while (try res.next()) |row| {
            var ev: Event = undefined;
            if (row.values.len != 7) break;
            ev.id = row.get([]u8, 0);
            ev.pubkey = row.get([]u8, 1);
            ev.created_at = row.get(i32, 2);
            ev.kind = row.get(i32, 3);
            const tagsj = row.get([]u8, 4);
            const tags = try std.json.parseFromSliceLeaky([][][]u8, self.context.allocator, tagsj, .{});
            defer self.context.allocator.free(tags);
            ev.tags = tags;
            ev.content = row.get([]u8, 5);
            ev.sig = row.get([]u8, 6);

            if (!eventMatched(ev, filters)) continue;

            var buf: std.ArrayList(u8) = .{};
            defer buf.deinit(self.context.allocator);
            const event_array = .{ "EVENT", sub, ev };
            try buf.writer(self.context.allocator).print("{f}", .{std.json.fmt(event_array, .{})});
            try self.conn.write(buf.items);
        }

        const result = [_]std.json.Value{
            .{ .string = "EOSE" },
            .{ .string = sub },
            .{ .bool = true },
            .{ .string = "" },
        };
        var json_buf: std.ArrayList(u8) = .{};
        defer json_buf.deinit(self.context.allocator);
        try json_buf.writer(self.context.allocator).print("{f}", .{std.json.fmt(result, .{})});
        try self.conn.write(json_buf.items);
    }

    pub fn clientMessage(self: *Handler, allocator: std.mem.Allocator, data: []const u8) !void {
        _ = allocator;
        std.debug.print("{s}\n", .{data});
        const parsed = std.json.parseFromSlice(std.json.Value, self.context.allocator, data, .{}) catch |err| {
            std.debug.print("error: {s}\n", .{@errorName(err)});
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        };
        defer parsed.deinit();
        if (parsed.value.array.items.len < 2) {
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        }
        if (std.mem.eql(u8, parsed.value.array.items[0].string, "EVENT")) {
            try self.handleEvent(parsed.value);
        } else if (std.mem.eql(u8, parsed.value.array.items[0].string, "REQ")) {
            try self.handleReq(parsed.value);
        }
    }

    pub fn close(self: *Handler) void {
        for (self.context.subscribers.items, 0..) |subscriber, i| {
            if (subscriber.conn == self.conn) {
                var s = self.context.subscribers.orderedRemove(i);
                s.deinit();
            }
        }
        self.conn.writeFrame(websocket.OpCode.close, &[_]u8{ 3, 232 }) catch {};
    }
};

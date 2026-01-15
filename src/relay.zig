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

pub const Context = struct {
    allocator: std.mem.Allocator,
    subscribers: std.ArrayList(Subscriber),
    subscribers_mutex: std.Thread.Mutex,
    pool: *pg.Pool,
};

pub fn initDatabase(pool: *pg.Pool) !void {
    const db = try pool.acquire();
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

const Config = struct {
    db_host: []const u8 = "localhost",
    db_port: u16 = 5432,
    db_database: []const u8 = "zig-nostr-relay",
    db_username: []const u8 = "postgres",
    db_password: []const u8 = "postgres",
    db_use_tls: bool = false,
    db_ca_bundle: []const u8 = undefined,
    db_timeout: u32 = 10_000,
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
            try writer.writeAll("\"");
            try writer.writeAll(item);
            try writer.writeAll("\"");
        }
        try writer.writeAll("]");
    }
    try writer.writeAll("]");

    return result.toOwnedSlice(allocator);
}

pub fn handleEventMessage(allocator: std.mem.Allocator, socket: std.posix.socket_t, pool: *pg.Pool, value: std.json.Value) !void {
    const parsedEvent = try std.json.parseFromValue(Event, allocator, value.array.items[1], .{});
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

    const db = try pool.acquire();
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
    const db = try context.pool.acquire();
    defer context.pool.release(db);

    var sql: std.ArrayList(u8) = .{};
    defer sql.deinit(allocator);
    var params = std.ArrayList([]const u8){};
    defer params.deinit(allocator);

    try sql.appendSlice(allocator, "SELECT id, pubkey, created_at, kind, tags, content, sig FROM event WHERE 1=1");

    var limit: i64 = 500;
    for (filters.items) |filter| {
        if (filter.limit > 0 and filter.limit < limit) {
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
            try sql.writer(allocator).print(" AND content LIKE ${}", .{params.items.len + 1});
            const search_pattern = try std.fmt.allocPrint(allocator, "%{s}%", .{filter.search});
            try params.append(allocator, search_pattern);
        }
    }

    try sql.writer(allocator).print(" ORDER BY created_at DESC LIMIT {}", .{limit});

    // Execute query
    var stmt = try pg.Stmt.init(db, .{});
    defer stmt.deinit();

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

        const id = row.get([]u8, 0);
        const pubkey = row.get([]u8, 1);
        const created_at = row.get(i32, 2);
        const kind = row.get(i32, 3);
        const tags = row.get([]u8, 4);
        const content = row.get([]u8, 5);
        const sig = row.get([]u8, 6);

        try response.writer(allocator).print("[\"EVENT\",\"{s}\",{{\"id\":\"{s}\",\"pubkey\":\"{s}\",\"created_at\":{},\"kind\":{},\"tags\":{s},\"content\":", .{ sub_id.string, id, pubkey, created_at, kind, tags });
        try std.json.encodeJsonString(content, .{}, response.writer(allocator));
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
            try writer.writeAll("\"");
            try writer.writeAll(v);
            try writer.writeAll("\"");
        }
        try writer.writeAll("]");
    }
    try writer.writeAll("]");

    try writer.writeAll(",\"");
    try writer.writeAll(ev.content);
    try writer.writeAll("\"]");

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

        const db = try self.context.pool.acquire();
        defer self.context.pool.release(db);
        var stmt = try pg.Stmt.init(db, .{});
        defer stmt.deinit();

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
        const db = try self.context.pool.acquire();
        defer self.context.pool.release(db);
        var stmt = try pg.Stmt.init(db, .{});
        defer stmt.deinit();

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

        const db = try self.context.pool.acquire();
        defer self.context.pool.release(db);
        var stmt = try pg.Stmt.init(db, .{});
        defer stmt.deinit();

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
                try writer.writeAll("\"");
                try writer.writeAll(item);
                try writer.writeAll("\"");
            }
            try writer.writeAll("]");
        }
        try writer.writeAll("],\"");
        try writer.writeAll(ev.content);
        try writer.writeAll("\"]");

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
        const ev = parsedEvent.value;

        const verified = verify_event(self.context.allocator, ev) catch |err| {
            logger.warn("Event verification failed: {s}", .{@errorName(err)});
            return;
        };
        if (!verified) {
            logger.warn("Event has invalid signature", .{});
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
                \\insert into event (id, pubkey, created_at, kind, tags, content, sig) values ($1, $2, $3, $4, $5, $6, $7)
            , .{ ev.id, ev.pubkey, ev.created_at, ev.kind, @constCast(tagsj), ev.content, ev.sig }) catch |err| {
                logger.warn("Error inserting event: {s}", .{@errorName(err)});
            };
        }

        // Notify subscribers (copy list under mutex, then process outside)
        var subscribers_to_notify = std.ArrayList(Subscriber){};
        defer subscribers_to_notify.deinit(self.context.allocator);

        {
            self.context.subscribers_mutex.lock();
            defer self.context.subscribers_mutex.unlock();

            for (self.context.subscribers.items) |subscriber| {
                if (!eventMatched(ev, subscriber.filters)) continue;
                if (subscriber.conn._closed) continue;
                try subscribers_to_notify.append(self.context.allocator, subscriber);
            }
        }

        // Now notify outside the mutex
        for (subscribers_to_notify.items) |subscriber| {
            // Double-check connection is still open
            if (subscriber.conn._closed) {
                continue;
            }

            var buf: std.ArrayList(u8) = .{};
            defer buf.deinit(self.context.allocator);
            var event_writer = buf.writer(self.context.allocator);
            try event_writer.writeAll("[\"EVENT\",\"");
            try event_writer.writeAll(subscriber.sub);
            try event_writer.writeAll("\",{\"id\":\"");
            try event_writer.writeAll(ev.id);
            try event_writer.writeAll("\",\"kind\":");
            try event_writer.print("{d}", .{ev.kind});
            try event_writer.writeAll(",\"created_at\":");
            try event_writer.print("{d}", .{ev.created_at});
            try event_writer.writeAll(",\"pubkey\":\"");
            try event_writer.writeAll(ev.pubkey);
            try event_writer.writeAll("\",\"content\":\"");
            try event_writer.writeAll(ev.content);
            try event_writer.writeAll("\",\"sig\":\"");
            try event_writer.writeAll(ev.sig);
            try event_writer.writeAll("\",\"tags\":");
            const tags = try make_tagsj(self.context.allocator, ev);
            defer self.context.allocator.free(tags);
            try event_writer.writeAll(tags);
            try event_writer.writeAll("}]");
            subscriber.conn.write(buf.items) catch {
                // Silently ignore write errors (connection probably closed)
                continue;
            };
        }

        var buf: std.ArrayList(u8) = .{};
        defer buf.deinit(self.context.allocator);
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

        const filters = try make_filter(self.context.allocator, value.array);
        const subscriber = try Subscriber.init(self.context.allocator, sub, self.conn, filters);

        // Add subscriber with mutex protection
        self.context.subscribers_mutex.lock();
        try self.context.subscribers.append(self.context.allocator, subscriber);
        self.context.subscribers_mutex.unlock();

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
                const search_pattern = try std.fmt.allocPrint(self.context.allocator, "%{s}%", .{filter.search});
                try params.append(self.context.allocator, .{ .string = search_pattern });
                try sql_writer.print("content LIKE ${}", .{params.items.len});
            }

            if (filter.limit < limit) {
                limit = filter.limit;
            }
        }

        try sql_writer.print(" ORDER BY created_at DESC LIMIT {}", .{limit});

        const db = try self.context.pool.acquire();
        defer self.context.pool.release(db);

        var stmt = try pg.Stmt.init(db, .{});

        try stmt.prepare(sqlbuf.items, null);
        for (params.items) |param| {
            switch (param) {
                .number => |number| try stmt.bind(number),
                .string => |string| try stmt.bind(@constCast(string)),
            }
        }
        var res = try stmt.execute();
        defer res.deinit();

        while (try res.next()) |row| {
            if (row.values.len != 7) break;

            const id = row.get([]u8, 0);
            const pubkey = row.get([]u8, 1);
            const created_at = row.get(i32, 2);
            const kind = row.get(i32, 3);
            const tagsj = row.get([]u8, 4);
            const content = row.get([]u8, 5);
            const sig = row.get([]u8, 6);

            var buf: std.ArrayList(u8) = .{};
            defer buf.deinit(self.context.allocator);
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
            try event_writer.writeAll("\",\"content\":\"");
            try event_writer.writeAll(content);
            try event_writer.writeAll("\",\"sig\":\"");
            try event_writer.writeAll(sig);
            try event_writer.writeAll("\",\"tags\":");
            try event_writer.writeAll(tagsj);
            try event_writer.writeAll("}]");
            try self.conn.write(buf.items);
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

        // Validate data is not empty
        if (data.len == 0) {
            self.conn.write("[\"NOTICE\", \"error: empty message\"]") catch |err| {
                return err;
            };
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

        // Additional validation: check balanced brackets
        var bracket_count: i32 = 0;
        for (data) |c| {
            if (c == '[' or c == '{') bracket_count += 1;
            if (c == ']' or c == '}') bracket_count -= 1;
            if (bracket_count < 0) {
                try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
                return;
            }
        }
        if (bracket_count != 0) {
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        }

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

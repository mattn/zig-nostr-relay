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
    kind: i64 = 0,
    created_at: i64,
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

    pub fn empty(self: *const Filter) bool {
        return self.ids.items.len == 0 and
            self.authors.items.len == 0 and
            self.kinds.items.len == 0 and
            self.tags.items.len == 0 and
            self.since == 0 and
            self.until == 0 and
            self.search.len == 0;
    }
};

const Subscriber = struct {
    sub: []const u8,
    client: *Handler,
    filters: std.ArrayList(Filter),
};

const Context = struct {
    allocator: std.mem.Allocator,
    subscribers: std.ArrayList(Subscriber),
    pool: *pg.Pool,
};

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
    const Px = try Secp256k1.Fe.fromBytes(public_key, .Big);
    const Py = try Secp256k1.recoverY(Px, false);
    const P = try Secp256k1.fromAffineCoordinates(.{ .x = Px, .y = Py });
    const r = try Secp256k1.Fe.fromBytes(signature[0..32].*, .Big);
    const s = try Secp256k1.scalar.Scalar.fromBytes(signature[32..64].*, .Big);
    var to_hash: [96]u8 = undefined;
    @memcpy(to_hash[0..32], signature[0..32]);
    @memcpy(to_hash[32..64], public_key[0..]);
    @memcpy(to_hash[64..96], msg[0..]);
    const e = try Scalar.fromBytes(
        taggedHash("BIP0340/challenge", to_hash[0..]),
        .Big,
    );
    const R = (try Secp256k1.basePoint.mulPublic(
        s.toBytes(.Big),
        .Big,
    )).sub(try P.mul(e.toBytes(.Big), .Big));
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

    std.debug.print("{s}\n", .{env.db_host});
    var bundle = std.crypto.Certificate.Bundle{};
    defer bundle.deinit(allocator);
    if (env.db_ca_bundle.len > 0) {
        try bundle.addCertsFromFilePath(allocator, std.fs.cwd(), "hub.crt");
    }
    std.debug.print("{} {s}\n", .{ env.db_use_tls, env.db_ca_bundle });
    var pool = pg.Pool.init(allocator, .{
        .size = 5,
        .connect = .{
            .port = env.db_port,
            .host = env.db_host,
            .tls = env.db_use_tls,
            .ca_bundle = bundle,
        },
        .auth = .{
            .database = env.db_database,
            .username = env.db_username,
            .password = env.db_password,
            .timeout = env.db_timeout,
        },
    }) catch return;
    defer pool.deinit();

    var context = Context{
        .allocator = allocator,
        .subscribers = std.ArrayList(Subscriber).init(allocator),
        .pool = pool,
    };

    try websocket.listen(Handler, allocator, &context, .{
        .port = env.relay_port,
        .max_headers = 10,
        .address = env.relay_addr,
    });
}

const Handler = struct {
    conn: *Conn,
    context: *Context,

    pub fn init(h: Handshake, conn: *Conn, context: *Context) !Handler {
        _ = h;
        return Handler{
            .conn = conn,
            .context = context,
        };
    }

    pub fn afterInit(self: *Handler) !void {
        const conn = try self.context.pool.acquire();
        defer self.context.pool.release(conn);
        _ = try conn.exec(
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

    fn kindInSlice(haystack: []i64, needle: i64) bool {
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

    fn delete_record_by_id(pool: *pg.Pool, tag: [][]u8) i32 {
        _ = pool;
        _ = tag;
        //for (events.items, 0..) |event, i| {
        //    for (event.tags) |item| {
        //        if (item.len != 2) continue;
        //        if (std.mem.eql(u8, item[0], tag[0]) and std.mem.eql(u8, item[1], tag[1])) {
        //            _ = events.orderedRemove(i);
        //            return 0;
        //        }
        //    }
        //}
        return -1;
    }

    fn delete_record_by_kind_and_pubkey(pool: *pg.Pool, kind: i64, pubkey: []u8) i32 {
        _ = pool;
        _ = kind;
        _ = pubkey;
        //for (events.items, 0..) |event, i| {
        //    if (event.kind != kind or !std.mem.eql(u8, event.pubkey, pubkey)) continue;
        //    _ = events.orderedRemove(i);
        //    return 0;
        //}
        return -1;
    }

    fn delete_record_by_kind_and_pubkey_and_dtag(pool: *pg.Pool, kind: i64, pubkey: []u8, tag: [][]u8) i32 {
        _ = pool;
        _ = kind;
        _ = pubkey;
        _ = tag;
        //for (events.items, 0..) |event, i| {
        //    if (event.kind != kind or !std.mem.eql(u8, event.pubkey, pubkey)) continue;
        //    for (event.tags) |item| {
        //        if (item.len != 2) continue;
        //        if (std.mem.eql(u8, item[0], tag[0]) and std.mem.eql(u8, item[1], tag[1])) {
        //            _ = events.orderedRemove(i);
        //            return 0;
        //        }
        //    }
        //}
        return -1;
    }

    fn make_tagsj(allocator: std.mem.Allocator, ev: Event) ![]const u8 {
        var tags = std.json.Array.init(allocator);
        defer tags.deinit();
        for (ev.tags) |tag| {
            var tmptag = std.json.Array.init(allocator);
            defer tmptag.deinit();
            for (tag) |v| {
                try tmptag.append(std.json.Value{ .string = v });
            }
            try tags.append(std.json.Value{ .array = tmptag });
        }
        return try std.json.stringifyAlloc(allocator, tags.items, .{});
    }

    fn verify_event(allocator: std.mem.Allocator, ev: Event) !bool {
        var tags = std.json.Array.init(allocator);
        defer tags.deinit();
        for (ev.tags) |tag| {
            var newtag = std.json.Array.init(allocator);
            defer newtag.deinit();
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

        const buf = try std.json.stringifyAlloc(allocator, result, .{});
        defer allocator.free(buf);

        var msgbuf: [32]u8 = undefined;
        var sha256 = Sha256.init(.{});
        sha256.update(buf);
        sha256.final(&msgbuf);

        return try verify(
            bytes_pk,
            msgbuf,
            bytes_sig,
        );
    }

    fn make_filter(allocator: std.mem.Allocator, array: std.json.Array) !std.ArrayList(Filter) {
        var filters = std.ArrayList(Filter).init(allocator);
        for (array.items[2..]) |elem| {
            var filter: Filter = .{
                .ids = std.ArrayList([]const u8).init(allocator),
                .authors = std.ArrayList([]const u8).init(allocator),
                .tags = std.ArrayList([][]const u8).init(allocator),
                .kinds = std.ArrayList(i64).init(allocator),
            };
            for (elem.object.keys()) |key| {
                if (std.mem.eql(u8, key, "ids")) {
                    const ids = elem.object.get(key);
                    if (ids.? != .array) continue;
                    for (ids.?.array.items) |id| {
                        if (id != .string) continue;
                        try filter.ids.append(id.string);
                    }
                } else if (std.mem.eql(u8, key, "authors")) {
                    const authors = elem.object.get(key);
                    if (authors.? != .array) continue;
                    for (authors.?.array.items) |pubkey| {
                        if (pubkey != .string) continue;
                        try filter.authors.append(pubkey.string);
                    }
                } else if (std.mem.eql(u8, key, "tags")) {
                    const tags = elem.object.get(key);
                    if (tags.? != .array) continue;
                    for (tags.?.array.items) |tag| {
                        if (tag != .array) continue;
                        var newarr = std.ArrayList([]const u8).init(allocator);
                        for (tag.array.items) |v| {
                            try newarr.append(v.string);
                        }
                        try filter.tags.append(newarr.items);
                    }
                } else if (std.mem.startsWith(u8, key, "#")) {
                    const tag = elem.object.get(key);
                    if (tag.? != .array) continue;
                    var newarr = std.ArrayList([]const u8).init(allocator);
                    try newarr.append(key[1..]);
                    for (tag.?.array.items) |v| {
                        try newarr.append(v.string);
                    }
                    try filter.tags.append(newarr.items);
                } else if (std.mem.eql(u8, key, "kinds")) {
                    const kinds = elem.object.get(key);
                    if (kinds.? != .array) continue;
                    for (kinds.?.array.items) |kind| {
                        if (kind != .integer) continue;
                        try filter.kinds.append(kind.integer);
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
                    filter.search = search.?.string;
                }
            }

            try filters.append(filter);
        }
        return filters;
    }

    pub fn handle(self: *Handler, message: Message) !void {
        const data = message.data;
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
            const parsedEvent = try std.json.parseFromValue(Event, self.context.allocator, parsed.value.array.items[1], .{});
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
                        if (delete_record_by_id(self.context.pool, tag[1..]) < 0) {
                            return;
                        }
                    }
                }
            } else {
                if (20000 <= ev.kind and ev.kind < 30000) {} else if (ev.kind == 0 or ev.kind == 3 or (10000 <= ev.kind and ev.kind < 20000)) {
                    if (delete_record_by_kind_and_pubkey(self.context.pool, ev.kind, ev.pubkey) < 0) {
                        return;
                    }
                } else if (30000 <= ev.kind and ev.kind < 40000) {
                    for (ev.tags) |tag| {
                        if (tag.len >= 2 and std.mem.eql(u8, tag[0], "d")) {
                            if (delete_record_by_kind_and_pubkey_and_dtag(self.context.pool, ev.kind, ev.pubkey, tag) < 0) {
                                return;
                            }
                        }
                    }
                }

                const tagsj = try make_tagsj(self.context.allocator, ev);
                _ = tagsj;
                //var tagsbj: []u8 = std.mem.bytesAsSlice(u8, tagsj[0..]);
                const conn = try self.context.pool.acquire();
                defer self.context.pool.release(conn);
                _ = try conn.exec(
                    \\INSERT INTO event (id, pubkey, created_at, kind, tags, content, sig) VALUES ($1, $2, $3, $4, $5, $6, $7)
                , .{ ev.id, ev.pubkey, ev.created_at, ev.kind, "[]", ev.content, ev.sig });
            }

            for (self.context.subscribers.items) |subscriber| {
                if (!eventMatched(ev, subscriber.filters)) continue;

                var buf = std.ArrayList(u8).init(self.context.allocator);
                defer buf.deinit();
                var jw = std.json.writeStream(buf.writer(), .{});
                defer jw.deinit();
                try jw.beginArray();
                try jw.write("EVENT");
                try jw.write(subscriber.sub);
                try jw.write(ev);
                try jw.endArray();
                try subscriber.client.conn.write(buf.items);
            }

            const result = [_]std.json.Value{
                .{ .string = "OK" },
                .{ .string = ev.id },
                .{ .bool = true },
                .{ .string = "" },
            };
            const buf = try std.json.stringifyAlloc(self.context.allocator, result, .{});
            try self.conn.write(buf);
        } else if (std.mem.eql(u8, parsed.value.array.items[0].string, "REQ")) {
            if (parsed.value.array.items.len < 3) {
                try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
                return;
            }
            const sub = parsed.value.array.items[1].string;

            const filters = try make_filter(self.context.allocator, parsed.value.array);
            try self.context.subscribers.append(.{
                .sub = sub,
                .client = self,
                .filters = filters,
            });

            const conn = try self.context.pool.acquire();
            defer self.context.pool.release(conn);
            var res = try conn.query("select id, pubkey, created_at, kind, tags, content, sig from event order by created_at desc limit 500", .{});
            defer res.deinit();

            while (try res.next()) |row| {
                var ev: Event = undefined;
                ev.id = row.get([]u8, 0);
                ev.pubkey = row.get([]u8, 1);
                ev.created_at = row.get(i32, 2);
                ev.kind = row.get(i32, 3);
                var tagsj = row.get([]u8, 4);
                const tags = try std.json.parseFromSliceLeaky([][][]u8, self.context.allocator, tagsj, .{});
                ev.tags = tags;
                ev.content = row.get([]u8, 5);
                ev.sig = row.get([]u8, 6);

                if (!eventMatched(ev, filters)) continue;

                var buf = std.ArrayList(u8).init(self.context.allocator);
                defer buf.deinit();
                var jw = std.json.writeStream(buf.writer(), .{});
                defer jw.deinit();
                try jw.beginArray();
                try jw.write("EVENT");
                try jw.write(sub);
                try jw.write(ev);
                try jw.endArray();
                try self.conn.write(buf.items);
            }

            const result = [_]std.json.Value{
                .{ .string = "EOSE" },
                .{ .string = sub },
                .{ .bool = true },
                .{ .string = "" },
            };
            const buf = try std.json.stringifyAlloc(self.context.allocator, result, .{});
            try self.conn.write(buf);
        }
    }

    pub fn close(_: *Handler) void {}
};

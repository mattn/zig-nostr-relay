const std = @import("std");
const websocket = @import("websocket");
const Conn = websocket.Conn;
const Message = websocket.Message;
const Handshake = websocket.Handshake;

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
};

const Subscriber = struct {
    sub: []const u8,
    client: *Handler,
    filters: std.ArrayList(Filter),
};

const Context = struct {
    allocator: std.mem.Allocator,
    events: std.ArrayList(Event),
    subscribers: std.ArrayList(Subscriber),
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var context = Context{
        .allocator = allocator,
        .events = std.ArrayList(Event).init(allocator),
        .subscribers = std.ArrayList(Subscriber).init(allocator),
    };

    try websocket.listen(Handler, allocator, &context, .{
        .port = 7447,
        .max_headers = 10,
        .address = "127.0.0.1",
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

    // optional hook that, if present, will be called after initialization is complete
    pub fn afterInit(_: *Handler) !void {}

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
            if (idInSlice(filter.ids.items, event.id)) return true;
            if (idInSlice(filter.authors.items, event.pubkey)) return true;
            if (tagsInSlice(filter.tags.items, event.tags)) return true;
            if (kindInSlice(filter.kinds.items, event.kind)) return true;
            if (filter.since > 0 and event.created_at >= filter.since) return true;
            if (filter.until > 0 and event.created_at <= filter.until) return true;
        }
        return false;
    }

    fn delete_record_by_id(events: *std.ArrayList(Event), tag: [][]u8) i32 {
        for (events.items, 0..) |event, i| {
            for (event.tags) |item| {
                if (item.len != 2) continue;
                if (std.mem.eql(u8, item[0], tag[0]) and std.mem.eql(u8, item[1], tag[1])) {
                    _ = events.orderedRemove(i);
                    return 0;
                }
            }
        }
        return -1;
    }

    fn delete_record_by_kind_and_pubkey(events: *std.ArrayList(Event), kind: i32, pubkey: []u8) i32 {
        for (events.items, 0..) |event, i| {
            if (event.kind != kind or !std.mem.eql(u8, event.pubkey, pubkey)) continue;
            _ = events.orderedRemove(i);
            return 0;
        }
        return -1;
    }

    fn delete_record_by_kind_and_pubkey_and_dtag(events: *std.ArrayList(Event), kind: i32, pubkey: []u8, tag: [][]u8) i32 {
        for (events.items, 0..) |event, i| {
            if (event.kind != kind or !std.mem.eql(u8, event.pubkey, pubkey)) continue;
            for (event.tags) |item| {
                if (item.len != 2) continue;
                if (std.mem.eql(u8, item[0], tag[0]) and std.mem.eql(u8, item[1], tag[1])) {
                    _ = events.orderedRemove(i);
                    return 0;
                }
            }
        }
        return -1;
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

            if (ev.kind == 5) {
                for (ev.tags) |tag| {
                    if (tag.len >= 2 and std.mem.eql(u8, tag[0], "e")) {
                        if (delete_record_by_id(&self.context.events, tag[1..]) < 0) {
                            return;
                        }
                    }
                }
            } else {
                if (20000 <= ev.kind and ev.kind < 30000) {} else if (ev.kind == 0 or ev.kind == 3 or (10000 <= ev.kind and ev.kind < 20000)) {
                    if (delete_record_by_kind_and_pubkey(&self.context.events, ev.kind, ev.pubkey) < 0) {
                        return;
                    }
                } else if (30000 <= ev.kind and ev.kind < 40000) {
                    for (ev.tags) |tag| {
                        if (tag.len >= 2 and std.mem.eql(u8, tag[0], "d")) {
                            if (delete_record_by_kind_and_pubkey_and_dtag(&self.context.events, ev.kind, ev.pubkey, tag) < 0) {
                                return;
                            }
                        }
                    }
                }
                try self.context.events.append(ev);
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

            var filters = std.ArrayList(Filter).init(self.context.allocator);
            for (parsed.value.array.items[2..]) |elem| {
                var filter: Filter = .{
                    .ids = std.ArrayList([]const u8).init(self.context.allocator),
                    .authors = std.ArrayList([]const u8).init(self.context.allocator),
                    .tags = std.ArrayList([][]const u8).init(self.context.allocator),
                    .kinds = std.ArrayList(i32).init(self.context.allocator),
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
                            var newarr = std.ArrayList([]const u8).init(self.context.allocator);
                            for (tag.array.items) |v| {
                                try newarr.append(v.string);
                            }
                            try filter.tags.append(newarr.items);
                        }
                    } else if (std.mem.startsWith(u8, key, "#")) {
                        const tag = elem.object.get(key);
                        if (tag.? != .array) continue;
                        var newarr = std.ArrayList([]const u8).init(self.context.allocator);
                        try newarr.append(key[1..]);
                        for (tag.?.array.items) |v| {
                            try newarr.append(v.string);
                        }
                        try filter.tags.append(newarr.items);
                    } else if (std.mem.eql(u8, key, "kinds")) {
                        const kinds = elem.object.get(key);
                        if (kinds.? != .array) continue;
                        for (kinds.?.array.items) |kind| {
                            if (kind != .float) continue;
                            try filter.kinds.append(@intFromFloat(kind.float));
                        }
                    } else if (std.mem.eql(u8, key, "since")) {
                        const since = elem.object.get(key);
                        if (since.? != .float) continue;
                        filter.since = @intFromFloat(since.?.float);
                    } else if (std.mem.eql(u8, key, "until")) {
                        const until = elem.object.get(key);
                        if (until.? != .float) continue;
                        filter.until = @intFromFloat(until.?.float);
                    } else if (std.mem.eql(u8, key, "search")) {
                        const search = elem.object.get(key);
                        if (search.? != .string) continue;
                        filter.search = search.?.string;
                    }
                }

                try filters.append(filter);
            }

            try self.context.subscribers.append(.{
                .sub = sub,
                .client = self,
                .filters = filters,
            });

            for (self.context.events.items) |event| {
                if (!eventMatched(event, filters)) continue;

                var buf = std.ArrayList(u8).init(self.context.allocator);
                defer buf.deinit();
                var jw = std.json.writeStream(buf.writer(), .{});
                defer jw.deinit();
                try jw.beginArray();
                try jw.write("EVENT");
                try jw.write(sub);
                try jw.write(event);
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

    // called whenever the connection is closed, can do some cleanup in here
    pub fn close(_: *Handler) void {}
};

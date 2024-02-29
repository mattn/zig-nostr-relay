const std = @import("std");
const websocket = @import("websocket");
const Conn = websocket.Conn;
const Message = websocket.Message;
const Handshake = websocket.Handshake;

const EVENT = struct {
    id: []u8,
    kind: i32 = 0,
    created_at: i32,
    pubkey: []u8,
    content: []u8,
    sig: []u8,
    tags: [][]u8,
};

const FILTER = struct {
    ids: ?[][]u8 = undefined,
    authors: ?[][]u8 = undefined,
};

const SUBSCRIBER = struct {
    sub: []const u8,
    client: *Handler,
    filters: FILTER,
};

const Context = struct {
    allocator: std.mem.Allocator,
    events: std.ArrayList(EVENT),
    subscribers: std.ArrayList(SUBSCRIBER),
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    var context = Context{
        .allocator = allocator,
        .events = std.ArrayList(EVENT).init(allocator),
        .subscribers = std.ArrayList(SUBSCRIBER).init(allocator),
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

    pub fn handle(self: *Handler, message: Message) !void {
        const data = message.data;
        std.debug.print("{s}\n", .{data});
        const parsed = std.json.parseFromSlice(std.json.Value, self.context.allocator, data, .{}) catch |err| {
            std.debug.print("error: {s}", .{@errorName(err)});
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        };
        defer parsed.deinit();
        if (parsed.value.array.items.len < 2) {
            try self.conn.write("[\"NOTICE\", \"error: invalid request\"]");
            return;
        }
        if (std.mem.eql(u8, parsed.value.array.items[0].string, "EVENT")) {
            const parsedEvent = try std.json.parseFromValue(EVENT, self.context.allocator, parsed.value.array.items[1], .{});
            try self.context.events.append(parsedEvent.value);

            for (self.context.subscribers.items) |subscriber| {
                // TODO: handle filter

                var buf = std.ArrayList(u8).init(self.context.allocator);
                defer buf.deinit();
                var jw = std.json.writeStream(buf.writer(), .{});
                defer jw.deinit();
                try jw.beginArray();
                try jw.write("EVENT");
                try jw.write(subscriber.sub);
                try jw.write(parsedEvent.value);
                try jw.endArray();
                try subscriber.client.conn.write(buf.items);
            }

            const result = [_]std.json.Value{
                .{ .string = "OK" },
                .{ .string = parsedEvent.value.id },
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
            const id = parsed.value.array.items[1].string;
            // TODO: parse filter

            for (self.context.events.items) |event| {
                var buf = std.ArrayList(u8).init(self.context.allocator);
                defer buf.deinit();
                var jw = std.json.writeStream(buf.writer(), .{});
                defer jw.deinit();
                try jw.beginArray();
                try jw.write("EVENT");
                try jw.write(id);
                try jw.write(event);
                try jw.endArray();
                try self.conn.write(buf.items);
            }
            const result = [_]std.json.Value{
                .{ .string = "EOSE" },
                .{ .string = id },
                .{ .bool = true },
                .{ .string = "" },
            };
            const buf = try std.json.stringifyAlloc(self.context.allocator, result, .{});
            try self.conn.write(buf);

            try self.context.subscribers.append(.{
                .sub = id,
                .client = self,
                .filters = .{},
            });
        }
    }

    // called whenever the connection is closed, can do some cleanup in here
    pub fn close(_: *Handler) void {}
};

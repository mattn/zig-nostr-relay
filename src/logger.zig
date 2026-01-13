const std = @import("std");

var log_mutex: std.Thread.Mutex = .{};

pub const Level = enum {
    debug,
    info,
    warn,
    err,

    fn prefix(self: Level) []const u8 {
        return switch (self) {
            .debug => "[DEBUG]",
            .info => "[INFO] ",
            .warn => "[WARN] ",
            .err => "[ERROR]",
        };
    }
};

fn getTimestamp(buf: []u8) ![]const u8 {
    const now = std.time.timestamp();
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(now) };
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    });
}

pub fn log(level: Level, comptime fmt: []const u8, args: anytype) void {
    log_mutex.lock();
    defer log_mutex.unlock();

    var timestamp_buf: [32]u8 = undefined;
    const timestamp = getTimestamp(&timestamp_buf) catch "????-??-?? ??:??:??";
    
    var buffer: [256]u8 = undefined;
    const writer = std.debug.lockStderrWriter(&buffer);
    defer std.debug.unlockStderrWriter();
    
    writer.print("{s} {s} ", .{ timestamp, level.prefix() }) catch return;
    writer.print(fmt, args) catch return;
    writer.writeAll("\n") catch return;
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    log(.debug, fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    log(.info, fmt, args);
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
    log(.warn, fmt, args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    log(.err, fmt, args);
}

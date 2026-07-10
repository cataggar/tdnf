const std = @import("std");

pub const RecordKind = enum(u32) {
    unknown = 0,
    primary = 1,
    filelists = 2,
    other = 3,
    updateinfo = 4,
};

pub const Checksum = extern struct {
    pszType: ?[*:0]const u8 = null,
    pszValue: ?[*:0]const u8 = null,
};

pub const Record = extern struct {
    pszType: ?[*:0]const u8 = null,
    dwKind: u32 = @intFromEnum(RecordKind.unknown),
    pszLocationHref: ?[*:0]const u8 = null,
    checksum: Checksum = .{},
    openChecksum: Checksum = .{},
    nTimestamp: u64 = 0,
    nSize: u64 = 0,
    nOpenSize: u64 = 0,
    nDatabaseVersion: u64 = 0,
    nHasTimestamp: c_int = 0,
    nHasSize: c_int = 0,
    nHasOpenSize: c_int = 0,
    nHasDatabaseVersion: c_int = 0,
};

pub const ParsedRepoMd = struct {
    pszRevision: ?[*:0]const u8 = null,
    pRecords: []Record = &[_]Record{},
};

pub fn kindFromRawType(raw_type: []const u8) RecordKind {
    if (std.mem.eql(u8, raw_type, "primary")) return .primary;
    if (std.mem.eql(u8, raw_type, "filelists")) return .filelists;
    if (std.mem.eql(u8, raw_type, "other")) return .other;
    if (std.mem.startsWith(u8, raw_type, "updateinfo")) return .updateinfo;
    return .unknown;
}

pub fn dupZ(allocator: std.mem.Allocator, bytes: []const u8) ![:0]const u8 {
    const out = try allocator.allocSentinel(u8, bytes.len, 0);
    @memcpy(out[0..bytes.len], bytes);
    return out;
}

//! RPM header v3 format decoder.
//!
//! Binary layout (no 8-byte magic prefix inside rpmdb sqlite blobs;
//! the magic is added by `headerWrite()` for standalone .rpm files
//! only — `headerExport()` strips it for rpmdb storage):
//!
//!   u32 be: nindex   - number of index entries (each 16 bytes)
//!   u32 be: hsize    - total bytes in data section
//!   nindex × {
//!       u32 be: tag
//!       u32 be: type     (1=char, 2=int8, 3=int16, 4=int32, 5=int64,
//!                         6=string, 7=bin, 8=string_array, 9=i18n_string)
//!       u32 be: offset   (into data section)
//!       u32 be: count
//!   }
//!   hsize bytes: data
//!
//! The first index entry in modern rpm headers is the "region trailer"
//! tag (RPMTAG_HEADERIMAGE = 63, type = BIN, count = 16). We skip it
//! when iterating data tags; the region machinery is only needed when
//! writing.
//!
//! This module is read-only and does not allocate. All returned slices
//! point into the input blob — callers must keep the blob alive while
//! using a decoded `Header`.

const std = @import("std");

pub const TagId = enum(u32) {
    name = 1000,
    version = 1001,
    release = 1002,
    epoch = 1003,
    summary = 1004,
    arch = 1022,
    install_tid = 1128,
    install_time = 1008,
    payload_format = 1124,
    payload_compressor = 1125,
    payload_flags = 1126,
    // STRING_ARRAY / INT32_ARRAY dep tags
    requirename = 1049,
    requireversion = 1050,
    requireflags = 1048,
    providename = 1047,
    provideversion = 1113,
    provideflags = 1112,
    conflictname = 1054,
    conflictversion = 1055,
    conflictflags = 1053,
    obsoletename = 1090,
    obsoleteversion = 1115,
    obsoleteflags = 1114,
    // signature-header tags (numbered in the sig header's own space).
    // Presence of any of these on a `.rpm`'s sig header means the
    // package is signed; T3 will route them through gpgme for
    // verification.
    sig_sigpgp = 265,
    sig_siggpg = 266,
    sig_dsa = 267,
    sig_rsa = 268,
    sig_sha1 = 269,
    sig_sha256 = 273,
    sig_openpgp = 278,
    _,
};

pub const TypeId = enum(u32) {
    null_type = 0,
    char_type = 1,
    int8 = 2,
    int16 = 3,
    int32 = 4,
    int64 = 5,
    string = 6,
    bin = 7,
    string_array = 8,
    i18n_string = 9,
    _,
};

/// region marker — RPMTAG_HEADERIMAGE. Index 0 of most rpmdb blobs.
const RPMTAG_HEADERIMAGE: u32 = 63;
const RPMTAG_HEADERSIGNATURES: u32 = 62;
const RPMTAG_HEADERIMMUTABLE: u32 = 61;

pub const Error = error{
    Truncated,
    BadIndexCount,
    BadMagic,
    OffsetOutOfRange,
    InvalidUtf8, // we don't enforce UTF-8 strictly; reserved
};

pub const IndexEntry = struct {
    tag: u32,
    typ: u32,
    offset: u32,
    count: u32,
};

pub const Header = struct {
    /// the full blob (index + data); slices we return alias into here.
    bytes: []const u8,
    index_count: u32,
    /// offset of first index entry in `bytes` (always 8).
    index_off: usize,
    /// offset of data section in `bytes` (= 8 + 16 * index_count).
    data_off: usize,
    /// total size of data section in bytes.
    data_size: u32,

    pub fn parse(blob: []const u8) Error!Header {
        if (blob.len < 8) return error.Truncated;
        const nindex = readU32(blob, 0);
        const hsize = readU32(blob, 4);
        if (nindex == 0 or nindex > (1 << 20)) return error.BadIndexCount;
        const index_off: usize = 8;
        const data_off: usize = 8 + 16 * @as(usize, nindex);
        const total = data_off + hsize;
        if (blob.len < total) return error.Truncated;
        return .{
            .bytes = blob,
            .index_count = nindex,
            .index_off = index_off,
            .data_off = data_off,
            .data_size = hsize,
        };
    }

    /// Parses a header with the 8-byte "standalone" magic prefix
    /// (`8e ad e8 01 00 00 00 00`), as used in `.rpm` files for the
    /// signature header and main header. Returns the parsed header
    /// plus its **total on-disk size** (magic + counts + index + data),
    /// without any trailing pad-to-8 alignment — the caller applies
    /// alignment when seeking from one header to the next.
    pub fn parseStandalone(blob: []const u8) Error!struct { header: Header, on_disk_size: usize } {
        const magic = [_]u8{ 0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00 };
        if (blob.len < magic.len) return error.Truncated;
        if (!std.mem.eql(u8, blob[0..magic.len], &magic)) return error.BadMagic;
        const h = try Header.parse(blob[magic.len..]);
        return .{
            .header = h,
            .on_disk_size = magic.len + 8 + 16 * @as(usize, h.index_count) + h.data_size,
        };
    }

    pub fn entry(self: Header, i: u32) IndexEntry {
        const base = self.index_off + 16 * @as(usize, i);
        return .{
            .tag = readU32(self.bytes, base),
            .typ = readU32(self.bytes, base + 4),
            .offset = readU32(self.bytes, base + 8),
            .count = readU32(self.bytes, base + 12),
        };
    }

    /// Find the index entry for `tag`. Skips region tags (61/62/63).
    pub fn find(self: Header, tag: TagId) ?IndexEntry {
        const target = @intFromEnum(tag);
        var i: u32 = 0;
        while (i < self.index_count) : (i += 1) {
            const e = self.entry(i);
            if (e.tag == RPMTAG_HEADERIMAGE or
                e.tag == RPMTAG_HEADERSIGNATURES or
                e.tag == RPMTAG_HEADERIMMUTABLE) continue;
            if (e.tag == target) return e;
        }
        return null;
    }

    /// Get a STRING-typed tag as a slice into the blob.
    /// I18N_STRING tags return their first (English / "C" locale)
    /// entry. Returns null if the tag is missing or has the wrong type.
    pub fn getString(self: Header, tag: TagId) ?[]const u8 {
        const e = self.find(tag) orelse return null;
        return self.readString(e);
    }

    fn readString(self: Header, e: IndexEntry) ?[]const u8 {
        switch (@as(TypeId, @enumFromInt(e.typ))) {
            .string, .string_array, .i18n_string => {},
            else => return null,
        }
        const start = self.data_off + @as(usize, e.offset);
        if (start >= self.bytes.len) return null;
        const end = std.mem.indexOfScalarPos(u8, self.bytes, start, 0) orelse return null;
        return self.bytes[start..end];
    }

    /// Get an INT32-typed tag.
    pub fn getU32(self: Header, tag: TagId) ?u32 {
        const e = self.find(tag) orelse return null;
        if (@as(TypeId, @enumFromInt(e.typ)) != .int32) return null;
        const start = self.data_off + @as(usize, e.offset);
        if (start + 4 > self.bytes.len) return null;
        return readU32(self.bytes, start);
    }

    /// Get a BIN-typed tag as a slice into the blob. Used for raw
    /// binary payloads such as signature packets (sig_sigpgp,
    /// sig_dsa, sig_rsa, …) and stored digests (sig_sha1,
    /// sig_sha256).
    pub fn getBinary(self: Header, tag: TagId) ?[]const u8 {
        const e = self.find(tag) orelse return null;
        if (@as(TypeId, @enumFromInt(e.typ)) != .bin) return null;
        const start = self.data_off + @as(usize, e.offset);
        const end = start + e.count;
        if (end > self.bytes.len) return null;
        return self.bytes[start..end];
    }

    /// Count of entries in a STRING_ARRAY / I18N_STRING tag. Returns
    /// 0 when the tag is absent or of a different type.
    pub fn stringArrayCount(self: Header, tag: TagId) usize {
        const e = self.find(tag) orelse return 0;
        switch (@as(TypeId, @enumFromInt(e.typ))) {
            .string_array, .i18n_string => return e.count,
            else => return 0,
        }
    }

    /// Look up the `i`th entry of a STRING_ARRAY / I18N_STRING tag.
    /// O(i) — scans NULs from the start. Suitable for one-shot
    /// access; callers that iterate the whole array should keep a
    /// running offset themselves.
    pub fn stringArrayItem(self: Header, tag: TagId, i: usize) ?[]const u8 {
        const e = self.find(tag) orelse return null;
        switch (@as(TypeId, @enumFromInt(e.typ))) {
            .string_array, .i18n_string => {},
            else => return null,
        }
        if (i >= e.count) return null;
        var off = self.data_off + @as(usize, e.offset);
        var skipped: usize = 0;
        while (skipped < i) : (skipped += 1) {
            const next_nul = std.mem.indexOfScalarPos(u8, self.bytes, off, 0) orelse return null;
            off = next_nul + 1;
        }
        const end = std.mem.indexOfScalarPos(u8, self.bytes, off, 0) orelse return null;
        return self.bytes[off..end];
    }

    /// Look up the `i`th entry of an INT32 array tag.
    pub fn u32ArrayItem(self: Header, tag: TagId, i: usize) ?u32 {
        const e = self.find(tag) orelse return null;
        if (@as(TypeId, @enumFromInt(e.typ)) != .int32) return null;
        if (i >= e.count) return null;
        const start = self.data_off + @as(usize, e.offset) + i * 4;
        if (start + 4 > self.bytes.len) return null;
        return readU32(self.bytes, start);
    }

    /// Build the canonical NEVRA string `name-[epoch:]version-release[.arch]`.
    /// Epoch is included iff RPMTAG_EPOCH is present in the header.
    /// Arch is included iff RPMTAG_ARCH is present (which is not the
    /// case for `gpg-pubkey` rpmdb entries).
    ///
    /// Matches `headerGetAsString(h, RPMTAG_NEVRA)` for both normal
    /// packages (`bash-5.2.15-3.azl3.aarch64`) and pubkey records
    /// (`gpg-pubkey-3135ce90-5e6fda74`).
    ///
    /// Returns null only on missing NAME / VERSION / RELEASE — which
    /// should never happen in a well-formed rpmdb. Caller owns the
    /// returned slice.
    pub fn allocNevra(self: Header, alloc: std.mem.Allocator) std.mem.Allocator.Error!?[]u8 {
        const name = self.getString(.name) orelse return null;
        const version = self.getString(.version) orelse return null;
        const release = self.getString(.release) orelse return null;
        const arch = self.getString(.arch); // optional (gpg-pubkey lacks it)
        const epoch = self.getU32(.epoch);

        if (epoch) |ep| {
            if (arch) |a| {
                return try std.fmt.allocPrint(alloc, "{s}-{d}:{s}-{s}.{s}", .{
                    name, ep, version, release, a,
                });
            }
            return try std.fmt.allocPrint(alloc, "{s}-{d}:{s}-{s}", .{
                name, ep, version, release,
            });
        }
        if (arch) |a| {
            return try std.fmt.allocPrint(alloc, "{s}-{s}-{s}.{s}", .{
                name, version, release, a,
            });
        }
        return try std.fmt.allocPrint(alloc, "{s}-{s}-{s}", .{
            name, version, release,
        });
    }
};

fn readU32(buf: []const u8, off: usize) u32 {
    return @as(u32, buf[off]) << 24 |
        @as(u32, buf[off + 1]) << 16 |
        @as(u32, buf[off + 2]) << 8 |
        @as(u32, buf[off + 3]);
}

// --- tests ----------------------------------------------------------

test "parse rejects truncated" {
    try std.testing.expectError(error.Truncated, Header.parse(""));
    try std.testing.expectError(error.Truncated, Header.parse("\x00\x00\x00\x01"));
}

test "parse a minimal hand-built header" {
    // One entry: NAME (1000) -> "hello\0", type=string, count=1
    // nindex = 1, hsize = 6
    const blob = [_]u8{
        0,    0,    0,    1, // nindex
        0,    0,    0,    6, // hsize
        // index entry: tag=1000, type=6 (string), offset=0, count=1
        0,    0,    0x03, 0xe8,
        0,    0,    0,    6,
        0,    0,    0,    0,
        0,    0,    0,    1,
        // data: "hello\0"
        'h',  'e',  'l',  'l',
        'o',  0,
    };
    const h = try Header.parse(&blob);
    try std.testing.expectEqual(@as(u32, 1), h.index_count);
    try std.testing.expectEqualStrings("hello", h.getString(.name).?);
    try std.testing.expect(h.getString(.version) == null);
}

test "nevra with arch, no epoch" {
    // name=foo, version=1.0, release=2, arch=x86_64 → foo-1.0-2.x86_64
    const blob = [_]u8{
        0,    0,    0,    4,
        0,    0,    0,    16,
        // NAME    tag=1000  type=6  offset=0   count=1
        0, 0, 0x03, 0xe8, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 1,
        // VERSION tag=1001  type=6  offset=4   count=1
        0, 0, 0x03, 0xe9, 0, 0, 0, 6, 0, 0, 0, 4, 0, 0, 0, 1,
        // RELEASE tag=1002  type=6  offset=8   count=1
        0, 0, 0x03, 0xea, 0, 0, 0, 6, 0, 0, 0, 8, 0, 0, 0, 1,
        // ARCH    tag=1022  type=6  offset=10  count=1
        0, 0, 0x03, 0xfe, 0, 0, 0, 6, 0, 0, 0, 10, 0, 0, 0, 1,
        'f', 'o', 'o', 0,
        '1', '.', '0', 0,
        '2', 0,
        'x', '8', '6', '_', '6', '4', 0,
    };
    const h = try Header.parse(&blob);
    const nevra = (try h.allocNevra(std.testing.allocator)).?;
    defer std.testing.allocator.free(nevra);
    try std.testing.expectEqualStrings("foo-1.0-2.x86_64", nevra);
}

test "nevra without arch (gpg-pubkey style)" {
    const blob = [_]u8{
        // nindex=3, hsize=3+9+9 = 21? compute: "gpg-pubkey\0" (11) +
        // "3135ce90\0" (9) + "5e6fda74\0" (9) = 29
        0, 0, 0, 3,
        0, 0, 0, 29,
        // NAME    tag=1000  type=6  offset=0   count=1
        0, 0, 0x03, 0xe8, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 1,
        // VERSION tag=1001  type=6  offset=11  count=1
        0, 0, 0x03, 0xe9, 0, 0, 0, 6, 0, 0, 0, 11, 0, 0, 0, 1,
        // RELEASE tag=1002  type=6  offset=20  count=1
        0, 0, 0x03, 0xea, 0, 0, 0, 6, 0, 0, 0, 20, 0, 0, 0, 1,
        // data: gpg-pubkey\0 3135ce90\0 5e6fda74\0
        'g', 'p', 'g', '-', 'p', 'u', 'b', 'k', 'e', 'y', 0,
        '3', '1', '3', '5', 'c', 'e', '9', '0', 0,
        '5', 'e', '6', 'f', 'd', 'a', '7', '4', 0,
    };
    const h = try Header.parse(&blob);
    const nevra = (try h.allocNevra(std.testing.allocator)).?;
    defer std.testing.allocator.free(nevra);
    try std.testing.expectEqualStrings("gpg-pubkey-3135ce90-5e6fda74", nevra);
}

test "string array + u32 array + binary accessors" {
    // Build a header with one STRING_ARRAY tag (REQUIRENAME, 1049,
    // count=3), one INT32 array tag (REQUIREFLAGS, 1048, count=3),
    // one BIN tag (SIG_SHA256, 273, count=4).
    //
    // Data layout (relative to data_off, byte counts below):
    //   "libc\0glibc\0openssl\0"   (5+6+8 = 19 bytes)
    //   padding to next 4-byte boundary               (19 -> 20)
    //   INT32_be 0x08000000 0x04000008 0x02000000     (12 bytes)
    //   4 bytes of opaque SHA256 (truncated digest)   (4 bytes)
    //   total data = 36
    const blob = [_]u8{
        0, 0, 0, 3, // nindex = 3
        0, 0, 0, 36, // hsize = 36
        // REQUIRENAME tag=1049 type=8 (string_array) offset=0 count=3
        0, 0, 0x04, 0x19, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 3,
        // REQUIREFLAGS tag=1048 type=4 (int32) offset=20 count=3
        0, 0, 0x04, 0x18, 0, 0, 0, 4, 0, 0, 0, 20, 0, 0, 0, 3,
        // SIG_SHA256 tag=273 type=7 (bin) offset=32 count=4
        0, 0, 0x01, 0x11, 0, 0, 0, 7, 0, 0, 0, 32, 0, 0, 0, 4,
        // data starts here
        'l', 'i', 'b', 'c', 0,
        'g', 'l', 'i', 'b', 'c', 0,
        'o', 'p', 'e', 'n', 's', 's', 'l', 0,
        0, // padding to 4-byte alignment for the int32 array
        0, 0, 0, 0x08,
        0, 0, 0, 0x10,
        0, 0, 0, 0x02,
        0xde, 0xad, 0xbe, 0xef, // SIG_SHA256 (truncated)
    };
    const h = try Header.parse(&blob);

    try std.testing.expectEqual(@as(usize, 3), h.stringArrayCount(.requirename));
    try std.testing.expectEqualStrings("libc", h.stringArrayItem(.requirename, 0).?);
    try std.testing.expectEqualStrings("glibc", h.stringArrayItem(.requirename, 1).?);
    try std.testing.expectEqualStrings("openssl", h.stringArrayItem(.requirename, 2).?);
    try std.testing.expectEqual(@as(?[]const u8, null), h.stringArrayItem(.requirename, 3));

    try std.testing.expectEqual(@as(u32, 0x08), h.u32ArrayItem(.requireflags, 0).?);
    try std.testing.expectEqual(@as(u32, 0x10), h.u32ArrayItem(.requireflags, 1).?);
    try std.testing.expectEqual(@as(u32, 0x02), h.u32ArrayItem(.requireflags, 2).?);
    try std.testing.expectEqual(@as(?u32, null), h.u32ArrayItem(.requireflags, 3));

    const bin = h.getBinary(.sig_sha256).?;
    try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, bin);
}

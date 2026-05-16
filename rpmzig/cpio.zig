//! Minimal cpio "newc" format walker.
//!
//! cpio newc is the only archive format rpm uses for the payload (the
//! older "odc" format hasn't shipped in rpm packages for ~20 years).
//! Spec: https://www.kernel.org/pub/linux/utils/cpio/cpio.html
//!
//! Per-entry layout:
//!
//!   Header (110 ASCII bytes):
//!     c_magic     [6]   "070701"
//!     c_ino       [8]   hex
//!     c_mode      [8]   hex
//!     c_uid       [8]   hex
//!     c_gid       [8]   hex
//!     c_nlink     [8]   hex
//!     c_mtime     [8]   hex
//!     c_filesize  [8]   hex
//!     c_devmajor  [8]   hex
//!     c_devminor  [8]   hex
//!     c_rdevmajor [8]   hex
//!     c_rdevminor [8]   hex
//!     c_namesize  [8]   hex (includes the trailing NUL)
//!     c_check     [8]   "00000000"
//!   Name        [namesize]   null-terminated
//!   Padding     to 4-byte boundary from start of header
//!   Data        [filesize]
//!   Padding     to 4-byte boundary
//!
//! End marker: an entry whose name is "TRAILER!!!".

const std = @import("std");

pub const MAGIC = "070701";
pub const HEADER_SIZE: usize = 110;
const TRAILER = "TRAILER!!!";

pub const Error = error{
    Truncated,
    BadMagic,
    BadHexField,
};

pub const Entry = struct {
    /// Aliases into the underlying buffer; lifetime = walker's
    /// input slice. For rpm payloads, names are prefixed with "./"
    /// (rpm convention).
    name: []const u8,
    mode: u32,
    size: u32,
    uid: u32,
    gid: u32,
    mtime: u32,
    nlink: u32,
};

pub const Walker = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn init(buf: []const u8) Walker {
        return .{ .buf = buf };
    }

    /// Advance to the next entry. Returns null when the TRAILER!!!
    /// marker is hit.
    pub fn next(self: *Walker) Error!?Entry {
        if (self.pos + HEADER_SIZE > self.buf.len) return error.Truncated;
        const h = self.buf[self.pos..][0..HEADER_SIZE];
        if (!std.mem.eql(u8, h[0..6], MAGIC)) return error.BadMagic;

        const mode = try parseHex(h[14..22]);
        const uid = try parseHex(h[22..30]);
        const gid = try parseHex(h[30..38]);
        const nlink = try parseHex(h[38..46]);
        const mtime = try parseHex(h[46..54]);
        const filesize = try parseHex(h[54..62]);
        const namesize = try parseHex(h[94..102]);

        const name_start = self.pos + HEADER_SIZE;
        const name_end = name_start + namesize;
        if (name_end > self.buf.len) return error.Truncated;
        // Strip the trailing NUL from `namesize` for the returned slice.
        const name_slice = self.buf[name_start .. name_end - 1];

        // Advance past name + pad-to-4 boundary measured from header start.
        const after_name = roundUp4(name_end - self.pos) + self.pos;
        // Then past data + pad-to-4.
        const data_end = after_name + filesize;
        if (data_end > self.buf.len) return error.Truncated;
        const after_data = roundUp4(data_end - self.pos) + self.pos;
        self.pos = after_data;

        if (std.mem.eql(u8, name_slice, TRAILER)) return null;

        return .{
            .name = name_slice,
            .mode = mode,
            .size = filesize,
            .uid = uid,
            .gid = gid,
            .mtime = mtime,
            .nlink = nlink,
        };
    }
};

fn roundUp4(x: usize) usize {
    return (x + 3) & ~@as(usize, 3);
}

fn parseHex(s: []const u8) Error!u32 {
    var v: u32 = 0;
    for (s) |ch| {
        const digit: u32 = switch (ch) {
            '0'...'9' => ch - '0',
            'a'...'f' => ch - 'a' + 10,
            'A'...'F' => ch - 'A' + 10,
            else => return error.BadHexField,
        };
        v = (v << 4) | digit;
    }
    return v;
}

// ----- tests -----

test "parseHex" {
    try std.testing.expectEqual(@as(u32, 0), try parseHex("00000000"));
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), try parseHex("deadbeef"));
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), try parseHex("DEADBEEF"));
    try std.testing.expectError(error.BadHexField, parseHex("xxxxxxxx"));
}

test "roundUp4" {
    try std.testing.expectEqual(@as(usize, 0), roundUp4(0));
    try std.testing.expectEqual(@as(usize, 4), roundUp4(1));
    try std.testing.expectEqual(@as(usize, 4), roundUp4(4));
    try std.testing.expectEqual(@as(usize, 8), roundUp4(5));
}

test "walker — TRAILER only" {
    // A cpio with just the end-of-archive marker. namesize = 11
    // (10 chars of "TRAILER!!!" + 1 NUL); filesize = 0; mode = 0;
    // pad-to-4 from start of header: (110 + 11 = 121) → 124.
    var buf: [124]u8 = undefined;
    @memset(&buf, 0);
    @memcpy(buf[0..6], "070701");
    @memcpy(buf[6..14], "00000000");          // ino
    @memcpy(buf[14..22], "00000000");          // mode
    @memcpy(buf[22..30], "00000000");          // uid
    @memcpy(buf[30..38], "00000000");          // gid
    @memcpy(buf[38..46], "00000001");          // nlink
    @memcpy(buf[46..54], "00000000");          // mtime
    @memcpy(buf[54..62], "00000000");          // filesize
    @memcpy(buf[62..70], "00000000");          // devmajor
    @memcpy(buf[70..78], "00000000");          // devminor
    @memcpy(buf[78..86], "00000000");          // rdevmajor
    @memcpy(buf[86..94], "00000000");          // rdevminor
    @memcpy(buf[94..102], "0000000b");         // namesize = 11
    @memcpy(buf[102..110], "00000000");        // check
    @memcpy(buf[110..121], "TRAILER!!!\x00");
    // bytes 121..124 are padding

    var w: Walker = .init(&buf);
    try std.testing.expectEqual(@as(?Entry, null), try w.next());
}

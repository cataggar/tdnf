//! OpenPGP ASCII armor decoder (RFC 4880 §6.2).
//!
//! Strips the `-----BEGIN PGP …-----` / `-----END PGP …-----`
//! envelope, ignores any "Key: Value" armor headers, base64-decodes
//! the body, and verifies the trailing `=XXXX` CRC-24-OpenPGP
//! checksum line. Returns the raw OpenPGP packet stream that lives
//! inside an armored `gpg-pubkey-*` blob.
//!
//! This is PR #1 of the pure-Zig OpenPGP verifier plan (see
//! plan-pure-zig-pgp.md, section 5 Phase A). It is intentionally
//! self-contained — no other rpmzig module imports it yet. PR #5 will
//! wire it into libtdnf's package-signature verify path.

const std = @import("std");
const packet = @import("packet.zig");

/// Errors produced by `decode` / `decodeAny`.
pub const ArmorError = error{
    /// No `-----BEGIN PGP …-----` marker was found.
    NoHeader,
    /// No `-----END PGP …-----` marker was found after the body.
    NoFooter,
    /// The decoded body did not match the `=XXXX` CRC-24 checksum,
    /// or the checksum line is missing/malformed.
    BadCrc,
    /// The body contained characters outside the base64 alphabet
    /// (and outside the whitespace ignore set).
    InvalidBase64,
    /// Input ended mid-line before the BEGIN line was terminated.
    Truncated,
    /// BEGIN/END labels did not describe complete public-key blocks,
    /// or non-whitespace data appeared between concatenated blocks.
    BadFraming,
    /// Allocator failed.
    OutOfMemory,
};

/// Owned, freshly-allocated raw OpenPGP packet bytes. Caller must
/// call `deinit` (or free `bytes` directly).
pub const DecodedKey = struct {
    bytes: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *DecodedKey) void {
        self.allocator.free(self.bytes);
        self.bytes = &.{};
    }
};

/// Owned decoded blocks from concatenated public-key armor. Each block stays
/// separate so callers that need certificate boundaries can validate them
/// independently before combining any data.
pub const DecodedBlocks = struct {
    blocks: []DecodedKey,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *DecodedBlocks) void {
        for (self.blocks) |*block| block.deinit();
        self.allocator.free(self.blocks);
        self.blocks = &.{};
    }
};

const Crc24 = std.hash.crc.Crc24Openpgp;

/// Decode an ASCII-armored OpenPGP blob into raw packet bytes.
///
/// Accepts LF or CRLF line endings. Armor headers ("Version:",
/// "Comment:", …) between the BEGIN line and the body are skipped.
/// The trailing `=XXXX` checksum line is required and must match a
/// CRC-24-OpenPGP over the decoded bytes.
pub fn decode(allocator: std.mem.Allocator, armored: []const u8) ArmorError!DecodedKey {
    const begin_marker = "-----BEGIN PGP";
    const begin_idx = std.mem.indexOf(u8, armored, begin_marker) orelse return error.NoHeader;

    // Walk past the BEGIN line.
    var i = begin_idx;
    while (i < armored.len and armored[i] != '\n') : (i += 1) {}
    if (i >= armored.len) return error.Truncated;
    i += 1;

    // Skip armor headers up to (and including) the mandatory blank
    // separator line. Header lines have the shape "Key: Value"; the
    // separator is empty (after stripping CR).
    while (i < armored.len) {
        const line_start = i;
        while (i < armored.len and armored[i] != '\n') : (i += 1) {}
        var line_end = i;
        if (line_end > line_start and armored[line_end - 1] == '\r') line_end -= 1;
        const is_blank = line_end == line_start;
        if (i < armored.len) i += 1;
        if (is_blank) break;
    }

    // The body runs from here up to (but not including) the
    // checksum line. Locate the END marker first so we can bound the
    // search and surface NoFooter early on truncated input.
    const footer_marker = "-----END";
    const footer_idx = std.mem.indexOfPos(u8, armored, i, footer_marker) orelse return error.NoFooter;

    // Find the checksum line `=XXXX` between body and footer. RFC
    // 4880 requires the `=` to be the first character of a line, so
    // we scan for "\n=" (or accept `=` at i if the body is empty).
    var crc_line_start: ?usize = null;
    if (i < footer_idx and armored[i] == '=') {
        crc_line_start = i;
    } else {
        var scan = i;
        while (scan + 1 < footer_idx) : (scan += 1) {
            if (armored[scan] == '\n' and armored[scan + 1] == '=') {
                crc_line_start = scan + 1;
                break;
            }
        }
    }
    const crc_start = crc_line_start orelse return error.BadCrc;

    // crc_b64 = the 4 base64 chars after '='. Trim trailing CR.
    var crc_end = crc_start + 1;
    while (crc_end < footer_idx and armored[crc_end] != '\n' and armored[crc_end] != '\r') : (crc_end += 1) {}
    const crc_b64 = armored[crc_start + 1 .. crc_end];
    if (crc_b64.len != 4) return error.BadCrc;
    for (armored[crc_end..footer_idx]) |ch| {
        if (!std.ascii.isWhitespace(ch)) return error.BadFraming;
    }

    var crc_bytes: [3]u8 = undefined;
    std.base64.standard.Decoder.decode(&crc_bytes, crc_b64) catch return error.BadCrc;
    const expected_crc: u24 =
        (@as(u24, crc_bytes[0]) << 16) |
        (@as(u24, crc_bytes[1]) << 8) |
        @as(u24, crc_bytes[2]);

    // Decode the body, ignoring whitespace. We over-allocate based
    // on the input length, decode, verify the CRC, and only then
    // dupe a tightly-sized buffer for the caller — this keeps the
    // ownership story simple (one allocation, one free) regardless
    // of which error path we hit.
    const body = armored[i..crc_start];
    const decoder = std.base64.standard.decoderWithIgnore(" \r\n\t");
    const upper = decoder.calcSizeUpperBound(body.len);
    const scratch = try allocator.alloc(u8, upper);
    defer allocator.free(scratch);
    const decoded_len = decoder.decode(scratch, body) catch return error.InvalidBase64;

    // Verify CRC-24-OpenPGP before transferring ownership.
    var crc = Crc24.init();
    crc.update(scratch[0..decoded_len]);
    if (crc.final() != expected_crc) return error.BadCrc;

    const out = try allocator.dupe(u8, scratch[0..decoded_len]);
    return DecodedKey{ .bytes = out, .allocator = allocator };
}

/// Decode one or more concatenated ASCII-armored public-key blocks.
///
/// Unlike `decode`, this validates the exact public-key BEGIN/END
/// labels and rejects non-whitespace between blocks. Each block's
/// CRC-24 is checked before any decoded bytes are returned.
pub fn decodeAll(allocator: std.mem.Allocator, armored: []const u8) ArmorError!DecodedKey {
    var blocks = try decodeBlocks(allocator, armored);
    defer blocks.deinit();

    var decoded = std.array_list.Managed(u8).init(allocator);
    errdefer decoded.deinit();
    for (blocks.blocks) |block| try decoded.appendSlice(block.bytes);

    return .{
        .bytes = try decoded.toOwnedSlice(),
        .allocator = allocator,
    };
}

/// Decode one or more public-key armor blocks without erasing their
/// boundaries. This is used by certificate import, where every armor block
/// must independently begin with a primary key packet.
pub fn decodeBlocks(
    allocator: std.mem.Allocator,
    armored: []const u8,
) ArmorError!DecodedBlocks {
    const begin_line = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    const end_line = "-----END PGP PUBLIC KEY BLOCK-----";

    var blocks = std.array_list.Managed(DecodedKey).init(allocator);
    errdefer {
        for (blocks.items) |*block| block.deinit();
        blocks.deinit();
    }

    var pos: usize = 0;
    while (true) {
        while (pos < armored.len and std.ascii.isWhitespace(armored[pos])) : (pos += 1) {}
        if (pos == armored.len) break;
        if (!std.mem.startsWith(u8, armored[pos..], begin_line)) return error.BadFraming;

        const begin_end = lineEnd(armored, pos) orelse return error.Truncated;
        if (!std.mem.eql(u8, trimCr(armored[pos..begin_end]), begin_line))
            return error.BadFraming;

        const end_start = findExactLine(armored, begin_end + 1, end_line) orelse
            return error.NoFooter;
        const end_end = lineEndOrEof(armored, end_start);
        if (!std.mem.eql(u8, trimCr(armored[end_start..end_end]), end_line))
            return error.BadFraming;
        var block = try decode(allocator, armored[pos..end_end]);
        errdefer block.deinit();
        var packets = packet.iterate(block.bytes);
        const first = packets.next() catch return error.BadFraming;
        if (first == null or first.?.tag != .public_key)
            return error.BadFraming;
        try blocks.append(block);

        pos = end_end;
        if (pos < armored.len and armored[pos] == '\r') pos += 1;
        if (pos < armored.len and armored[pos] == '\n') pos += 1;
    }
    if (blocks.items.len == 0) return error.NoHeader;

    return .{
        .blocks = try blocks.toOwnedSlice(),
        .allocator = allocator,
    };
}

/// Convenience wrapper that accepts either ASCII armor or a raw
/// binary OpenPGP packet stream. Detects armor by looking for
/// `-----BEGIN PGP` as the first non-whitespace token; otherwise
/// returns a freshly-allocated copy of the input so callers always
/// own the returned buffer.
pub fn decodeAny(allocator: std.mem.Allocator, blob: []const u8) ArmorError!DecodedKey {
    if (looksLikeArmor(blob)) return decodeAll(allocator, blob);
    const copy = try allocator.dupe(u8, blob);
    return DecodedKey{ .bytes = copy, .allocator = allocator };
}

pub fn looksLikeArmor(blob: []const u8) bool {
    var idx: usize = 0;
    while (idx < blob.len) : (idx += 1) {
        switch (blob[idx]) {
            ' ', '\t', '\r', '\n' => continue,
            else => return std.mem.startsWith(u8, blob[idx..], "-----BEGIN PGP"),
        }
    }
    return false;
}

fn lineEnd(input: []const u8, start: usize) ?usize {
    return std.mem.indexOfScalarPos(u8, input, start, '\n');
}

fn lineEndOrEof(input: []const u8, start: usize) usize {
    return lineEnd(input, start) orelse input.len;
}

fn trimCr(line: []const u8) []const u8 {
    return if (line.len != 0 and line[line.len - 1] == '\r')
        line[0 .. line.len - 1]
    else
        line;
}

fn findExactLine(input: []const u8, start: usize, wanted: []const u8) ?usize {
    var pos = start;
    while (pos < input.len) {
        const end = lineEndOrEof(input, pos);
        if (std.mem.eql(u8, trimCr(input[pos..end]), wanted)) return pos;
        if (end == input.len) return null;
        pos = end + 1;
    }
    return null;
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

const testing = std.testing;
const microsoft_key = @embedFile("testdata/microsoft-rpm-key.asc");

test "decode happy path: Microsoft RPM GPG key" {
    var key = try decode(testing.allocator, microsoft_key);
    defer key.deinit();

    try testing.expect(key.bytes.len > 0);
    // First packet must be Tag 6 (Public-Key). Acceptable framings:
    //   0x98 = old-format Tag 6, 1-octet length
    //   0x99 = old-format Tag 6, 2-octet length
    //   0xC6 = new-format Tag 6
    const tag = key.bytes[0];
    try testing.expect(tag == 0x98 or tag == 0x99 or tag == 0xC6);
}

test "decode bad CRC" {
    // Flip a byte inside the base64 body. Find the first 'm' after
    // the blank line separator (the body begins with `mQEN…` in the
    // Microsoft key) and swap it for another valid base64 char so
    // the input is still well-formed base64 but the CRC fails.
    var copy = try testing.allocator.dupe(u8, microsoft_key);
    defer testing.allocator.free(copy);

    const body_start = std.mem.indexOf(u8, copy, "mQEN") orelse return error.TestUnexpectedResult;
    copy[body_start] = 'n'; // still valid base64, different bits

    try testing.expectError(error.BadCrc, decode(testing.allocator, copy));
}

test "decode missing footer" {
    const end_idx = std.mem.indexOf(u8, microsoft_key, "-----END") orelse return error.TestUnexpectedResult;
    const truncated = microsoft_key[0..end_idx];

    try testing.expectError(error.NoFooter, decode(testing.allocator, truncated));
}

test "decode handles CRLF line endings" {
    // Re-emit the fixture with \n -> \r\n.
    var crlf = std.array_list.Managed(u8).init(testing.allocator);
    defer crlf.deinit();
    for (microsoft_key) |c| {
        if (c == '\n') try crlf.append('\r');
        try crlf.append(c);
    }

    var key = try decode(testing.allocator, crlf.items);
    defer key.deinit();
    try testing.expect(key.bytes.len > 0);
}

test "decodeAny passes binary input through unchanged" {
    // Fake old-format Tag 6 (Public-Key): 0x98 = tag byte, 0x01 =
    // 1-byte body length, then version=4 and one padding byte.
    const binary = [_]u8{ 0x98, 0x01, 0x04, 0x00 };

    var out = try decodeAny(testing.allocator, &binary);
    defer out.deinit();

    try testing.expectEqualSlices(u8, &binary, out.bytes);
    // Must be a fresh allocation, not a borrow of the input.
    try testing.expect(@intFromPtr(out.bytes.ptr) != @intFromPtr(&binary[0]));
}

test "decodeAny on armored input matches decode" {
    var a = try decodeAny(testing.allocator, microsoft_key);
    defer a.deinit();
    var b = try decode(testing.allocator, microsoft_key);
    defer b.deinit();
    try testing.expectEqualSlices(u8, b.bytes, a.bytes);
}

test "decode rejects input with no BEGIN line" {
    try testing.expectError(error.NoHeader, decode(testing.allocator, "just some bytes\n"));
}

test "decodeAll accepts concatenated CRLF blocks" {
    var input = std.array_list.Managed(u8).init(testing.allocator);
    defer input.deinit();
    for (0..2) |_| {
        for (microsoft_key) |ch| {
            if (ch == '\n') try input.append('\r');
            try input.append(ch);
        }
    }

    var keys = try decodeAll(testing.allocator, input.items);
    defer keys.deinit();
    var one = try decode(testing.allocator, microsoft_key);
    defer one.deinit();
    try testing.expectEqual(one.bytes.len * 2, keys.bytes.len);
    try testing.expectEqualSlices(u8, one.bytes, keys.bytes[0..one.bytes.len]);
    try testing.expectEqualSlices(u8, one.bytes, keys.bytes[one.bytes.len..]);
}

test "decodeAll rejects mismatched framing" {
    var copy = try testing.allocator.dupe(u8, microsoft_key);
    defer testing.allocator.free(copy);
    const end = std.mem.indexOf(u8, copy, "-----END PGP PUBLIC KEY BLOCK-----") orelse
        return error.TestUnexpectedResult;
    copy[end + "-----END PGP ".len] = 'X';
    try testing.expectError(error.NoFooter, decodeAll(testing.allocator, copy));
}

test "decodeAll rejects data between CRC and footer" {
    const footer = std.mem.indexOf(
        u8,
        microsoft_key,
        "-----END PGP PUBLIC KEY BLOCK-----",
    ) orelse return error.TestUnexpectedResult;
    var input = std.array_list.Managed(u8).init(testing.allocator);
    defer input.deinit();
    try input.appendSlice(microsoft_key[0..footer]);
    try input.appendSlice("junk\n");
    try input.appendSlice(microsoft_key[footer..]);

    try testing.expectError(
        error.BadFraming,
        decodeAll(testing.allocator, input.items),
    );
}

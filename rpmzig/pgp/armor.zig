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
//! wire it into the verify path under `-Drpmzig-verify=true`.

const std = @import("std");

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

/// Convenience wrapper that accepts either ASCII armor or a raw
/// binary OpenPGP packet stream. Detects armor by looking for
/// `-----BEGIN PGP` as the first non-whitespace token; otherwise
/// returns a freshly-allocated copy of the input so callers always
/// own the returned buffer.
pub fn decodeAny(allocator: std.mem.Allocator, blob: []const u8) ArmorError!DecodedKey {
    if (looksLikeArmor(blob)) return decode(allocator, blob);
    const copy = try allocator.dupe(u8, blob);
    return DecodedKey{ .bytes = copy, .allocator = allocator };
}

fn looksLikeArmor(blob: []const u8) bool {
    var idx: usize = 0;
    while (idx < blob.len) : (idx += 1) {
        switch (blob[idx]) {
            ' ', '\t', '\r', '\n' => continue,
            else => return std.mem.startsWith(u8, blob[idx..], "-----BEGIN PGP"),
        }
    }
    return false;
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

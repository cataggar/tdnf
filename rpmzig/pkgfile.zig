//! `.rpm` file parser.
//!
//! Reads the lead + signature header + main header from a `.rpm`
//! file and exposes:
//!   - the parsed main header (for NEVRA, file lists, deps, etc.)
//!   - the offset and size of the payload in the underlying buffer
//!   - the payload compressor name ("gzip", "xz", "zstd", "lzma",
//!     "lz4", "bzip2", or "none")
//!
//! File layout:
//!
//!   Lead       (96 bytes; magic ed ab ee db; mostly historical)
//!   SigHeader  (header v3 + 8-byte magic + pad to 8-byte boundary)
//!   MainHeader (header v3 + 8-byte magic)
//!   Payload    (cpio archive, possibly gzip/xz/zstd-compressed)
//!
//! The signature header's pad-to-8 alignment is applied to its
//! *end* — i.e. the main header always starts on an 8-byte boundary
//! relative to file offset 0.
//!
//! This module reads the *whole* file into a single heap buffer
//! today. Streaming/mmap can come later; typical `.rpm` files are
//! well under 100 MB.

const std = @import("std");
const header = @import("header.zig");

const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("sys/stat.h");
});

const LEAD_SIZE: usize = 96;
const LEAD_MAGIC = [_]u8{ 0xed, 0xab, 0xee, 0xdb };

pub const Compressor = enum {
    none,
    gzip,
    bzip2,
    xz,
    lzma,
    zstd,
    lz4,
    unknown,

    pub fn fromString(s: []const u8) Compressor {
        if (s.len == 0) return .none;
        if (std.mem.eql(u8, s, "none")) return .none;
        if (std.mem.eql(u8, s, "gzip")) return .gzip;
        if (std.mem.eql(u8, s, "bzip2")) return .bzip2;
        if (std.mem.eql(u8, s, "xz")) return .xz;
        if (std.mem.eql(u8, s, "lzma")) return .lzma;
        if (std.mem.eql(u8, s, "zstd")) return .zstd;
        if (std.mem.eql(u8, s, "lz4")) return .lz4;
        return .unknown;
    }

    pub fn name(self: Compressor) []const u8 {
        return switch (self) {
            .none => "none",
            .gzip => "gzip",
            .bzip2 => "bzip2",
            .xz => "xz",
            .lzma => "lzma",
            .zstd => "zstd",
            .lz4 => "lz4",
            .unknown => "unknown",
        };
    }
};

pub const Error = error{
    OpenFailed,
    StatFailed,
    ReadFailed,
    BadLeadMagic,
    HeaderParseFailed,
    OutOfMemory,
    UnsupportedCompressor,
    DecompressFailed,
};

pub const RpmFile = struct {
    /// Heap-allocated copy of the entire file. Sig/main headers and
    /// payload all alias into this slice.
    bytes: []u8,
    /// Signature header (parsed at open time). Used by T3 to verify
    /// the package's GPG signature; for now we just expose presence
    /// via `signatureKind()`.
    sig: header.Header,
    main: header.Header,
    /// Offset of the main header (including its 8-byte standalone
    /// magic) in `bytes`. RSA/DSA signatures cover the byte range
    /// `[main_header_offset, payload_offset)`; PGP/GPG signatures
    /// cover `[main_header_offset, end-of-file)`.
    main_header_offset: usize,
    /// Offset of the payload in `bytes` (relative to bytes[0]).
    payload_offset: usize,
    /// Compressor declared by `RPMTAG_PAYLOADCOMPRESSOR` (defaults to
    /// `.gzip` per the rpm spec when absent).
    compressor: Compressor,

    /// Open and read a `.rpm` file via libc stdio. Returns an
    /// initialised RpmFile that owns the heap buffer.
    pub fn open(alloc: std.mem.Allocator, path: [:0]const u8) Error!RpmFile {
        var st: c.struct_stat = undefined;
        if (c.stat(path.ptr, &st) != 0) return error.StatFailed;
        const size: usize = @intCast(st.st_size);
        if (size == 0) return error.BadLeadMagic;

        const fp = c.fopen(path.ptr, "rb") orelse return error.OpenFailed;
        defer _ = c.fclose(fp);

        const buf = alloc.alloc(u8, size) catch return error.OutOfMemory;
        errdefer alloc.free(buf);

        const got = c.fread(buf.ptr, 1, size, fp);
        if (got != size) return error.ReadFailed;

        return parseBytes(buf);
    }

    pub fn close(self: *RpmFile, alloc: std.mem.Allocator) void {
        alloc.free(self.bytes);
        self.bytes = &.{};
    }

    /// Parse a `.rpm` file already loaded into `buf`. The RpmFile
    /// takes ownership of `buf` (i.e. `close` will free it).
    pub fn parseBytes(buf: []u8) Error!RpmFile {
        if (buf.len < LEAD_SIZE) return error.BadLeadMagic;
        if (!std.mem.eql(u8, buf[0..LEAD_MAGIC.len], &LEAD_MAGIC)) {
            return error.BadLeadMagic;
        }

        // Signature header starts at byte 96.
        const sig_start = LEAD_SIZE;
        if (buf.len < sig_start + 16) return error.HeaderParseFailed;
        const sig_info = header.Header.parseStandalone(buf[sig_start..]) catch
            return error.HeaderParseFailed;

        // Pad to 8-byte boundary at the end of the sig header.
        const main_start = roundUp8(sig_start + sig_info.on_disk_size);
        if (buf.len < main_start + 16) return error.HeaderParseFailed;

        const main_info = header.Header.parseStandalone(buf[main_start..]) catch
            return error.HeaderParseFailed;

        // Payload starts immediately after the main header (no
        // alignment padding here, unlike between sig and main).
        const payload_offset = main_start + main_info.on_disk_size;

        const compressor: Compressor = if (main_info.header.getString(.payload_compressor)) |s|
            Compressor.fromString(s)
        else
            .gzip; // rpm spec: default is gzip when the tag is absent

        return .{
            .bytes = buf,
            .sig = sig_info.header,
            .main = main_info.header,
            .main_header_offset = main_start,
            .payload_offset = payload_offset,
            .compressor = compressor,
        };
    }

    pub fn allocNevra(self: RpmFile, alloc: std.mem.Allocator) std.mem.Allocator.Error!?[]u8 {
        return self.main.allocNevra(alloc);
    }

    /// The kind of signature carried on this rpm's sig header.
    pub const SignatureKind = enum {
        none,
        rsa,
        dsa,
        pgp,
        gpg,
        openpgp,

        pub fn name(self: SignatureKind) []const u8 {
            return switch (self) {
                .none => "none",
                .rsa => "rsa",
                .dsa => "dsa",
                .pgp => "pgp",
                .gpg => "gpg",
                .openpgp => "openpgp",
            };
        }
    };

    /// Returns the kind of signature carried in the sig header.
    /// Checks tags in priority order: RSA → DSA → PGP → GPG →
    /// OpenPGP. Returns `.none` if no signature tag is present.
    pub fn signatureKind(self: RpmFile) SignatureKind {
        if (self.sig.getBinaryRaw(@intFromEnum(header.SigTagId.rsa)) != null) return .rsa;
        if (self.sig.getBinaryRaw(@intFromEnum(header.SigTagId.dsa)) != null) return .dsa;
        if (self.sig.getBinaryRaw(@intFromEnum(header.SigTagId.pgp)) != null) return .pgp;
        if (self.sig.getBinaryRaw(@intFromEnum(header.SigTagId.gpg)) != null) return .gpg;
        if (self.sig.getBinaryRaw(@intFromEnum(header.SigTagId.openpgp)) != null) return .openpgp;
        return .none;
    }

    /// Returns true iff the signature header carries any of the known
    /// GPG/RSA/DSA signature payloads.
    pub fn isSigned(self: RpmFile) bool {
        return self.signatureKind() != .none;
    }

    /// Returns the signature payload bytes from the sig header and
    /// the byte range of the rpm file that those signature bytes
    /// cover.
    ///
    /// Returns null if the rpm carries no signature.
    pub fn signatureSlice(self: RpmFile) ?struct { sig: []const u8, signed: []const u8 } {
        const kind = self.signatureKind();
        const tag: u32 = switch (kind) {
            .none => return null,
            .rsa => @intFromEnum(header.SigTagId.rsa),
            .dsa => @intFromEnum(header.SigTagId.dsa),
            .pgp => @intFromEnum(header.SigTagId.pgp),
            .gpg => @intFromEnum(header.SigTagId.gpg),
            .openpgp => @intFromEnum(header.SigTagId.openpgp),
        };
        const sig_bytes = self.sig.getBinaryRaw(tag) orelse return null;
        const signed_end: usize = switch (kind) {
            // RSA / DSA: cover only the main header (with magic).
            .rsa, .dsa => self.payload_offset,
            // PGP / GPG / OpenPGP: cover main header + payload.
            .pgp, .gpg, .openpgp => self.bytes.len,
            .none => unreachable,
        };
        return .{
            .sig = sig_bytes,
            .signed = self.bytes[self.main_header_offset..signed_end],
        };
    }

    /// Decompress the payload (cpio archive) into a freshly allocated
    /// slice. Caller frees with `alloc.free`.
    ///
    /// Supports gzip, xz, zstd, and lzma. bzip2 and lz4 are returned
    /// as `error.UnsupportedCompressor` — neither is part of Zig
    /// std's decompressor set, and neither is the default on any rpm
    /// distro tdnf targets.
    pub fn decompressPayload(self: RpmFile, alloc: std.mem.Allocator) Error![]u8 {
        const payload = self.bytes[self.payload_offset..];
        return decompressSlice(alloc, payload, self.compressor);
    }
};

fn decompressSlice(
    alloc: std.mem.Allocator,
    payload: []const u8,
    compressor: Compressor,
) Error![]u8 {
    var input = std.Io.Reader.fixed(payload);

    switch (compressor) {
        .none => {
            const out = alloc.alloc(u8, payload.len) catch return error.OutOfMemory;
            @memcpy(out, payload);
            return out;
        },
        .gzip => {
            var decoder: std.compress.flate.Decompress = .init(&input, .gzip, &.{});
            return decoder.reader.allocRemaining(alloc, .unlimited) catch error.DecompressFailed;
        },
        .zstd => {
            var decoder: std.compress.zstd.Decompress = .init(&input, &.{}, .{});
            return decoder.reader.allocRemaining(alloc, .unlimited) catch error.DecompressFailed;
        },
        .xz => {
            // xz Decompress takes ownership of an initially-empty
            // heap buffer that it grows as the LZMA2 dictionary
            // size requires (block-by-block; up to 4 GB worst case).
            const start_buf = alloc.alloc(u8, 0) catch return error.OutOfMemory;
            var decoder = std.compress.xz.Decompress.init(&input, alloc, start_buf) catch
                return error.DecompressFailed;
            // Decompress will realloc start_buf as needed; we don't free it ourselves.
            return decoder.reader.allocRemaining(alloc, .unlimited) catch error.DecompressFailed;
        },
        .lzma,
        .bzip2,
        .lz4,
        .unknown,
        => return error.UnsupportedCompressor,
    }
}

fn roundUp8(x: usize) usize {
    return (x + 7) & ~@as(usize, 7);
}

test "roundUp8" {
    try std.testing.expectEqual(@as(usize, 0), roundUp8(0));
    try std.testing.expectEqual(@as(usize, 8), roundUp8(1));
    try std.testing.expectEqual(@as(usize, 8), roundUp8(8));
    try std.testing.expectEqual(@as(usize, 16), roundUp8(9));
    try std.testing.expectEqual(@as(usize, 16), roundUp8(15));
    try std.testing.expectEqual(@as(usize, 16), roundUp8(16));
}

test "Compressor.fromString" {
    try std.testing.expectEqual(Compressor.gzip, Compressor.fromString("gzip"));
    try std.testing.expectEqual(Compressor.zstd, Compressor.fromString("zstd"));
    try std.testing.expectEqual(Compressor.xz, Compressor.fromString("xz"));
    try std.testing.expectEqual(Compressor.none, Compressor.fromString(""));
    try std.testing.expectEqual(Compressor.unknown, Compressor.fromString("bogus"));
}

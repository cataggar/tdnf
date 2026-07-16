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
const header = @import("rpm_header");

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

pub const PackageKind = enum {
    binary,
    source,
    nosrc,
};

pub const MetadataError = error{
    InvalidMetadata,
    InvalidPackageKind,
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
    kind: PackageKind,

    /// Open and read a `.rpm` file via libc stdio. Returns an
    /// initialised RpmFile that owns the heap buffer.
    pub fn open(alloc: std.mem.Allocator, path: [:0]const u8) Error!RpmFile {
        var st: c.struct_stat = undefined;
        if (c.stat(path.ptr, &st) != 0) return error.StatFailed;
        if (st.st_size < 0) return error.StatFailed;
        const size = std.math.cast(usize, st.st_size) orelse
            return error.StatFailed;
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
        _ = try parseLead(buf);

        // Signature header starts at byte 96.
        const sig_start = LEAD_SIZE;
        if (!rangeFits(sig_start, 16, buf.len)) return error.HeaderParseFailed;
        const sig_info = header.Header.parseStandaloneWithRegionCoverage(
            buf[sig_start..],
            .signatures,
            false,
        ) catch
            return error.HeaderParseFailed;

        // Pad to 8-byte boundary at the end of the sig header.
        const sig_end = std.math.add(usize, sig_start, sig_info.on_disk_size) catch
            return error.HeaderParseFailed;
        const main_start = roundUp8Checked(sig_end) orelse
            return error.HeaderParseFailed;
        if (main_start > buf.len) return error.HeaderParseFailed;
        for (buf[sig_end..main_start]) |padding| {
            if (padding != 0) return error.HeaderParseFailed;
        }
        if (!rangeFits(main_start, 16, buf.len)) return error.HeaderParseFailed;

        const main_info = header.Header.parseStandaloneWithRegion(
            buf[main_start..],
            .immutable,
        ) catch
            return error.HeaderParseFailed;

        // Payload starts immediately after the main header (no
        // alignment padding here, unlike between sig and main).
        const payload_offset = std.math.add(
            usize,
            main_start,
            main_info.on_disk_size,
        ) catch return error.HeaderParseFailed;
        if (payload_offset > buf.len) return error.HeaderParseFailed;

        validateSignatureMetadata(sig_info.header) catch
            return error.HeaderParseFailed;
        const kind = validatePackageMetadata(main_info.header) catch
            return error.HeaderParseFailed;
        const compressor_string = main_info.header.getStringChecked(.payload_compressor) catch
            return error.HeaderParseFailed;
        const compressor: Compressor = if (compressor_string) |value|
            Compressor.fromString(value)
        else
            // The rpm format specifies gzip when the tag is genuinely absent.
            // A present malformed tag was rejected above rather than defaulted.
            .gzip;

        return .{
            .bytes = buf,
            .sig = sig_info.header,
            .main = main_info.header,
            .main_header_offset = main_start,
            .payload_offset = payload_offset,
            .compressor = compressor,
            .kind = kind,
        };
    }

    pub fn packageKind(self: RpmFile) PackageKind {
        return self.kind;
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
    /// RPM6 OPENPGP arrays take precedence, followed by the historical
    /// deterministic RSA → DSA → PGP → GPG compatibility order.
    pub fn signatureKind(self: RpmFile) SignatureKind {
        const openpgp_count = self.sig.stringArrayCountRawChecked(
            @intFromEnum(header.SigTagId.openpgp),
        ) catch null;
        if (openpgp_count != null and openpgp_count.? != 0) return .openpgp;
        if (self.sig.getBinaryRaw(@intFromEnum(header.SigTagId.rsa)) != null) return .rsa;
        if (self.sig.getBinaryRaw(@intFromEnum(header.SigTagId.dsa)) != null) return .dsa;
        if (self.sig.getBinaryRaw(@intFromEnum(header.SigTagId.pgp)) != null) return .pgp;
        if (self.sig.getBinaryRaw(@intFromEnum(header.SigTagId.gpg)) != null) return .gpg;
        return .none;
    }

    /// Returns true iff the signature header carries any of the known
    /// GPG/RSA/DSA signature payloads.
    pub fn isSigned(self: RpmFile) bool {
        return self.hasSignatureCandidate();
    }

    /// Returns true when the signature header contains any recognized
    /// signature namespace, including a malformed candidate.  Callers use
    /// this to distinguish an unsigned RPM from a signed RPM whose signature
    /// must be rejected by the integrity verifier.
    pub fn hasSignatureCandidate(self: RpmFile) bool {
        const known_tags = [_]header.SigTagId{
            .openpgp,
            .rsa,
            .dsa,
            .pgp,
            .gpg,
        };
        for (known_tags) |tag| {
            if (self.sig.findRaw(@intFromEnum(tag)) != null) return true;
        }
        return false;
    }

    /// Returns the signature payload bytes from the sig header and
    /// the byte range of the rpm file that those signature bytes
    /// cover.
    ///
    /// Returns null if the rpm carries no signature, or if OPENPGP is
    /// selected: this borrowed single-slice API cannot base64-decode or
    /// represent an array of independent signatures. Use integrity.zig's
    /// signature candidate API for RPM6 packages.
    pub fn signatureSlice(self: RpmFile) ?struct { sig: []const u8, signed: []const u8 } {
        const legacy = [_]struct {
            kind: SignatureKind,
            tag: u32,
        }{
            .{ .kind = .rsa, .tag = @intFromEnum(header.SigTagId.rsa) },
            .{ .kind = .dsa, .tag = @intFromEnum(header.SigTagId.dsa) },
            .{ .kind = .pgp, .tag = @intFromEnum(header.SigTagId.pgp) },
            .{ .kind = .gpg, .tag = @intFromEnum(header.SigTagId.gpg) },
        };
        var kind: SignatureKind = .none;
        var sig_bytes: []const u8 = undefined;
        for (legacy) |candidate| {
            if (self.sig.getBinaryRaw(candidate.tag)) |bytes| {
                kind = candidate.kind;
                sig_bytes = bytes;
                break;
            }
        }
        if (kind == .none) return null;
        const signed_end: usize = switch (kind) {
            // RSA / DSA: cover only the main header (with magic).
            .rsa, .dsa => self.payload_offset,
            // PGP / GPG cover main header + payload.
            .pgp, .gpg => self.bytes.len,
            .openpgp => unreachable,
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

const Lead = struct {
    major: u8,
    minor: u8,
    package_type: u16,
    arch: u16,
    name: []const u8,
    os: u16,
    signature_type: u16,
    reserved: []const u8,
};

fn parseLead(buf: []const u8) Error!Lead {
    if (buf.len < LEAD_SIZE) return error.BadLeadMagic;
    if (!std.mem.eql(u8, buf[0..LEAD_MAGIC.len], &LEAD_MAGIC))
        return error.BadLeadMagic;

    // rpmLeadRead() deliberately treats every field except magic as
    // informational legacy data. Decode all 96 bytes so field boundaries are
    // checked, but do not reject odd versions, package types, names, arches,
    // OS values, signature types, or reserved bytes that upstream accepts.
    return .{
        .major = buf[4],
        .minor = buf[5],
        .package_type = readU16(buf, 6),
        .arch = readU16(buf, 8),
        .name = buf[10..76],
        .os = readU16(buf, 76),
        .signature_type = readU16(buf, 78),
        .reserved = buf[80..96],
    };
}

pub fn classifyPackage(h: header.Header) MetadataError!PackageKind {
    const source_count = try optionalCount(h, .sourcepackage, .int32);
    if (source_count) |count| {
        if (count != 1) return error.InvalidMetadata;
    }
    const nosource_count = try optionalCount(h, .nosource, .int32);
    const source_rpm_count = try optionalCount(h, .source_rpm, .string);
    if (source_rpm_count) |count| {
        if (count != 1) return error.InvalidMetadata;
    }

    if (nosource_count != null and source_count == null)
        return error.InvalidPackageKind;
    if (source_count != null and source_rpm_count != null)
        return error.InvalidPackageKind;
    if (source_count != null)
        return if (nosource_count != null) .nosrc else .source;
    return .binary;
}

fn validateSignatureMetadata(h: header.Header) MetadataError!void {
    if (h.findRaw(@intFromEnum(header.SigTagId.reserved)) != null and
        !h.hasStrictlyIncreasingDataTags())
    {
        return error.InvalidMetadata;
    }
}

fn validatePackageMetadata(h: header.Header) MetadataError!PackageKind {
    try requireScalar(h, .name, .string);
    try requireScalar(h, .version, .string);
    try requireScalar(h, .release, .string);
    try requireScalar(h, .arch, .string);

    const optional_strings = [_]header.TagId{
        .source_rpm,
        .payload_format,
        .payload_compressor,
        .payload_flags,
    };
    for (optional_strings) |tag| try optionalScalar(h, tag, .string);
    try optionalScalar(h, .epoch, .int32);
    try optionalScalar(h, .sourcepackage, .int32);
    _ = try optionalCount(h, .nosource, .int32);

    const localized_strings = [_]header.TagId{ .summary, .description, .group };
    for (localized_strings) |tag| {
        const e = h.find(tag) orelse continue;
        if (e.typ != @intFromEnum(header.TypeId.string) and
            e.typ != @intFromEnum(header.TypeId.i18n_string))
        {
            return error.InvalidMetadata;
        }
        if (e.typ == @intFromEnum(header.TypeId.string) and e.count != 1)
            return error.InvalidMetadata;
    }

    const dependencies = [_][3]header.TagId{
        .{ .requirename, .requireversion, .requireflags },
        .{ .providename, .provideversion, .provideflags },
        .{ .conflictname, .conflictversion, .conflictflags },
        .{ .obsoletename, .obsoleteversion, .obsoleteflags },
        .{ .recommendname, .recommendversion, .recommendflags },
        .{ .suggestname, .suggestversion, .suggestflags },
        .{ .supplementname, .supplementversion, .supplementflags },
        .{ .enhancename, .enhanceversion, .enhanceflags },
        .{ .oldsuggestsname, .oldsuggestsversion, .oldsuggestsflags },
        .{ .oldenhancesname, .oldenhancesversion, .oldenhancesflags },
    };
    for (dependencies) |family| try validateParallel3(
        h,
        family[0],
        .string_array,
        family[1],
        .string_array,
        family[2],
        .int32,
    );

    try validateParallel3(
        h,
        .changelogtime,
        .int32,
        .changelogname,
        .string_array,
        .changelogtext,
        .string_array,
    );
    try validateFiles(h);
    try validateTriggers(h);

    return classifyPackage(h);
}

fn requireScalar(h: header.Header, tag: header.TagId, typ: header.TypeId) MetadataError!void {
    const count = try optionalCount(h, tag, typ) orelse return error.InvalidMetadata;
    if (count != 1) return error.InvalidMetadata;
}

fn optionalScalar(h: header.Header, tag: header.TagId, typ: header.TypeId) MetadataError!void {
    const count = try optionalCount(h, tag, typ) orelse return;
    if (count != 1) return error.InvalidMetadata;
}

fn optionalCount(
    h: header.Header,
    tag: header.TagId,
    typ: header.TypeId,
) MetadataError!?usize {
    const e = h.find(tag) orelse return null;
    if (e.typ != @intFromEnum(typ)) return error.InvalidMetadata;
    return std.math.cast(usize, e.count) orelse error.InvalidMetadata;
}

fn validateParallel3(
    h: header.Header,
    first_tag: header.TagId,
    first_type: header.TypeId,
    second_tag: header.TagId,
    second_type: header.TypeId,
    third_tag: header.TagId,
    third_type: header.TypeId,
) MetadataError!void {
    const first = try optionalCount(h, first_tag, first_type);
    const second = try optionalCount(h, second_tag, second_type);
    const third = try optionalCount(h, third_tag, third_type);
    if (first == null and second == null and third == null) return;
    if (first == null or second == null or third == null)
        return error.InvalidMetadata;
    if (first.? != second.? or first.? != third.?)
        return error.InvalidMetadata;
}

fn validateFiles(h: header.Header) MetadataError!void {
    const basenames = try optionalCount(h, .basenames, .string_array);
    const dirindexes = try optionalCount(h, .dirindexes, .int32);
    const dirnames = try optionalCount(h, .dirnames, .string_array);
    if (basenames == null and dirindexes == null and dirnames == null) {
        // Per-file arrays without the path triplet are never meaningful.
        try validatePerFileArrays(h, null);
        return;
    }
    if (basenames == null or dirindexes == null or dirnames == null)
        return error.InvalidMetadata;
    if (basenames.? != dirindexes.?) return error.InvalidMetadata;

    var i: usize = 0;
    while (i < dirindexes.?) : (i += 1) {
        const index = h.u32ArrayItem(.dirindexes, i) orelse
            return error.InvalidMetadata;
        if (index >= dirnames.?) return error.InvalidMetadata;
    }
    try validatePerFileArrays(h, basenames.?);
}

fn validatePerFileArrays(h: header.Header, file_count: ?usize) MetadataError!void {
    const specs = [_]struct {
        tag: header.TagId,
        typ: header.TypeId,
    }{
        .{ .tag = .filesizes, .typ = .int32 },
        .{ .tag = .file_states, .typ = .char_type },
        .{ .tag = .filemodes, .typ = .int16 },
        .{ .tag = .filerdevs, .typ = .int16 },
        .{ .tag = .filemtimes, .typ = .int32 },
        .{ .tag = .filedigests, .typ = .string_array },
        .{ .tag = .filelinktos, .typ = .string_array },
        .{ .tag = .fileflags, .typ = .int32 },
        .{ .tag = .fileusername, .typ = .string_array },
        .{ .tag = .filegroupname, .typ = .string_array },
        .{ .tag = .fileverifyflags, .typ = .int32 },
        .{ .tag = .filedevices, .typ = .int32 },
        .{ .tag = .fileinodes, .typ = .int32 },
        .{ .tag = .filelangs, .typ = .string_array },
        .{ .tag = .filecolors, .typ = .int32 },
        .{ .tag = .fileclass, .typ = .int32 },
        .{ .tag = .filedependsx, .typ = .int32 },
        .{ .tag = .filedependsn, .typ = .int32 },
        .{ .tag = .filecontexts, .typ = .string_array },
        .{ .tag = .filedigestalgos, .typ = .int32 },
        .{ .tag = .filexattrsx, .typ = .int32 },
        .{ .tag = .filecaps, .typ = .string_array },
        .{ .tag = .filenlinks, .typ = .int32 },
        .{ .tag = .filesignatures, .typ = .string_array },
    };
    for (specs) |spec| {
        const count = try optionalCount(h, spec.tag, spec.typ) orelse continue;
        if (file_count == null or count != file_count.?)
            return error.InvalidMetadata;
    }
}

fn validateTriggers(h: header.Header) MetadataError!void {
    try validateTriggerGroup(h, .{
        .scripts = .triggerscripts,
        .programs = .triggerscriptprog,
        .script_flags = .triggerscriptflags,
        .names = .triggername,
        .versions = .triggerversion,
        .flags = .triggerflags,
        .indexes = .triggerindex,
        .conditions = .triggerconds,
        .types = .triggertype,
    });
    try validateTriggerGroup(h, .{
        .scripts = .filetriggerscripts,
        .programs = .filetriggerscriptprog,
        .script_flags = .filetriggerscriptflags,
        .priorities = .filetriggerpriorities,
        .names = .filetriggername,
        .versions = .filetriggerversion,
        .flags = .filetriggerflags,
        .indexes = .filetriggerindex,
        .conditions = .filetriggerconds,
        .types = .filetriggertype,
    });
    try validateTriggerGroup(h, .{
        .scripts = .transfiletriggerscripts,
        .programs = .transfiletriggerscriptprog,
        .script_flags = .transfiletriggerscriptflags,
        .priorities = .transfiletriggerpriorities,
        .names = .transfiletriggername,
        .versions = .transfiletriggerversion,
        .flags = .transfiletriggerflags,
        .indexes = .transfiletriggerindex,
        .conditions = .transfiletriggerconds,
        .types = .transfiletriggertype,
    });
}

const TriggerTags = struct {
    scripts: header.TagId,
    programs: header.TagId,
    script_flags: header.TagId,
    priorities: ?header.TagId = null,
    names: header.TagId,
    versions: header.TagId,
    flags: header.TagId,
    indexes: header.TagId,
    conditions: header.TagId,
    types: header.TagId,
};

fn validateTriggerGroup(h: header.Header, tags: TriggerTags) MetadataError!void {
    const names = try optionalCount(h, tags.names, .string_array);
    const versions = try optionalCount(h, tags.versions, .string_array);
    const flags = try optionalCount(h, tags.flags, .int32);
    const indexes = try optionalCount(h, tags.indexes, .int32);
    const scripts = try optionalCount(h, tags.scripts, .string_array);
    if (names == null and versions == null and flags == null and
        indexes == null and scripts == null)
    {
        return;
    }
    if (names == null or versions == null or flags == null or
        indexes == null or scripts == null)
    {
        return error.InvalidMetadata;
    }
    if (names.? != versions.? or names.? != flags.? or names.? != indexes.?)
        return error.InvalidMetadata;

    var i: usize = 0;
    while (i < indexes.?) : (i += 1) {
        const index = h.u32ArrayItem(tags.indexes, i) orelse
            return error.InvalidMetadata;
        if (index >= scripts.?) return error.InvalidMetadata;
    }

    const programs = try optionalCount(h, tags.programs, .string_array);
    if (programs != null and programs.? != scripts.?)
        return error.InvalidMetadata;
    const script_flags = try optionalCount(h, tags.script_flags, .int32);
    if (script_flags != null and script_flags.? != scripts.?)
        return error.InvalidMetadata;
    if (tags.priorities) |tag| {
        const priorities = try optionalCount(h, tag, .int32);
        if (priorities != null and priorities.? != scripts.?)
            return error.InvalidMetadata;
    }
    const conditions = try optionalCount(h, tags.conditions, .string_array);
    if (conditions != null and conditions.? != names.?)
        return error.InvalidMetadata;
    const types = try optionalCount(h, tags.types, .string_array);
    if (types != null and types.? != names.?)
        return error.InvalidMetadata;
}

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

fn roundUp8Checked(x: usize) ?usize {
    const with_padding = std.math.add(usize, x, 7) catch return null;
    return with_padding & ~@as(usize, 7);
}

fn rangeFits(start: usize, len: usize, end: usize) bool {
    if (start > end) return false;
    return len <= end - start;
}

fn readU16(buf: []const u8, off: usize) u16 {
    return @as(u16, buf[off]) << 8 | @as(u16, buf[off + 1]);
}

test "roundUp8" {
    try std.testing.expectEqual(@as(?usize, 0), roundUp8Checked(0));
    try std.testing.expectEqual(@as(?usize, 8), roundUp8Checked(1));
    try std.testing.expectEqual(@as(?usize, 8), roundUp8Checked(8));
    try std.testing.expectEqual(@as(?usize, 16), roundUp8Checked(9));
    try std.testing.expectEqual(@as(?usize, 16), roundUp8Checked(15));
    try std.testing.expectEqual(@as(?usize, 16), roundUp8Checked(16));
    try std.testing.expectEqual(@as(?usize, null), roundUp8Checked(std.math.maxInt(usize)));
}

test "Compressor.fromString" {
    try std.testing.expectEqual(Compressor.gzip, Compressor.fromString("gzip"));
    try std.testing.expectEqual(Compressor.zstd, Compressor.fromString("zstd"));
    try std.testing.expectEqual(Compressor.xz, Compressor.fromString("xz"));
    try std.testing.expectEqual(Compressor.none, Compressor.fromString(""));
    try std.testing.expectEqual(Compressor.unknown, Compressor.fromString("bogus"));
}

const TestEntry = struct {
    tag: header.TagId,
    typ: header.TypeId,
    count: u32,
    data: []const u8,
};

fn appendTestU32(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: u32,
) !void {
    try list.append(allocator, @truncate(value >> 24));
    try list.append(allocator, @truncate(value >> 16));
    try list.append(allocator, @truncate(value >> 8));
    try list.append(allocator, @truncate(value));
}

fn testTypeAlignment(typ: header.TypeId) usize {
    return switch (typ) {
        .int16 => 2,
        .int32 => 4,
        .int64 => 8,
        else => 1,
    };
}

fn buildTestRegionHeader(
    allocator: std.mem.Allocator,
    region: header.RegionTag,
    entries: []const TestEntry,
) ![]u8 {
    var data = std.ArrayList(u8).empty;
    defer data.deinit(allocator);
    var offsets = std.ArrayList(u32).empty;
    defer offsets.deinit(allocator);

    for (entries) |entry| {
        const alignment = testTypeAlignment(entry.typ);
        while (data.items.len % alignment != 0) try data.append(allocator, 0);
        try offsets.append(allocator, @intCast(data.items.len));
        try data.appendSlice(allocator, entry.data);
    }

    const trailer_offset: u32 = @intCast(data.items.len);
    const region_tag = @intFromEnum(region);
    try appendTestU32(&data, allocator, region_tag);
    try appendTestU32(&data, allocator, @intFromEnum(header.TypeId.bin));
    const index_count: u32 = @intCast(entries.len + 1);
    const negative_span: i32 = -@as(i32, @intCast(index_count * 16));
    try appendTestU32(&data, allocator, @bitCast(negative_span));
    try appendTestU32(&data, allocator, 16);

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(
        allocator,
        &.{ 0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0 },
    );
    try appendTestU32(&out, allocator, index_count);
    try appendTestU32(&out, allocator, @intCast(data.items.len));
    try appendTestU32(&out, allocator, region_tag);
    try appendTestU32(&out, allocator, @intFromEnum(header.TypeId.bin));
    try appendTestU32(&out, allocator, trailer_offset);
    try appendTestU32(&out, allocator, 16);
    for (entries, offsets.items) |entry, offset| {
        try appendTestU32(&out, allocator, @intFromEnum(entry.tag));
        try appendTestU32(&out, allocator, @intFromEnum(entry.typ));
        try appendTestU32(&out, allocator, offset);
        try appendTestU32(&out, allocator, entry.count);
    }
    try out.appendSlice(allocator, data.items);
    return out.toOwnedSlice(allocator);
}

const BuiltTestRpm = struct {
    bytes: []u8,
    padding_start: usize,
    padding_len: usize,
};

fn buildTestRpm(
    allocator: std.mem.Allocator,
    main_entries: []const TestEntry,
) !BuiltTestRpm {
    const sig = try buildTestRegionHeader(allocator, .signatures, &.{
        .{
            .tag = @enumFromInt(@intFromEnum(header.SigTagId.size)),
            .typ = .int32,
            .count = 1,
            .data = "\x00\x00\x00\x01",
        },
    });
    defer allocator.free(sig);
    const main = try buildTestRegionHeader(allocator, .immutable, main_entries);
    defer allocator.free(main);

    const padding_len = (8 - (sig.len % 8)) % 8;
    const total = try std.math.add(
        usize,
        LEAD_SIZE + sig.len + padding_len,
        main.len,
    );
    const bytes = try allocator.alloc(u8, total);
    @memset(bytes, 0);
    @memcpy(bytes[0..4], &LEAD_MAGIC);
    @memcpy(bytes[LEAD_SIZE .. LEAD_SIZE + sig.len], sig);
    const main_start = LEAD_SIZE + sig.len + padding_len;
    @memcpy(bytes[main_start .. main_start + main.len], main);
    return .{
        .bytes = bytes,
        .padding_start = LEAD_SIZE + sig.len,
        .padding_len = padding_len,
    };
}

test "package classification is based on header tags" {
    const source = "\x00\x00\x00\x01";
    const nosource = "\x00\x00\x00\x00";
    const Cases = [_]struct {
        source: bool,
        nosource: bool,
        source_rpm: bool,
        expected: ?PackageKind,
    }{
        .{ .source = false, .nosource = false, .source_rpm = false, .expected = .binary },
        .{ .source = false, .nosource = false, .source_rpm = true, .expected = .binary },
        .{ .source = true, .nosource = false, .source_rpm = false, .expected = .source },
        .{ .source = true, .nosource = true, .source_rpm = false, .expected = .nosrc },
        .{ .source = false, .nosource = true, .source_rpm = false, .expected = null },
        .{ .source = true, .nosource = false, .source_rpm = true, .expected = null },
    };

    for (Cases) |case| {
        var entries = std.ArrayList(TestEntry).empty;
        defer entries.deinit(std.testing.allocator);
        if (case.source) try entries.append(std.testing.allocator, .{
            .tag = .sourcepackage,
            .typ = .int32,
            .count = 1,
            .data = source,
        });
        if (case.nosource) try entries.append(std.testing.allocator, .{
            .tag = .nosource,
            .typ = .int32,
            .count = 1,
            .data = nosource,
        });
        if (case.source_rpm) try entries.append(std.testing.allocator, .{
            .tag = .source_rpm,
            .typ = .string,
            .count = 1,
            .data = "pkg.src.rpm\x00",
        });
        const standalone = try buildTestRegionHeader(
            std.testing.allocator,
            .immutable,
            entries.items,
        );
        defer std.testing.allocator.free(standalone);
        const h = (try header.Header.parseStandaloneWithRegion(standalone, .immutable)).header;
        if (case.expected) |expected| {
            try std.testing.expectEqual(expected, try classifyPackage(h));
        } else {
            try std.testing.expectError(error.InvalidPackageKind, classifyPackage(h));
        }
    }
}

test "metadata parallel arrays and indexes are strict" {
    const required = [_]TestEntry{
        .{ .tag = .name, .typ = .string, .count = 1, .data = "pkg\x00" },
        .{ .tag = .version, .typ = .string, .count = 1, .data = "1\x00" },
        .{ .tag = .release, .typ = .string, .count = 1, .data = "1\x00" },
        .{ .tag = .arch, .typ = .string, .count = 1, .data = "noarch\x00" },
    };
    const malformed = [_][]const TestEntry{
        &(required ++ [_]TestEntry{
            .{ .tag = .requirename, .typ = .string_array, .count = 1, .data = "dep\x00" },
        }),
        &(required ++ [_]TestEntry{
            .{ .tag = .changelogtime, .typ = .int32, .count = 1, .data = "\x00\x00\x00\x01" },
            .{ .tag = .changelogname, .typ = .string_array, .count = 1, .data = "A\x00" },
            .{ .tag = .changelogtext, .typ = .string_array, .count = 2, .data = "a\x00b\x00" },
        }),
        &(required ++ [_]TestEntry{
            .{ .tag = .basenames, .typ = .string_array, .count = 1, .data = "file\x00" },
            .{ .tag = .dirnames, .typ = .string_array, .count = 1, .data = "/\x00" },
            .{ .tag = .dirindexes, .typ = .int32, .count = 1, .data = "\x00\x00\x00\x01" },
        }),
        &(required ++ [_]TestEntry{
            .{ .tag = .triggerscripts, .typ = .string_array, .count = 1, .data = ":\x00" },
            .{ .tag = .triggername, .typ = .string_array, .count = 1, .data = "pkg\x00" },
            .{ .tag = .triggerversion, .typ = .string_array, .count = 1, .data = "\x00" },
            .{ .tag = .triggerflags, .typ = .int32, .count = 1, .data = "\x00\x00\x00\x00" },
            .{ .tag = .triggerindex, .typ = .int32, .count = 1, .data = "\x00\x00\x00\x01" },
        }),
        &(required ++ [_]TestEntry{
            .{ .tag = .payload_compressor, .typ = .int32, .count = 1, .data = "\x00\x00\x00\x01" },
        }),
    };

    for (malformed) |entries| {
        const standalone = try buildTestRegionHeader(
            std.testing.allocator,
            .immutable,
            entries,
        );
        defer std.testing.allocator.free(standalone);
        const h = (try header.Header.parseStandaloneWithRegion(standalone, .immutable)).header;
        try std.testing.expectError(error.InvalidMetadata, validatePackageMetadata(h));
    }
}

test "rpm parser checks regions padding truncation and legacy lead fields" {
    const main_entries = [_]TestEntry{
        .{ .tag = .name, .typ = .string, .count = 1, .data = "pkg\x00" },
        .{ .tag = .version, .typ = .string, .count = 1, .data = "1\x00" },
        .{ .tag = .release, .typ = .string, .count = 1, .data = "1\x00" },
        .{ .tag = .arch, .typ = .string, .count = 1, .data = "noarch\x00" },
        .{ .tag = .payload_compressor, .typ = .string, .count = 1, .data = "zstd\x00" },
    };

    var valid = try buildTestRpm(std.testing.allocator, &main_entries);
    // Upstream ignores all legacy lead fields except magic. In particular,
    // package type 1 here must not contradict modern header classification.
    @memset(valid.bytes[4..LEAD_SIZE], 0xff);
    valid.bytes[6] = 0;
    valid.bytes[7] = 1;
    var rpm = try RpmFile.parseBytes(valid.bytes);
    defer rpm.close(std.testing.allocator);
    try std.testing.expectEqual(Compressor.zstd, rpm.compressor);
    try std.testing.expectEqual(PackageKind.binary, rpm.packageKind());

    var bad_padding = try buildTestRpm(std.testing.allocator, &main_entries);
    defer std.testing.allocator.free(bad_padding.bytes);
    try std.testing.expect(bad_padding.padding_len != 0);
    bad_padding.bytes[bad_padding.padding_start] = 1;
    try std.testing.expectError(error.HeaderParseFailed, RpmFile.parseBytes(bad_padding.bytes));

    const truncated = try buildTestRpm(std.testing.allocator, &main_entries);
    defer std.testing.allocator.free(truncated.bytes);
    try std.testing.expectError(
        error.HeaderParseFailed,
        RpmFile.parseBytes(truncated.bytes[0 .. truncated.bytes.len - 1]),
    );
}

test "RPM6 signature header tags must be sorted and unique" {
    const sha3 = "0000000000000000000000000000000000000000000000000000000000000000\x00";
    const sorted = try buildTestRegionHeader(std.testing.allocator, .signatures, &.{
        .{ .tag = @enumFromInt(@intFromEnum(header.SigTagId.sha3_256)), .typ = .string, .count = 1, .data = sha3 },
        .{ .tag = @enumFromInt(@intFromEnum(header.SigTagId.reserved)), .typ = .bin, .count = 1, .data = "\x00" },
    });
    defer std.testing.allocator.free(sorted);
    const sorted_header =
        (try header.Header.parseStandaloneWithRegion(sorted, .signatures)).header;
    try validateSignatureMetadata(sorted_header);

    const unsorted = try buildTestRegionHeader(std.testing.allocator, .signatures, &.{
        .{ .tag = @enumFromInt(@intFromEnum(header.SigTagId.reserved)), .typ = .bin, .count = 1, .data = "\x00" },
        .{ .tag = @enumFromInt(@intFromEnum(header.SigTagId.sha3_256)), .typ = .string, .count = 1, .data = sha3 },
    });
    defer std.testing.allocator.free(unsorted);
    const unsorted_header =
        (try header.Header.parseStandaloneWithRegion(unsorted, .signatures)).header;
    try std.testing.expectError(
        error.InvalidMetadata,
        validateSignatureMetadata(unsorted_header),
    );

    const duplicate = try buildTestRegionHeader(std.testing.allocator, .signatures, &.{
        .{ .tag = @enumFromInt(@intFromEnum(header.SigTagId.sha3_256)), .typ = .string, .count = 1, .data = sha3 },
        .{ .tag = @enumFromInt(@intFromEnum(header.SigTagId.sha3_256)), .typ = .string, .count = 1, .data = sha3 },
        .{ .tag = @enumFromInt(@intFromEnum(header.SigTagId.reserved)), .typ = .bin, .count = 1, .data = "\x00" },
    });
    defer std.testing.allocator.free(duplicate);
    const duplicate_header =
        (try header.Header.parseStandaloneWithRegion(duplicate, .signatures)).header;
    try std.testing.expectError(
        error.InvalidMetadata,
        validateSignatureMetadata(duplicate_header),
    );
}

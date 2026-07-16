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
//! The first index entry in modern rpm headers is a region marker
//! (RPMTAG_HEADERIMMUTABLE = 63, type = BIN, count = 16). Its offset points
//! to a matching entry-info trailer in the data section. Standalone package
//! parsing requires the appropriate complete region; rpmdb parsing accepts
//! old regionless blobs but validates a marker whenever one is present.
//!
//! This module is read-only and does not allocate. All returned slices
//! point into the input blob — callers must keep the blob alive while
//! using a decoded `Header`.

const std = @import("std");

pub const TagId = enum(u32) {
    sigsize = 257,
    sigpgp = 259,
    sigmd5 = 261,
    siggpg = 262,
    dsaheader = 267,
    rsaheader = 268,
    sha1header = 269,
    longsigsize = 270,
    longarchivesize = 271,
    sha256header = 273,
    openpgp = 278,
    sha3_256header = 279,
    pubkeys = 266,
    header_i18ntable = 100,
    name = 1000,
    version = 1001,
    release = 1002,
    epoch = 1003,
    summary = 1004,
    description = 1005,
    build_time = 1006,
    buildhost = 1007,
    arch = 1022,
    prein = 1023,
    postin = 1024,
    preun = 1025,
    postun = 1026,
    install_tid = 1128,
    install_time = 1008,
    size = 1009,
    vendor = 1011,
    license = 1014,
    packager = 1015,
    group = 1016,
    url = 1020,
    source_rpm = 1044,
    rpmversion = 1064,
    file_states = 1029,
    archive_size = 1046,
    triggerscripts = 1065,
    triggername = 1066,
    triggerversion = 1067,
    triggerflags = 1068,
    triggerindex = 1069,
    payload_format = 1124,
    payload_compressor = 1125,
    payload_flags = 1126,
    install_color = 1127,
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
    nosource = 1051,
    obsoletename = 1090,
    obsoleteversion = 1115,
    obsoleteflags = 1114,
    changelogtime = 1080,
    changelogname = 1081,
    changelogtext = 1082,
    preinprog = 1085,
    postinprog = 1086,
    preunprog = 1087,
    postunprog = 1088,
    pretrans = 1151,
    posttrans = 1152,
    pretransprog = 1153,
    posttransprog = 1154,
    sourcepackage = 1106,
    filesizes = 1028,
    filemodes = 1030,
    filerdevs = 1033,
    filemtimes = 1034,
    filedigests = 1035,
    filelinktos = 1036,
    fileflags = 1037,
    fileusername = 1039,
    filegroupname = 1040,
    fileverifyflags = 1045,
    filedevices = 1095,
    fileinodes = 1096,
    filelangs = 1097,
    dirindexes = 1116,
    basenames = 1117,
    dirnames = 1118,
    filecolors = 1140,
    fileclass = 1141,
    filedependsx = 1143,
    filedependsn = 1144,
    filecontexts = 1147,
    filedigestalgos = 1177,
    filexattrsx = 1187,
    filecaps = 5010,
    filedigestalgo = 5011,
    filenlinks = 5045,
    recommendname = 5046,
    recommendversion = 5047,
    recommendflags = 5048,
    suggestname = 5049,
    suggestversion = 5050,
    suggestflags = 5051,
    supplementname = 5052,
    supplementversion = 5053,
    supplementflags = 5054,
    enhancename = 5055,
    enhanceversion = 5056,
    enhanceflags = 5057,
    oldsuggestsname = 1156,
    oldsuggestsversion = 1157,
    oldsuggestsflags = 1158,
    oldenhancesname = 1159,
    oldenhancesversion = 1160,
    oldenhancesflags = 1161,
    longsize = 5009,
    triggerconds = 5005,
    triggertype = 5006,
    filetriggerscripts = 5066,
    filetriggerscriptprog = 5067,
    filetriggerscriptflags = 5068,
    filetriggername = 5069,
    filetriggerindex = 5070,
    filetriggerversion = 5071,
    filetriggerflags = 5072,
    transfiletriggerscripts = 5076,
    transfiletriggerscriptprog = 5077,
    transfiletriggerscriptflags = 5078,
    transfiletriggername = 5079,
    transfiletriggerindex = 5080,
    transfiletriggerversion = 5081,
    transfiletriggerflags = 5082,
    filetriggerpriorities = 5084,
    transfiletriggerpriorities = 5085,
    filetriggerconds = 5086,
    filetriggertype = 5087,
    transfiletriggerconds = 5088,
    transfiletriggertype = 5089,
    triggerscriptflags = 5027,
    triggerscriptprog = 1092,
    filesignatures = 5090,
    filesignaturelength = 5091,
    payloadsha256 = 5092,
    payloadsha256algo = 5093,
    modularitylabel = 5096,
    payloadsha256alt = 5097,
    payloadsize = 5112,
    payloadsizealt = 5113,
    rpmformat = 5114,
    packagedigests = 5118,
    packagedigestalgos = 5119,
    payloadsha512 = 5121,
    payloadsha512alt = 5122,
    payloadsha3_256 = 5123,
    payloadsha3_256alt = 5124,
    preinflags = 5020,
    postinflags = 5021,
    preunflags = 5022,
    postunflags = 5023,
    pretransflags = 5024,
    posttransflags = 5025,
    _,
};

/// Tag IDs that appear in an rpm's **signature header**. Distinct
/// from `TagId` because the signature header has its own numbering
/// space (1002 = RPMSIGTAG_PGP, while 1002 in the main header is
/// RELEASE). The accessors that take a `TagId` accept this via
/// `@enumFromInt(@intFromEnum(s))` — see `Header.findRaw`.
pub const SigTagId = enum(u32) {
    // Region trailer (skipped during walk).
    region = 62,
    // 267 RPMSIGTAG_DSA      (BIN, DSA sig of main header)
    // 268 RPMSIGTAG_RSA      (BIN, RSA sig of main header)
    // 269 RPMSIGTAG_SHA1     (STRING, hex SHA1 of main header)
    // 273 RPMSIGTAG_SHA256   (STRING, hex SHA256 of main header)
    // 278 RPMSIGTAG_OPENPGP  (STRING_ARRAY, base64 OpenPGP sigs)
    // 1000 RPMSIGTAG_SIZE    (INT32, header+payload size)
    // 1002 RPMSIGTAG_PGP     (BIN, PGP sig of header+payload)
    // 1004 RPMSIGTAG_MD5     (BIN, MD5 of header+payload)
    // 1005 RPMSIGTAG_GPG     (BIN, GPG sig of header+payload)
    dsa = 267,
    rsa = 268,
    sha1 = 269,
    sha256 = 273,
    openpgp = 278,
    sha3_256 = 279,
    reserved = 999,
    size = 1000,
    pgp = 1002,
    md5 = 1004,
    gpg = 1005,
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

/// region markers. Modern rpmdb blobs start with HEADERIMMUTABLE.
const RPMTAG_HEADERIMAGE: u32 = 61;
const RPMTAG_HEADERSIGNATURES: u32 = 62;
const RPMTAG_HEADERIMMUTABLE: u32 = 63;

pub const RegionTag = enum(u32) {
    signatures = RPMTAG_HEADERSIGNATURES,
    immutable = RPMTAG_HEADERIMMUTABLE,
};

pub const Error = error{
    Truncated,
    BadIndexCount,
    BadDataSize,
    BadMagic,
    SizeOverflow,
    InvalidType,
    InvalidCount,
    MisalignedOffset,
    OffsetOutOfRange,
    UnterminatedString,
    InvalidRegion,
    InvalidUtf8, // we don't enforce UTF-8 strictly; reserved
};

pub const AccessError = error{Malformed};

pub const StringArrayIterator = struct {
    bytes: []const u8,
    off: usize,
    data_end: usize,
    remaining: usize,

    pub fn next(self: *StringArrayIterator) AccessError!?[]const u8 {
        if (self.remaining == 0) return null;

        const end = std.mem.indexOfScalarPos(
            u8,
            self.bytes[0..self.data_end],
            self.off,
            0,
        ) orelse return error.Malformed;
        const value = self.bytes[self.off..end];
        self.off = end + 1;
        self.remaining -= 1;
        return value;
    }
};

pub const Standalone = struct {
    header: Header,
    on_disk_size: usize,
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
        return parseInternal(blob, null, false);
    }

    /// Parse a raw header and require its first entry to describe the
    /// requested immutable region. `full_coverage` additionally requires
    /// the region to cover every index and data byte, as package headers do.
    pub fn parseWithRegion(
        blob: []const u8,
        expected: RegionTag,
        full_coverage: bool,
    ) Error!Header {
        return parseInternal(blob, @intFromEnum(expected), full_coverage);
    }

    /// Parses a header with the 8-byte "standalone" magic prefix
    /// (`8e ad e8 01 00 00 00 00`), as used in `.rpm` files for the
    /// signature header and main header. Returns the parsed header
    /// plus its **total on-disk size** (magic + counts + index + data),
    /// without any trailing pad-to-8 alignment — the caller applies
    /// alignment when seeking from one header to the next.
    pub fn parseStandalone(blob: []const u8) Error!Standalone {
        return parseStandaloneInternal(blob, null, false);
    }

    /// Strict standalone parser for package signature and main headers.
    /// Unlike `parseStandalone`, this requires a complete immutable region.
    pub fn parseStandaloneWithRegion(
        blob: []const u8,
        expected: RegionTag,
    ) Error!Standalone {
        return parseStandaloneWithRegionCoverage(blob, expected, true);
    }

    /// Signature headers can append mutable "dribble" entries after their
    /// immutable region. Main package headers require complete coverage.
    pub fn parseStandaloneWithRegionCoverage(
        blob: []const u8,
        expected: RegionTag,
        full_coverage: bool,
    ) Error!Standalone {
        return parseStandaloneInternal(
            blob,
            @intFromEnum(expected),
            full_coverage,
        );
    }

    fn parseStandaloneInternal(
        blob: []const u8,
        expected: ?u32,
        full_coverage: bool,
    ) Error!Standalone {
        const magic = [_]u8{ 0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00 };
        if (blob.len < magic.len) return error.Truncated;
        if (!std.mem.eql(u8, blob[0..magic.len], &magic)) return error.BadMagic;
        const h = try parseInternal(blob[magic.len..], expected, full_coverage);
        const on_disk_size = std.math.add(usize, magic.len, h.bytes.len) catch
            return error.SizeOverflow;
        return .{
            .header = h,
            .on_disk_size = on_disk_size,
        };
    }

    /// Checked form of `entry`; useful to callers accepting an external index.
    pub fn entryChecked(self: Header, i: u32) ?IndexEntry {
        if (i >= self.index_count) return null;
        return self.entry(i);
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
        return self.findRaw(@intFromEnum(tag));
    }

    /// Variant of `find` that accepts a raw u32 tag value, used by
    /// callers that work in the signature header's distinct
    /// numbering space (see `SigTagId`).
    pub fn findRaw(self: Header, tag: u32) ?IndexEntry {
        var i: u32 = 0;
        while (i < self.index_count) : (i += 1) {
            const e = self.entry(i);
            if (e.tag == RPMTAG_HEADERIMAGE or
                e.tag == RPMTAG_HEADERSIGNATURES or
                e.tag == RPMTAG_HEADERIMMUTABLE) continue;
            if (e.tag == tag) return e;
        }
        return null;
    }

    /// Region-aware variant used by write-path code that needs to
    /// verify the presence of immutable/header-signature markers.
    pub fn findRawIncludingRegions(self: Header, tag: u32) ?IndexEntry {
        var i: u32 = 0;
        while (i < self.index_count) : (i += 1) {
            const e = self.entry(i);
            if (e.tag == tag) return e;
        }
        return null;
    }

    /// RPM v6 signature headers require all non-region index tags to
    /// be strictly increasing. This also rejects duplicate tags.
    pub fn hasStrictlyIncreasingDataTags(self: Header) bool {
        var previous: ?u32 = null;
        var i: u32 = 0;
        while (i < self.index_count) : (i += 1) {
            const e = self.entry(i);
            if (isRegionTag(e.tag)) continue;
            if (previous) |tag| {
                if (e.tag <= tag) return false;
            }
            previous = e.tag;
        }
        return true;
    }

    /// Get a STRING-typed tag as a slice into the blob.
    /// I18N_STRING tags return their first (English / "C" locale)
    /// entry. Returns null if the tag is missing or has the wrong type.
    pub fn getString(self: Header, tag: TagId) ?[]const u8 {
        return self.getStringChecked(tag) catch null;
    }

    pub fn getStringRaw(self: Header, tag: u32) ?[]const u8 {
        return self.getStringRawChecked(tag) catch null;
    }

    /// Checked scalar string lookup. Absence is `null`; a present tag with an
    /// incompatible type/count is `error.Malformed`. I18N strings explicitly
    /// select their first locale, but STRING_ARRAY is never treated as scalar.
    pub fn getStringChecked(self: Header, tag: TagId) AccessError!?[]const u8 {
        return self.getStringRawChecked(@intFromEnum(tag));
    }

    pub fn getStringRawChecked(self: Header, tag: u32) AccessError!?[]const u8 {
        const e = self.findRaw(tag) orelse return null;
        return try self.readScalarStringChecked(e);
    }

    fn readScalarStringChecked(self: Header, e: IndexEntry) AccessError![]const u8 {
        switch (@as(TypeId, @enumFromInt(e.typ))) {
            .string => if (e.count != 1) return error.Malformed,
            .i18n_string => {},
            else => return error.Malformed,
        }
        const start = self.dataOffset(e.offset) orelse return error.Malformed;
        const end = std.mem.indexOfScalarPos(
            u8,
            self.bytes[0..self.dataEnd()],
            start,
            0,
        ) orelse return error.Malformed;
        return self.bytes[start..end];
    }

    /// Get an INT32-typed tag.
    pub fn getU32(self: Header, tag: TagId) ?u32 {
        return self.u32ArrayItem(tag, 0);
    }

    pub fn getU32Raw(self: Header, tag: u32) ?u32 {
        return self.u32ArrayItemRaw(tag, 0);
    }

    pub fn getU32Checked(self: Header, tag: TagId) AccessError!?u32 {
        return self.getU32RawChecked(@intFromEnum(tag));
    }

    pub fn getU32RawChecked(self: Header, tag: u32) AccessError!?u32 {
        const e = self.findRaw(tag) orelse return null;
        if (@as(TypeId, @enumFromInt(e.typ)) != .int32 or e.count != 1)
            return error.Malformed;
        const start = self.dataOffset(e.offset) orelse return error.Malformed;
        if (!rangeFits(start, 4, self.dataEnd())) return error.Malformed;
        return readU32(self.bytes, start);
    }

    /// Get an INT64-typed tag.
    pub fn getU64(self: Header, tag: TagId) ?u64 {
        const e = self.find(tag) orelse return null;
        if (@as(TypeId, @enumFromInt(e.typ)) != .int64) return null;
        const start = self.dataOffset(e.offset) orelse return null;
        if (!rangeFits(start, 8, self.dataEnd())) return null;
        return readU64(self.bytes, start);
    }

    pub fn getU64Checked(self: Header, tag: TagId) AccessError!?u64 {
        const e = self.find(tag) orelse return null;
        if (@as(TypeId, @enumFromInt(e.typ)) != .int64 or e.count != 1)
            return error.Malformed;
        const start = self.dataOffset(e.offset) orelse return error.Malformed;
        if (!rangeFits(start, 8, self.dataEnd())) return error.Malformed;
        return readU64(self.bytes, start);
    }

    /// Get a BIN-typed tag as a slice into the blob. Used for raw
    /// binary payloads such as signature packets (sig_sigpgp,
    /// sig_dsa, sig_rsa, …) and stored digests (sig_sha1,
    /// sig_sha256).
    pub fn getBinary(self: Header, tag: TagId) ?[]const u8 {
        return self.getBinaryRaw(@intFromEnum(tag));
    }

    /// Raw-tag variant of `getBinary`, used by the signature-header
    /// inspectors.
    pub fn getBinaryRaw(self: Header, tag: u32) ?[]const u8 {
        return self.getBinaryRawChecked(tag) catch null;
    }

    pub fn getBinaryChecked(self: Header, tag: TagId) AccessError!?[]const u8 {
        return self.getBinaryRawChecked(@intFromEnum(tag));
    }

    pub fn getBinaryRawChecked(self: Header, tag: u32) AccessError!?[]const u8 {
        const e = self.findRaw(tag) orelse return null;
        if (@as(TypeId, @enumFromInt(e.typ)) != .bin) return error.Malformed;
        const start = self.dataOffset(e.offset) orelse return error.Malformed;
        const len = std.math.cast(usize, e.count) orelse return error.Malformed;
        if (!rangeFits(start, len, self.dataEnd())) return error.Malformed;
        const end = start + len;
        return self.bytes[start..end];
    }

    /// Count of entries in a STRING_ARRAY / I18N_STRING tag. Returns
    /// 0 when the tag is absent or of a different type.
    pub fn stringArrayCount(self: Header, tag: TagId) usize {
        return self.stringArrayCountChecked(tag) catch 0 orelse 0;
    }

    pub fn stringArrayCountRaw(self: Header, tag: u32) usize {
        return self.stringArrayCountRawChecked(tag) catch 0 orelse 0;
    }

    pub fn stringArrayCountChecked(self: Header, tag: TagId) AccessError!?usize {
        return self.stringArrayCountRawChecked(@intFromEnum(tag));
    }

    pub fn stringArrayCountRawChecked(self: Header, tag: u32) AccessError!?usize {
        const e = self.findRaw(tag) orelse return null;
        switch (@as(TypeId, @enumFromInt(e.typ))) {
            .string_array, .i18n_string => return std.math.cast(usize, e.count) orelse
                error.Malformed,
            else => return error.Malformed,
        }
    }

    pub fn stringArrayIteratorChecked(
        self: Header,
        tag: TagId,
    ) AccessError!?StringArrayIterator {
        return self.stringArrayIteratorRawChecked(@intFromEnum(tag));
    }

    pub fn stringArrayIterator(
        self: Header,
        tag: TagId,
    ) ?StringArrayIterator {
        return self.stringArrayIteratorChecked(tag) catch null;
    }

    pub fn stringArrayIteratorRawChecked(
        self: Header,
        tag: u32,
    ) AccessError!?StringArrayIterator {
        const e = self.findRaw(tag) orelse return null;
        switch (@as(TypeId, @enumFromInt(e.typ))) {
            .string_array, .i18n_string => {},
            else => return error.Malformed,
        }
        return .{
            .bytes = self.bytes,
            .off = self.dataOffset(e.offset) orelse return error.Malformed,
            .data_end = self.dataEnd(),
            .remaining = std.math.cast(usize, e.count) orelse
                return error.Malformed,
        };
    }

    /// Count of entries in an INT32 array tag.
    pub fn u32ArrayCountChecked(self: Header, tag: TagId) AccessError!?usize {
        const e = self.find(tag) orelse return null;
        if (@as(TypeId, @enumFromInt(e.typ)) != .int32) return error.Malformed;
        return std.math.cast(usize, e.count) orelse error.Malformed;
    }

    /// Look up the `i`th entry of a STRING_ARRAY / I18N_STRING tag.
    /// O(i) — scans NULs from the start. Suitable for one-shot
    /// access; callers that iterate the whole array should keep a
    /// running offset themselves.
    pub fn stringArrayItem(self: Header, tag: TagId, i: usize) ?[]const u8 {
        return self.stringArrayItemChecked(tag, i) catch null;
    }

    pub fn stringArrayItemRaw(self: Header, tag: u32, i: usize) ?[]const u8 {
        return self.stringArrayItemRawChecked(tag, i) catch null;
    }

    pub fn stringArrayItemChecked(
        self: Header,
        tag: TagId,
        i: usize,
    ) AccessError!?[]const u8 {
        return self.stringArrayItemRawChecked(@intFromEnum(tag), i);
    }

    pub fn stringArrayItemRawChecked(
        self: Header,
        tag: u32,
        i: usize,
    ) AccessError!?[]const u8 {
        const e = self.findRaw(tag) orelse return null;
        switch (@as(TypeId, @enumFromInt(e.typ))) {
            .string_array, .i18n_string => {},
            else => return error.Malformed,
        }
        const count = std.math.cast(usize, e.count) orelse return error.Malformed;
        if (i >= count) return null;
        var off = self.dataOffset(e.offset) orelse return error.Malformed;
        const data_end = self.dataEnd();
        var skipped: usize = 0;
        while (skipped < i) : (skipped += 1) {
            const next_nul = std.mem.indexOfScalarPos(
                u8,
                self.bytes[0..data_end],
                off,
                0,
            ) orelse return error.Malformed;
            off = next_nul + 1;
        }
        const end = std.mem.indexOfScalarPos(
            u8,
            self.bytes[0..data_end],
            off,
            0,
        ) orelse return error.Malformed;
        return self.bytes[off..end];
    }

    /// Look up the `i`th entry of an INT32 array tag.
    pub fn u32ArrayItem(self: Header, tag: TagId, i: usize) ?u32 {
        return self.u32ArrayItemChecked(tag, i) catch null;
    }

    pub fn u32ArrayItemRaw(self: Header, tag: u32, i: usize) ?u32 {
        return self.u32ArrayItemRawChecked(tag, i) catch null;
    }

    pub fn u32ArrayItemChecked(self: Header, tag: TagId, i: usize) AccessError!?u32 {
        return self.u32ArrayItemRawChecked(@intFromEnum(tag), i);
    }

    pub fn u32ArrayItemRawChecked(self: Header, tag: u32, i: usize) AccessError!?u32 {
        const e = self.findRaw(tag) orelse return null;
        if (@as(TypeId, @enumFromInt(e.typ)) != .int32) return error.Malformed;
        const count = std.math.cast(usize, e.count) orelse return error.Malformed;
        if (i >= count) return null;
        const item_off = std.math.mul(usize, i, 4) catch return error.Malformed;
        const relative = std.math.add(
            usize,
            std.math.cast(usize, e.offset) orelse return error.Malformed,
            item_off,
        ) catch return error.Malformed;
        const start = self.dataOffset(relative) orelse return error.Malformed;
        if (!rangeFits(start, 4, self.dataEnd())) return error.Malformed;
        return readU32(self.bytes, start);
    }

    /// Look up the `i`th entry of an INT16 array tag.
    pub fn u16ArrayItem(self: Header, tag: TagId, i: usize) ?u16 {
        return self.u16ArrayItemChecked(tag, i) catch null;
    }

    pub fn u16ArrayItemChecked(self: Header, tag: TagId, i: usize) AccessError!?u16 {
        const e = self.find(tag) orelse return null;
        if (@as(TypeId, @enumFromInt(e.typ)) != .int16) return error.Malformed;
        const count = std.math.cast(usize, e.count) orelse return error.Malformed;
        if (i >= count) return null;
        const item_off = std.math.mul(usize, i, 2) catch return error.Malformed;
        const relative = std.math.add(
            usize,
            std.math.cast(usize, e.offset) orelse return error.Malformed,
            item_off,
        ) catch return error.Malformed;
        const start = self.dataOffset(relative) orelse return error.Malformed;
        if (!rangeFits(start, 2, self.dataEnd())) return error.Malformed;
        return readU16(self.bytes, start);
    }

    pub fn rawEntryBytes(self: Header, e: IndexEntry) ?[]const u8 {
        const start = self.dataOffset(e.offset) orelse return null;
        const data_end = self.dataEnd();

        const len: usize = switch (@as(TypeId, @enumFromInt(e.typ))) {
            .char_type, .int8, .bin => std.math.cast(usize, e.count) orelse return null,
            .int16 => std.math.mul(usize, e.count, 2) catch return null,
            .int32 => std.math.mul(usize, e.count, 4) catch return null,
            .int64 => std.math.mul(usize, e.count, 8) catch return null,
            .string => blk: {
                if (e.count != 1) return null;
                const end = std.mem.indexOfScalarPos(
                    u8,
                    self.bytes[0..data_end],
                    start,
                    0,
                ) orelse return null;
                break :blk end + 1 - start;
            },
            .string_array, .i18n_string => blk: {
                var off = start;
                var remaining = e.count;
                while (remaining > 0) : (remaining -= 1) {
                    const end = std.mem.indexOfScalarPos(
                        u8,
                        self.bytes[0..data_end],
                        off,
                        0,
                    ) orelse return null;
                    off = end + 1;
                }
                break :blk off - start;
            },
            else => return null,
        };

        if (!rangeFits(start, len, data_end)) return null;
        const end = start + len;
        return self.bytes[start..end];
    }

    fn dataEnd(self: Header) usize {
        return self.bytes.len;
    }

    fn dataOffset(self: Header, offset: anytype) ?usize {
        const relative = std.math.cast(usize, offset) orelse return null;
        const absolute = std.math.add(usize, self.data_off, relative) catch return null;
        if (absolute > self.dataEnd()) return null;
        return absolute;
    }

    /// Build the canonical NEVRA string `name-[epoch:]version-release[.arch]`.
    /// Epoch is included iff RPMTAG_EPOCH is present in the header.
    /// Arch is included iff RPMTAG_ARCH is present (which is not the
    /// case for `gpg-pubkey` rpmdb entries).
    ///
    /// Matches the legacy query format for both normal packages
    /// (`bash-5.2.15-3.azl3.aarch64`) and pubkey records
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

    /// Build the canonical EVR string `[epoch:]version-release`.
    /// Epoch is included iff RPMTAG_EPOCH is present.
    pub fn allocEvr(self: Header, alloc: std.mem.Allocator) std.mem.Allocator.Error!?[]u8 {
        const version = self.getString(.version) orelse return null;
        const release = self.getString(.release) orelse return null;
        if (self.getU32(.epoch)) |epoch| {
            return try std.fmt.allocPrint(alloc, "{d}:{s}-{s}", .{
                epoch, version, release,
            });
        }
        return try std.fmt.allocPrint(alloc, "{s}-{s}", .{
            version, release,
        });
    }
};

fn parseInternal(
    blob: []const u8,
    expected_region: ?u32,
    full_coverage: bool,
) Error!Header {
    if (blob.len < 8) return error.Truncated;
    const nindex = readU32(blob, 0);
    const hsize = readU32(blob, 4);

    // These are the upstream format limits. Besides bounding work, keeping the
    // arithmetic below checked makes this safe when compiled for 32-bit usize.
    if (nindex == 0 or nindex > 0x0000ffff) return error.BadIndexCount;
    if (hsize > 0x0fffffff) return error.BadDataSize;
    if (expected_region == RPMTAG_HEADERSIGNATURES) {
        if (nindex > 32) return error.BadIndexCount;
        if (hsize > 64 * 1024 * 1024) return error.BadDataSize;
    }

    const index_bytes = std.math.mul(
        usize,
        std.math.cast(usize, nindex) orelse return error.SizeOverflow,
        @sizeOf(IndexEntry),
    ) catch return error.SizeOverflow;
    const data_off = std.math.add(usize, 8, index_bytes) catch
        return error.SizeOverflow;
    const total = std.math.add(
        usize,
        data_off,
        std.math.cast(usize, hsize) orelse return error.SizeOverflow,
    ) catch return error.SizeOverflow;
    if (total >= 256 * 1024 * 1024) return error.BadDataSize;
    if (total > blob.len) return error.Truncated;

    const parsed: Header = .{
        // Do not retain bytes beyond the declared header. Accessors therefore
        // cannot accidentally find a NUL in a following header or payload.
        .bytes = blob[0..total],
        .index_count = nindex,
        .index_off = 8,
        .data_off = data_off,
        .data_size = hsize,
    };

    var marker: ?IndexEntry = null;
    var i: u32 = 0;
    while (i < nindex) : (i += 1) {
        const e = parsed.entry(i);
        if (isRegionTag(e.tag)) {
            if (i != 0 or marker != null) return error.InvalidRegion;
            marker = e;
            continue;
        }
        _ = try validateEntry(parsed, e);
    }

    if (marker) |region| {
        try validateRegion(parsed, region, expected_region, full_coverage);
    } else if (expected_region != null) {
        return error.InvalidRegion;
    }

    return parsed;
}

fn isRegionTag(tag: u32) bool {
    return tag == RPMTAG_HEADERIMAGE or
        tag == RPMTAG_HEADERSIGNATURES or
        tag == RPMTAG_HEADERIMMUTABLE;
}

fn validateEntry(h: Header, e: IndexEntry) Error!usize {
    if (e.typ < @intFromEnum(TypeId.char_type) or
        e.typ > @intFromEnum(TypeId.i18n_string))
    {
        return error.InvalidType;
    }
    if (e.count == 0 or e.count > h.data_size) return error.InvalidCount;

    const typ: TypeId = @enumFromInt(e.typ);
    const alignment: u32 = switch (typ) {
        .int16 => 2,
        .int32 => 4,
        .int64 => 8,
        else => 1,
    };
    if (e.offset % alignment != 0) return error.MisalignedOffset;
    if (e.offset > h.data_size) return error.OffsetOutOfRange;

    const start = h.dataOffset(e.offset) orelse return error.OffsetOutOfRange;
    const data_end = h.dataEnd();
    const len: usize = switch (typ) {
        .char_type, .int8, .bin => std.math.cast(usize, e.count) orelse
            return error.SizeOverflow,
        .int16 => try fixedWidthLength(e.count, 2),
        .int32 => try fixedWidthLength(e.count, 4),
        .int64 => try fixedWidthLength(e.count, 8),
        .string => blk: {
            if (e.count != 1) return error.InvalidCount;
            const nul = std.mem.indexOfScalarPos(
                u8,
                h.bytes[0..data_end],
                start,
                0,
            ) orelse return error.UnterminatedString;
            break :blk nul + 1 - start;
        },
        .string_array, .i18n_string => blk: {
            var off = start;
            var remaining = e.count;
            while (remaining != 0) : (remaining -= 1) {
                const nul = std.mem.indexOfScalarPos(
                    u8,
                    h.bytes[0..data_end],
                    off,
                    0,
                ) orelse return error.UnterminatedString;
                off = nul + 1;
            }
            break :blk off - start;
        },
        else => unreachable,
    };
    if (!rangeFits(start, len, data_end)) return error.OffsetOutOfRange;
    return len;
}

fn fixedWidthLength(count: u32, width: usize) Error!usize {
    return std.math.mul(
        usize,
        std.math.cast(usize, count) orelse return error.SizeOverflow,
        width,
    ) catch error.SizeOverflow;
}

fn validateRegion(
    h: Header,
    marker: IndexEntry,
    expected_region: ?u32,
    full_coverage: bool,
) Error!void {
    if (expected_region) |expected| {
        if (marker.tag != expected) return error.InvalidRegion;
    }
    if (marker.typ != @intFromEnum(TypeId.bin) or marker.count != @sizeOf(IndexEntry))
        return error.InvalidRegion;

    const trailer_off = std.math.cast(usize, marker.offset) orelse
        return error.InvalidRegion;
    if (!rangeFits(trailer_off, @sizeOf(IndexEntry), h.data_size))
        return error.InvalidRegion;
    const trailer_start = h.dataOffset(trailer_off) orelse return error.InvalidRegion;
    const trailer_tag = readU32(h.bytes, trailer_start);
    const trailer_type = readU32(h.bytes, trailer_start + 4);
    const trailer_raw_offset = readU32(h.bytes, trailer_start + 8);
    const trailer_count = readU32(h.bytes, trailer_start + 12);

    // rpm accepts HEADERIMAGE in old signature trailers and normalizes it to
    // HEADERSIGNATURES. No equivalent compatibility exception exists for the
    // main immutable header.
    const tag_matches = trailer_tag == marker.tag or
        (marker.tag == RPMTAG_HEADERSIGNATURES and trailer_tag == RPMTAG_HEADERIMAGE);
    if (!tag_matches or
        trailer_type != marker.typ or
        trailer_count != marker.count)
    {
        return error.InvalidRegion;
    }

    const signed_offset: i32 = @bitCast(trailer_raw_offset);
    if (signed_offset >= 0) return error.InvalidRegion;
    const span: u64 = @intCast(-@as(i64, signed_offset));
    if (span == 0 or span % @sizeOf(IndexEntry) != 0) return error.InvalidRegion;
    const region_indexes = span / @sizeOf(IndexEntry);
    if (region_indexes == 0 or region_indexes > h.index_count)
        return error.InvalidRegion;

    const region_data_end = std.math.add(
        usize,
        trailer_off,
        @sizeOf(IndexEntry),
    ) catch return error.InvalidRegion;
    if (full_coverage and
        (region_indexes != h.index_count or region_data_end != h.data_size))
    {
        return error.InvalidRegion;
    }

    // Entries inside the immutable portion may end immediately before the
    // trailer, and later "dribbles" may begin after it, but no entry may
    // overlap the trailer itself.
    var i: u32 = 1;
    while (i < h.index_count) : (i += 1) {
        const e = h.entry(i);
        if (isRegionTag(e.tag)) return error.InvalidRegion;
        const len = try validateEntry(h, e);
        const start = std.math.cast(usize, e.offset) orelse return error.InvalidRegion;
        const end = std.math.add(usize, start, len) catch return error.InvalidRegion;
        if (start < region_data_end and end > trailer_off) return error.InvalidRegion;
    }
}

fn rangeFits(start: usize, len: usize, end: usize) bool {
    if (start > end) return false;
    return len <= end - start;
}

fn readU32(buf: []const u8, off: usize) u32 {
    return @as(u32, buf[off]) << 24 |
        @as(u32, buf[off + 1]) << 16 |
        @as(u32, buf[off + 2]) << 8 |
        @as(u32, buf[off + 3]);
}

fn readU16(buf: []const u8, off: usize) u16 {
    return @as(u16, buf[off]) << 8 |
        @as(u16, buf[off + 1]);
}

fn readU64(buf: []const u8, off: usize) u64 {
    return @as(u64, buf[off]) << 56 |
        @as(u64, buf[off + 1]) << 48 |
        @as(u64, buf[off + 2]) << 40 |
        @as(u64, buf[off + 3]) << 32 |
        @as(u64, buf[off + 4]) << 24 |
        @as(u64, buf[off + 5]) << 16 |
        @as(u64, buf[off + 6]) << 8 |
        @as(u64, buf[off + 7]);
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
        0, 0, 0, 1, // nindex
        0,   0,   0,    6, // hsize
        // index entry: tag=1000, type=6 (string), offset=0, count=1
        0,   0,   0x03, 0xe8,
        0,   0,   0,    6,
        0,   0,   0,    0,
        0,   0,   0,    1,
        // data: "hello\0"
        'h', 'e', 'l',  'l',
        'o', 0,
    };
    const h = try Header.parse(&blob);
    try std.testing.expectEqual(@as(u32, 1), h.index_count);
    try std.testing.expectEqualStrings("hello", h.getString(.name).?);
    try std.testing.expect(h.getString(.version) == null);
}

test "nevra with arch, no epoch" {
    // name=foo, version=1.0, release=2, arch=x86_64 → foo-1.0-2.x86_64
    const blob = [_]u8{
        0,   0,   0,    4,
        0,   0,   0,    17,
        // NAME    tag=1000  type=6  offset=0   count=1
        0,   0,   0x03, 0xe8,
        0,   0,   0,    6,
        0,   0,   0,    0,
        0,   0,   0,    1,
        // VERSION tag=1001  type=6  offset=4   count=1
        0,   0,   0x03, 0xe9,
        0,   0,   0,    6,
        0,   0,   0,    4,
        0,   0,   0,    1,
        // RELEASE tag=1002  type=6  offset=8   count=1
        0,   0,   0x03, 0xea,
        0,   0,   0,    6,
        0,   0,   0,    8,
        0,   0,   0,    1,
        // ARCH    tag=1022  type=6  offset=10  count=1
        0,   0,   0x03, 0xfe,
        0,   0,   0,    6,
        0,   0,   0,    10,
        0,   0,   0,    1,
        'f', 'o', 'o',  0,
        '1', '.', '0',  0,
        '2', 0,   'x',  '8',
        '6', '_', '6',  '4',
        0,
    };
    const h = try Header.parse(&blob);
    const nevra = (try h.allocNevra(std.testing.allocator)).?;
    defer std.testing.allocator.free(nevra);
    try std.testing.expectEqualStrings("foo-1.0-2.x86_64", nevra);
    const evr = (try h.allocEvr(std.testing.allocator)).?;
    defer std.testing.allocator.free(evr);
    try std.testing.expectEqualStrings("1.0-2", evr);
}

test "nevra without arch (gpg-pubkey style)" {
    const blob = [_]u8{
        // nindex=3, hsize=3+9+9 = 21? compute: "gpg-pubkey\0" (11) +
        // "3135ce90\0" (9) + "5e6fda74\0" (9) = 29
        0,   0,   0,    3,
        0,   0,   0,    29,
        // NAME    tag=1000  type=6  offset=0   count=1
        0,   0,   0x03, 0xe8,
        0,   0,   0,    6,
        0,   0,   0,    0,
        0,   0,   0,    1,
        // VERSION tag=1001  type=6  offset=11  count=1
        0,   0,   0x03, 0xe9,
        0,   0,   0,    6,
        0,   0,   0,    11,
        0,   0,   0,    1,
        // RELEASE tag=1002  type=6  offset=20  count=1
        0,   0,   0x03, 0xea,
        0,   0,   0,    6,
        0,   0,   0,    20,
        0,   0,   0,    1,
        // data: gpg-pubkey\0 3135ce90\0 5e6fda74\0
        'g', 'p', 'g',  '-',
        'p', 'u', 'b',  'k',
        'e', 'y', 0,    '3',
        '1', '3', '5',  'c',
        'e', '9', '0',  0,
        '5', 'e', '6',  'f',
        'd', 'a', '7',  '4',
        0,
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
        0,   0,   0,    36, // hsize = 36
        // REQUIRENAME tag=1049 type=8 (string_array) offset=0 count=3
        0,   0,   0x04, 0x19,
        0,   0,   0,    8,
        0,   0,   0,    0,
        0,   0,   0,    3,
        // REQUIREFLAGS tag=1048 type=4 (int32) offset=20 count=3
        0,   0,   0x04, 0x18,
        0,   0,   0,    4,
        0,   0,   0,    20,
        0,   0,   0,    3,
        // SIG_SHA256 tag=273 type=7 (bin) offset=32 count=4
        0,   0,   0x01, 0x11,
        0,   0,   0,    7,
        0,   0,   0,    32,
        0,   0,   0,    4,
        // data starts here
        'l', 'i', 'b',  'c',
        0,   'g', 'l',  'i',
        'b', 'c', 0,    'o',
        'p', 'e', 'n',  's',
        's', 'l', 0,
        0, // padding to 4-byte alignment for the int32 array
        0,
        0,
        0,
        0x08,
        0,
        0,
        0,
        0x10,
        0,
        0,
        0,
        0x02,
        0xde, 0xad, 0xbe, 0xef, // SIG_SHA256 (truncated)
    };
    const h = try Header.parse(&blob);

    try std.testing.expectEqual(@as(usize, 3), h.stringArrayCount(.requirename));
    try std.testing.expectEqualStrings("libc", h.stringArrayItem(.requirename, 0).?);
    try std.testing.expectEqualStrings("glibc", h.stringArrayItem(.requirename, 1).?);
    try std.testing.expectEqualStrings("openssl", h.stringArrayItem(.requirename, 2).?);
    try std.testing.expectEqual(@as(?[]const u8, null), h.stringArrayItem(.requirename, 3));

    var names = (try h.stringArrayIteratorChecked(.requirename)).?;
    try std.testing.expectEqualStrings("libc", (try names.next()).?);
    try std.testing.expectEqualStrings("glibc", (try names.next()).?);
    try std.testing.expectEqualStrings("openssl", (try names.next()).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try names.next());

    try std.testing.expectEqual(@as(u32, 0x08), h.u32ArrayItem(.requireflags, 0).?);
    try std.testing.expectEqual(@as(u32, 0x10), h.u32ArrayItem(.requireflags, 1).?);
    try std.testing.expectEqual(@as(u32, 0x02), h.u32ArrayItem(.requireflags, 2).?);
    try std.testing.expectEqual(@as(?u32, null), h.u32ArrayItem(.requireflags, 3));

    const bin = h.getBinary(.summary) orelse {
        // .summary's type isn't BIN, so it returns null — verify that
        // path before falling through to the raw-tag check.
        const raw = h.getBinaryRaw(273).?;
        try std.testing.expectEqualSlices(u8, &.{ 0xde, 0xad, 0xbe, 0xef }, raw);
        return;
    };
    _ = bin;
}

fn writeTestU32(buf: []u8, off: usize, value: u32) void {
    buf[off] = @truncate(value >> 24);
    buf[off + 1] = @truncate(value >> 16);
    buf[off + 2] = @truncate(value >> 8);
    buf[off + 3] = @truncate(value);
}

test "parse rejects malformed entries table" {
    const Case = struct {
        typ: u32,
        offset: u32,
        count: u32,
        data_size: u32,
        data: [8]u8,
        expected: Error,
    };
    const cases = [_]Case{
        .{ .typ = 0, .offset = 0, .count = 1, .data_size = 1, .data = .{0} ** 8, .expected = error.InvalidType },
        .{ .typ = 10, .offset = 0, .count = 1, .data_size = 1, .data = .{0} ** 8, .expected = error.InvalidType },
        .{ .typ = 2, .offset = 0, .count = 0, .data_size = 1, .data = .{0} ** 8, .expected = error.InvalidCount },
        .{ .typ = 4, .offset = 1, .count = 1, .data_size = 8, .data = .{0} ** 8, .expected = error.MisalignedOffset },
        .{ .typ = 3, .offset = 1, .count = 1, .data_size = 8, .data = .{0} ** 8, .expected = error.MisalignedOffset },
        .{ .typ = 5, .offset = 4, .count = 1, .data_size = 8, .data = .{0} ** 8, .expected = error.MisalignedOffset },
        .{ .typ = 4, .offset = 8, .count = 1, .data_size = 8, .data = .{0} ** 8, .expected = error.OffsetOutOfRange },
        .{ .typ = 7, .offset = 7, .count = 2, .data_size = 8, .data = .{0} ** 8, .expected = error.OffsetOutOfRange },
        .{ .typ = 6, .offset = 0, .count = 2, .data_size = 2, .data = .{ 'x', 0, 0, 0, 0, 0, 0, 0 }, .expected = error.InvalidCount },
        .{ .typ = 6, .offset = 0, .count = 1, .data_size = 2, .data = .{ 'x', 'y', 0, 0, 0, 0, 0, 0 }, .expected = error.UnterminatedString },
        .{ .typ = 8, .offset = 0, .count = 2, .data_size = 3, .data = .{ 'x', 0, 'y', 0, 0, 0, 0, 0 }, .expected = error.UnterminatedString },
        .{ .typ = 9, .offset = 0, .count = 2, .data_size = 3, .data = .{ 'x', 0, 'y', 0, 0, 0, 0, 0 }, .expected = error.UnterminatedString },
        .{ .typ = 4, .offset = 0, .count = 0xffffffff, .data_size = 8, .data = .{0} ** 8, .expected = error.InvalidCount },
    };

    for (cases) |case| {
        var blob = [_]u8{0} ** 32;
        writeTestU32(&blob, 0, 1);
        writeTestU32(&blob, 4, case.data_size);
        writeTestU32(&blob, 8, @intFromEnum(TagId.name));
        writeTestU32(&blob, 12, case.typ);
        writeTestU32(&blob, 16, case.offset);
        writeTestU32(&blob, 20, case.count);
        @memcpy(blob[24..32], &case.data);
        try std.testing.expectError(case.expected, Header.parse(blob[0 .. 24 + case.data_size]));
    }
}

test "parse checks intro arithmetic and declared end" {
    var intro = [_]u8{0} ** 8;
    writeTestU32(&intro, 0, 0xffffffff);
    try std.testing.expectError(error.BadIndexCount, Header.parse(&intro));
    writeTestU32(&intro, 0, 1);
    writeTestU32(&intro, 4, 0xffffffff);
    try std.testing.expectError(error.BadDataSize, Header.parse(&intro));

    // The NUL in trailing bytes is not part of the declared data section.
    var blob = [_]u8{0} ** 26;
    writeTestU32(&blob, 0, 1);
    writeTestU32(&blob, 4, 1);
    writeTestU32(&blob, 8, @intFromEnum(TagId.name));
    writeTestU32(&blob, 12, @intFromEnum(TypeId.string));
    writeTestU32(&blob, 20, 1);
    blob[24] = 'x';
    blob[25] = 0;
    try std.testing.expectError(error.UnterminatedString, Header.parse(&blob));
}

fn makeRegionHeader(
    region_tag: u32,
    trailer_tag: u32,
    trailer_offset: i32,
) [58]u8 {
    var blob = [_]u8{0} ** 58;
    writeTestU32(&blob, 0, 2);
    writeTestU32(&blob, 4, 18);
    writeTestU32(&blob, 8, region_tag);
    writeTestU32(&blob, 12, @intFromEnum(TypeId.bin));
    writeTestU32(&blob, 16, 2);
    writeTestU32(&blob, 20, 16);
    writeTestU32(&blob, 24, @intFromEnum(TagId.name));
    writeTestU32(&blob, 28, @intFromEnum(TypeId.string));
    writeTestU32(&blob, 32, 0);
    writeTestU32(&blob, 36, 1);
    blob[40] = 'x';
    blob[41] = 0;
    writeTestU32(&blob, 42, trailer_tag);
    writeTestU32(&blob, 46, @intFromEnum(TypeId.bin));
    writeTestU32(&blob, 50, @bitCast(trailer_offset));
    writeTestU32(&blob, 54, 16);
    return blob;
}

test "immutable region validation is upstream compatible" {
    const main = makeRegionHeader(63, 63, -32);
    const parsed = try Header.parseWithRegion(&main, .immutable, true);
    try std.testing.expectEqualStrings("x", parsed.getString(.name).?);

    // Old signature headers can carry HEADERIMAGE in their trailer.
    const old_signature = makeRegionHeader(62, 61, -32);
    _ = try Header.parseWithRegion(&old_signature, .signatures, true);

    const Case = struct {
        mutate: enum { marker_type, marker_count, trailer_tag, trailer_type, trailer_count, trailer_positive, trailer_unaligned, trailer_span, incomplete },
    };
    const cases = [_]Case{
        .{ .mutate = .marker_type },
        .{ .mutate = .marker_count },
        .{ .mutate = .trailer_tag },
        .{ .mutate = .trailer_type },
        .{ .mutate = .trailer_count },
        .{ .mutate = .trailer_positive },
        .{ .mutate = .trailer_unaligned },
        .{ .mutate = .trailer_span },
        .{ .mutate = .incomplete },
    };
    for (cases) |case| {
        var bad = makeRegionHeader(63, 63, -32);
        switch (case.mutate) {
            .marker_type => writeTestU32(&bad, 12, @intFromEnum(TypeId.string)),
            .marker_count => writeTestU32(&bad, 20, 15),
            .trailer_tag => writeTestU32(&bad, 42, 62),
            .trailer_type => writeTestU32(&bad, 46, @intFromEnum(TypeId.string)),
            .trailer_count => writeTestU32(&bad, 54, 15),
            .trailer_positive => writeTestU32(&bad, 50, 32),
            .trailer_unaligned => writeTestU32(&bad, 50, @bitCast(@as(i32, -31))),
            .trailer_span => writeTestU32(&bad, 50, @bitCast(@as(i32, -48))),
            .incomplete => writeTestU32(&bad, 50, @bitCast(@as(i32, -16))),
        }
        try std.testing.expectError(
            error.InvalidRegion,
            Header.parseWithRegion(&bad, .immutable, true),
        );
    }

    var misplaced = makeRegionHeader(63, 63, -32);
    const first = misplaced[8..24].*;
    misplaced[8..24].* = misplaced[24..40].*;
    misplaced[24..40].* = first;
    try std.testing.expectError(error.InvalidRegion, Header.parse(&misplaced));
}

test "checked accessors distinguish absent and malformed types" {
    const blob = [_]u8{
        0, 0, 0,    1,    0, 0, 0, 4,
        0, 0, 0x04, 0x18, 0, 0, 0, 4,
        0, 0, 0,    0,    0, 0, 0, 1,
        0, 0, 0,    1,
    };
    const h = try Header.parse(&blob);
    try std.testing.expect((try h.getU32Checked(.requireflags)).? == 1);
    try std.testing.expect((try h.getU32Checked(.epoch)) == null);
    try std.testing.expectError(error.Malformed, h.getStringChecked(.requireflags));

    const array_blob = [_]u8{
        0,   0, 0,    1,    0, 0, 0, 2,
        0,   0, 0x03, 0xe8, 0, 0, 0, 8,
        0,   0, 0,    0,    0, 0, 0, 1,
        'x', 0,
    };
    const array_h = try Header.parse(&array_blob);
    try std.testing.expect(array_h.getString(.name) == null);
    try std.testing.expectError(error.Malformed, array_h.getStringChecked(.name));
}

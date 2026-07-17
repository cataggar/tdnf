//! Native OpenPGP certificate import into the SQLite rpm database.
//!
//! Records deliberately use rpm 4's common-denominator schema:
//! VERSION is the primary key's eight-hex-digit short ID. RPM 6 can use
//! a full-fingerprint VERSION, but that representation is not readable by
//! all supported rpm 4 hosts. Full primary and subkey fingerprints remain
//! available through `gpg(<id>)` provides and PUBKEYS is authoritative.

const std = @import("std");
const header = @import("rpm_header");
const rpmdb_write = @import("rpmdb_write.zig");
const txn_config = @import("txn_config.zig");
const certificate = @import("pgp/certificate.zig");

const RPMTAG_PUBKEYS: u32 = 266;
const RPMTAG_SHA1HEADER: u32 = 269;
const RPMTAG_SHA256HEADER: u32 = 273;
const RPMTAG_RPMVERSION: u32 = 1064;
const RPMSENSE_EQUAL: u32 = 1 << 3;
const RPMSENSE_KEYRING: u32 = 1 << 26;
const PROVIDE_FLAGS: u32 = RPMSENSE_EQUAL | RPMSENSE_KEYRING;
const HEADER_MAGIC = [_]u8{ 0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0 };

pub const Error = error{
    InvalidExistingPubkey,
    InvalidPubkeysEncoding,
} || certificate.ParseError || rpmdb_write.Error;

const BuiltRecord = struct {
    fingerprint: [32]u8,
    fingerprint_len: u8,
    blob: []u8,
};

const Provide = struct {
    name: []const u8,
    version: []const u8,
};

/// Parse every input certificate before opening the database, build all
/// headers, then replace matching fingerprint identities in one transaction.
pub fn importAtPath(
    allocator: std.mem.Allocator,
    db_path: []const u8,
    input: []const u8,
    timestamp: u32,
) Error!usize {
    var parsed = try certificate.parseAll(allocator, input);
    defer parsed.deinit();
    return importParsed(
        allocator,
        try rpmdb_write.Writer.openAtPath(db_path),
        &parsed,
        timestamp,
    );
}

pub fn importRoot(
    allocator: std.mem.Allocator,
    root: []const u8,
    input: []const u8,
    timestamp: u32,
) Error!usize {
    var parsed = try certificate.parseAll(allocator, input);
    defer parsed.deinit();
    return importParsed(
        allocator,
        try rpmdb_write.Writer.openRoot(root),
        &parsed,
        timestamp,
    );
}

pub fn importConfig(
    allocator: std.mem.Allocator,
    config: *const txn_config.TxnConfig,
    input: []const u8,
    timestamp: u32,
) Error!usize {
    var parsed = try certificate.parseAll(allocator, input);
    defer parsed.deinit();
    return importParsed(
        allocator,
        try rpmdb_write.Writer.openConfig(config),
        &parsed,
        timestamp,
    );
}

fn importParsed(
    allocator: std.mem.Allocator,
    opened_writer: rpmdb_write.Writer,
    parsed: *const certificate.Collection,
    timestamp: u32,
) Error!usize {
    var writer = opened_writer;
    defer writer.close();

    var unique = std.array_list.Managed(usize).init(allocator);
    defer unique.deinit();
    for (parsed.certificates, 0..) |cert, index| {
        var duplicate: ?usize = null;
        for (unique.items, 0..) |prior_index, unique_index| {
            const prior = parsed.certificates[prior_index];
            if (fingerprintEqual(
                cert.primary.fingerprint,
                prior.primary.fingerprint,
            )) {
                duplicate = unique_index;
                break;
            }
        }
        if (duplicate) |unique_index| {
            // A later transferable certificate may carry refreshed user IDs
            // or subkeys while retaining the same primary identity.
            unique.items[unique_index] = index;
        } else {
            try unique.append(index);
        }
    }

    var records = std.array_list.Managed(BuiltRecord).init(allocator);
    defer {
        for (records.items) |record| allocator.free(record.blob);
        records.deinit();
    }
    for (unique.items) |index| {
        const cert = parsed.certificates[index];
        try records.append(.{
            .fingerprint = cert.primary.fingerprint.bytes,
            .fingerprint_len = cert.primary.fingerprint.len,
            .blob = try buildRecord(allocator, cert, timestamp),
        });
    }
    const imported_count = records.items.len;

    try writer.beginTransaction();
    errdefer writer.rollbackTransaction() catch {};

    const existing = try writer.findHnumsByName(
        allocator,
        "gpg-pubkey",
    );
    defer allocator.free(existing);

    var remove = std.array_list.Managed(u32).init(allocator);
    defer remove.deinit();
    for (existing) |hnum| {
        const blob = try writer.readHeaderBlobCopy(allocator, hnum);
        defer allocator.free(blob);
        const hdr = header.Header.parse(blob) catch
            return error.InvalidExistingPubkey;
        var stored = try parseStoredHeader(allocator, hdr);
        defer stored.deinit();

        var replaced = false;
        for (stored.certificates) |cert| {
            if (certificateMatchesIncoming(cert, records.items[0..imported_count])) {
                replaced = true;
            }
        }
        if (!replaced) continue;

        for (stored.certificates) |cert| {
            if (certificateMatchesIncoming(cert, records.items[0..imported_count]))
                continue;
            try records.append(.{
                .fingerprint = cert.primary.fingerprint.bytes,
                .fingerprint_len = cert.primary.fingerprint.len,
                .blob = try buildRecord(allocator, cert, timestamp),
            });
        }
        try remove.append(hnum);
    }

    for (remove.items) |hnum| {
        try writer.eraseHeaderInTransaction(hnum);
    }
    for (records.items) |record| {
        _ = try writer.insertHeaderInTransaction(record.blob);
    }
    try writer.commitTransaction();
    return imported_count;
}

fn parseStoredHeader(
    allocator: std.mem.Allocator,
    hdr: header.Header,
) Error!certificate.Collection {
    const pubkeys = decodePubkeys(allocator, hdr) catch
        return error.InvalidExistingPubkey;
    defer if (pubkeys) |bytes| allocator.free(bytes);
    const source = if (pubkeys) |bytes| bytes else blk: {
        const description = (hdr.getStringChecked(.description) catch
            return error.InvalidExistingPubkey) orelse
            return error.InvalidExistingPubkey;
        break :blk description;
    };
    return certificate.parseAll(allocator, source) catch
        return error.InvalidExistingPubkey;
}

fn certificateMatchesIncoming(
    cert: certificate.Certificate,
    incoming: []const BuiltRecord,
) bool {
    for (incoming) |record| {
        if (record.fingerprint_len == cert.primary.fingerprint.len and
            std.mem.eql(
                u8,
                record.fingerprint[0..record.fingerprint_len],
                cert.primary.fingerprint.slice(),
            ))
        {
            return true;
        }
    }
    return false;
}

fn buildRecord(
    allocator: std.mem.Allocator,
    cert: certificate.Certificate,
    timestamp: u32,
) Error![]u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const short_id = try hexLower(arena, cert.primary.key_id[4..]);
    const long_id = try hexLower(arena, &cert.primary.key_id);
    const release = try hexU32(arena, cert.primary.created_at);
    const packager = cert.first_user_id orelse
        try std.fmt.allocPrint(arena, "gpg({s})", .{long_id});
    const summary = try std.fmt.allocPrint(
        arena,
        "{s} public key",
        .{packager},
    );
    const pubkeys = try encodeBase64Wrapped(arena, cert.bytes);
    const description = try encodeArmor(arena, cert.bytes);

    var provides = std.array_list.Managed(Provide).init(arena);
    defer provides.deinit();
    if (cert.first_user_id) |user_id| {
        try appendUniqueProvide(
            &provides,
            .{
                .name = try std.fmt.allocPrint(arena, "gpg({s})", .{user_id}),
                .version = try dependencyVersion(arena, cert.primary),
            },
        );
    }
    try appendIdentityProvides(arena, &provides, cert.primary);
    for (cert.subkeys) |subkey| {
        try appendIdentityProvides(arena, &provides, subkey);
    }

    const provide_versions = try arena.alloc(
        []const u8,
        provides.items.len,
    );
    const provide_names = try arena.alloc(
        []const u8,
        provides.items.len,
    );
    for (provides.items, 0..) |provide, index| {
        provide_names[index] = provide.name;
        provide_versions[index] = provide.version;
    }
    const provide_flags = try arena.alloc(u32, provides.items.len);
    @memset(provide_flags, PROVIDE_FLAGS);

    const immutable_fields = [_]rpmdb_write.HeaderField{
        stringArrayField(RPMTAG_PUBKEYS, try stringArrayBytes(
            arena,
            &.{pubkeys},
        ), 1),
        stringField(@intFromEnum(header.TagId.name), try stringBytes(
            arena,
            "gpg-pubkey",
        ), .string),
        stringField(@intFromEnum(header.TagId.version), try stringBytes(
            arena,
            short_id,
        ), .string),
        stringField(@intFromEnum(header.TagId.release), try stringBytes(
            arena,
            release,
        ), .string),
        stringField(@intFromEnum(header.TagId.summary), try stringBytes(
            arena,
            summary,
        ), .i18n_string),
        stringField(@intFromEnum(header.TagId.description), try stringBytes(
            arena,
            description,
        ), .i18n_string),
        u32Field(@intFromEnum(header.TagId.build_time), try u32Bytes(
            arena,
            cert.primary.created_at,
        )),
        stringField(@intFromEnum(header.TagId.buildhost), try stringBytes(
            arena,
            "localhost",
        ), .string),
        u32Field(@intFromEnum(header.TagId.size), try u32Bytes(arena, 0)),
        stringField(@intFromEnum(header.TagId.license), try stringBytes(
            arena,
            "pubkey",
        ), .string),
        stringField(@intFromEnum(header.TagId.packager), try stringBytes(
            arena,
            packager,
        ), .string),
        stringField(@intFromEnum(header.TagId.group), try stringBytes(
            arena,
            "Public Keys",
        ), .i18n_string),
        stringField(@intFromEnum(header.TagId.source_rpm), try stringBytes(
            arena,
            "(none)",
        ), .string),
        stringArrayField(
            @intFromEnum(header.TagId.providename),
            try stringArrayBytes(arena, provide_names),
            @intCast(provide_names.len),
        ),
        stringField(RPMTAG_RPMVERSION, try stringBytes(
            arena,
            "4.0.0",
        ), .string),
        int32ArrayField(
            @intFromEnum(header.TagId.provideflags),
            try u32ArrayBytes(arena, provide_flags),
            @intCast(provide_flags.len),
        ),
        stringArrayField(
            @intFromEnum(header.TagId.provideversion),
            try stringArrayBytes(arena, provide_versions),
            @intCast(provide_versions.len),
        ),
    };

    const immutable = try rpmdb_write.encodeImmutableHeader(
        allocator,
        &immutable_fields,
    );
    defer allocator.free(immutable);

    var sha1: [20]u8 = undefined;
    var sha1_hasher = std.crypto.hash.Sha1.init(.{});
    sha1_hasher.update(&HEADER_MAGIC);
    sha1_hasher.update(immutable);
    sha1_hasher.final(&sha1);

    var sha256: [32]u8 = undefined;
    var sha256_hasher = std.crypto.hash.sha2.Sha256.init(.{});
    sha256_hasher.update(&HEADER_MAGIC);
    sha256_hasher.update(immutable);
    sha256_hasher.final(&sha256);

    const mutable_fields = [_]rpmdb_write.HeaderField{
        stringField(RPMTAG_SHA1HEADER, try stringBytes(
            arena,
            try hexLower(arena, &sha1),
        ), .string),
        stringField(RPMTAG_SHA256HEADER, try stringBytes(
            arena,
            try hexLower(arena, &sha256),
        ), .string),
        u32Field(@intFromEnum(header.TagId.install_time), try u32Bytes(
            arena,
            timestamp,
        )),
        u32Field(@intFromEnum(header.TagId.install_tid), try u32Bytes(
            arena,
            timestamp,
        )),
    };
    return rpmdb_write.appendHeaderFields(
        allocator,
        immutable,
        &mutable_fields,
    );
}

fn appendIdentityProvides(
    allocator: std.mem.Allocator,
    provides: *std.array_list.Managed(Provide),
    identity: certificate.KeyIdentity,
) !void {
    const short_id = try hexLower(allocator, identity.key_id[4..]);
    const long_id = try hexLower(allocator, &identity.key_id);
    const fingerprint = try hexLower(
        allocator,
        identity.fingerprint.slice(),
    );
    const version = try dependencyVersion(allocator, identity);
    inline for (.{ short_id, long_id, fingerprint }) |id| {
        try appendUniqueProvide(
            provides,
            .{
                .name = try std.fmt.allocPrint(allocator, "gpg({s})", .{id}),
                .version = version,
            },
        );
    }
}

fn dependencyVersion(
    allocator: std.mem.Allocator,
    identity: certificate.KeyIdentity,
) ![]u8 {
    const long_id = try hexLower(allocator, &identity.key_id);
    defer allocator.free(long_id);
    const release = try hexU32(allocator, identity.created_at);
    defer allocator.free(release);
    return std.fmt.allocPrint(
        allocator,
        "{d}:{s}-{s}",
        .{ identity.version, long_id, release },
    );
}

fn appendUniqueProvide(
    provides: *std.array_list.Managed(Provide),
    provide: Provide,
) !void {
    for (provides.items) |existing| {
        if (std.mem.eql(u8, existing.name, provide.name)) return;
    }
    try provides.append(provide);
}

fn fingerprintEqual(a: anytype, b: @TypeOf(a)) bool {
    return a.len == b.len and std.mem.eql(u8, a.slice(), b.slice());
}

fn stringField(
    tag: u32,
    bytes: []const u8,
    typ: header.TypeId,
) rpmdb_write.HeaderField {
    return .{ .tag = tag, .typ = typ, .count = 1, .bytes = bytes };
}

fn stringArrayField(
    tag: u32,
    bytes: []const u8,
    count: u32,
) rpmdb_write.HeaderField {
    return .{ .tag = tag, .typ = .string_array, .count = count, .bytes = bytes };
}

fn u32Field(tag: u32, bytes: []const u8) rpmdb_write.HeaderField {
    return .{ .tag = tag, .typ = .int32, .count = 1, .bytes = bytes };
}

fn int32ArrayField(
    tag: u32,
    bytes: []const u8,
    count: u32,
) rpmdb_write.HeaderField {
    return .{ .tag = tag, .typ = .int32, .count = count, .bytes = bytes };
}

fn stringBytes(
    allocator: std.mem.Allocator,
    value: []const u8,
) ![]u8 {
    const out = try allocator.alloc(u8, value.len + 1);
    @memcpy(out[0..value.len], value);
    out[value.len] = 0;
    return out;
}

fn stringArrayBytes(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) ![]u8 {
    var total: usize = 0;
    for (values) |value| total += value.len + 1;
    const out = try allocator.alloc(u8, total);
    var offset: usize = 0;
    for (values) |value| {
        @memcpy(out[offset .. offset + value.len], value);
        offset += value.len;
        out[offset] = 0;
        offset += 1;
    }
    return out;
}

fn u32Bytes(allocator: std.mem.Allocator, value: u32) ![]u8 {
    const out = try allocator.alloc(u8, 4);
    writeU32(out, 0, value);
    return out;
}

fn u32ArrayBytes(
    allocator: std.mem.Allocator,
    values: []const u32,
) ![]u8 {
    const out = try allocator.alloc(u8, values.len * 4);
    for (values, 0..) |value, index| writeU32(out, index * 4, value);
    return out;
}

fn writeU32(out: []u8, offset: usize, value: u32) void {
    out[offset] = @truncate(value >> 24);
    out[offset + 1] = @truncate(value >> 16);
    out[offset + 2] = @truncate(value >> 8);
    out[offset + 3] = @truncate(value);
}

fn hexU32(allocator: std.mem.Allocator, value: u32) ![]u8 {
    var bytes: [4]u8 = undefined;
    writeU32(&bytes, 0, value);
    return hexLower(allocator, &bytes);
}

fn hexLower(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const alphabet = "0123456789abcdef";
    const out = try allocator.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |byte, index| {
        out[index * 2] = alphabet[byte >> 4];
        out[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return out;
}

fn encodeBase64Wrapped(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(bytes.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, bytes);
    const line_count = (encoded_len + 63) / 64;
    const out = try allocator.alloc(u8, encoded_len + line_count);
    var source: usize = 0;
    var dest: usize = 0;
    while (source < encoded.len) {
        const count = @min(@as(usize, 64), encoded.len - source);
        @memcpy(out[dest .. dest + count], encoded[source .. source + count]);
        source += count;
        dest += count;
        out[dest] = '\n';
        dest += 1;
    }
    return out;
}

fn encodeArmor(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const encoded = try encodeBase64Wrapped(allocator, bytes);
    defer allocator.free(encoded);
    var crc = std.hash.crc.Crc24Openpgp.init();
    crc.update(bytes);
    const value = crc.final();
    const crc_bytes = [_]u8{
        @truncate(value >> 16),
        @truncate(value >> 8),
        @truncate(value),
    };
    var crc_encoded: [4]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&crc_encoded, &crc_bytes);
    return std.fmt.allocPrint(
        allocator,
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" ++
            "Version: rpmzig-4.0.0\n\n{s}={s}\n" ++
            "-----END PGP PUBLIC KEY BLOCK-----\n",
        .{ encoded, crc_encoded },
    );
}

pub fn decodePubkeys(
    allocator: std.mem.Allocator,
    hdr: header.Header,
) Error!?[]u8 {
    const count = hdr.stringArrayCountChecked(.pubkeys) catch
        return error.InvalidExistingPubkey;
    const actual = count orelse return null;
    if (actual == 0) return error.InvalidExistingPubkey;

    var decoded = std.array_list.Managed(u8).init(allocator);
    errdefer decoded.deinit();
    var index: usize = 0;
    while (index < actual) : (index += 1) {
        const maybe_encoded = hdr.stringArrayItemChecked(
            .pubkeys,
            index,
        ) catch return error.InvalidExistingPubkey;
        const encoded = maybe_encoded orelse
            return error.InvalidExistingPubkey;
        try decodeBase64Append(&decoded, encoded);
    }
    return try decoded.toOwnedSlice();
}

fn decodeBase64Append(
    output: *std.array_list.Managed(u8),
    encoded: []const u8,
) Error!void {
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const upper = decoder.calcSizeUpperBound(encoded.len);
    const scratch = output.allocator.alloc(u8, upper) catch
        return error.OutOfMemory;
    defer output.allocator.free(scratch);
    const size = decoder.decode(scratch, encoded) catch
        return error.InvalidPubkeysEncoding;
    if (size == 0) return error.InvalidPubkeysEncoding;
    output.appendSlice(scratch[0..size]) catch return error.OutOfMemory;
}

const testing = std.testing;
const microsoft_armored = @embedFile("pgp/testdata/microsoft-rpm-key.asc");
const microsoft_binary = @embedFile("pgp/testdata/microsoft-rpm-key.bin");
const subkey_binary = @embedFile("pgp/testdata/rsa-primary-subkey-keyring.bin");

fn removeTestTree(path: []const u8) void {
    std.Io.Dir.cwd().deleteTree(std.testing.io, path) catch {};
}

fn testDbPath(
    allocator: std.mem.Allocator,
    name: []const u8,
) !struct { dir: []u8, db: []u8 } {
    const dir = try std.fmt.allocPrint(
        allocator,
        ".zig-cache/rpmdb-pubkey-{s}",
        .{name},
    );
    errdefer allocator.free(dir);
    removeTestTree(dir);
    const db = try std.fmt.allocPrint(allocator, "{s}/rpmdb.sqlite", .{dir});
    return .{ .dir = dir, .db = db };
}

test "pubkey import accepts armored binary and CRLF input" {
    const allocator = testing.allocator;
    inline for (.{ "armor", "binary", "crlf" }, 0..) |name, variant| {
        const paths = try testDbPath(allocator, name);
        defer allocator.free(paths.dir);
        defer allocator.free(paths.db);
        defer removeTestTree(paths.dir);

        var crlf = std.array_list.Managed(u8).init(allocator);
        defer crlf.deinit();
        if (variant == 2) {
            for (microsoft_armored) |ch| {
                if (ch == '\n') try crlf.append('\r');
                try crlf.append(ch);
            }
        }
        const input = switch (variant) {
            0 => microsoft_armored,
            1 => microsoft_binary,
            else => crlf.items,
        };
        try testing.expectEqual(
            @as(usize, 1),
            try importAtPath(allocator, paths.db, input, 0x12345678),
        );

        var writer = try rpmdb_write.Writer.openAtPath(paths.db);
        defer writer.close();
        const hnums = try writer.findHnumsByName(allocator, "gpg-pubkey");
        defer allocator.free(hnums);
        try testing.expectEqual(@as(usize, 1), hnums.len);
        const blob = try writer.readHeaderBlobCopy(allocator, hnums[0]);
        defer allocator.free(blob);
        const hdr = try header.Header.parse(blob);
        try testing.expectEqualStrings("3135ce90", hdr.getString(.version).?);
        try testing.expectEqual(@as(?u32, 0x12345678), hdr.getU32(.install_time));
        const decoded = (try decodePubkeys(allocator, hdr)).?;
        defer allocator.free(decoded);
        try testing.expectEqualSlices(u8, microsoft_binary, decoded);
    }
}

test "pubkey import deduplicates and replaces by full fingerprint" {
    const allocator = testing.allocator;
    const paths = try testDbPath(allocator, "replace");
    defer allocator.free(paths.dir);
    defer allocator.free(paths.db);
    defer removeTestTree(paths.dir);

    var duplicates = std.array_list.Managed(u8).init(allocator);
    defer duplicates.deinit();
    try duplicates.appendSlice(microsoft_binary);
    try duplicates.appendSlice(microsoft_binary);
    try testing.expectEqual(
        @as(usize, 1),
        try importAtPath(allocator, paths.db, duplicates.items, 1),
    );
    try testing.expectEqual(
        @as(usize, 1),
        try importAtPath(allocator, paths.db, microsoft_armored, 2),
    );

    var writer = try rpmdb_write.Writer.openAtPath(paths.db);
    defer writer.close();
    const hnums = try writer.findHnumsByName(allocator, "gpg-pubkey");
    defer allocator.free(hnums);
    try testing.expectEqual(@as(usize, 1), hnums.len);
    const blob = try writer.readHeaderBlobCopy(allocator, hnums[0]);
    defer allocator.free(blob);
    const hdr = try header.Header.parse(blob);
    try testing.expectEqual(@as(?u32, 2), hdr.getU32(.install_time));
}

test "replacing one certificate preserves other PUBKEYS in the same row" {
    const allocator = testing.allocator;
    const paths = try testDbPath(allocator, "replace-multi-pubkeys");
    defer allocator.free(paths.dir);
    defer allocator.free(paths.db);
    defer removeTestTree(paths.dir);

    var writer = try rpmdb_write.Writer.openAtPath(paths.db);
    defer writer.close();
    try insertMultiPubkeysTestRow(
        allocator,
        &writer,
        &.{ microsoft_binary, subkey_binary },
    );

    try testing.expectEqual(
        @as(usize, 1),
        try importAtPath(allocator, paths.db, microsoft_armored, 9),
    );

    const hnums = try writer.findHnumsByName(allocator, "gpg-pubkey");
    defer allocator.free(hnums);
    try testing.expectEqual(@as(usize, 2), hnums.len);
    var saw_replacement = false;
    var saw_preserved = false;
    for (hnums) |hnum| {
        const blob = try writer.readHeaderBlobCopy(allocator, hnum);
        defer allocator.free(blob);
        const hdr = try header.Header.parse(blob);
        const decoded = (try decodePubkeys(allocator, hdr)).?;
        defer allocator.free(decoded);
        saw_replacement = saw_replacement or
            std.mem.eql(u8, decoded, microsoft_binary);
        saw_preserved = saw_preserved or std.mem.eql(u8, decoded, subkey_binary);
    }
    try testing.expect(saw_replacement);
    try testing.expect(saw_preserved);
}

test "pubkey record gives subkey provides their own EVR" {
    const allocator = testing.allocator;
    const paths = try testDbPath(allocator, "subkey");
    defer allocator.free(paths.dir);
    defer allocator.free(paths.db);
    defer removeTestTree(paths.dir);

    _ = try importAtPath(allocator, paths.db, subkey_binary, 3);
    var parsed = try certificate.parseAll(allocator, subkey_binary);
    defer parsed.deinit();
    const cert = parsed.certificates[0];

    var writer = try rpmdb_write.Writer.openAtPath(paths.db);
    defer writer.close();
    const hnums = try writer.findHnumsByName(allocator, "gpg-pubkey");
    defer allocator.free(hnums);
    const blob = try writer.readHeaderBlobCopy(allocator, hnums[0]);
    defer allocator.free(blob);
    const hdr = try header.Header.parse(blob);

    const primary_fpr = try hexLower(allocator, cert.primary.fingerprint.slice());
    defer allocator.free(primary_fpr);
    const subkey_fpr = try hexLower(
        allocator,
        cert.subkeys[0].fingerprint.slice(),
    );
    defer allocator.free(subkey_fpr);
    try testing.expect(headerHasProvide(hdr, primary_fpr));
    try testing.expect(headerHasProvide(hdr, subkey_fpr));

    const subkey_version = try dependencyVersion(
        allocator,
        cert.subkeys[0],
    );
    defer allocator.free(subkey_version);
    const actual_subkey_version = headerProvideVersion(hdr, subkey_fpr) orelse
        return error.TestExpectedProvideVersion;
    try testing.expectEqualStrings(subkey_version, actual_subkey_version);
}

test "host rpm reads native pubkey package and fingerprint indexes" {
    const allocator = testing.allocator;
    const version = std.process.run(allocator, testing.io, .{
        .argv = &.{ "rpm", "--version" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    }) catch return error.SkipZigTest;
    defer allocator.free(version.stdout);
    defer allocator.free(version.stderr);
    switch (version.term) {
        .exited => |code| if (code != 0) return error.SkipZigTest,
        else => return error.SkipZigTest,
    }

    const paths = try testDbPath(allocator, "host-rpm");
    defer allocator.free(paths.dir);
    defer allocator.free(paths.db);
    defer removeTestTree(paths.dir);
    const root_db = try std.fmt.allocPrint(
        allocator,
        "{s}/var/lib/rpm/rpmdb.sqlite",
        .{paths.dir},
    );
    defer allocator.free(root_db);
    _ = try importAtPath(allocator, root_db, microsoft_binary, 5);

    const root = try std.Io.Dir.cwd().realPathFileAlloc(
        testing.io,
        paths.dir,
        allocator,
    );
    defer allocator.free(root);
    const query = try std.process.run(allocator, testing.io, .{
        .argv = &.{
            "rpm",
            "--root",
            root,
            "--dbpath",
            "/var/lib/rpm",
            "-q",
            "gpg-pubkey-3135ce90-5e6fda74",
        },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    defer allocator.free(query.stdout);
    defer allocator.free(query.stderr);
    switch (query.term) {
        .exited => |code| try testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }

    var parsed = try certificate.parseAll(allocator, microsoft_binary);
    defer parsed.deinit();
    const full_fingerprint = try hexLower(
        allocator,
        parsed.certificates[0].primary.fingerprint.slice(),
    );
    defer allocator.free(full_fingerprint);
    const provide = try std.fmt.allocPrint(
        allocator,
        "gpg({s})",
        .{full_fingerprint},
    );
    defer allocator.free(provide);
    const whatprovides = try std.process.run(allocator, testing.io, .{
        .argv = &.{
            "rpm",
            "--root",
            root,
            "--dbpath",
            "/var/lib/rpm",
            "-q",
            "--whatprovides",
            provide,
        },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    defer allocator.free(whatprovides.stdout);
    defer allocator.free(whatprovides.stderr);
    switch (whatprovides.term) {
        .exited => |code| try testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }

    const db_dir = try std.fmt.allocPrint(
        allocator,
        "{s}/var/lib/rpm",
        .{root},
    );
    defer allocator.free(db_dir);
    const fixture = try std.Io.Dir.cwd().realPathFileAlloc(
        testing.io,
        "rpmzig/pgp/testdata/microsoft-rpm-key.asc",
        allocator,
    );
    defer allocator.free(fixture);

    try expectHostCommandSuccess(&.{
        "rpmkeys",
        "--dbpath",
        db_dir,
        "--test",
        "--import",
        fixture,
    });
    try expectHostCommandSuccess(&.{
        "rpm",
        "--dbpath",
        db_dir,
        "--import",
        fixture,
    });
    const after_reimport = try runHostCommand(&.{
        "rpm",
        "--dbpath",
        db_dir,
        "-qa",
        "gpg-pubkey*",
    });
    defer allocator.free(after_reimport.stdout);
    defer allocator.free(after_reimport.stderr);
    try expectHostExitZero(after_reimport.term);
    try testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, after_reimport.stdout, "\n"),
    );

    try expectHostCommandSuccess(&.{
        "rpm",
        "--dbpath",
        db_dir,
        "-e",
        "gpg-pubkey-3135ce90-5e6fda74",
    });
    const after_erase = try runHostCommand(&.{
        "rpm",
        "--dbpath",
        db_dir,
        "-qa",
        "gpg-pubkey*",
    });
    defer allocator.free(after_erase.stdout);
    defer allocator.free(after_erase.stderr);
    try expectHostExitZero(after_erase.term);
    try testing.expectEqual(
        @as(usize, 0),
        std.mem.trim(u8, after_erase.stdout, " \t\r\n").len,
    );
}

fn runHostCommand(argv: []const []const u8) !std.process.RunResult {
    return std.process.run(testing.allocator, testing.io, .{
        .argv = argv,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
}

fn expectHostCommandSuccess(argv: []const []const u8) !void {
    const result = try runHostCommand(argv);
    defer testing.allocator.free(result.stdout);
    defer testing.allocator.free(result.stderr);
    try expectHostExitZero(result.term);
}

fn expectHostExitZero(term: std.process.Child.Term) !void {
    switch (term) {
        .exited => |code| try testing.expectEqual(@as(u8, 0), code),
        else => return error.TestUnexpectedResult,
    }
}

test "bad CRC and malformed later certificate roll back completely" {
    const allocator = testing.allocator;
    const paths = try testDbPath(allocator, "rollback");
    defer allocator.free(paths.dir);
    defer allocator.free(paths.db);
    defer removeTestTree(paths.dir);

    _ = try importAtPath(allocator, paths.db, microsoft_binary, 1);
    var bad_armor = try allocator.dupe(u8, microsoft_armored);
    defer allocator.free(bad_armor);
    const body = std.mem.indexOf(u8, bad_armor, "mQEN") orelse
        return error.TestUnexpectedResult;
    bad_armor[body] = 'n';
    try testing.expectError(
        error.BadCrc,
        importAtPath(allocator, paths.db, bad_armor, 2),
    );

    var malformed = std.array_list.Managed(u8).init(allocator);
    defer malformed.deinit();
    try malformed.appendSlice(microsoft_binary);
    try malformed.appendSlice(&.{ 0x98, 0x06, 0x03, 0, 0, 0, 0, 1 });
    try testing.expectError(
        error.UnsupportedKeyVersion,
        importAtPath(allocator, paths.db, malformed.items, 3),
    );

    const non_primary_block = try encodeArmor(
        allocator,
        &.{ 0xB4, 0x01, 'x' },
    );
    defer allocator.free(non_primary_block);
    var malformed_armor = std.array_list.Managed(u8).init(allocator);
    defer malformed_armor.deinit();
    try malformed_armor.appendSlice(microsoft_armored);
    try malformed_armor.appendSlice(non_primary_block);
    try testing.expectError(
        error.BadFraming,
        importAtPath(allocator, paths.db, malformed_armor.items, 4),
    );

    var writer = try rpmdb_write.Writer.openAtPath(paths.db);
    defer writer.close();
    const hnums = try writer.findHnumsByName(allocator, "gpg-pubkey");
    defer allocator.free(hnums);
    try testing.expectEqual(@as(usize, 1), hnums.len);
    const blob = try writer.readHeaderBlobCopy(allocator, hnums[0]);
    defer allocator.free(blob);
    const hdr = try header.Header.parse(blob);
    try testing.expectEqual(@as(?u32, 1), hdr.getU32(.install_time));
}

test "pubkey import and reader data have no 128-key ceiling" {
    const allocator = testing.allocator;
    const paths = try testDbPath(allocator, "many");
    defer allocator.free(paths.dir);
    defer allocator.free(paths.db);
    defer removeTestTree(paths.dir);

    var input = std.array_list.Managed(u8).init(allocator);
    defer input.deinit();
    const copy = try allocator.dupe(u8, microsoft_binary);
    defer allocator.free(copy);
    var packets = @import("pgp/packet.zig").iterate(copy);
    const primary = (try packets.next()).?;
    const body_offset =
        @intFromPtr(primary.body.ptr) - @intFromPtr(copy.ptr);
    for (0..129) |index| {
        writeU32(copy, body_offset + 1, @intCast(0x5e6f0000 + index));
        try input.appendSlice(copy);
    }
    try testing.expectEqual(
        @as(usize, 129),
        try importAtPath(allocator, paths.db, input.items, 4),
    );

    var writer = try rpmdb_write.Writer.openAtPath(paths.db);
    defer writer.close();
    const hnums = try writer.findHnumsByName(allocator, "gpg-pubkey");
    defer allocator.free(hnums);
    try testing.expectEqual(@as(usize, 129), hnums.len);
}

fn headerHasProvide(hdr: header.Header, hex_id: []const u8) bool {
    var expected_buf: [80]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &expected_buf,
        "gpg({s})",
        .{hex_id},
    ) catch return false;
    const count = hdr.stringArrayCount(.providename);
    for (0..count) |index| {
        const value = hdr.stringArrayItem(.providename, index) orelse continue;
        if (std.mem.eql(u8, value, expected)) return true;
    }
    return false;
}

fn headerProvideVersion(
    hdr: header.Header,
    hex_id: []const u8,
) ?[]const u8 {
    var expected_buf: [80]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &expected_buf,
        "gpg({s})",
        .{hex_id},
    ) catch return null;
    const names = hdr.stringArrayCount(.providename);
    const versions = hdr.stringArrayCount(.provideversion);
    if (names != versions) return null;
    for (0..names) |index| {
        const name = hdr.stringArrayItem(.providename, index) orelse continue;
        if (!std.mem.eql(u8, name, expected)) continue;
        return hdr.stringArrayItem(.provideversion, index);
    }
    return null;
}

fn insertMultiPubkeysTestRow(
    allocator: std.mem.Allocator,
    writer: *rpmdb_write.Writer,
    certificates: []const []const u8,
) !void {
    var encoded = try allocator.alloc([]u8, certificates.len);
    var encoded_len: usize = 0;
    defer {
        for (encoded[0..encoded_len]) |value| allocator.free(value);
        allocator.free(encoded);
    }
    for (certificates, 0..) |cert, index| {
        encoded[index] = try encodeBase64Wrapped(allocator, cert);
        encoded_len += 1;
    }
    const pubkeys = try stringArrayBytes(
        allocator,
        @as([]const []const u8, encoded),
    );
    defer allocator.free(pubkeys);
    const record = try rpmdb_write.encodeImmutableHeader(allocator, &.{
        .{
            .tag = RPMTAG_PUBKEYS,
            .typ = .string_array,
            .count = @intCast(encoded.len),
            .bytes = pubkeys,
        },
        .{
            .tag = @intFromEnum(header.TagId.name),
            .typ = .string,
            .count = 1,
            .bytes = "gpg-pubkey\x00",
        },
        .{
            .tag = @intFromEnum(header.TagId.version),
            .typ = .string,
            .count = 1,
            .bytes = "00000000\x00",
        },
        .{
            .tag = @intFromEnum(header.TagId.release),
            .typ = .string,
            .count = 1,
            .bytes = "00000000\x00",
        },
    });
    defer allocator.free(record);
    try writer.beginTransaction();
    errdefer writer.rollbackTransaction() catch {};
    _ = try writer.insertHeaderInTransaction(record);
    try writer.commitTransaction();
}

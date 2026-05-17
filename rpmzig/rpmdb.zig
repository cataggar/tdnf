//! tdnf rpmdb (Zig).
//!
//! T1 of the librpm-replacement plan (see
//! ../plan-replace-librpm.md). This module owns the read-only
//! interface to /var/lib/rpm/rpmdb.sqlite.
//!
//! T1 PR #1 (committed): the minimum viable surface —
//! `tdnf_rpmdb_count_packages` validates the FFI shape and build
//! wiring.
//!
//! T1 PR #2 (this file): iterator over the Packages table that
//! returns parsed RPM headers, plus a NEVRA-formatter shortcut.
//! `header.zig` decodes the binary header v3 blob. Header storage
//! is owned by the iterator (one row buffered at a time); NEVRA
//! strings are heap-allocated and freed by the caller via
//! `tdnf_rpmdb_string_free`.

const std = @import("std");
const header = @import("header.zig");

const c = @cImport({
    @cInclude("sqlite3.h");
    @cInclude("stdlib.h");
});

const PKG_TABLE = "Packages";
const DEFAULT_ROOT = "/";
const DEFAULT_DB_PATH = "var/lib/rpm/rpmdb.sqlite";

threadlocal var last_error_buf: [256]u8 = undefined;
threadlocal var last_error_len: usize = 0;

fn setError(comptime fmt: []const u8, args: anytype) void {
    const slice = std.fmt.bufPrint(&last_error_buf, fmt, args) catch blk: {
        const fallback = "(error message truncated)";
        @memcpy(last_error_buf[0..fallback.len], fallback);
        break :blk last_error_buf[0..fallback.len];
    };
    last_error_len = slice.len;
}

fn clearError() void {
    last_error_len = 0;
}

/// Count rows in the rpmdb's Packages table.
/// See rpmdb.h for the full contract.
export fn tdnf_rpmdb_count_packages(root: ?[*:0]const u8) i64 {
    clearError();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";

    const db_path = buildDbPath(&buf, root_slice) catch |err| {
        setError("path build failed: {t}", .{err});
        return -1;
    };

    var db: ?*c.sqlite3 = null;
    const open_rc = c.sqlite3_open_v2(
        db_path.ptr,
        &db,
        c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX,
        null,
    );
    defer {
        if (db != null) _ = c.sqlite3_close(db);
    }
    if (open_rc != c.SQLITE_OK) {
        setError("sqlite3_open_v2({s}): {s}", .{
            db_path,
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        return -1;
    }

    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT COUNT(*) FROM " ++ PKG_TABLE;
    const prepare_rc = c.sqlite3_prepare_v2(
        db,
        sql,
        sql.len,
        &stmt,
        null,
    );
    defer {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
    }
    if (prepare_rc != c.SQLITE_OK) {
        setError("sqlite3_prepare_v2 ({s}): {s}", .{
            sql,
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        return -1;
    }

    const step_rc = c.sqlite3_step(stmt);
    if (step_rc != c.SQLITE_ROW) {
        setError("sqlite3_step returned {d}, expected SQLITE_ROW", .{step_rc});
        return -1;
    }
    return c.sqlite3_column_int64(stmt, 0);
}

/// Returns the last error message produced by this thread.
export fn tdnf_rpmdb_last_error() [*:0]const u8 {
    if (last_error_len >= last_error_buf.len) last_error_len = last_error_buf.len - 1;
    last_error_buf[last_error_len] = 0;
    return @ptrCast(&last_error_buf);
}

/// Returns an opaque "cookie" string that captures the rpmdb state.
///
/// Two calls return the same cookie iff the rpmdb has not changed
/// between them (no install/remove/upgrade). Format is
/// `<max_hnum>:<count>` over the Packages table — both axes change
/// when packages are added or removed, and `max_hnum` advances even
/// on reinstalls (rpm allocates a fresh `hnum` for each row write).
///
/// Replaces librpm's `rpmdbCookie()` — same role, different format.
/// Existing history DBs from the librpm era will see one spurious
/// "delta" transaction on first sync after upgrade because the
/// format differs; subsequent syncs match.
///
/// Caller owns the returned string and must free it with
/// `tdnf_rpmdb_string_free`. Returns NULL on error.
export fn tdnf_rpmdb_cookie(root: ?[*:0]const u8) ?[*:0]u8 {
    clearError();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    const db_path = buildDbPath(&buf, root_slice) catch |err| {
        setError("path build failed: {t}", .{err});
        return null;
    };

    var db: ?*c.sqlite3 = null;
    const open_rc = c.sqlite3_open_v2(
        db_path.ptr,
        &db,
        c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX,
        null,
    );
    defer {
        if (db != null) _ = c.sqlite3_close(db);
    }
    if (open_rc != c.SQLITE_OK) {
        setError("sqlite3_open_v2({s}): {s}", .{
            db_path,
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        return null;
    }

    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT IFNULL(MAX(hnum), 0), COUNT(*) FROM " ++ PKG_TABLE;
    const prepare_rc = c.sqlite3_prepare_v2(db, sql, sql.len, &stmt, null);
    defer {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
    }
    if (prepare_rc != c.SQLITE_OK) {
        setError("sqlite3_prepare_v2: {s}", .{
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        return null;
    }
    const step_rc = c.sqlite3_step(stmt);
    if (step_rc != c.SQLITE_ROW) {
        setError("sqlite3_step returned {d}, expected SQLITE_ROW", .{step_rc});
        return null;
    }
    const max_hnum = c.sqlite3_column_int64(stmt, 0);
    const count = c.sqlite3_column_int64(stmt, 1);

    var local_buf: [64]u8 = undefined;
    const text = std.fmt.bufPrint(&local_buf, "{d}:{d}", .{ max_hnum, count }) catch {
        setError("cookie format buffer too small", .{});
        return null;
    };
    const out = c.malloc(text.len + 1) orelse {
        setError("out of memory", .{});
        return null;
    };
    const out_bytes = @as([*]u8, @ptrCast(out));
    @memcpy(out_bytes[0..text.len], text);
    out_bytes[text.len] = 0;
    return @ptrCast(out);
}

// -------------------------------------------------------------------
// Iterator
// -------------------------------------------------------------------

const Iter = struct {
    db: ?*c.sqlite3,
    stmt: ?*c.sqlite3_stmt,
};

/// Open a forward iterator over the rpmdb Packages table.
/// Returns NULL on error (use tdnf_rpmdb_last_error for details).
export fn tdnf_rpmdb_iter_open(root: ?[*:0]const u8) ?*Iter {
    clearError();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    const db_path = buildDbPath(&buf, root_slice) catch |err| {
        setError("path build failed: {t}", .{err});
        return null;
    };

    var db: ?*c.sqlite3 = null;
    const open_rc = c.sqlite3_open_v2(
        db_path.ptr,
        &db,
        c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX,
        null,
    );
    if (open_rc != c.SQLITE_OK) {
        setError("sqlite3_open_v2({s}): {s}", .{
            db_path,
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        if (db != null) _ = c.sqlite3_close(db);
        return null;
    }

    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT blob FROM " ++ PKG_TABLE ++ " ORDER BY hnum";
    const prepare_rc = c.sqlite3_prepare_v2(db, sql, sql.len, &stmt, null);
    if (prepare_rc != c.SQLITE_OK) {
        setError("sqlite3_prepare_v2: {s}", .{
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        _ = c.sqlite3_close(db);
        return null;
    }

    const iter = std.heap.c_allocator.create(Iter) catch {
        setError("out of memory", .{});
        _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_close(db);
        return null;
    };
    iter.* = .{ .db = db, .stmt = stmt };
    return iter;
}

/// Close and free an iterator opened by tdnf_rpmdb_iter_open.
export fn tdnf_rpmdb_iter_close(it: ?*Iter) void {
    const iter = it orelse return;
    if (iter.stmt) |s| _ = c.sqlite3_finalize(s);
    if (iter.db) |d| _ = c.sqlite3_close(d);
    std.heap.c_allocator.destroy(iter);
}

/// Advance the iterator and write the next package's NEVRA string into
/// `*nevra_out`. Caller owns the string and must free it with
/// tdnf_rpmdb_string_free.
///
/// Returns 1 on hit, 0 on end-of-iteration, -1 on error.
export fn tdnf_rpmdb_iter_next_nevra(it: ?*Iter, nevra_out: ?*[*:0]u8) i32 {
    clearError();
    const iter = it orelse {
        setError("null iterator", .{});
        return -1;
    };
    const out = nevra_out orelse {
        setError("null out param", .{});
        return -1;
    };

    while (true) {
        const step_rc = c.sqlite3_step(iter.stmt);
        if (step_rc == c.SQLITE_DONE) return 0;
        if (step_rc != c.SQLITE_ROW) {
            setError("sqlite3_step: {s}", .{
                std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(iter.db))),
            });
            return -1;
        }
        const blob_ptr = c.sqlite3_column_blob(iter.stmt, 0);
        const blob_len: usize = @intCast(c.sqlite3_column_bytes(iter.stmt, 0));
        if (blob_ptr == null or blob_len == 0) {
            // Empty header row — skip silently. rpmdb shouldn't have
            // these, but we don't want to fail the whole walk.
            continue;
        }
        const blob: []const u8 = @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len];

        const h = header.Header.parse(blob) catch |err| {
            setError("header.parse: {t}", .{err});
            return -1;
        };
        const nevra_opt = h.allocNevra(std.heap.c_allocator) catch {
            setError("out of memory building NEVRA", .{});
            return -1;
        };
        const nevra = nevra_opt orelse {
            setError("header missing required tag for NEVRA", .{});
            return -1;
        };
        // Re-allocate with a trailing NUL so the caller gets a C string.
        const zptr = c.malloc(nevra.len + 1) orelse {
            std.heap.c_allocator.free(nevra);
            setError("out of memory", .{});
            return -1;
        };
        const zbytes = @as([*]u8, @ptrCast(zptr));
        @memcpy(zbytes[0..nevra.len], nevra);
        zbytes[nevra.len] = 0;
        std.heap.c_allocator.free(nevra);
        out.* = @ptrCast(zbytes);
        return 1;
    }
}

/// Free a string returned by an iterator. (Wraps `free(3)` so callers
/// don't have to think about which allocator we used.)
export fn tdnf_rpmdb_string_free(s: ?[*:0]u8) void {
    if (s) |p| c.free(@ptrCast(p));
}

// -------------------------------------------------------------------
// Pubkey iterator (gpg-pubkey-* installed packages)
// -------------------------------------------------------------------
//
// `rpm --import` stores each imported public key as an installed
// package whose NAME is "gpg-pubkey", VERSION is the key id, RELEASE
// is the key's creation timestamp, and DESCRIPTION is the armored
// ASCII key block. We walk the rpmdb the same way the NEVRA iterator
// does and yield the description for each gpg-pubkey row.
//
// This is the read-only side of the T3 PR #5 verifier flip: the
// rpmzig verifier can preload the rpmdb's existing trust set rather
// than re-prompting users for keys that librpm already has.

const PubkeyIter = struct {
    db: ?*c.sqlite3,
    stmt: ?*c.sqlite3_stmt,
};

/// Open a forward iterator over rpmdb rows whose RPMTAG_NAME is
/// "gpg-pubkey".
export fn tdnf_rpmdb_pubkeys_open(root: ?[*:0]const u8) ?*PubkeyIter {
    clearError();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root_slice: []const u8 = if (root) |p| std.mem.span(p) else "";
    const db_path = buildDbPath(&buf, root_slice) catch |err| {
        setError("path build failed: {t}", .{err});
        return null;
    };

    var db: ?*c.sqlite3 = null;
    const open_rc = c.sqlite3_open_v2(
        db_path.ptr,
        &db,
        c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_NOMUTEX,
        null,
    );
    if (open_rc != c.SQLITE_OK) {
        setError("sqlite3_open_v2({s}): {s}", .{
            db_path,
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        if (db != null) _ = c.sqlite3_close(db);
        return null;
    }

    var stmt: ?*c.sqlite3_stmt = null;
    // Same query as iter_open; we filter the gpg-pubkey rows in Zig
    // because the NAME tag is buried inside the binary blob.
    const sql = "SELECT blob FROM " ++ PKG_TABLE ++ " ORDER BY hnum";
    const prepare_rc = c.sqlite3_prepare_v2(db, sql, sql.len, &stmt, null);
    if (prepare_rc != c.SQLITE_OK) {
        setError("sqlite3_prepare_v2: {s}", .{
            std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(db))),
        });
        _ = c.sqlite3_close(db);
        return null;
    }

    const iter = std.heap.c_allocator.create(PubkeyIter) catch {
        setError("out of memory", .{});
        _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_close(db);
        return null;
    };
    iter.* = .{ .db = db, .stmt = stmt };
    return iter;
}

/// Close and free a pubkey iterator.
export fn tdnf_rpmdb_pubkeys_close(it: ?*PubkeyIter) void {
    const iter = it orelse return;
    if (iter.stmt) |s| _ = c.sqlite3_finalize(s);
    if (iter.db) |d| _ = c.sqlite3_close(d);
    std.heap.c_allocator.destroy(iter);
}

/// Advance to the next `gpg-pubkey-*` row and write the armored key
/// block (RPMTAG_DESCRIPTION) into a heap buffer.
///
/// On hit, writes:
///   *key_out      → malloc'd NUL-terminated C string with the
///                   armored key (free with tdnf_rpmdb_string_free)
///   *key_len_out  → byte length of the armored key, not counting
///                   the trailing NUL (may be NULL if uninterested)
///   *keyid_out    → malloc'd lowercase hex 8-character key id
///                   (= RPMTAG_VERSION); free with
///                   tdnf_rpmdb_string_free (may be NULL)
///
/// Returns 1 on hit, 0 on end-of-iteration, -1 on error.
export fn tdnf_rpmdb_pubkeys_next(
    it: ?*PubkeyIter,
    key_out: ?*[*:0]u8,
    key_len_out: ?*usize,
    keyid_out: ?*[*:0]u8,
) i32 {
    clearError();
    const iter = it orelse {
        setError("null iterator", .{});
        return -1;
    };
    const out = key_out orelse {
        setError("null key_out", .{});
        return -1;
    };

    while (true) {
        const step_rc = c.sqlite3_step(iter.stmt);
        if (step_rc == c.SQLITE_DONE) return 0;
        if (step_rc != c.SQLITE_ROW) {
            setError("sqlite3_step: {s}", .{
                std.mem.span(@as([*:0]const u8, c.sqlite3_errmsg(iter.db))),
            });
            return -1;
        }
        const blob_ptr = c.sqlite3_column_blob(iter.stmt, 0);
        const blob_len: usize = @intCast(c.sqlite3_column_bytes(iter.stmt, 0));
        if (blob_ptr == null or blob_len == 0) continue;
        const blob: []const u8 = @as([*]const u8, @ptrCast(blob_ptr))[0..blob_len];

        const h = header.Header.parse(blob) catch |err| {
            setError("header.parse: {t}", .{err});
            return -1;
        };
        const name = h.getString(.name) orelse continue;
        if (!std.mem.eql(u8, name, "gpg-pubkey")) continue;

        const desc = h.getString(.description) orelse {
            // gpg-pubkey package with no DESCRIPTION — should not
            // happen, but skip rather than fail the walk.
            continue;
        };
        const keyid = h.getString(.version) orelse continue;

        out.* = dupZ(desc) orelse return -1;
        if (key_len_out) |p| p.* = desc.len;
        if (keyid_out) |p| {
            const id_z = dupZ(keyid) orelse {
                c.free(@ptrCast(out.*));
                return -1;
            };
            p.* = id_z;
        }
        return 1;
    }
}

/// Helper: malloc + copy + NUL-terminate. Returns null and sets
/// last-error on allocation failure.
fn dupZ(src: []const u8) ?[*:0]u8 {
    const ptr = c.malloc(src.len + 1) orelse {
        setError("out of memory", .{});
        return null;
    };
    const bytes = @as([*]u8, @ptrCast(ptr));
    @memcpy(bytes[0..src.len], src);
    bytes[src.len] = 0;
    return @ptrCast(bytes);
}

// -------------------------------------------------------------------
// `.rpm` file reader (T2)
// -------------------------------------------------------------------

const pkgfile = @import("pkgfile.zig");
const cpio = @import("cpio.zig");

/// Opaque handle wrapping a parsed RpmFile and its allocator.
pub const FileHandle = struct {
    file: pkgfile.RpmFile,
};

/// Open and parse a `.rpm` file. Returns NULL on error (consult
/// tdnf_rpmdb_last_error()).
export fn tdnf_rpm_file_open(path: ?[*:0]const u8) ?*FileHandle {
    clearError();
    const p = path orelse {
        setError("null path", .{});
        return null;
    };
    const path_slice = std.mem.span(p);
    // Convert to sentinel-terminated for libc.
    const path_z = std.heap.c_allocator.dupeZ(u8, path_slice) catch {
        setError("out of memory", .{});
        return null;
    };
    defer std.heap.c_allocator.free(path_z);

    const fh = std.heap.c_allocator.create(FileHandle) catch {
        setError("out of memory", .{});
        return null;
    };
    fh.file = pkgfile.RpmFile.open(std.heap.c_allocator, path_z) catch |err| {
        setError("rpm_file_open({s}): {t}", .{ path_slice, err });
        std.heap.c_allocator.destroy(fh);
        return null;
    };
    return fh;
}

/// Free a file handle. Accepts NULL.
export fn tdnf_rpm_file_close(fh: ?*FileHandle) void {
    const f = fh orelse return;
    f.file.close(std.heap.c_allocator);
    std.heap.c_allocator.destroy(f);
}

/// Returns a heap-allocated NEVRA string for this rpm file. Caller
/// frees with tdnf_rpmdb_string_free.
export fn tdnf_rpm_file_nevra(fh: ?*FileHandle) ?[*:0]u8 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return null;
    };
    const nevra_opt = f.file.allocNevra(std.heap.c_allocator) catch {
        setError("out of memory", .{});
        return null;
    };
    const nevra = nevra_opt orelse {
        setError("file header missing required tag for NEVRA", .{});
        return null;
    };
    defer std.heap.c_allocator.free(nevra);

    const out = c.malloc(nevra.len + 1) orelse {
        setError("out of memory", .{});
        return null;
    };
    const out_bytes = @as([*]u8, @ptrCast(out));
    @memcpy(out_bytes[0..nevra.len], nevra);
    out_bytes[nevra.len] = 0;
    return @ptrCast(out_bytes);
}

/// Returns the payload compressor name as a static C string.
/// One of: "none", "gzip", "bzip2", "xz", "lzma", "zstd", "lz4",
/// "unknown".
export fn tdnf_rpm_file_compressor(fh: ?*FileHandle) [*:0]const u8 {
    const f = fh orelse return "unknown";
    return switch (f.file.compressor) {
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

/// Returns the byte offset of the payload (cpio archive) within the
/// underlying file. Useful for callers that want to stream the
/// payload through a decompressor.
export fn tdnf_rpm_file_payload_offset(fh: ?*FileHandle) i64 {
    const f = fh orelse return -1;
    return @intCast(f.file.payload_offset);
}

/// Returns 1 if the rpm has any of the known signature tags
/// (RSA/DSA/PGP/GPG/OpenPGP) in its signature header, 0 otherwise.
/// Returns -1 on a NULL handle. This is *presence* only — real
/// verification is T3.
export fn tdnf_rpm_file_is_signed(fh: ?*FileHandle) i32 {
    const f = fh orelse return -1;
    return if (f.file.isSigned()) 1 else 0;
}

/// Returns a static C string naming the kind of signature on this
/// rpm: "none", "rsa", "dsa", "pgp", "gpg", or "openpgp". Returns
/// "none" on a NULL handle.
export fn tdnf_rpm_file_signature_kind(fh: ?*FileHandle) [*:0]const u8 {
    const f = fh orelse return "none";
    return switch (f.file.signatureKind()) {
        .none => "none",
        .rsa => "rsa",
        .dsa => "dsa",
        .pgp => "pgp",
        .gpg => "gpg",
        .openpgp => "openpgp",
    };
}

/// Returns the signature payload + signed byte range. Both slices
/// alias into the file's owned buffer (do NOT free them).
///
/// Returns 0 on success, -1 on NULL handle or no signature.
export fn tdnf_rpm_file_signed_range(
    fh: ?*FileHandle,
    sig_out: ?*[*]const u8,
    sig_len_out: ?*usize,
    signed_out: ?*[*]const u8,
    signed_len_out: ?*usize,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const r = f.file.signatureSlice() orelse {
        setError("rpm carries no signature", .{});
        return -1;
    };
    if (sig_out) |p| p.* = r.sig.ptr;
    if (sig_len_out) |p| p.* = r.sig.len;
    if (signed_out) |p| p.* = r.signed.ptr;
    if (signed_len_out) |p| p.* = r.signed.len;
    return 0;
}

/// Decompress the payload (cpio archive) into a fresh malloc'd
/// buffer. On success, writes the pointer to `*out` and the byte
/// count to `*out_size`. Caller frees with tdnf_rpmdb_string_free
/// (it wraps `free(3)`).
///
/// Returns 0 on success, -1 on error (use tdnf_rpmdb_last_error).
export fn tdnf_rpm_file_decompress_payload(
    fh: ?*FileHandle,
    out: ?*[*]u8,
    out_size: ?*usize,
) i32 {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return -1;
    };
    const out_p = out orelse {
        setError("null out pointer", .{});
        return -1;
    };
    const out_sz = out_size orelse {
        setError("null out_size pointer", .{});
        return -1;
    };

    const bytes = f.file.decompressPayload(std.heap.c_allocator) catch |err| {
        setError("decompressPayload: {t}", .{err});
        return -1;
    };
    defer std.heap.c_allocator.free(bytes);

    const buf = c.malloc(bytes.len) orelse {
        setError("out of memory", .{});
        return -1;
    };
    @memcpy(@as([*]u8, @ptrCast(buf))[0..bytes.len], bytes);
    out_p.* = @ptrCast(buf);
    out_sz.* = bytes.len;
    return 0;
}

/// Files-in-package iterator state. Each call to
/// `tdnf_rpm_file_next_filename` returns the next file path or 0 at
/// end-of-archive.
pub const FilesIter = struct {
    /// Decompressed cpio payload owned by this iterator.
    cpio_bytes: []u8,
    walker: cpio.Walker,
    /// Stable scratch for returning a NUL-terminated copy of the
    /// current entry's name. Reused between calls.
    name_scratch: ?[*:0]u8 = null,
    name_scratch_cap: usize = 0,
};

/// Open a files-in-package iterator. Decompresses the payload up
/// front; large packages briefly hold the full cpio archive in
/// memory.
export fn tdnf_rpm_file_files_open(fh: ?*FileHandle) ?*FilesIter {
    clearError();
    const f = fh orelse {
        setError("null file handle", .{});
        return null;
    };
    const bytes = f.file.decompressPayload(std.heap.c_allocator) catch |err| {
        setError("decompressPayload: {t}", .{err});
        return null;
    };
    const it = std.heap.c_allocator.create(FilesIter) catch {
        std.heap.c_allocator.free(bytes);
        setError("out of memory", .{});
        return null;
    };
    it.* = .{
        .cpio_bytes = bytes,
        .walker = cpio.Walker.init(bytes),
    };
    return it;
}

/// Free a files iterator. Accepts NULL.
export fn tdnf_rpm_file_files_close(it: ?*FilesIter) void {
    const i = it orelse return;
    std.heap.c_allocator.free(i.cpio_bytes);
    if (i.name_scratch) |p| c.free(@ptrCast(p));
    std.heap.c_allocator.destroy(i);
}

/// Advance the iterator and write the next entry's name into
/// `*name_out` (stable until the next call; do NOT free) and its
/// mode into `*mode_out`. Returns 1 on hit, 0 on end, -1 on error.
export fn tdnf_rpm_file_files_next(
    it: ?*FilesIter,
    name_out: ?*[*:0]const u8,
    mode_out: ?*u32,
) i32 {
    clearError();
    const i = it orelse {
        setError("null files iterator", .{});
        return -1;
    };
    const np = name_out orelse {
        setError("null name out pointer", .{});
        return -1;
    };

    const maybe_entry = i.walker.next() catch |err| {
        setError("cpio walker: {t}", .{err});
        return -1;
    };
    const entry = maybe_entry orelse return 0;

    // Stash a NUL-terminated copy in the iterator's scratch.
    const needed = entry.name.len + 1;
    if (i.name_scratch == null or i.name_scratch_cap < needed) {
        if (i.name_scratch) |p| c.free(@ptrCast(p));
        const buf = c.malloc(needed) orelse {
            i.name_scratch = null;
            i.name_scratch_cap = 0;
            setError("out of memory", .{});
            return -1;
        };
        i.name_scratch = @ptrCast(@as([*]u8, @ptrCast(buf)));
        i.name_scratch_cap = needed;
    }
    const scratch_bytes = @as([*]u8, @ptrCast(i.name_scratch.?));
    @memcpy(scratch_bytes[0..entry.name.len], entry.name);
    scratch_bytes[entry.name.len] = 0;
    np.* = i.name_scratch.?;
    if (mode_out) |mo| mo.* = entry.mode;
    return 1;
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

fn buildDbPath(buf: []u8, root: []const u8) ![]const u8 {
    const effective_root = if (root.len == 0) DEFAULT_ROOT else root;
    var trimmed = std.mem.trimEnd(u8, effective_root, "/");
    if (trimmed.len == 0) trimmed = "";
    const needed = trimmed.len + 1 + DEFAULT_DB_PATH.len + 1;
    if (needed > buf.len) return error.PathTooLong;
    return try std.fmt.bufPrintZ(buf, "{s}/{s}", .{ trimmed, DEFAULT_DB_PATH });
}

test "buildDbPath default root" {
    var buf: [256]u8 = undefined;
    const path = try buildDbPath(&buf, "");
    try std.testing.expectEqualStrings("/var/lib/rpm/rpmdb.sqlite", path);
}

test "buildDbPath relative root" {
    var buf: [256]u8 = undefined;
    const path = try buildDbPath(&buf, "/mnt/sysroot");
    try std.testing.expectEqualStrings("/mnt/sysroot/var/lib/rpm/rpmdb.sqlite", path);
}

test "buildDbPath strips trailing slash" {
    var buf: [256]u8 = undefined;
    const path = try buildDbPath(&buf, "/mnt/sysroot/");
    try std.testing.expectEqualStrings("/mnt/sysroot/var/lib/rpm/rpmdb.sqlite", path);
}

test {
    // pull in header.zig + pkgfile.zig + cpio.zig tests
    _ = header;
    _ = pkgfile;
    _ = cpio;
    // PGP submodules (PR #1 of plan-pure-zig-pgp.md). Imported here
    // only for test discovery; no runtime dependency.
    _ = @import("pgp/armor.zig");
}

test {
    _ = @import("pgp/packet.zig");
}


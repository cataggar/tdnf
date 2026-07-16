const std = @import("std");
const c = @cImport({
    @cInclude("tdnf.h");
    @cInclude("tdnfrepomd.h");
});

test "public configuration layout remains stable" {
    const pointer_size = @sizeOf(*anyopaque);
    const expected_size: usize = if (pointer_size == 8) 216 else 136;
    const expected_alignment: usize = if (pointer_size == 8) 8 else 4;

    try std.testing.expect(pointer_size == 4 or pointer_size == 8);
    try std.testing.expectEqual(expected_size, @sizeOf(c.TDNF_CONF));
    try std.testing.expectEqual(expected_alignment, @alignOf(c.TDNF_CONF));
    try std.testing.expectEqual(@as(usize, 40), @offsetOf(
        c.TDNF_CONF,
        "rpmTransFlags",
    ));
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(
        @TypeOf(@as(c.TDNF_CONF, undefined).rpmTransFlags),
    ));
}

test "legacy native transaction item layout remains stable" {
    const pointer_size = @sizeOf(*anyopaque);
    const first_pointer_offset: usize = if (pointer_size == 8) 8 else 4;
    const legacy_size: usize = if (pointer_size == 8) 40 else 20;
    const v2_size: usize = if (pointer_size == 8) 48 else 24;

    try std.testing.expect(pointer_size == 4 or pointer_size == 8);
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
        "dwOperation",
    ));
    try std.testing.expectEqual(first_pointer_offset, @offsetOf(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
        "pszPath",
    ));
    try std.testing.expectEqual(first_pointer_offset + pointer_size, @offsetOf(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
        "pszName",
    ));
    try std.testing.expectEqual(first_pointer_offset + 2 * pointer_size, @offsetOf(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
        "pszEVR",
    ));
    try std.testing.expectEqual(first_pointer_offset + 3 * pointer_size, @offsetOf(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
        "pszArch",
    ));
    try std.testing.expectEqual(legacy_size, @sizeOf(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM,
    ));

    try std.testing.expectEqual(first_pointer_offset + 3 * pointer_size, @offsetOf(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
        "pszArch",
    ));
    try std.testing.expectEqual(legacy_size, @offsetOf(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
        "dwRpmDbHnum",
    ));
    try std.testing.expectEqual(v2_size, @sizeOf(
        c.TDNF_REPOMD_NATIVE_TRANSACTION_ITEM_V2,
    ));
}

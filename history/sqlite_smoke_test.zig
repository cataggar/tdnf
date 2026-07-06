const std = @import("std");
const sqlite = @import("sqlite");

test "vendored sqlite dependency smoke test" {
    const db = try sqlite.Database.open(.{ .path = ":memory:" });
    defer db.close();

    try db.exec(
        \\CREATE TABLE history_smoke (
        \\    id INTEGER PRIMARY KEY,
        \\    name TEXT NOT NULL
        \\)
    , .{});

    const InsertParams = struct {
        id: i64,
        name: sqlite.Text,
    };
    const insert = try db.prepare(
        InsertParams,
        void,
        "INSERT INTO history_smoke (id, name) VALUES (:id, :name)",
    );
    defer insert.finalize();

    try insert.exec(.{
        .id = 1,
        .name = sqlite.text("sqlite-smoke"),
    });

    const SelectParams = struct {
        id: i64,
    };
    const Result = struct {
        id: i64,
        name: sqlite.Text,
    };
    const select = try db.prepare(
        SelectParams,
        Result,
        "SELECT id, name FROM history_smoke WHERE id = :id",
    );
    defer select.finalize();

    try select.bind(.{ .id = 1 });
    defer select.reset();

    const maybe_result = try select.step();
    try std.testing.expect(maybe_result != null);
    const result = maybe_result.?;
    try std.testing.expectEqual(@as(i64, 1), result.id);
    try std.testing.expectEqualStrings("sqlite-smoke", result.name.data);
    try std.testing.expect((try select.step()) == null);
}

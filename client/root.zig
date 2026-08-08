pub const updateinfo = @import("client_updateinfo");

comptime {
    _ = @import("repoutils.zig");
    _ = @import("remoterepo.zig");
    _ = @import("repomd_client_exports").query_native;
    _ = @import("repomd_client_exports").repo_cache;
    _ = @import("transaction_plan_capture");
    _ = @import("transaction_plan_integration");
    _ = @import("client_init");
    _ = @import("builtin_plugins");
    _ = @import("client_history");
    _ = @import("config.zig");
    _ = @import("excludes.zig");
    _ = updateinfo;
    _ = @import("client_varsdir");
}

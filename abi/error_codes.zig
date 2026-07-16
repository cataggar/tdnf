const std = @import("std");

pub const ERROR_TDNF_REPO_PERFORM: u32 = 1006;
pub const ERROR_TDNF_OPERATION_ABORTED: u32 = 1032;
pub const ERROR_TDNF_SET_SSL_SETTINGS: u32 = 1401;
pub const ERROR_TDNF_URL_INVALID: u32 = 1524;
pub const ERROR_TDNF_SYSTEM_BASE: u32 = 1600;
pub const ERROR_TDNF_INVALID_PARAMETER: u32 = fromErrno(.INVAL);
pub const ERROR_TDNF_OUT_OF_MEMORY: u32 = fromErrno(.NOMEM);
pub const ERROR_TDNF_CALL_NOT_SUPPORTED: u32 = fromErrno(.NOSYS);
pub const ERROR_TDNF_TIMED_OUT: u32 = fromErrno(.TIMEDOUT);

pub fn fromErrno(value: std.posix.E) u32 {
    return ERROR_TDNF_SYSTEM_BASE + @intFromEnum(value);
}

test "system error values match the public Linux ABI" {
    try std.testing.expectEqual(@as(u32, 1612), ERROR_TDNF_OUT_OF_MEMORY);
    try std.testing.expectEqual(@as(u32, 1622), ERROR_TDNF_INVALID_PARAMETER);
    try std.testing.expectEqual(@as(u32, 1638), ERROR_TDNF_CALL_NOT_SUPPORTED);
    try std.testing.expectEqual(@as(u32, 1710), ERROR_TDNF_TIMED_OUT);
}

pub const Repository = extern struct {
    pszId: ?[*:0]const u8,
    pszCacheDir: ?[*:0]const u8,
    pszSnapshotFile: ?[*:0]const u8,
    nPriority: i32,
    dwCost: u32,
};

pub const Job = extern struct {
    pszRepository: ?[*:0]const u8,
    pszName: ?[*:0]const u8,
    pszVersion: ?[*:0]const u8,
    pszRelease: ?[*:0]const u8,
    pszArch: ?[*:0]const u8,
    pszChecksumType: ?[*:0]const u8,
    pszChecksumValue: ?[*:0]const u8,
    dwEpoch: u32,
    nChecksumIsPkgId: c_int,
};

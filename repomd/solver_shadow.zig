const std = @import("std");
const query_index = @import("index.zig");
const result_abi = @import("solver_result_abi.zig");
const shadow_abi = @import("solver_shadow_abi.zig");

pub const CompareError = error{
    InvalidInput,
    OutOfMemory,
};

const status_projected_match: u32 = 1;
const status_mismatch: u32 = 2;
const status_unsupported: u32 = 3;
const status_invalid: u32 = 4;

const reason_none: u32 = 0;
const reason_native_problems: u32 = 1;
const reason_skipped_jobs: u32 = 2;
const reason_prior_action: u32 = 3;
const reason_native_action_kind: u32 = 4;
const reason_legacy_action_bucket: u32 = 5;
const reason_duplicate_key: u32 = 6;

const action_install: u32 = 1;
const action_erase: u32 = 2;
const action_upgrade: u32 = 3;
const action_reinstall: u32 = 5;
const action_obsolete: u32 = 6;
const transaction_reason_obsoletes: u32 = 5;

const BucketProjection = enum {
    target,
    prior,
    removal,
};

const Key = struct {
    repository: []const u8,
    name: []const u8,
    epoch: u32,
    version: []const u8,
    release: []const u8,
    arch: []const u8,
};

pub fn compare(
    allocator: std.mem.Allocator,
    native: *const result_abi.Result,
    legacy: *const shadow_abi.LegacyResult,
    output: *shadow_abi.Comparison,
) CompareError!void {
    output.* = invalidComparison();
    try validateNative(native);
    _ = try validateLegacyList(legacy.pPkgsToInstall);
    _ = try validateLegacyList(legacy.pPkgsToRemove);
    _ = try validateLegacyList(legacy.pPkgsToUpgrade);
    _ = try validateLegacyList(legacy.pPkgsToReinstall);
    _ = try validateLegacyList(legacy.pPkgsObsoleted);

    if (native.dwProblemCount != 0) {
        setUnsupported(output, reason_native_problems, 0);
        return;
    }
    if (native.dwSkippedJobCount != 0) {
        setUnsupported(output, reason_skipped_jobs, 0);
        return;
    }
    if (hasSharedObsoletePrior(native)) {
        setUnsupported(output, reason_prior_action, action_obsolete);
        return;
    }
    if (native.dwActionCount != 0) {
        for (native.pActions[0..native.dwActionCount]) |action| {
            if (action.dwKind == action_reinstall) {
                if (!hasExactReinstallPrior(native, action)) {
                    setUnsupported(output, reason_prior_action, action.dwKind);
                    return;
                }
                continue;
            }
            if (action.dwKind == action_upgrade) {
                if (!hasExactUpgradePrior(native, action)) {
                    setUnsupported(output, reason_prior_action, action.dwKind);
                    return;
                }
                continue;
            }
            if (action.dwKind == action_obsolete) {
                if (!hasExactObsoletePrior(native, action)) {
                    setUnsupported(output, reason_prior_action, action.dwKind);
                    return;
                }
                continue;
            }
            if (action.dwPriorCount != 0) {
                setUnsupported(output, reason_prior_action, action.dwKind);
                return;
            }
            if (action.dwKind != action_install and action.dwKind != action_erase) {
                setUnsupported(output, reason_native_action_kind, action.dwKind);
                return;
            }
        }
    }
    if (hasUnsupportedLegacyBucket(legacy)) {
        setUnsupported(output, reason_legacy_action_bucket, 0);
        return;
    }

    if (try compareBucket(
        allocator,
        native,
        legacy.pPkgsToInstall,
        action_install,
        .target,
        output,
    )) return;
    if (try compareBucket(
        allocator,
        native,
        legacy.pPkgsToRemove,
        action_erase,
        .removal,
        output,
    )) return;
    if (try compareBucket(
        allocator,
        native,
        legacy.pPkgsToUpgrade,
        action_upgrade,
        .target,
        output,
    )) return;
    if (try compareBucket(
        allocator,
        native,
        legacy.pPkgsToReinstall,
        action_reinstall,
        .target,
        output,
    )) return;
    if (try compareBucket(
        allocator,
        native,
        legacy.pPkgsObsoleted,
        action_obsolete,
        .prior,
        output,
    )) return;

    output.* = .{
        .dwStatus = status_projected_match,
        .dwReason = reason_none,
        .dwActionKind = 0,
        .dwDifferenceIndex = 0,
        .dwNativeCount = 0,
        .dwLegacyCount = 0,
    };
}

fn compareBucket(
    allocator: std.mem.Allocator,
    native: *const result_abi.Result,
    legacy_head: [*c]shadow_abi.LegacyPackage,
    action_kind: u32,
    projection: BucketProjection,
    output: *shadow_abi.Comparison,
) CompareError!bool {
    var native_count: usize = 0;
    if (native.dwActionCount != 0) {
        for (native.pActions[0..native.dwActionCount]) |action| {
            if (projectsIntoBucket(action.dwKind, action_kind, projection)) {
                native_count += 1;
            }
        }
    }
    const legacy_count = try validateLegacyList(legacy_head);
    const native_count_u32 = std.math.cast(u32, native_count) orelse
        return error.InvalidInput;
    const legacy_count_u32 = std.math.cast(u32, legacy_count) orelse
        return error.InvalidInput;

    const native_keys = allocator.alloc(Key, native_count) catch
        return error.OutOfMemory;
    defer allocator.free(native_keys);
    const legacy_keys = allocator.alloc(Key, legacy_count) catch
        return error.OutOfMemory;
    defer allocator.free(legacy_keys);

    var native_index: usize = 0;
    if (native.dwActionCount != 0) {
        for (native.pActions[0..native.dwActionCount]) |action| {
            if (!projectsIntoBucket(action.dwKind, action_kind, projection)) {
                continue;
            }
            const package_ref = switch (projection) {
                .target => action.dwPackageRef,
                .prior => native.pdwPriorPackageRefs[action.dwPriorOffset],
                .removal => if (action.dwKind == action_obsolete)
                    native.pdwPriorPackageRefs[action.dwPriorOffset]
                else
                    action.dwPackageRef,
            };
            native_keys[native_index] = nativeKey(
                @ptrCast(&native.pPackages[package_ref]),
            );
            native_index += 1;
        }
    }

    var node = legacy_head;
    var legacy_index: usize = 0;
    while (node != null) : (node = node[0].pNext) {
        legacy_keys[legacy_index] = legacyKey(@ptrCast(&node[0]));
        legacy_index += 1;
    }

    std.mem.sort(Key, native_keys, {}, keyLessThan);
    std.mem.sort(Key, legacy_keys, {}, keyLessThan);
    if (hasDuplicate(native_keys) or hasDuplicate(legacy_keys)) {
        output.* = .{
            .dwStatus = status_unsupported,
            .dwReason = reason_duplicate_key,
            .dwActionKind = action_kind,
            .dwDifferenceIndex = 0,
            .dwNativeCount = native_count_u32,
            .dwLegacyCount = legacy_count_u32,
        };
        return true;
    }

    const common_count = @min(native_keys.len, legacy_keys.len);
    for (0..common_count) |index| {
        if (keysEqual(native_keys[index], legacy_keys[index])) continue;
        setMismatch(
            output,
            action_kind,
            @intCast(index),
            native_count_u32,
            legacy_count_u32,
        );
        return true;
    }
    if (native_keys.len != legacy_keys.len) {
        setMismatch(
            output,
            action_kind,
            @intCast(common_count),
            native_count_u32,
            legacy_count_u32,
        );
        return true;
    }
    return false;
}

fn projectsIntoBucket(
    native_action_kind: u32,
    legacy_action_kind: u32,
    projection: BucketProjection,
) bool {
    return switch (projection) {
        .target => native_action_kind == legacy_action_kind or
            (legacy_action_kind == action_install and
                native_action_kind == action_obsolete),
        .prior => legacy_action_kind == action_obsolete and
            native_action_kind == action_obsolete,
        .removal => legacy_action_kind == action_erase and
            (native_action_kind == action_erase or
                native_action_kind == action_obsolete),
    };
}

fn validateNative(native: *const result_abi.Result) CompareError!void {
    try requireArray(native.pPackages, native.dwPackageCount);
    try requireArray(
        native.pdwSelectedPackageRefs,
        native.dwSelectedPackageCount,
    );
    try requireArray(native.pActions, native.dwActionCount);
    try requireArray(
        native.pdwPriorPackageRefs,
        native.dwPriorPackageRefCount,
    );
    try requireArray(native.pdwPriorHnums, native.dwPriorPackageRefCount);
    try requireArray(native.pProblems, native.dwProblemCount);
    try requireArray(native.pdwSkippedJobIds, native.dwSkippedJobCount);

    var previous_package_id: ?u32 = null;
    if (native.dwPackageCount != 0) {
        for (native.pPackages[0..native.dwPackageCount]) |package| {
            try requireString(package.pszRepository);
            try requireString(package.pszName);
            try requireString(package.pszVersion);
            try requireString(package.pszRelease);
            try requireString(package.pszArch);
            try requireString(package.pszChecksumType);
            try requireString(package.pszChecksumValue);
            try requireString(package.pszLocationHref);
            try validateFlag(package.nHasEpoch);
            try validateFlag(package.nHasRpmDbHnum);
            try validateFlag(package.nChecksumIsPkgId);
            try validateFlag(package.nHasPackageSize);
            try validateFlag(package.nHasInstalledSize);
            if (package.nRepositoryKind < 1 or package.nRepositoryKind > 3) {
                return error.InvalidInput;
            }
            if (previous_package_id) |previous| {
                if (package.dwPackageId <= previous) return error.InvalidInput;
            }
            previous_package_id = package.dwPackageId;
        }
    }

    var previous_selected_ref: ?u32 = null;
    if (native.dwSelectedPackageCount != 0) {
        for (native.pdwSelectedPackageRefs[0..native.dwSelectedPackageCount]) |package_ref| {
            try validatePackageRef(native, package_ref);
            if (previous_selected_ref) |previous| {
                if (package_ref <= previous) return error.InvalidInput;
            }
            previous_selected_ref = package_ref;
        }
    }

    var expected_prior_offset: u32 = 0;
    if (native.dwActionCount != 0) {
        for (native.pActions[0..native.dwActionCount]) |action| {
            try validatePackageRef(native, action.dwPackageRef);
            if (action.dwKind < 1 or action.dwKind > 6) {
                return error.InvalidInput;
            }
            if (action.dwReason < 1 or action.dwReason > 7) {
                return error.InvalidInput;
            }
            try validateFlag(action.nHasRequestedJobId);
            if (action.dwPriorOffset != expected_prior_offset) {
                return error.InvalidInput;
            }
            expected_prior_offset = std.math.add(
                u32,
                expected_prior_offset,
                action.dwPriorCount,
            ) catch return error.InvalidInput;
            if (expected_prior_offset > native.dwPriorPackageRefCount) {
                return error.InvalidInput;
            }
            const start: usize = @intCast(action.dwPriorOffset);
            const end: usize = @intCast(expected_prior_offset);
            if (start != end) {
                for (
                    native.pdwPriorPackageRefs[start..end],
                    native.pdwPriorHnums[start..end],
                ) |prior_ref, prior_hnum| {
                    try validatePackageRef(native, prior_ref);
                    const prior = native.pPackages[prior_ref];
                    if (prior.nHasRpmDbHnum == 0 or
                        prior.dwRpmDbHnum != prior_hnum)
                    {
                        return error.InvalidInput;
                    }
                }
            }
        }
    }
    if (expected_prior_offset != native.dwPriorPackageRefCount) {
        return error.InvalidInput;
    }

    if (native.dwProblemCount != 0) {
        for (native.pProblems[0..native.dwProblemCount]) |problem| {
            if (problem.dwKind < 1 or problem.dwKind > 7) {
                return error.InvalidInput;
            }
            try validateFlag(problem.nHasPackageRef);
            try validateFlag(problem.nHasRelatedPackageRef);
            try validateFlag(problem.nHasCapability);
            try validateFlag(problem.nHasJobId);
            if (problem.nHasPackageRef != 0) {
                try validatePackageRef(native, problem.dwPackageRef);
            }
            if (problem.nHasRelatedPackageRef != 0) {
                try validatePackageRef(native, problem.dwRelatedPackageRef);
            }
            if (problem.nHasCapability != 0) {
                try requireString(problem.capability.pszName);
                if (problem.capability.dwComparison > 5) {
                    return error.InvalidInput;
                }
                try validateFlag(problem.capability.nHasEpoch);
                try validateFlag(problem.capability.nPre);
            }
        }
    }
}

fn validateLegacyList(
    head: [*c]shadow_abi.LegacyPackage,
) CompareError!usize {
    var slow = head;
    var fast = head;
    while (fast != null and fast[0].pNext != null) {
        slow = slow[0].pNext;
        fast = fast[0].pNext[0].pNext;
        if (slow == fast) return error.InvalidInput;
    }

    var count: usize = 0;
    var node = head;
    while (node != null) : (node = node[0].pNext) {
        try requireString(node[0].pszRepoName);
        try requireString(node[0].pszName);
        try requireString(node[0].pszVersion);
        try requireString(node[0].pszRelease);
        try requireString(node[0].pszArch);
        count = std.math.add(usize, count, 1) catch
            return error.InvalidInput;
    }
    return count;
}

fn validatePackageRef(
    native: *const result_abi.Result,
    package_ref: u32,
) CompareError!void {
    if (package_ref >= native.dwPackageCount) return error.InvalidInput;
}

fn validateFlag(flag: c_int) CompareError!void {
    if (flag != 0 and flag != 1) return error.InvalidInput;
}

fn requireArray(pointer: anytype, count: u32) CompareError!void {
    if (count != 0 and pointer == null) return error.InvalidInput;
}

fn requireString(pointer: ?[*:0]const u8) CompareError!void {
    if (pointer == null) return error.InvalidInput;
}

fn hasUnsupportedLegacyBucket(
    legacy: *const shadow_abi.LegacyResult,
) bool {
    return legacy.pPkgsToDowngrade != null or
        legacy.pPkgsUnNeeded != null or
        legacy.pPkgsRemovedByDowngrade != null;
}

fn hasExactObsoletePrior(
    native: *const result_abi.Result,
    action: result_abi.Action,
) bool {
    if (action.dwPriorCount != 1 or
        action.dwReason != transaction_reason_obsoletes)
    {
        return false;
    }
    const target = native.pPackages[action.dwPackageRef];
    const prior_ref = native.pdwPriorPackageRefs[action.dwPriorOffset];
    const prior = native.pPackages[prior_ref];
    return target.nRepositoryKind == 2 and
        prior.nRepositoryKind == 1 and
        !std.mem.eql(
            u8,
            std.mem.span(target.pszName.?),
            std.mem.span(prior.pszName.?),
        ) and
        std.mem.eql(
            u8,
            std.mem.span(target.pszArch.?),
            std.mem.span(prior.pszArch.?),
        );
}

fn hasSharedObsoletePrior(native: *const result_abi.Result) bool {
    if (native.dwActionCount == 0) return false;
    const actions = native.pActions[0..native.dwActionCount];
    for (actions, 0..) |action, index| {
        if (action.dwKind != action_obsolete or action.dwPriorCount != 1) {
            continue;
        }
        const prior_ref = native.pdwPriorPackageRefs[action.dwPriorOffset];
        const prior_hnum = native.pdwPriorHnums[action.dwPriorOffset];
        for (actions[index + 1 ..]) |other| {
            if (other.dwKind != action_obsolete or other.dwPriorCount != 1) {
                continue;
            }
            if (native.pdwPriorPackageRefs[other.dwPriorOffset] == prior_ref or
                native.pdwPriorHnums[other.dwPriorOffset] == prior_hnum)
            {
                return true;
            }
        }
    }
    return false;
}

fn hasExactUpgradePrior(
    native: *const result_abi.Result,
    action: result_abi.Action,
) bool {
    if (action.dwPriorCount != 1) return false;
    const target = native.pPackages[action.dwPackageRef];
    const prior_ref = native.pdwPriorPackageRefs[action.dwPriorOffset];
    const prior = native.pPackages[prior_ref];
    return target.nRepositoryKind == 2 and
        prior.nRepositoryKind == 1 and
        std.mem.eql(
            u8,
            std.mem.span(target.pszName.?),
            std.mem.span(prior.pszName.?),
        ) and
        std.mem.eql(
            u8,
            std.mem.span(target.pszArch.?),
            std.mem.span(prior.pszArch.?),
        ) and
        query_index.compareEvr(
            if (target.nHasEpoch != 0) target.dwEpoch else null,
            std.mem.span(target.pszVersion.?),
            std.mem.span(target.pszRelease.?),
            if (prior.nHasEpoch != 0) prior.dwEpoch else null,
            std.mem.span(prior.pszVersion.?),
            std.mem.span(prior.pszRelease.?),
        ) > 0;
}

fn hasExactReinstallPrior(
    native: *const result_abi.Result,
    action: result_abi.Action,
) bool {
    if (action.dwPriorCount != 1) return false;
    const target = native.pPackages[action.dwPackageRef];
    const prior_ref = native.pdwPriorPackageRefs[action.dwPriorOffset];
    const prior = native.pPackages[prior_ref];
    return target.nRepositoryKind == 2 and
        prior.nRepositoryKind == 1 and
        std.mem.eql(
            u8,
            std.mem.span(target.pszName.?),
            std.mem.span(prior.pszName.?),
        ) and
        (if (target.nHasEpoch != 0) target.dwEpoch else 0) ==
            (if (prior.nHasEpoch != 0) prior.dwEpoch else 0) and
        std.mem.eql(
            u8,
            std.mem.span(target.pszVersion.?),
            std.mem.span(prior.pszVersion.?),
        ) and
        std.mem.eql(
            u8,
            std.mem.span(target.pszRelease.?),
            std.mem.span(prior.pszRelease.?),
        ) and
        std.mem.eql(
            u8,
            std.mem.span(target.pszArch.?),
            std.mem.span(prior.pszArch.?),
        );
}

fn nativeKey(package: *const result_abi.Package) Key {
    return .{
        .repository = std.mem.span(package.pszRepository.?),
        .name = std.mem.span(package.pszName.?),
        .epoch = if (package.nHasEpoch != 0) package.dwEpoch else 0,
        .version = std.mem.span(package.pszVersion.?),
        .release = std.mem.span(package.pszRelease.?),
        .arch = std.mem.span(package.pszArch.?),
    };
}

fn legacyKey(package: *const shadow_abi.LegacyPackage) Key {
    return .{
        .repository = std.mem.span(package.pszRepoName.?),
        .name = std.mem.span(package.pszName.?),
        .epoch = package.dwEpoch,
        .version = std.mem.span(package.pszVersion.?),
        .release = std.mem.span(package.pszRelease.?),
        .arch = std.mem.span(package.pszArch.?),
    };
}

fn keyLessThan(_: void, left: Key, right: Key) bool {
    const repository_order = std.mem.order(
        u8,
        left.repository,
        right.repository,
    );
    if (repository_order != .eq) return repository_order == .lt;
    const name_order = std.mem.order(u8, left.name, right.name);
    if (name_order != .eq) return name_order == .lt;
    if (left.epoch != right.epoch) return left.epoch < right.epoch;
    const version_order = std.mem.order(u8, left.version, right.version);
    if (version_order != .eq) return version_order == .lt;
    const release_order = std.mem.order(u8, left.release, right.release);
    if (release_order != .eq) return release_order == .lt;
    return std.mem.lessThan(u8, left.arch, right.arch);
}

fn keysEqual(left: Key, right: Key) bool {
    return left.epoch == right.epoch and
        std.mem.eql(u8, left.repository, right.repository) and
        std.mem.eql(u8, left.name, right.name) and
        std.mem.eql(u8, left.version, right.version) and
        std.mem.eql(u8, left.release, right.release) and
        std.mem.eql(u8, left.arch, right.arch);
}

fn hasDuplicate(keys: []const Key) bool {
    if (keys.len < 2) return false;
    for (keys[1..], 1..) |key, index| {
        if (keysEqual(keys[index - 1], key)) return true;
    }
    return false;
}

fn invalidComparison() shadow_abi.Comparison {
    return .{
        .dwStatus = status_invalid,
        .dwReason = reason_none,
        .dwActionKind = 0,
        .dwDifferenceIndex = 0,
        .dwNativeCount = 0,
        .dwLegacyCount = 0,
    };
}

fn setUnsupported(
    output: *shadow_abi.Comparison,
    reason: u32,
    action_kind: u32,
) void {
    output.* = .{
        .dwStatus = status_unsupported,
        .dwReason = reason,
        .dwActionKind = action_kind,
        .dwDifferenceIndex = 0,
        .dwNativeCount = 0,
        .dwLegacyCount = 0,
    };
}

fn setMismatch(
    output: *shadow_abi.Comparison,
    action_kind: u32,
    difference_index: u32,
    native_count: u32,
    legacy_count: u32,
) void {
    output.* = .{
        .dwStatus = status_mismatch,
        .dwReason = reason_none,
        .dwActionKind = action_kind,
        .dwDifferenceIndex = difference_index,
        .dwNativeCount = native_count,
        .dwLegacyCount = legacy_count,
    };
}

fn testNativePackage(
    repository: [*:0]const u8,
    name: [*:0]const u8,
    version: [*:0]const u8,
) result_abi.Package {
    var package = std.mem.zeroes(result_abi.Package);
    package.pszRepository = repository;
    package.pszName = name;
    package.pszVersion = version;
    package.pszRelease = "1";
    package.pszArch = "x86_64";
    package.pszChecksumType = "sha256";
    package.pszChecksumValue = "checksum";
    package.pszLocationHref = "package.rpm";
    package.nRepositoryKind = 2;
    return package;
}

fn testLegacyPackage(
    repository: [*:0]const u8,
    name: [*:0]const u8,
    version: [*:0]const u8,
) shadow_abi.LegacyPackage {
    var package = std.mem.zeroes(shadow_abi.LegacyPackage);
    package.pszRepoName = repository;
    package.pszName = name;
    package.pszVersion = version;
    package.pszRelease = "1";
    package.pszArch = "x86_64";
    return package;
}

fn testNativeResult(
    packages: []result_abi.Package,
    actions: []result_abi.Action,
) result_abi.Result {
    var result = std.mem.zeroes(result_abi.Result);
    result.pPackages = if (packages.len == 0) null else packages.ptr;
    result.dwPackageCount = @intCast(packages.len);
    result.pActions = if (actions.len == 0) null else actions.ptr;
    result.dwActionCount = @intCast(actions.len);
    return result;
}

test "shadow comparator matches reordered install and erase projections" {
    var packages = [_]result_abi.Package{
        testNativePackage("available", "bravo", "2"),
        testNativePackage("@System", "alpha", "1"),
        testNativePackage("available", "alpha", "2"),
    };
    for (&packages, 0..) |*package, index| {
        package.dwPackageId = @intCast(index);
    }
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
        std.mem.zeroes(result_abi.Action),
        std.mem.zeroes(result_abi.Action),
    };
    actions[0].dwPackageRef = 0;
    actions[0].dwKind = action_install;
    actions[0].dwReason = 2;
    actions[1].dwPackageRef = 1;
    actions[1].dwKind = action_erase;
    actions[1].dwReason = 4;
    actions[2].dwPackageRef = 2;
    actions[2].dwKind = action_install;
    actions[2].dwReason = 1;
    var native = testNativeResult(&packages, &actions);

    var legacy_installs = [_]shadow_abi.LegacyPackage{
        testLegacyPackage("available", "alpha", "2"),
        testLegacyPackage("available", "bravo", "2"),
    };
    legacy_installs[0].pNext = @ptrCast(&legacy_installs[1]);
    var legacy_remove = testLegacyPackage("@System", "alpha", "1");
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    legacy.pPkgsToInstall = @ptrCast(&legacy_installs[0]);
    legacy.pPkgsToRemove = @ptrCast(&legacy_remove);
    var output: shadow_abi.Comparison = undefined;

    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_projected_match, output.dwStatus);
    try std.testing.expectEqual(reason_none, output.dwReason);
}

test "shadow comparator matches only an exact single-prior reinstall" {
    var packages = [_]result_abi.Package{
        testNativePackage("@System", "alpha", "1"),
        testNativePackage("available", "alpha", "1"),
    };
    for (&packages, 0..) |*package, index| {
        package.dwPackageId = @intCast(index);
    }
    packages[0].nRepositoryKind = 1;
    packages[0].nHasRpmDbHnum = 1;
    packages[0].dwRpmDbHnum = 7;
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
    };
    actions[0].dwPackageRef = 1;
    actions[0].dwKind = action_reinstall;
    actions[0].dwReason = 1;
    actions[0].dwPriorCount = 1;
    var native = testNativeResult(&packages, &actions);
    var prior_refs = [_]u32{ 0, 0 };
    var prior_hnums = [_]u32{ 7, 7 };
    native.pdwPriorPackageRefs = &prior_refs;
    native.pdwPriorHnums = &prior_hnums;
    native.dwPriorPackageRefCount = 1;
    var legacy_package = testLegacyPackage("available", "alpha", "1");
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    legacy.pPkgsToReinstall = @ptrCast(&legacy_package);
    var output: shadow_abi.Comparison = undefined;

    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_projected_match, output.dwStatus);

    legacy_package.pszVersion = "2";
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_mismatch, output.dwStatus);
    try std.testing.expectEqual(action_reinstall, output.dwActionKind);

    legacy_package.pszVersion = "1";
    packages[0].pszVersion = "0";
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);

    packages[0].pszVersion = "1";
    actions[0].dwPriorCount = 0;
    native.pdwPriorPackageRefs = null;
    native.pdwPriorHnums = null;
    native.dwPriorPackageRefCount = 0;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);

    actions[0].dwPriorCount = 2;
    prior_refs = .{ 0, 0 };
    prior_hnums = .{ 7, 7 };
    native.pdwPriorPackageRefs = &prior_refs;
    native.pdwPriorHnums = &prior_hnums;
    native.dwPriorPackageRefCount = 2;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);
}

test "shadow comparator matches only an exact single-prior upgrade" {
    var packages = [_]result_abi.Package{
        testNativePackage("@System", "alpha", "1"),
        testNativePackage("available", "alpha", "2"),
    };
    for (&packages, 0..) |*package, index| {
        package.dwPackageId = @intCast(index);
    }
    packages[0].nRepositoryKind = 1;
    packages[0].nHasRpmDbHnum = 1;
    packages[0].dwRpmDbHnum = 7;
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
    };
    actions[0].dwPackageRef = 1;
    actions[0].dwKind = action_upgrade;
    actions[0].dwReason = 1;
    actions[0].dwPriorCount = 1;
    var native = testNativeResult(&packages, &actions);
    var prior_refs = [_]u32{ 0, 0 };
    var prior_hnums = [_]u32{ 7, 7 };
    native.pdwPriorPackageRefs = &prior_refs;
    native.pdwPriorHnums = &prior_hnums;
    native.dwPriorPackageRefCount = 1;
    var legacy_package = testLegacyPackage("available", "alpha", "2");
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    legacy.pPkgsToUpgrade = @ptrCast(&legacy_package);
    var output: shadow_abi.Comparison = undefined;

    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_projected_match, output.dwStatus);

    legacy_package.pszVersion = "3";
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_mismatch, output.dwStatus);
    try std.testing.expectEqual(action_upgrade, output.dwActionKind);

    legacy_package.pszVersion = "2";
    packages[0].pszVersion = "2";
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);

    packages[0].pszVersion = "1";
    packages[0].pszName = "beta";
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);

    packages[0].pszName = "alpha";
    packages[0].pszArch = "aarch64";
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);

    packages[0].pszArch = "x86_64";
    actions[0].dwPriorCount = 0;
    native.pdwPriorPackageRefs = null;
    native.pdwPriorHnums = null;
    native.dwPriorPackageRefCount = 0;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);

    actions[0].dwPriorCount = 2;
    native.pdwPriorPackageRefs = &prior_refs;
    native.pdwPriorHnums = &prior_hnums;
    native.dwPriorPackageRefCount = 2;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);
}

test "shadow comparator projects an exact single-prior obsoletion" {
    var packages = [_]result_abi.Package{
        testNativePackage("@System", "old", "1"),
        testNativePackage("available", "replacement", "1"),
    };
    for (&packages, 0..) |*package, index| {
        package.dwPackageId = @intCast(index);
    }
    packages[0].nRepositoryKind = 1;
    packages[0].nHasRpmDbHnum = 1;
    packages[0].dwRpmDbHnum = 7;
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
    };
    actions[0].dwPackageRef = 1;
    actions[0].dwKind = action_obsolete;
    actions[0].dwReason = transaction_reason_obsoletes;
    actions[0].dwPriorCount = 1;
    var native = testNativeResult(&packages, &actions);
    var prior_refs = [_]u32{ 0, 0 };
    var prior_hnums = [_]u32{ 7, 7 };
    native.pdwPriorPackageRefs = &prior_refs;
    native.pdwPriorHnums = &prior_hnums;
    native.dwPriorPackageRefCount = 1;
    var legacy_install = testLegacyPackage("available", "replacement", "1");
    var legacy_remove = testLegacyPackage("@System", "old", "1");
    var legacy_obsoleted = testLegacyPackage("@System", "old", "1");
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    legacy.pPkgsToInstall = @ptrCast(&legacy_install);
    legacy.pPkgsToRemove = @ptrCast(&legacy_remove);
    legacy.pPkgsObsoleted = @ptrCast(&legacy_obsoleted);
    var output: shadow_abi.Comparison = undefined;

    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_projected_match, output.dwStatus);

    legacy_install.pszVersion = "2";
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_mismatch, output.dwStatus);
    try std.testing.expectEqual(action_install, output.dwActionKind);

    legacy_install.pszVersion = "1";
    legacy_remove.pszVersion = "2";
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_mismatch, output.dwStatus);
    try std.testing.expectEqual(action_erase, output.dwActionKind);

    legacy_remove.pszVersion = "1";
    legacy_obsoleted.pszVersion = "2";
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_mismatch, output.dwStatus);
    try std.testing.expectEqual(action_obsolete, output.dwActionKind);

    legacy_obsoleted.pszVersion = "1";
    packages[0].pszName = "replacement";
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);

    packages[0].pszName = "old";
    packages[0].pszArch = "aarch64";
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);

    packages[0].pszArch = "x86_64";
    actions[0].dwReason = 1;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);

    actions[0].dwReason = transaction_reason_obsoletes;
    actions[0].dwPriorCount = 0;
    native.pdwPriorPackageRefs = null;
    native.pdwPriorHnums = null;
    native.dwPriorPackageRefCount = 0;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);

    actions[0].dwPriorCount = 2;
    native.pdwPriorPackageRefs = &prior_refs;
    native.pdwPriorHnums = &prior_hnums;
    native.dwPriorPackageRefCount = 2;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);
}

test "shadow comparator rejects shared obsoletion priors before mismatch" {
    var packages = [_]result_abi.Package{
        testNativePackage("@System", "old", "1"),
        testNativePackage("available", "replacement-one", "1"),
        testNativePackage("available", "replacement-two", "1"),
    };
    for (&packages, 0..) |*package, index| {
        package.dwPackageId = @intCast(index);
    }
    packages[0].nRepositoryKind = 1;
    packages[0].nHasRpmDbHnum = 1;
    packages[0].dwRpmDbHnum = 7;
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
        std.mem.zeroes(result_abi.Action),
    };
    for (&actions, 0..) |*action, index| {
        action.dwPackageRef = @intCast(index + 1);
        action.dwKind = action_obsolete;
        action.dwReason = transaction_reason_obsoletes;
        action.dwPriorOffset = @intCast(index);
        action.dwPriorCount = 1;
    }
    var native = testNativeResult(&packages, &actions);
    var prior_refs = [_]u32{ 0, 0 };
    var prior_hnums = [_]u32{ 7, 7 };
    native.pdwPriorPackageRefs = &prior_refs;
    native.pdwPriorHnums = &prior_hnums;
    native.dwPriorPackageRefCount = 2;
    var legacy_install = testLegacyPackage(
        "available",
        "different",
        "1",
    );
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    legacy.pPkgsToInstall = @ptrCast(&legacy_install);
    var output: shadow_abi.Comparison = undefined;

    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);
    try std.testing.expectEqual(action_obsolete, output.dwActionKind);
}

test "shadow comparator reports the first canonical mismatch" {
    var packages = [_]result_abi.Package{
        testNativePackage("available", "alpha", "1"),
    };
    packages[0].dwPackageId = 0;
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
    };
    actions[0].dwKind = action_install;
    actions[0].dwReason = 1;
    var native = testNativeResult(&packages, &actions);
    var legacy_package = testLegacyPackage("available", "alpha", "2");
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    legacy.pPkgsToInstall = @ptrCast(&legacy_package);
    var output: shadow_abi.Comparison = undefined;

    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_mismatch, output.dwStatus);
    try std.testing.expectEqual(action_install, output.dwActionKind);
    try std.testing.expectEqual(@as(u32, 0), output.dwDifferenceIndex);
    try std.testing.expectEqual(@as(u32, 1), output.dwNativeCount);
    try std.testing.expectEqual(@as(u32, 1), output.dwLegacyCount);
}

test "shadow comparator preserves unsupported distinctions" {
    var packages = [_]result_abi.Package{
        testNativePackage("available", "alpha", "1"),
    };
    packages[0].dwPackageId = 0;
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
    };
    actions[0].dwKind = action_install;
    actions[0].dwReason = 1;
    var native = testNativeResult(&packages, &actions);
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    var output: shadow_abi.Comparison = undefined;

    native.dwProblemCount = 1;
    var problems = [_]result_abi.Problem{
        std.mem.zeroes(result_abi.Problem),
    };
    problems[0].dwKind = 4;
    native.pProblems = &problems;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(reason_native_problems, output.dwReason);

    native.dwProblemCount = 0;
    native.pProblems = null;
    native.dwSkippedJobCount = 1;
    var skipped_jobs = [_]u32{0};
    native.pdwSkippedJobIds = &skipped_jobs;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(reason_skipped_jobs, output.dwReason);

    native.dwSkippedJobCount = 0;
    native.pdwSkippedJobIds = null;
    actions[0].dwPriorCount = 1;
    var prior_refs = [_]u32{0};
    var prior_hnums = [_]u32{7};
    packages[0].nHasRpmDbHnum = 1;
    packages[0].dwRpmDbHnum = 7;
    native.dwPriorPackageRefCount = 1;
    native.pdwPriorPackageRefs = &prior_refs;
    native.pdwPriorHnums = &prior_hnums;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(reason_prior_action, output.dwReason);

    actions[0].dwPriorCount = 0;
    native.dwPriorPackageRefCount = 0;
    native.pdwPriorPackageRefs = null;
    native.pdwPriorHnums = null;
    actions[0].dwKind = 4;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(reason_native_action_kind, output.dwReason);

    actions[0].dwKind = action_install;
    var unsupported_package = testLegacyPackage("available", "alpha", "1");
    legacy.pPkgsToDowngrade = @ptrCast(&unsupported_package);
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(reason_legacy_action_bucket, output.dwReason);
}

test "shadow comparator treats duplicate projected identities as unsupported" {
    var packages = [_]result_abi.Package{
        testNativePackage("available", "alpha", "1"),
        testNativePackage("available", "alpha", "1"),
    };
    packages[0].dwPackageId = 0;
    packages[1].dwPackageId = 1;
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
        std.mem.zeroes(result_abi.Action),
    };
    for (&actions, 0..) |*action, index| {
        action.dwPackageRef = @intCast(index);
        action.dwKind = action_install;
        action.dwReason = 1;
    }
    var native = testNativeResult(&packages, &actions);
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    var output: shadow_abi.Comparison = undefined;

    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_duplicate_key, output.dwReason);
}

test "shadow comparator rejects duplicate legacy identities as unsupported" {
    var packages = [_]result_abi.Package{
        testNativePackage("available", "alpha", "1"),
    };
    packages[0].dwPackageId = 0;
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
    };
    actions[0].dwKind = action_install;
    actions[0].dwReason = 1;
    var native = testNativeResult(&packages, &actions);
    var legacy_packages = [_]shadow_abi.LegacyPackage{
        testLegacyPackage("available", "alpha", "1"),
        testLegacyPackage("available", "alpha", "1"),
    };
    legacy_packages[0].pNext = @ptrCast(&legacy_packages[1]);
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    legacy.pPkgsToInstall = @ptrCast(&legacy_packages[0]);
    var output: shadow_abi.Comparison = undefined;

    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_unsupported, output.dwStatus);
    try std.testing.expectEqual(reason_duplicate_key, output.dwReason);
    try std.testing.expectEqual(@as(u32, 1), output.dwNativeCount);
    try std.testing.expectEqual(@as(u32, 2), output.dwLegacyCount);
}

test "shadow comparator reports count mismatch after common keys" {
    var packages = [_]result_abi.Package{
        testNativePackage("available", "alpha", "1"),
        testNativePackage("available", "bravo", "1"),
    };
    packages[0].dwPackageId = 0;
    packages[1].dwPackageId = 1;
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
        std.mem.zeroes(result_abi.Action),
    };
    for (&actions, 0..) |*action, index| {
        action.dwPackageRef = @intCast(index);
        action.dwKind = action_install;
        action.dwReason = 1;
    }
    var native = testNativeResult(&packages, &actions);
    var legacy_package = testLegacyPackage("available", "alpha", "1");
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    legacy.pPkgsToInstall = @ptrCast(&legacy_package);
    var output: shadow_abi.Comparison = undefined;

    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_mismatch, output.dwStatus);
    try std.testing.expectEqual(@as(u32, 1), output.dwDifferenceIndex);
    try std.testing.expectEqual(@as(u32, 2), output.dwNativeCount);
    try std.testing.expectEqual(@as(u32, 1), output.dwLegacyCount);
}

test "shadow comparator rejects invalid refs and legacy cycles" {
    var packages = [_]result_abi.Package{
        testNativePackage("available", "alpha", "1"),
    };
    packages[0].dwPackageId = 0;
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
    };
    actions[0].dwPackageRef = 1;
    actions[0].dwKind = action_install;
    actions[0].dwReason = 1;
    var native = testNativeResult(&packages, &actions);
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    var output: shadow_abi.Comparison = undefined;
    try std.testing.expectError(
        error.InvalidInput,
        compare(std.testing.allocator, &native, &legacy, &output),
    );
    try std.testing.expectEqual(status_invalid, output.dwStatus);

    actions[0].dwPackageRef = 0;
    var legacy_package = testLegacyPackage("available", "alpha", "1");
    legacy_package.pNext = @ptrCast(&legacy_package);
    legacy.pPkgsToInstall = @ptrCast(&legacy_package);
    try std.testing.expectError(
        error.InvalidInput,
        compare(std.testing.allocator, &native, &legacy, &output),
    );
}

fn comparisonAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var packages = [_]result_abi.Package{
        testNativePackage("available", "alpha", "1"),
    };
    packages[0].dwPackageId = 0;
    var actions = [_]result_abi.Action{
        std.mem.zeroes(result_abi.Action),
    };
    actions[0].dwKind = action_install;
    actions[0].dwReason = 1;
    var native = testNativeResult(&packages, &actions);
    var legacy_package = testLegacyPackage("available", "alpha", "1");
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    legacy.pPkgsToInstall = @ptrCast(&legacy_package);
    var output: shadow_abi.Comparison = undefined;

    try compare(allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_projected_match, output.dwStatus);
}

test "shadow comparator cleans every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        comparisonAllocationFailureCase,
        .{},
    );
}

test "shadow comparator matches empty projections" {
    var native = std.mem.zeroes(result_abi.Result);
    var legacy = std.mem.zeroes(shadow_abi.LegacyResult);
    var output: shadow_abi.Comparison = undefined;
    try compare(std.testing.allocator, &native, &legacy, &output);
    try std.testing.expectEqual(status_projected_match, output.dwStatus);
}

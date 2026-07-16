//! Typed RPM package digest and OpenPGP signature verification.
//!
//! Both reports retain every raw result so callers can apply RPM-compatible
//! policy without losing the underlying failure.

const std = @import("std");
const header = @import("rpm_header");
const pkgfile = @import("rpm_pkgfile");
const pgp_pubkey = @import("pgp/pubkey.zig");
const pgp_verify = @import("pgp/verify.zig");

const rpm_hash_sha256: u32 = 8;

pub const Algorithm = enum {
    md5,
    sha1,
    sha256,
    sha512,
    sha3_256,
};

pub const Range = enum {
    header,
    header_payload,
    compressed_payload,
    uncompressed_payload,
};

pub const CandidateKind = enum {
    legacy_md5,
    header_sha1,
    header_sha256,
    header_sha3_256,
    payload_sha256,
    payload_sha256_alt,
    payload_sha512,
    payload_sha512_alt,
    payload_sha3_256,
    payload_sha3_256_alt,
};

/// Matches RPM's digest-disabling classes. Raw and alternate payload digest
/// variants intentionally share a class.
pub const DisablerClass = enum {
    md5,
    sha1_header,
    sha256_header,
    sha3_256_header,
    sha256_payload,
    sha512_payload,
    sha3_256_payload,
};

/// A payload digest alternative is valid only within this class. In
/// particular, a SHA512 payload digest never masks a SHA256 failure.
pub const AlternativeGroup = enum {
    sha256_payload,
    sha512_payload,
    sha3_256_payload,
};

pub const Outcome = enum {
    verified,
    absent,
    malformed_tag,
    bad_digest,
    unsupported_digest,
    disabled_by_policy,
};

pub const Candidate = struct {
    kind: CandidateKind,
    range: Range,
    algorithm: Algorithm,
    tag: u32,
    /// Index in a STRING_ARRAY payload digest tag. Null for scalar and binary
    /// tags, and for an absent or malformed array tag.
    item_index: ?usize = null,
    disabler: DisablerClass,
    alternative_group: ?AlternativeGroup = null,
    outcome: Outcome,
    /// Retained separately from `outcome` so malformed disabled candidates
    /// remain diagnosable without counting as enabled policy failures.
    policy_enabled: bool = true,
    /// RPM6 can suppress the legacy signature-header namespace without
    /// changing the retained raw digest outcome.
    suppressed_legacy: bool = false,

    // This aliases the RpmFile header data and is used only while constructing
    // the report. It remains useful to callers that want to diagnose a result,
    // and is valid while the RpmFile remains alive.
    expected: ?[]const u8 = null,
    expected_is_binary: bool = false,

    pub fn isPresent(self: Candidate) bool {
        return self.outcome != .absent;
    }
};

/// Digest checks are independently controllable, but no policy is enforced
/// here. A disabled check is represented by a candidate with
/// `.disabled_by_policy`, allowing callers to report it accurately.
pub const Policy = struct {
    md5: bool = true,
    sha1_header: bool = true,
    sha256_header: bool = true,
    sha3_256_header: bool = true,
    sha256_payload: bool = true,
    sha512_payload: bool = true,
    sha3_256_payload: bool = true,
};

pub const Coverage = struct {
    /// A verified header-only or legacy header+payload digest exists.
    header_verified: bool,
    /// A verified compressed, uncompressed, or legacy header+payload digest
    /// exists.
    payload_verified: bool,
    /// No digest candidates were present in either header.
    no_digest_candidates: bool,
    /// This deliberately uses raw candidate outcomes: a bad digest remains
    /// observable even if an RPM-compatible alternative later suppresses it.
    any_enabled_present_bad_or_malformed: bool,
};

/// The report owns `candidates`; callers must call `deinit()` with the same
/// allocator passed to `verifyPackage()`.
pub const Report = struct {
    candidates: []Candidate,
    coverage: Coverage,

    pub fn deinit(self: *Report, allocator: std.mem.Allocator) void {
        allocator.free(self.candidates);
        self.candidates = &.{};
    }

    /// RPM only suppresses a bad, malformed, or unsupported payload
    /// alternative when another digest in the same
    /// algorithm/disabler/coverage class verifies. The raw candidate itself
    /// is never changed by this helper.
    pub fn failureSuppressedByAlternative(self: Report, index: usize) bool {
        if (index >= self.candidates.len) return false;
        const candidate = self.candidates[index];
        if (candidate.outcome != .bad_digest and
            candidate.outcome != .malformed_tag and
            candidate.outcome != .unsupported_digest)
        {
            return false;
        }
        const group = candidate.alternative_group orelse return false;
        for (self.candidates) |alternative| {
            if (alternative.alternative_group == group and
                alternative.disabler == candidate.disabler and
                alternative.outcome == .verified)
            {
                return true;
            }
        }
        return false;
    }

    pub fn suppressLegacySignatureHeader(self: *Report) void {
        for (self.candidates) |*candidate| {
            if (candidate.kind == .legacy_md5)
                candidate.suppressed_legacy = true;
        }
        self.coverage = aggregateCoverage(self.candidates);
    }
};

pub const SignatureKind = enum {
    legacy_pgp,
    legacy_gpg,
    header_rsa,
    header_dsa,
    openpgp,
};

pub const SignatureOutcome = enum {
    unchecked,
    verified,
    absent,
    malformed_tag,
    malformed_base64,
    malformed_openpgp,
    bad_signature,
    no_key,
    unsupported_openpgp,
    suppressed_legacy,
    disabled_by_policy,
};

pub const SignatureCandidate = struct {
    kind: SignatureKind,
    range: Range,
    signed_start: usize,
    signed_end: usize,
    tag: u32,
    array_index: ?usize = null,
    policy_enabled: bool,
    signature_version: ?u8 = null,
    signature_type: ?u8 = null,
    public_key_algorithm: ?u8 = null,
    hash_algorithm: ?u8 = null,
    packet_len: ?usize = null,
    outcome: SignatureOutcome,
    /// Parse/verification result before suppression and policy.
    raw_outcome: SignatureOutcome,

    pub fn isPresent(self: SignatureCandidate) bool {
        return self.raw_outcome != .absent;
    }
};

pub const SignaturePolicy = struct {
    legacy_pgp: bool = true,
    legacy_gpg: bool = true,
    header_rsa: bool = true,
    header_dsa: bool = true,
    openpgp: bool = true,
};

pub const SignatureCoverage = struct {
    header_relevant: bool,
    payload_relevant: bool,
    header_verified: bool,
    payload_verified: bool,
    no_signature_candidates: bool,
    any_enabled_unsuppressed_failure: bool,
    fully_verified: bool,
};

pub const SignatureReport = struct {
    candidates: []SignatureCandidate,
    coverage: SignatureCoverage,
    openpgp_suppresses_legacy: bool,
    rpm6_suppresses_legacy_signature_header: bool,
    legacy_md5_suppressed: bool,

    pub fn deinit(self: *SignatureReport, allocator: std.mem.Allocator) void {
        allocator.free(self.candidates);
        self.candidates = &.{};
    }
};

pub const PackageReport = struct {
    digests: Report,
    signatures: SignatureReport,

    pub fn deinit(self: *PackageReport, allocator: std.mem.Allocator) void {
        self.digests.deinit(allocator);
        self.signatures.deinit(allocator);
    }
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidRpmRange,
};

pub fn rpm6SuppressesLegacySignatureHeader(
    rpm: *const pkgfile.RpmFile,
) bool {
    return rpm.sig.findRaw(@intFromEnum(header.SigTagId.reserved)) != null and
        rpm.sig.findRaw(@intFromEnum(header.SigTagId.sha3_256)) != null;
}

const PendingSignature = struct {
    candidate: SignatureCandidate,
    packet: ?[]const u8 = null,
    owned_packet: ?[]u8 = null,
    syntax_valid: bool = false,
};

/// Enumerate and verify every recognized signature candidate. The report owns
/// all of its storage and remains valid after `rpm` and `key_blobs` are freed.
pub fn verifySignatures(
    allocator: std.mem.Allocator,
    rpm: *const pkgfile.RpmFile,
    policy: SignaturePolicy,
    key_blobs: []const []const u8,
) Error!SignatureReport {
    if (rpm.main_header_offset > rpm.payload_offset or
        rpm.payload_offset > rpm.bytes.len)
    {
        return error.InvalidRpmRange;
    }

    var pending = std.ArrayList(PendingSignature).empty;
    defer {
        for (pending.items) |item| {
            if (item.owned_packet) |bytes| allocator.free(bytes);
        }
        pending.deinit(allocator);
    }

    try appendOpenPgpCandidates(&pending, allocator, rpm.sig, policy.openpgp);
    try appendLegacySignatureCandidates(
        &pending,
        allocator,
        rpm.sig,
        @intFromEnum(header.SigTagId.pgp),
        .legacy_pgp,
        .header_payload,
        policy.legacy_pgp,
    );
    try appendLegacySignatureCandidates(
        &pending,
        allocator,
        rpm.sig,
        @intFromEnum(header.SigTagId.gpg),
        .legacy_gpg,
        .header_payload,
        policy.legacy_gpg,
    );
    try appendLegacySignatureCandidates(
        &pending,
        allocator,
        rpm.sig,
        @intFromEnum(header.SigTagId.rsa),
        .header_rsa,
        .header,
        policy.header_rsa,
    );
    try appendLegacySignatureCandidates(
        &pending,
        allocator,
        rpm.sig,
        @intFromEnum(header.SigTagId.dsa),
        .header_dsa,
        .header,
        policy.header_dsa,
    );

    var openpgp_suppresses_legacy = false;
    for (pending.items) |item| {
        if (item.candidate.kind == .openpgp and
            item.candidate.policy_enabled and
            item.syntax_valid)
        {
            openpgp_suppresses_legacy = true;
            break;
        }
    }
    const rpm6_suppresses_legacy =
        rpm6SuppressesLegacySignatureHeader(rpm);

    const header_bytes = rpm.bytes[rpm.main_header_offset..rpm.payload_offset];
    const header_payload_bytes = rpm.bytes[rpm.main_header_offset..];
    for (pending.items) |*item| {
        const candidate = &item.candidate;
        candidate.signed_start = rpm.main_header_offset;
        candidate.signed_end = switch (candidate.range) {
            .header => rpm.payload_offset,
            .header_payload => rpm.bytes.len,
            .compressed_payload, .uncompressed_payload => unreachable,
        };
        if (!candidate.isPresent()) {
            candidate.outcome = .absent;
            continue;
        }

        const legacy = candidate.kind != .openpgp;
        if (legacy and
            (openpgp_suppresses_legacy or
                (rpm6_suppresses_legacy and candidate.tag >= 1000)))
        {
            candidate.outcome = .suppressed_legacy;
            continue;
        }
        if (!candidate.policy_enabled) {
            candidate.outcome = .disabled_by_policy;
            continue;
        }
        if (!item.syntax_valid) {
            candidate.outcome = candidate.raw_outcome;
            continue;
        }

        const packet_bytes = item.packet orelse {
            candidate.raw_outcome = .malformed_openpgp;
            candidate.outcome = .malformed_openpgp;
            continue;
        };
        const signed = switch (candidate.range) {
            .header => header_bytes,
            .header_payload => header_payload_bytes,
            .compressed_payload, .uncompressed_payload => unreachable,
        };
        const result = mapSignatureVerification(pgp_verify.verifyDetachedDetailed(
            allocator,
            packet_bytes,
            signed,
            key_blobs,
        ));
        candidate.raw_outcome = result;
        candidate.outcome = result;
    }

    const candidates = try allocator.alloc(SignatureCandidate, pending.items.len);
    for (pending.items, candidates) |item, *candidate|
        candidate.* = item.candidate;
    return .{
        .candidates = candidates,
        .coverage = aggregateSignatureCoverage(candidates),
        .openpgp_suppresses_legacy = openpgp_suppresses_legacy,
        .rpm6_suppresses_legacy_signature_header = rpm6_suppresses_legacy,
        .legacy_md5_suppressed = rpm6_suppresses_legacy,
    };
}

/// Combined report used by callers that need RPM's cross-digest/signature
/// suppression semantics while preserving the legacy digest-only API.
pub fn verifyIntegrity(
    allocator: std.mem.Allocator,
    rpm: *const pkgfile.RpmFile,
    digest_policy: Policy,
    signature_policy: SignaturePolicy,
    key_blobs: []const []const u8,
) Error!PackageReport {
    var digests = try verifyPackage(allocator, rpm, digest_policy);
    errdefer digests.deinit(allocator);
    var signatures = try verifySignatures(allocator, rpm, signature_policy, key_blobs);
    errdefer signatures.deinit(allocator);
    if (signatures.legacy_md5_suppressed)
        digests.suppressLegacySignatureHeader();
    return .{
        .digests = digests,
        .signatures = signatures,
    };
}

fn makeSignatureCandidate(
    kind: SignatureKind,
    range: Range,
    tag: u32,
    array_index: ?usize,
    enabled: bool,
    outcome: SignatureOutcome,
) SignatureCandidate {
    return .{
        .kind = kind,
        .range = range,
        .signed_start = 0,
        .signed_end = 0,
        .tag = tag,
        .array_index = array_index,
        .policy_enabled = enabled,
        .outcome = outcome,
        .raw_outcome = outcome,
    };
}

fn inspectPendingSignature(item: *PendingSignature) void {
    const bytes = item.packet orelse return;
    item.candidate.packet_len = bytes.len;
    const sig = pgp_verify.parseDetached(bytes) catch |err| {
        item.candidate.raw_outcome = switch (err) {
            error.UnsupportedOpenPgp => .unsupported_openpgp,
            error.NoSignature, error.MalformedOpenPgp => .malformed_openpgp,
        };
        item.candidate.outcome = item.candidate.raw_outcome;
        return;
    };
    item.candidate.signature_version = sig.version;
    item.candidate.signature_type = @intFromEnum(sig.sig_type);
    item.candidate.public_key_algorithm = @intFromEnum(sig.pk_algo);
    item.candidate.hash_algorithm = @intFromEnum(sig.hash_algo);
    item.candidate.raw_outcome = .unchecked;
    item.candidate.outcome = .unchecked;
    item.syntax_valid = true;
}

fn appendLegacySignatureCandidates(
    pending: *std.ArrayList(PendingSignature),
    allocator: std.mem.Allocator,
    source: header.Header,
    tag: u32,
    kind: SignatureKind,
    range: Range,
    enabled: bool,
) std.mem.Allocator.Error!void {
    var found = false;
    var index: u32 = 0;
    while (index < source.index_count) : (index += 1) {
        const entry = source.entry(index);
        if (entry.tag != tag) continue;
        found = true;
        var item: PendingSignature = .{
            .candidate = makeSignatureCandidate(
                kind,
                range,
                tag,
                null,
                enabled,
                .malformed_tag,
            ),
        };
        if (entry.typ == @intFromEnum(header.TypeId.bin)) {
            if (source.rawEntryBytes(entry)) |bytes| {
                item.packet = bytes;
                inspectPendingSignature(&item);
            }
        }
        try pending.append(allocator, item);
    }
    if (!found) {
        try pending.append(allocator, .{
            .candidate = makeSignatureCandidate(
                kind,
                range,
                tag,
                null,
                enabled,
                .absent,
            ),
        });
    }
}

fn appendOpenPgpCandidates(
    pending: *std.ArrayList(PendingSignature),
    allocator: std.mem.Allocator,
    source: header.Header,
    enabled: bool,
) std.mem.Allocator.Error!void {
    const tag = @intFromEnum(header.SigTagId.openpgp);
    var found = false;
    var entry_index: u32 = 0;
    while (entry_index < source.index_count) : (entry_index += 1) {
        const entry = source.entry(entry_index);
        if (entry.tag != tag) continue;
        found = true;
        if (entry.typ != @intFromEnum(header.TypeId.string_array)) {
            try pending.append(allocator, .{
                .candidate = makeSignatureCandidate(
                    .openpgp,
                    .header,
                    tag,
                    null,
                    enabled,
                    .malformed_tag,
                ),
            });
            continue;
        }
        const raw = source.rawEntryBytes(entry) orelse {
            try pending.append(allocator, .{
                .candidate = makeSignatureCandidate(
                    .openpgp,
                    .header,
                    tag,
                    null,
                    enabled,
                    .malformed_tag,
                ),
            });
            continue;
        };

        var offset: usize = 0;
        var array_index: usize = 0;
        while (array_index < entry.count) : (array_index += 1) {
            const end = std.mem.indexOfScalarPos(u8, raw, offset, 0) orelse {
                try pending.append(allocator, .{
                    .candidate = makeSignatureCandidate(
                        .openpgp,
                        .header,
                        tag,
                        array_index,
                        enabled,
                        .malformed_tag,
                    ),
                });
                break;
            };
            const encoded = raw[offset..end];
            offset = end + 1;

            const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch {
                try pending.append(allocator, .{
                    .candidate = makeSignatureCandidate(
                        .openpgp,
                        .header,
                        tag,
                        array_index,
                        enabled,
                        .malformed_base64,
                    ),
                });
                continue;
            };
            const decoded = try allocator.alloc(u8, decoded_len);
            std.base64.standard.Decoder.decode(decoded, encoded) catch {
                allocator.free(decoded);
                try pending.append(allocator, .{
                    .candidate = makeSignatureCandidate(
                        .openpgp,
                        .header,
                        tag,
                        array_index,
                        enabled,
                        .malformed_base64,
                    ),
                });
                continue;
            };
            var item: PendingSignature = .{
                .candidate = makeSignatureCandidate(
                    .openpgp,
                    .header,
                    tag,
                    array_index,
                    enabled,
                    .unchecked,
                ),
                .packet = decoded,
                .owned_packet = decoded,
            };
            inspectPendingSignature(&item);
            pending.append(allocator, item) catch |err| {
                allocator.free(decoded);
                return err;
            };
        }
    }
    if (!found) {
        try pending.append(allocator, .{
            .candidate = makeSignatureCandidate(
                .openpgp,
                .header,
                tag,
                null,
                enabled,
                .absent,
            ),
        });
    }
}

fn mapSignatureVerification(status: pgp_verify.DetailedStatus) SignatureOutcome {
    return switch (status) {
        .verified => .verified,
        .no_signature, .malformed_openpgp => .malformed_openpgp,
        .no_key => .no_key,
        .bad_signature => .bad_signature,
        .unsupported_openpgp => .unsupported_openpgp,
    };
}

fn aggregateSignatureCoverage(candidates: []const SignatureCandidate) SignatureCoverage {
    var coverage: SignatureCoverage = .{
        .header_relevant = false,
        .payload_relevant = false,
        .header_verified = false,
        .payload_verified = false,
        .no_signature_candidates = true,
        .any_enabled_unsuppressed_failure = false,
        .fully_verified = false,
    };
    for (candidates) |candidate| {
        if (candidate.isPresent()) coverage.no_signature_candidates = false;
        if (candidate.outcome == .absent or
            candidate.outcome == .suppressed_legacy or
            candidate.outcome == .disabled_by_policy)
        {
            continue;
        }
        coverage.header_relevant = true;
        if (candidate.range == .header_payload)
            coverage.payload_relevant = true;
        if (candidate.outcome != .verified) {
            coverage.any_enabled_unsuppressed_failure = true;
            continue;
        }
        coverage.header_verified = true;
        if (candidate.range == .header_payload)
            coverage.payload_verified = true;
    }
    const any_relevant = coverage.header_relevant or coverage.payload_relevant;
    coverage.fully_verified = any_relevant and
        (!coverage.header_relevant or coverage.header_verified) and
        (!coverage.payload_relevant or coverage.payload_verified);
    return coverage;
}

/// Verify every recognized package digest. This function neither verifies
/// OpenPGP signatures nor decides whether missing/failed digests reject a
/// package; those are caller policy decisions.
pub fn verifyPackage(
    allocator: std.mem.Allocator,
    rpm: *const pkgfile.RpmFile,
    policy: Policy,
) Error!Report {
    if (rpm.main_header_offset > rpm.payload_offset or
        rpm.payload_offset > rpm.bytes.len)
    {
        return error.InvalidRpmRange;
    }

    var candidates = std.ArrayList(Candidate).empty;
    errdefer candidates.deinit(allocator);

    try appendBinaryCandidate(
        &candidates,
        allocator,
        rpm.sig,
        @intFromEnum(header.SigTagId.md5),
        .legacy_md5,
        .header_payload,
        .md5,
        .md5,
        null,
        policy.md5,
        16,
    );
    try appendScalarHexCandidate(
        &candidates,
        allocator,
        rpm.sig,
        @intFromEnum(header.SigTagId.sha1),
        .header_sha1,
        .header,
        .sha1,
        .sha1_header,
        null,
        policy.sha1_header,
        40,
    );
    try appendScalarHexCandidate(
        &candidates,
        allocator,
        rpm.sig,
        @intFromEnum(header.SigTagId.sha256),
        .header_sha256,
        .header,
        .sha256,
        .sha256_header,
        null,
        policy.sha256_header,
        64,
    );
    try appendScalarHexCandidate(
        &candidates,
        allocator,
        rpm.sig,
        @intFromEnum(header.SigTagId.sha3_256),
        .header_sha3_256,
        .header,
        .sha3_256,
        .sha3_256_header,
        null,
        policy.sha3_256_header,
        64,
    );

    const payload_sha256_algo_ok = payloadSha256AlgorithmValid(rpm.main);
    try appendArrayHexCandidates(
        &candidates,
        allocator,
        rpm.main,
        @intFromEnum(header.TagId.payloadsha256),
        .payload_sha256,
        .compressed_payload,
        .sha256,
        .sha256_payload,
        .sha256_payload,
        policy.sha256_payload,
        64,
        !payload_sha256_algo_ok,
    );
    try appendArrayHexCandidates(
        &candidates,
        allocator,
        rpm.main,
        @intFromEnum(header.TagId.payloadsha256alt),
        .payload_sha256_alt,
        .uncompressed_payload,
        .sha256,
        .sha256_payload,
        .sha256_payload,
        policy.sha256_payload,
        64,
        false,
    );
    try appendScalarHexCandidate(
        &candidates,
        allocator,
        rpm.main,
        @intFromEnum(header.TagId.payloadsha512),
        .payload_sha512,
        .compressed_payload,
        .sha512,
        .sha512_payload,
        .sha512_payload,
        policy.sha512_payload,
        128,
    );
    try appendScalarHexCandidate(
        &candidates,
        allocator,
        rpm.main,
        @intFromEnum(header.TagId.payloadsha512alt),
        .payload_sha512_alt,
        .uncompressed_payload,
        .sha512,
        .sha512_payload,
        .sha512_payload,
        policy.sha512_payload,
        128,
    );
    try appendScalarHexCandidate(
        &candidates,
        allocator,
        rpm.main,
        @intFromEnum(header.TagId.payloadsha3_256),
        .payload_sha3_256,
        .compressed_payload,
        .sha3_256,
        .sha3_256_payload,
        .sha3_256_payload,
        policy.sha3_256_payload,
        64,
    );
    try appendScalarHexCandidate(
        &candidates,
        allocator,
        rpm.main,
        @intFromEnum(header.TagId.payloadsha3_256alt),
        .payload_sha3_256_alt,
        .uncompressed_payload,
        .sha3_256,
        .sha3_256_payload,
        .sha3_256_payload,
        policy.sha3_256_payload,
        64,
    );

    for (candidates.items) |*candidate|
        candidate.policy_enabled = policyEnables(policy, candidate.disabler);

    const header_bytes = rpm.bytes[rpm.main_header_offset..rpm.payload_offset];
    const header_payload_bytes = rpm.bytes[rpm.main_header_offset..];
    const compressed_payload = rpm.bytes[rpm.payload_offset..];
    for (candidates.items) |*candidate| {
        if (candidate.expected == null or candidate.range == .uncompressed_payload)
            continue;
        const bytes = switch (candidate.range) {
            .header => header_bytes,
            .header_payload => header_payload_bytes,
            .compressed_payload => compressed_payload,
            .uncompressed_payload => unreachable,
        };
        candidate.outcome = verifyExpected(candidate.*, bytes);
    }

    var need_uncompressed_payload = false;
    for (candidates.items) |candidate| {
        if (candidate.range == .uncompressed_payload and candidate.expected != null) {
            need_uncompressed_payload = true;
            break;
        }
    }
    if (need_uncompressed_payload) {
        const uncompressed_payload: ?[]u8 = rpm.decompressPayload(allocator) catch |err| blk: {
            switch (err) {
                error.UnsupportedCompressor => {
                    markUncompressedPending(&candidates, .unsupported_digest);
                    break :blk null;
                },
                error.DecompressFailed => {
                    markUncompressedPending(&candidates, .malformed_tag);
                    break :blk null;
                },
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    markUncompressedPending(&candidates, .malformed_tag);
                    break :blk null;
                },
            }
        };
        if (uncompressed_payload) |bytes| {
            defer allocator.free(bytes);
            for (candidates.items) |*candidate| {
                if (candidate.range == .uncompressed_payload and candidate.expected != null)
                    candidate.outcome = verifyExpected(candidate.*, bytes);
            }
        }
    }

    const coverage = aggregateCoverage(candidates.items);
    return .{
        .candidates = try candidates.toOwnedSlice(allocator),
        .coverage = coverage,
    };
}

fn appendBinaryCandidate(
    candidates: *std.ArrayList(Candidate),
    allocator: std.mem.Allocator,
    source: header.Header,
    tag: u32,
    kind: CandidateKind,
    range: Range,
    algorithm: Algorithm,
    disabler: DisablerClass,
    alternative_group: ?AlternativeGroup,
    enabled: bool,
    expected_len: usize,
) std.mem.Allocator.Error!void {
    const entry = source.findRaw(tag) orelse {
        try appendCandidate(candidates, allocator, kind, range, algorithm, tag, null, disabler, alternative_group, .absent, null, false);
        return;
    };
    if (entry.typ != @intFromEnum(header.TypeId.bin) or entry.count != expected_len) {
        try appendCandidate(candidates, allocator, kind, range, algorithm, tag, null, disabler, alternative_group, .malformed_tag, null, true);
        return;
    }
    const value = source.getBinaryRawChecked(tag) catch {
        try appendCandidate(candidates, allocator, kind, range, algorithm, tag, null, disabler, alternative_group, .malformed_tag, null, true);
        return;
    } orelse {
        try appendCandidate(candidates, allocator, kind, range, algorithm, tag, null, disabler, alternative_group, .malformed_tag, null, true);
        return;
    };
    if (value.len != expected_len) {
        try appendCandidate(candidates, allocator, kind, range, algorithm, tag, null, disabler, alternative_group, .malformed_tag, null, true);
        return;
    }
    try appendCandidate(
        candidates,
        allocator,
        kind,
        range,
        algorithm,
        tag,
        null,
        disabler,
        alternative_group,
        if (enabled) .absent else .disabled_by_policy,
        if (enabled) value else null,
        true,
    );
}

fn appendScalarHexCandidate(
    candidates: *std.ArrayList(Candidate),
    allocator: std.mem.Allocator,
    source: header.Header,
    tag: u32,
    kind: CandidateKind,
    range: Range,
    algorithm: Algorithm,
    disabler: DisablerClass,
    alternative_group: ?AlternativeGroup,
    enabled: bool,
    expected_hex_len: usize,
) std.mem.Allocator.Error!void {
    const entry = source.findRaw(tag) orelse {
        try appendCandidate(candidates, allocator, kind, range, algorithm, tag, null, disabler, alternative_group, .absent, null, false);
        return;
    };
    if (entry.typ != @intFromEnum(header.TypeId.string) or entry.count != 1) {
        try appendCandidate(candidates, allocator, kind, range, algorithm, tag, null, disabler, alternative_group, .malformed_tag, null, false);
        return;
    }
    const raw = source.rawEntryBytes(entry) orelse {
        try appendCandidate(candidates, allocator, kind, range, algorithm, tag, null, disabler, alternative_group, .malformed_tag, null, false);
        return;
    };
    if (raw.len != expected_hex_len + 1 or raw[expected_hex_len] != 0 or
        !isHex(raw[0..expected_hex_len]))
    {
        try appendCandidate(candidates, allocator, kind, range, algorithm, tag, null, disabler, alternative_group, .malformed_tag, null, false);
        return;
    }
    try appendCandidate(
        candidates,
        allocator,
        kind,
        range,
        algorithm,
        tag,
        null,
        disabler,
        alternative_group,
        if (enabled) .absent else .disabled_by_policy,
        if (enabled) raw[0..expected_hex_len] else null,
        false,
    );
}

fn appendArrayHexCandidates(
    candidates: *std.ArrayList(Candidate),
    allocator: std.mem.Allocator,
    source: header.Header,
    tag: u32,
    kind: CandidateKind,
    range: Range,
    algorithm: Algorithm,
    disabler: DisablerClass,
    alternative_group: AlternativeGroup,
    enabled: bool,
    expected_hex_len: usize,
    force_malformed: bool,
) std.mem.Allocator.Error!void {
    const entry = source.findRaw(tag) orelse {
        try appendCandidate(
            candidates,
            allocator,
            kind,
            range,
            algorithm,
            tag,
            null,
            disabler,
            alternative_group,
            if (force_malformed) .malformed_tag else .absent,
            null,
            false,
        );
        return;
    };
    if (entry.typ != @intFromEnum(header.TypeId.string_array) or entry.count == 0) {
        try appendCandidate(candidates, allocator, kind, range, algorithm, tag, null, disabler, alternative_group, .malformed_tag, null, false);
        return;
    }

    var index: usize = 0;
    while (index < entry.count) : (index += 1) {
        const value = source.stringArrayItemRawChecked(tag, index) catch {
            try appendCandidate(candidates, allocator, kind, range, algorithm, tag, index, disabler, alternative_group, .malformed_tag, null, false);
            continue;
        } orelse {
            try appendCandidate(candidates, allocator, kind, range, algorithm, tag, index, disabler, alternative_group, .malformed_tag, null, false);
            continue;
        };
        const malformed = force_malformed or value.len != expected_hex_len or !isHex(value);
        try appendCandidate(
            candidates,
            allocator,
            kind,
            range,
            algorithm,
            tag,
            index,
            disabler,
            alternative_group,
            if (malformed) .malformed_tag else if (enabled) .absent else .disabled_by_policy,
            if (!malformed and enabled) value else null,
            false,
        );
    }
}

fn appendCandidate(
    candidates: *std.ArrayList(Candidate),
    allocator: std.mem.Allocator,
    kind: CandidateKind,
    range: Range,
    algorithm: Algorithm,
    tag: u32,
    item_index: ?usize,
    disabler: DisablerClass,
    alternative_group: ?AlternativeGroup,
    outcome: Outcome,
    expected: ?[]const u8,
    expected_is_binary: bool,
) std.mem.Allocator.Error!void {
    try candidates.append(allocator, .{
        .kind = kind,
        .range = range,
        .algorithm = algorithm,
        .tag = tag,
        .item_index = item_index,
        .disabler = disabler,
        .alternative_group = alternative_group,
        .outcome = outcome,
        .expected = expected,
        .expected_is_binary = expected_is_binary,
    });
}

fn payloadSha256AlgorithmValid(main: header.Header) bool {
    const entry = main.find(.payloadsha256algo) orelse return true;
    if (entry.typ != @intFromEnum(header.TypeId.int32) or entry.count != 1)
        return false;
    const algorithm = main.getU32Checked(.payloadsha256algo) catch return false;
    return algorithm != null and algorithm.? == rpm_hash_sha256;
}

fn policyEnables(policy: Policy, disabler: DisablerClass) bool {
    return switch (disabler) {
        .md5 => policy.md5,
        .sha1_header => policy.sha1_header,
        .sha256_header => policy.sha256_header,
        .sha3_256_header => policy.sha3_256_header,
        .sha256_payload => policy.sha256_payload,
        .sha512_payload => policy.sha512_payload,
        .sha3_256_payload => policy.sha3_256_payload,
    };
}

fn markUncompressedPending(
    candidates: *std.ArrayList(Candidate),
    outcome: Outcome,
) void {
    for (candidates.items) |*candidate| {
        if (candidate.range == .uncompressed_payload and candidate.expected != null) {
            candidate.outcome = outcome;
            candidate.expected = null;
        }
    }
}

fn verifyExpected(candidate: Candidate, bytes: []const u8) Outcome {
    const expected = candidate.expected orelse return candidate.outcome;
    return switch (candidate.algorithm) {
        .md5 => verifyHash(std.crypto.hash.Md5, bytes, expected, candidate.expected_is_binary),
        .sha1 => verifyHash(std.crypto.hash.Sha1, bytes, expected, candidate.expected_is_binary),
        .sha256 => verifyHash(std.crypto.hash.sha2.Sha256, bytes, expected, candidate.expected_is_binary),
        .sha512 => verifyHash(std.crypto.hash.sha2.Sha512, bytes, expected, candidate.expected_is_binary),
        .sha3_256 => if (comptime @hasDecl(std.crypto.hash, "sha3") and
            @hasDecl(std.crypto.hash.sha3, "Sha3_256"))
            verifyHash(std.crypto.hash.sha3.Sha3_256, bytes, expected, candidate.expected_is_binary)
        else
            .unsupported_digest,
    };
}

fn verifyHash(
    comptime Hash: type,
    bytes: []const u8,
    expected_value: []const u8,
    expected_is_binary: bool,
) Outcome {
    var expected: [Hash.digest_length]u8 = undefined;
    if (expected_is_binary) {
        if (expected_value.len != expected.len) return .malformed_tag;
        @memcpy(&expected, expected_value);
    } else if (!decodeHexExact(expected_value, &expected)) {
        return .malformed_tag;
    }

    var hasher = Hash.init(.{});
    hasher.update(bytes);
    var actual: [Hash.digest_length]u8 = undefined;
    hasher.final(&actual);
    return if (std.crypto.timing_safe.eql([Hash.digest_length]u8, actual, expected))
        .verified
    else
        .bad_digest;
}

fn aggregateCoverage(candidates: []const Candidate) Coverage {
    var coverage: Coverage = .{
        .header_verified = false,
        .payload_verified = false,
        .no_digest_candidates = true,
        .any_enabled_present_bad_or_malformed = false,
    };
    for (candidates) |candidate| {
        if (candidate.outcome != .absent) coverage.no_digest_candidates = false;
        if (candidate.suppressed_legacy) continue;
        if (candidate.policy_enabled and
            (candidate.outcome == .bad_digest or candidate.outcome == .malformed_tag))
            coverage.any_enabled_present_bad_or_malformed = true;
        if (candidate.outcome != .verified) continue;
        switch (candidate.range) {
            .header => coverage.header_verified = true,
            .header_payload => {
                coverage.header_verified = true;
                coverage.payload_verified = true;
            },
            .compressed_payload, .uncompressed_payload => coverage.payload_verified = true,
        }
    }
    return coverage;
}

fn isHex(bytes: []const u8) bool {
    if (bytes.len % 2 != 0) return false;
    for (bytes) |byte| {
        if (hexNibble(byte) == null) return false;
    }
    return true;
}

fn decodeHexExact(input: []const u8, output: []u8) bool {
    if (input.len != output.len * 2) return false;
    for (output, 0..) |*byte, index| {
        const high = hexNibble(input[index * 2]) orelse return false;
        const low = hexNibble(input[index * 2 + 1]) orelse return false;
        byte.* = high << 4 | low;
    }
    return true;
}

fn hexNibble(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

const TestEntry = struct {
    tag: u32,
    typ: header.TypeId,
    count: u32,
    data: []const u8,
};

const FixtureOptions = struct {
    include_all: bool = true,
    compressor: []const u8 = "none",
    payload: []const u8 = "raw payload",
    alternate_payload: ?[]const u8 = null,
    rpm6_reserved: bool = false,
    bad_legacy_md5: bool = false,
};

fn appendU32(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    try list.append(allocator, @truncate(value >> 24));
    try list.append(allocator, @truncate(value >> 16));
    try list.append(allocator, @truncate(value >> 8));
    try list.append(allocator, @truncate(value));
}

fn typeAlignment(typ: header.TypeId) usize {
    return switch (typ) {
        .int16 => 2,
        .int32 => 4,
        .int64 => 8,
        else => 1,
    };
}

fn buildRegionHeader(
    allocator: std.mem.Allocator,
    region: header.RegionTag,
    entries: []const TestEntry,
) ![]u8 {
    var data = std.ArrayList(u8).empty;
    defer data.deinit(allocator);
    var offsets = std.ArrayList(u32).empty;
    defer offsets.deinit(allocator);

    for (entries) |entry| {
        while (data.items.len % typeAlignment(entry.typ) != 0)
            try data.append(allocator, 0);
        try offsets.append(allocator, @intCast(data.items.len));
        try data.appendSlice(allocator, entry.data);
    }
    const trailer_offset: u32 = @intCast(data.items.len);
    const index_count: u32 = @intCast(entries.len + 1);
    const region_tag = @intFromEnum(region);
    try appendU32(&data, allocator, region_tag);
    try appendU32(&data, allocator, @intFromEnum(header.TypeId.bin));
    try appendU32(&data, allocator, @bitCast(-@as(i32, @intCast(index_count * 16))));
    try appendU32(&data, allocator, 16);

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &.{ 0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0 });
    try appendU32(&out, allocator, index_count);
    try appendU32(&out, allocator, @intCast(data.items.len));
    try appendU32(&out, allocator, region_tag);
    try appendU32(&out, allocator, @intFromEnum(header.TypeId.bin));
    try appendU32(&out, allocator, trailer_offset);
    try appendU32(&out, allocator, 16);
    for (entries, offsets.items) |entry, offset| {
        try appendU32(&out, allocator, entry.tag);
        try appendU32(&out, allocator, @intFromEnum(entry.typ));
        try appendU32(&out, allocator, offset);
        try appendU32(&out, allocator, entry.count);
    }
    try out.appendSlice(allocator, data.items);
    return out.toOwnedSlice(allocator);
}

fn digestHex(comptime Hash: type, bytes: []const u8) [Hash.digest_length * 2]u8 {
    var hasher = Hash.init(.{});
    hasher.update(bytes);
    var digest: [Hash.digest_length]u8 = undefined;
    hasher.final(&digest);
    var hex: [Hash.digest_length * 2]u8 = undefined;
    const alphabet = "0123456789abcdef";
    for (digest, 0..) |byte, index| {
        hex[index * 2] = alphabet[byte >> 4];
        hex[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return hex;
}

fn appendHexEntry(
    entries: *std.ArrayList(TestEntry),
    data: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    tag: u32,
    typ: header.TypeId,
    digest: []const u8,
) !void {
    const offset = data.items.len;
    try data.appendSlice(allocator, digest);
    try data.append(allocator, 0);
    try entries.append(allocator, .{
        .tag = tag,
        .typ = typ,
        .count = 1,
        .data = data.items[offset..],
    });
}

fn makeFixture(allocator: std.mem.Allocator, options: FixtureOptions) !pkgfile.RpmFile {
    const sha256 = digestHex(std.crypto.hash.sha2.Sha256, options.payload);
    const sha512 = digestHex(std.crypto.hash.sha2.Sha512, options.payload);
    const sha3 = digestHex(std.crypto.hash.sha3.Sha3_256, options.payload);
    const alt_payload = options.alternate_payload orelse options.payload;
    const alt_sha256 = digestHex(std.crypto.hash.sha2.Sha256, alt_payload);
    const alt_sha512 = digestHex(std.crypto.hash.sha2.Sha512, alt_payload);
    const alt_sha3 = digestHex(std.crypto.hash.sha3.Sha3_256, alt_payload);

    var main_entries = std.ArrayList(TestEntry).empty;
    defer main_entries.deinit(allocator);
    var main_data = std.ArrayList(u8).empty;
    defer main_data.deinit(allocator);
    try main_data.ensureTotalCapacity(allocator, 1024);
    try main_entries.append(allocator, .{ .tag = @intFromEnum(header.TagId.name), .typ = .string, .count = 1, .data = "pkg\x00" });
    try main_entries.append(allocator, .{ .tag = @intFromEnum(header.TagId.version), .typ = .string, .count = 1, .data = "1\x00" });
    try main_entries.append(allocator, .{ .tag = @intFromEnum(header.TagId.release), .typ = .string, .count = 1, .data = "1\x00" });
    try main_entries.append(allocator, .{ .tag = @intFromEnum(header.TagId.arch), .typ = .string, .count = 1, .data = "noarch\x00" });
    try main_data.appendSlice(allocator, options.compressor);
    try main_data.append(allocator, 0);
    try main_entries.append(allocator, .{
        .tag = @intFromEnum(header.TagId.payload_compressor),
        .typ = .string,
        .count = 1,
        .data = main_data.items[0..],
    });
    if (options.include_all) {
        try appendHexEntry(&main_entries, &main_data, allocator, @intFromEnum(header.TagId.payloadsha256), .string_array, &sha256);
        try main_entries.append(allocator, .{
            .tag = @intFromEnum(header.TagId.payloadsha256algo),
            .typ = .int32,
            .count = 1,
            .data = "\x00\x00\x00\x08",
        });
        try appendHexEntry(&main_entries, &main_data, allocator, @intFromEnum(header.TagId.payloadsha256alt), .string_array, &alt_sha256);
        try appendHexEntry(&main_entries, &main_data, allocator, @intFromEnum(header.TagId.payloadsha512), .string, &sha512);
        try appendHexEntry(&main_entries, &main_data, allocator, @intFromEnum(header.TagId.payloadsha512alt), .string, &alt_sha512);
        try appendHexEntry(&main_entries, &main_data, allocator, @intFromEnum(header.TagId.payloadsha3_256), .string, &sha3);
        try appendHexEntry(&main_entries, &main_data, allocator, @intFromEnum(header.TagId.payloadsha3_256alt), .string, &alt_sha3);
    }
    const main = try buildRegionHeader(allocator, .immutable, main_entries.items);
    defer allocator.free(main);

    const sha1_header = digestHex(std.crypto.hash.Sha1, main);
    const sha256_header = digestHex(std.crypto.hash.sha2.Sha256, main);
    const sha3_header = digestHex(std.crypto.hash.sha3.Sha3_256, main);
    var md5_hasher = std.crypto.hash.Md5.init(.{});
    md5_hasher.update(main);
    md5_hasher.update(options.payload);
    var md5: [std.crypto.hash.Md5.digest_length]u8 = undefined;
    md5_hasher.final(&md5);
    if (options.bad_legacy_md5)
        md5[0] ^= 1;

    var sig_entries = std.ArrayList(TestEntry).empty;
    defer sig_entries.deinit(allocator);
    var sig_data = std.ArrayList(u8).empty;
    defer sig_data.deinit(allocator);
    try sig_data.ensureTotalCapacity(allocator, 256);
    try sig_entries.append(allocator, .{
        .tag = @intFromEnum(header.SigTagId.size),
        .typ = .int32,
        .count = 1,
        .data = "\x00\x00\x00\x01",
    });
    if (options.include_all) {
        try sig_entries.append(allocator, .{
            .tag = @intFromEnum(header.SigTagId.md5),
            .typ = .bin,
            .count = md5.len,
            .data = &md5,
        });
        try appendHexEntry(&sig_entries, &sig_data, allocator, @intFromEnum(header.SigTagId.sha1), .string, &sha1_header);
        try appendHexEntry(&sig_entries, &sig_data, allocator, @intFromEnum(header.SigTagId.sha256), .string, &sha256_header);
        try appendHexEntry(&sig_entries, &sig_data, allocator, @intFromEnum(header.SigTagId.sha3_256), .string, &sha3_header);
    }
    if (options.rpm6_reserved) {
        try sig_entries.append(allocator, .{
            .tag = @intFromEnum(header.SigTagId.reserved),
            .typ = .bin,
            .count = 1,
            .data = "\x00",
        });
        std.sort.pdq(TestEntry, sig_entries.items, {}, struct {
            fn lessThan(_: void, left: TestEntry, right: TestEntry) bool {
                return left.tag < right.tag;
            }
        }.lessThan);
    }
    const sig = try buildRegionHeader(allocator, .signatures, sig_entries.items);
    defer allocator.free(sig);

    const padding = (8 - (sig.len % 8)) % 8;
    const main_offset = 96 + sig.len + padding;
    const bytes = try allocator.alloc(u8, main_offset + main.len + options.payload.len);
    @memset(bytes, 0);
    @memcpy(bytes[0..4], &[_]u8{ 0xed, 0xab, 0xee, 0xdb });
    @memcpy(bytes[96 .. 96 + sig.len], sig);
    @memcpy(bytes[main_offset .. main_offset + main.len], main);
    @memcpy(bytes[main_offset + main.len ..], options.payload);
    return pkgfile.RpmFile.parseBytes(bytes);
}

pub fn makeRpm6BadLegacyDigestFixtureForTest(
    allocator: std.mem.Allocator,
) !pkgfile.RpmFile {
    return makeFixture(allocator, .{
        .rpm6_reserved = true,
        .bad_legacy_md5 = true,
    });
}

pub fn makeLz4AlternateDigestFixtureForTest(
    allocator: std.mem.Allocator,
) !pkgfile.RpmFile {
    return makeFixture(allocator, .{ .compressor = "lz4" });
}

fn makeMinimalMain(allocator: std.mem.Allocator) ![]u8 {
    return buildRegionHeader(allocator, .immutable, &.{
        .{ .tag = @intFromEnum(header.TagId.name), .typ = .string, .count = 1, .data = "pkg\x00" },
        .{ .tag = @intFromEnum(header.TagId.version), .typ = .string, .count = 1, .data = "1\x00" },
        .{ .tag = @intFromEnum(header.TagId.release), .typ = .string, .count = 1, .data = "1\x00" },
        .{ .tag = @intFromEnum(header.TagId.arch), .typ = .string, .count = 1, .data = "noarch\x00" },
        .{ .tag = @intFromEnum(header.TagId.payload_compressor), .typ = .string, .count = 1, .data = "none\x00" },
    });
}

fn assembleSignatureFixture(
    allocator: std.mem.Allocator,
    main: []const u8,
    sig_entries: []const TestEntry,
    payload: []const u8,
) !pkgfile.RpmFile {
    const sig = try buildRegionHeader(allocator, .signatures, sig_entries);
    defer allocator.free(sig);
    const padding = (8 - (sig.len % 8)) % 8;
    const main_offset = 96 + sig.len + padding;
    const bytes = try allocator.alloc(u8, main_offset + main.len + payload.len);
    @memset(bytes, 0);
    @memcpy(bytes[0..4], &[_]u8{ 0xed, 0xab, 0xee, 0xdb });
    @memcpy(bytes[96 .. 96 + sig.len], sig);
    @memcpy(bytes[main_offset .. main_offset + main.len], main);
    @memcpy(bytes[main_offset + main.len ..], payload);
    return pkgfile.RpmFile.parseBytes(bytes);
}

fn encodeSignatureArray(
    allocator: std.mem.Allocator,
    packets: []const []const u8,
) ![]u8 {
    var total: usize = 0;
    for (packets) |packet_bytes| {
        total = try std.math.add(
            usize,
            total,
            std.base64.standard.Encoder.calcSize(packet_bytes.len) + 1,
        );
    }
    const encoded = try allocator.alloc(u8, total);
    var offset: usize = 0;
    for (packets) |packet_bytes| {
        const len = std.base64.standard.Encoder.calcSize(packet_bytes.len);
        _ = std.base64.standard.Encoder.encode(
            encoded[offset .. offset + len],
            packet_bytes,
        );
        offset += len;
        encoded[offset] = 0;
        offset += 1;
    }
    return encoded;
}

const GeneratedV6Signature = struct {
    key_packet: [44]u8,
    signature_packet: [148]u8,
};

fn generateV6Ed25519Signature(signed_data: []const u8) !GeneratedV6Signature {
    const Ed = std.crypto.sign.Ed25519;
    var seed: [Ed.KeyPair.seed_length]u8 = undefined;
    for (&seed, 0..) |*byte, index| byte.* = @intCast(index + 1);
    const key_pair = try Ed.KeyPair.generateDeterministic(seed);

    var key_packet: [44]u8 = @splat(0);
    key_packet[0] = 0xc6;
    key_packet[1] = 42;
    const key_body = key_packet[2..];
    key_body[0] = 6;
    key_body[5] = 27;
    key_body[9] = 32;
    @memcpy(key_body[10..42], &key_pair.public_key.toBytes());
    const fingerprint = pgp_pubkey.fingerprintV6(key_body);

    var signature_packet: [148]u8 = @splat(0);
    signature_packet[0] = 0xc2;
    signature_packet[1] = 146;
    const body = signature_packet[2..];
    body[0] = 6;
    body[2] = 27;
    body[3] = 10;
    body[7] = 35;
    body[8] = 34;
    body[9] = 33;
    body[10] = 6;
    @memcpy(body[11..43], fingerprint.slice());
    body[49] = 32;
    for (body[50..82], 0..) |*byte, index| byte.* = @intCast(0xa0 + index);

    const hashed_prefix = body[0..43];
    const trailer = [_]u8{ 6, 0xff, 0, 0, 0, hashed_prefix.len };
    var hasher = std.crypto.hash.sha2.Sha512.init(.{});
    hasher.update(body[50..82]);
    hasher.update(signed_data);
    hasher.update(hashed_prefix);
    hasher.update(&trailer);
    var digest: [64]u8 = undefined;
    hasher.final(&digest);
    body[47] = digest[0];
    body[48] = digest[1];
    const sig = try key_pair.sign(&digest, null);
    @memcpy(body[82..146], &sig.toBytes());
    return .{
        .key_packet = key_packet,
        .signature_packet = signature_packet,
    };
}

fn findSignatureCandidate(
    report: SignatureReport,
    kind: SignatureKind,
    array_index: ?usize,
) SignatureCandidate {
    for (report.candidates) |candidate| {
        if (candidate.kind == kind and candidate.array_index == array_index)
            return candidate;
    }
    unreachable;
}

fn findCandidate(report: Report, kind: CandidateKind) Candidate {
    for (report.candidates) |candidate| {
        if (candidate.kind == kind) return candidate;
    }
    unreachable;
}

fn candidateIndex(report: Report, kind: CandidateKind) usize {
    for (report.candidates, 0..) |candidate, index| {
        if (candidate.kind == kind) return index;
    }
    unreachable;
}

fn tagEntryOffset(rpm: *const pkgfile.RpmFile, source: header.Header, tag: u32) usize {
    var index: u32 = 0;
    while (index < source.index_count) : (index += 1) {
        if (source.entry(index).tag == tag) {
            return @intFromPtr(source.bytes.ptr) - @intFromPtr(rpm.bytes.ptr) +
                source.index_off + @as(usize, index) * 16;
        }
    }
    unreachable;
}

fn tagDataOffset(rpm: *const pkgfile.RpmFile, source: header.Header, tag: u32) usize {
    const entry = source.findRaw(tag) orelse unreachable;
    return @intFromPtr(source.bytes.ptr) - @intFromPtr(rpm.bytes.ptr) +
        source.data_off + entry.offset;
}

fn setU32(bytes: []u8, offset: usize, value: u32) void {
    bytes[offset] = @truncate(value >> 24);
    bytes[offset + 1] = @truncate(value >> 16);
    bytes[offset + 2] = @truncate(value >> 8);
    bytes[offset + 3] = @truncate(value);
}

test "package digest verification covers every digest range" {
    var rpm = try makeFixture(std.testing.allocator, .{});
    defer rpm.close(std.testing.allocator);
    var report = try verifyPackage(std.testing.allocator, &rpm, .{});
    defer report.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 10), report.candidates.len);
    for (report.candidates) |candidate|
        try std.testing.expectEqual(Outcome.verified, candidate.outcome);
    try std.testing.expect(report.coverage.header_verified);
    try std.testing.expect(report.coverage.payload_verified);
    try std.testing.expect(!report.coverage.no_digest_candidates);
    try std.testing.expect(!report.coverage.any_enabled_present_bad_or_malformed);
}

test "digest verifier reports absent candidates and policy disablement" {
    var rpm = try makeFixture(std.testing.allocator, .{ .include_all = false });
    defer rpm.close(std.testing.allocator);
    var report = try verifyPackage(std.testing.allocator, &rpm, .{});
    defer report.deinit(std.testing.allocator);
    for (report.candidates) |candidate|
        try std.testing.expectEqual(Outcome.absent, candidate.outcome);
    try std.testing.expect(report.coverage.no_digest_candidates);
    try std.testing.expect(!report.coverage.header_verified);
    try std.testing.expect(!report.coverage.payload_verified);

    var present = try makeFixture(std.testing.allocator, .{});
    defer present.close(std.testing.allocator);
    var disabled = try verifyPackage(std.testing.allocator, &present, .{ .sha256_payload = false });
    defer disabled.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.disabled_by_policy, findCandidate(disabled, .payload_sha256).outcome);
    try std.testing.expectEqual(Outcome.disabled_by_policy, findCandidate(disabled, .payload_sha256_alt).outcome);
}

test "header raw payload and expected digest mutations stay independent" {
    var header_mutated = try makeFixture(std.testing.allocator, .{});
    defer header_mutated.close(std.testing.allocator);
    const name_offset = tagDataOffset(&header_mutated, header_mutated.main, @intFromEnum(header.TagId.name));
    header_mutated.bytes[name_offset] = 'q';
    var header_report = try verifyPackage(std.testing.allocator, &header_mutated, .{});
    defer header_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.bad_digest, findCandidate(header_report, .legacy_md5).outcome);
    try std.testing.expectEqual(Outcome.bad_digest, findCandidate(header_report, .header_sha1).outcome);
    try std.testing.expectEqual(Outcome.bad_digest, findCandidate(header_report, .header_sha256).outcome);
    try std.testing.expectEqual(Outcome.bad_digest, findCandidate(header_report, .header_sha3_256).outcome);
    try std.testing.expectEqual(Outcome.verified, findCandidate(header_report, .payload_sha256).outcome);

    var payload_mutated = try makeFixture(std.testing.allocator, .{});
    defer payload_mutated.close(std.testing.allocator);
    payload_mutated.bytes[payload_mutated.payload_offset] ^= 1;
    var payload_report = try verifyPackage(std.testing.allocator, &payload_mutated, .{});
    defer payload_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.verified, findCandidate(payload_report, .header_sha256).outcome);
    try std.testing.expectEqual(Outcome.bad_digest, findCandidate(payload_report, .legacy_md5).outcome);
    try std.testing.expectEqual(Outcome.bad_digest, findCandidate(payload_report, .payload_sha256).outcome);

    var expected_mutated = try makeFixture(std.testing.allocator, .{});
    defer expected_mutated.close(std.testing.allocator);
    const expected_offset = tagDataOffset(&expected_mutated, expected_mutated.sig, @intFromEnum(header.SigTagId.sha256));
    expected_mutated.bytes[expected_offset] = if (expected_mutated.bytes[expected_offset] == '0') '1' else '0';
    var expected_report = try verifyPackage(std.testing.allocator, &expected_mutated, .{});
    defer expected_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.bad_digest, findCandidate(expected_report, .header_sha256).outcome);
    try std.testing.expectEqual(Outcome.verified, findCandidate(expected_report, .header_sha1).outcome);
    try std.testing.expect(expected_report.coverage.any_enabled_present_bad_or_malformed);
}

test "digest tag type count length hex and algorithm malformations are typed" {
    var type_mutated = try makeFixture(std.testing.allocator, .{});
    defer type_mutated.close(std.testing.allocator);
    const sha1_entry = tagEntryOffset(&type_mutated, type_mutated.sig, @intFromEnum(header.SigTagId.sha1));
    setU32(type_mutated.bytes, sha1_entry + 4, @intFromEnum(header.TypeId.bin));
    var type_report = try verifyPackage(std.testing.allocator, &type_mutated, .{});
    defer type_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.malformed_tag, findCandidate(type_report, .header_sha1).outcome);

    var count_mutated = try makeFixture(std.testing.allocator, .{});
    defer count_mutated.close(std.testing.allocator);
    const sha256_entry = tagEntryOffset(&count_mutated, count_mutated.sig, @intFromEnum(header.SigTagId.sha256));
    setU32(count_mutated.bytes, sha256_entry + 12, 2);
    var count_report = try verifyPackage(std.testing.allocator, &count_mutated, .{});
    defer count_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.malformed_tag, findCandidate(count_report, .header_sha256).outcome);

    var length_mutated = try makeFixture(std.testing.allocator, .{});
    defer length_mutated.close(std.testing.allocator);
    const sha3_offset = tagDataOffset(&length_mutated, length_mutated.sig, @intFromEnum(header.SigTagId.sha3_256));
    length_mutated.bytes[sha3_offset + 4] = 0;
    var length_report = try verifyPackage(std.testing.allocator, &length_mutated, .{});
    defer length_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.malformed_tag, findCandidate(length_report, .header_sha3_256).outcome);

    var hex_mutated = try makeFixture(std.testing.allocator, .{});
    defer hex_mutated.close(std.testing.allocator);
    const sha512_offset = tagDataOffset(&hex_mutated, hex_mutated.main, @intFromEnum(header.TagId.payloadsha512));
    hex_mutated.bytes[sha512_offset] = 'g';
    var hex_report = try verifyPackage(std.testing.allocator, &hex_mutated, .{});
    defer hex_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.malformed_tag, findCandidate(hex_report, .payload_sha512).outcome);

    var algorithm_mutated = try makeFixture(std.testing.allocator, .{});
    defer algorithm_mutated.close(std.testing.allocator);
    const algo_offset = tagDataOffset(&algorithm_mutated, algorithm_mutated.main, @intFromEnum(header.TagId.payloadsha256algo));
    setU32(algorithm_mutated.bytes, algo_offset, 7);
    var algorithm_report = try verifyPackage(std.testing.allocator, &algorithm_mutated, .{});
    defer algorithm_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.malformed_tag, findCandidate(algorithm_report, .payload_sha256).outcome);
    try std.testing.expectEqual(Outcome.verified, findCandidate(algorithm_report, .payload_sha256_alt).outcome);
}

test "alternate payload digest failures retain raw results and alternative grouping" {
    const gzip_payload =
        "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03\xcb\x2d\x2d\x49\x2c\x49\x4d\xd1" ++
        "\x4d\x49\x4d\xce\xcf\x2d\x28\x4a\x2d\x2e\x06\x72\x0a\x12\x2b\x73\xf2\x13" ++
        "\x53\x00\xce\xf5\xe8\x95\x1c\x00\x00\x00";
    var decompressed_mutated = try makeFixture(std.testing.allocator, .{
        .compressor = "gzip",
        .payload = gzip_payload,
        .alternate_payload = "decompressed-payload",
    });
    defer decompressed_mutated.close(std.testing.allocator);
    var report = try verifyPackage(std.testing.allocator, &decompressed_mutated, .{});
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.verified, findCandidate(report, .payload_sha256).outcome);
    try std.testing.expectEqual(Outcome.bad_digest, findCandidate(report, .payload_sha256_alt).outcome);
    try std.testing.expect(report.failureSuppressedByAlternative(candidateIndex(report, .payload_sha256_alt)));

    var unsupported = try makeFixture(std.testing.allocator, .{ .compressor = "lz4" });
    defer unsupported.close(std.testing.allocator);
    var unsupported_report = try verifyPackage(std.testing.allocator, &unsupported, .{});
    defer unsupported_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.verified, findCandidate(unsupported_report, .payload_sha256).outcome);
    try std.testing.expectEqual(Outcome.unsupported_digest, findCandidate(unsupported_report, .payload_sha256_alt).outcome);

    var malformed = try makeFixture(std.testing.allocator, .{
        .compressor = "gzip",
        .payload = "not a gzip stream",
    });
    defer malformed.close(std.testing.allocator);
    var malformed_report = try verifyPackage(std.testing.allocator, &malformed, .{});
    defer malformed_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.verified, findCandidate(malformed_report, .payload_sha256).outcome);
    try std.testing.expectEqual(Outcome.malformed_tag, findCandidate(malformed_report, .payload_sha256_alt).outcome);
    try std.testing.expect(malformed_report.failureSuppressedByAlternative(
        candidateIndex(malformed_report, .payload_sha256_alt),
    ));
}

test "digest algorithm vectors are standard" {
    try std.testing.expectEqualStrings(
        "900150983cd24fb0d6963f7d28e17f72",
        &digestHex(std.crypto.hash.Md5, "abc"),
    );
    try std.testing.expectEqualStrings(
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        &digestHex(std.crypto.hash.Sha1, "abc"),
    );
    try std.testing.expectEqualStrings(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        &digestHex(std.crypto.hash.sha2.Sha256, "abc"),
    );
    try std.testing.expectEqualStrings(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" ++
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        &digestHex(std.crypto.hash.sha2.Sha512, "abc"),
    );
    try std.testing.expectEqualStrings(
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        &digestHex(std.crypto.hash.sha3.Sha3_256, "abc"),
    );
}

test "legacy signature candidates preserve standalone header ranges" {
    const signature_packet = @embedFile("pgp/testdata/rsa2048-sig.bin");
    const main = try makeMinimalMain(std.testing.allocator);
    defer std.testing.allocator.free(main);
    var rpm = try assembleSignatureFixture(std.testing.allocator, main, &.{
        .{ .tag = @intFromEnum(header.SigTagId.pgp), .typ = .bin, .count = signature_packet.len, .data = signature_packet },
        .{ .tag = @intFromEnum(header.SigTagId.gpg), .typ = .bin, .count = signature_packet.len, .data = signature_packet },
        .{ .tag = @intFromEnum(header.SigTagId.rsa), .typ = .bin, .count = signature_packet.len, .data = signature_packet },
        .{ .tag = @intFromEnum(header.SigTagId.dsa), .typ = .bin, .count = signature_packet.len, .data = signature_packet },
    }, "payload");
    defer rpm.close(std.testing.allocator);

    var report = try verifySignatures(std.testing.allocator, &rpm, .{}, &.{});
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        Range.header_payload,
        findSignatureCandidate(report, .legacy_pgp, null).range,
    );
    try std.testing.expectEqual(
        Range.header_payload,
        findSignatureCandidate(report, .legacy_gpg, null).range,
    );
    try std.testing.expectEqual(
        Range.header,
        findSignatureCandidate(report, .header_rsa, null).range,
    );
    try std.testing.expectEqual(
        Range.header,
        findSignatureCandidate(report, .header_dsa, null).range,
    );
    try std.testing.expectEqual(
        rpm.main_header_offset,
        findSignatureCandidate(report, .legacy_pgp, null).signed_start,
    );
    try std.testing.expectEqual(
        rpm.bytes.len,
        findSignatureCandidate(report, .legacy_pgp, null).signed_end,
    );
    try std.testing.expectEqual(
        rpm.payload_offset,
        findSignatureCandidate(report, .header_rsa, null).signed_end,
    );
    for (report.candidates) |candidate| {
        if (candidate.isPresent())
            try std.testing.expectEqual(SignatureOutcome.no_key, candidate.outcome);
    }
    try std.testing.expect(report.coverage.header_relevant);
    try std.testing.expect(report.coverage.payload_relevant);
    try std.testing.expect(!report.coverage.fully_verified);
}

test "OPENPGP base64 arrays enumerate every entry and suppress legacy" {
    const signature_packet = @embedFile("pgp/testdata/rsa2048-sig.bin");
    const packets = [_][]const u8{ signature_packet, signature_packet };
    const encoded = try encodeSignatureArray(std.testing.allocator, &packets);
    defer std.testing.allocator.free(encoded);
    const main = try makeMinimalMain(std.testing.allocator);
    defer std.testing.allocator.free(main);
    var rpm = try assembleSignatureFixture(std.testing.allocator, main, &.{
        .{
            .tag = @intFromEnum(header.SigTagId.openpgp),
            .typ = .string_array,
            .count = 2,
            .data = encoded,
        },
        .{ .tag = @intFromEnum(header.SigTagId.pgp), .typ = .bin, .count = signature_packet.len, .data = signature_packet },
    }, "");
    defer rpm.close(std.testing.allocator);

    try std.testing.expectEqual(pkgfile.RpmFile.SignatureKind.openpgp, rpm.signatureKind());
    try std.testing.expect(rpm.signatureSlice() != null);
    var report = try verifySignatures(std.testing.allocator, &rpm, .{}, &.{});
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 6), report.candidates.len);
    try std.testing.expectEqual(
        SignatureOutcome.no_key,
        findSignatureCandidate(report, .openpgp, 0).outcome,
    );
    try std.testing.expectEqual(
        SignatureOutcome.no_key,
        findSignatureCandidate(report, .openpgp, 1).outcome,
    );
    try std.testing.expectEqual(
        SignatureOutcome.suppressed_legacy,
        findSignatureCandidate(report, .legacy_pgp, null).outcome,
    );
    try std.testing.expect(report.openpgp_suppresses_legacy);

    var disabled = try verifySignatures(
        std.testing.allocator,
        &rpm,
        .{ .openpgp = false },
        &.{},
    );
    defer disabled.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        SignatureOutcome.disabled_by_policy,
        findSignatureCandidate(disabled, .openpgp, 0).outcome,
    );
    try std.testing.expectEqual(
        SignatureOutcome.unchecked,
        findSignatureCandidate(disabled, .openpgp, 0).raw_outcome,
    );
    try std.testing.expectEqual(
        SignatureOutcome.no_key,
        findSignatureCandidate(disabled, .legacy_pgp, null).outcome,
    );
    try std.testing.expect(!disabled.openpgp_suppresses_legacy);
}

test "malformed OPENPGP base64 and tag type do not suppress legacy" {
    const signature_packet = @embedFile("pgp/testdata/rsa2048-sig.bin");
    const main = try makeMinimalMain(std.testing.allocator);
    defer std.testing.allocator.free(main);
    var malformed_base64 = try assembleSignatureFixture(std.testing.allocator, main, &.{
        .{
            .tag = @intFromEnum(header.SigTagId.openpgp),
            .typ = .string_array,
            .count = 1,
            .data = "!!!\x00",
        },
        .{ .tag = @intFromEnum(header.SigTagId.pgp), .typ = .bin, .count = signature_packet.len, .data = signature_packet },
    }, "");
    defer malformed_base64.close(std.testing.allocator);
    var base64_report = try verifySignatures(
        std.testing.allocator,
        &malformed_base64,
        .{},
        &.{},
    );
    defer base64_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        SignatureOutcome.malformed_base64,
        findSignatureCandidate(base64_report, .openpgp, 0).outcome,
    );
    try std.testing.expectEqual(
        SignatureOutcome.no_key,
        findSignatureCandidate(base64_report, .legacy_pgp, null).outcome,
    );
    try std.testing.expect(!base64_report.openpgp_suppresses_legacy);

    const malformed_packet = [_]u8{ 0xc2, 0x01, 0x06 };
    const malformed_packets = [_][]const u8{&malformed_packet};
    const malformed_encoded = try encodeSignatureArray(
        std.testing.allocator,
        &malformed_packets,
    );
    defer std.testing.allocator.free(malformed_encoded);
    var malformed_openpgp = try assembleSignatureFixture(std.testing.allocator, main, &.{
        .{
            .tag = @intFromEnum(header.SigTagId.openpgp),
            .typ = .string_array,
            .count = 1,
            .data = malformed_encoded,
        },
    }, "");
    defer malformed_openpgp.close(std.testing.allocator);
    var openpgp_report = try verifySignatures(
        std.testing.allocator,
        &malformed_openpgp,
        .{},
        &.{},
    );
    defer openpgp_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        SignatureOutcome.malformed_openpgp,
        findSignatureCandidate(openpgp_report, .openpgp, 0).outcome,
    );
    try std.testing.expect(!openpgp_report.openpgp_suppresses_legacy);

    const packets = [_][]const u8{signature_packet};
    const encoded = try encodeSignatureArray(std.testing.allocator, &packets);
    defer std.testing.allocator.free(encoded);
    var wrong_type = try assembleSignatureFixture(std.testing.allocator, main, &.{
        .{
            .tag = @intFromEnum(header.SigTagId.openpgp),
            .typ = .bin,
            .count = @intCast(encoded.len),
            .data = encoded,
        },
    }, "");
    defer wrong_type.close(std.testing.allocator);
    var type_report = try verifySignatures(std.testing.allocator, &wrong_type, .{}, &.{});
    defer type_report.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        SignatureOutcome.malformed_tag,
        findSignatureCandidate(type_report, .openpgp, null).outcome,
    );
    try std.testing.expect(!type_report.openpgp_suppresses_legacy);
}

test "RPM6 RESERVED and SHA3 suppress tags at legacy signature base" {
    const signature_packet = @embedFile("pgp/testdata/rsa2048-sig.bin");
    const main = try makeMinimalMain(std.testing.allocator);
    defer std.testing.allocator.free(main);
    const md5: [16]u8 = @splat(0);
    var rpm = try assembleSignatureFixture(std.testing.allocator, main, &.{
        .{ .tag = @intFromEnum(header.SigTagId.rsa), .typ = .bin, .count = signature_packet.len, .data = signature_packet },
        .{ .tag = @intFromEnum(header.SigTagId.sha3_256), .typ = .string, .count = 1, .data = "0000000000000000000000000000000000000000000000000000000000000000\x00" },
        .{ .tag = @intFromEnum(header.SigTagId.reserved), .typ = .bin, .count = 1, .data = "\x00" },
        .{ .tag = @intFromEnum(header.SigTagId.pgp), .typ = .bin, .count = signature_packet.len, .data = signature_packet },
        .{ .tag = @intFromEnum(header.SigTagId.md5), .typ = .bin, .count = md5.len, .data = &md5 },
        .{ .tag = @intFromEnum(header.SigTagId.gpg), .typ = .bin, .count = signature_packet.len, .data = signature_packet },
    }, "payload");
    defer rpm.close(std.testing.allocator);

    var report = try verifyIntegrity(std.testing.allocator, &rpm, .{}, .{}, &.{});
    defer report.deinit(std.testing.allocator);
    try std.testing.expect(report.signatures.rpm6_suppresses_legacy_signature_header);
    try std.testing.expect(report.signatures.legacy_md5_suppressed);
    try std.testing.expectEqual(
        SignatureOutcome.no_key,
        findSignatureCandidate(report.signatures, .header_rsa, null).outcome,
    );
    try std.testing.expectEqual(
        SignatureOutcome.suppressed_legacy,
        findSignatureCandidate(report.signatures, .legacy_pgp, null).outcome,
    );
    try std.testing.expectEqual(
        SignatureOutcome.suppressed_legacy,
        findSignatureCandidate(report.signatures, .legacy_gpg, null).outcome,
    );
    try std.testing.expect(findCandidate(report.digests, .legacy_md5).suppressed_legacy);
}

test "mixed RPM6 signatures retain no-key bad and verified outcomes" {
    const main = try makeMinimalMain(std.testing.allocator);
    defer std.testing.allocator.free(main);
    const generated = try generateV6Ed25519Signature(main);
    var bad_packet = generated.signature_packet;
    bad_packet[bad_packet.len - 1] ^= 1;
    var unsupported_packet = generated.signature_packet;
    unsupported_packet[2 + 2] = 99;
    const packets = [_][]const u8{
        &generated.signature_packet,
        &bad_packet,
        &unsupported_packet,
    };
    const encoded = try encodeSignatureArray(std.testing.allocator, &packets);
    defer std.testing.allocator.free(encoded);
    var rpm = try assembleSignatureFixture(std.testing.allocator, main, &.{
        .{
            .tag = @intFromEnum(header.SigTagId.openpgp),
            .typ = .string_array,
            .count = 3,
            .data = encoded,
        },
    }, "");
    defer rpm.close(std.testing.allocator);

    const keys = [_][]const u8{&generated.key_packet};
    var report = try verifySignatures(std.testing.allocator, &rpm, .{}, &keys);
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        SignatureOutcome.verified,
        findSignatureCandidate(report, .openpgp, 0).outcome,
    );
    try std.testing.expectEqual(
        SignatureOutcome.bad_signature,
        findSignatureCandidate(report, .openpgp, 1).outcome,
    );
    try std.testing.expectEqual(
        SignatureOutcome.unsupported_openpgp,
        findSignatureCandidate(report, .openpgp, 2).outcome,
    );
    try std.testing.expect(report.coverage.header_verified);
    try std.testing.expect(report.coverage.fully_verified);
    try std.testing.expect(report.coverage.any_enabled_unsuppressed_failure);

    var no_keys = try verifySignatures(std.testing.allocator, &rpm, .{}, &.{});
    defer no_keys.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        SignatureOutcome.no_key,
        findSignatureCandidate(no_keys, .openpgp, 0).outcome,
    );
    try std.testing.expectEqual(
        SignatureOutcome.no_key,
        findSignatureCandidate(no_keys, .openpgp, 1).outcome,
    );
    try std.testing.expectEqual(
        SignatureOutcome.unsupported_openpgp,
        findSignatureCandidate(no_keys, .openpgp, 2).outcome,
    );
}

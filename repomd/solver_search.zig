//! Deterministic SAT search for native package-solver formulas.
//!
//! This module is deliberately policy-neutral. Every input clause is hard,
//! weak metadata is ignored, and the result exposes only SAT or UNSAT.

const std = @import("std");
const metadata = @import("model.zig");
const solver_model = @import("solver_model.zig");
const solver_rules = @import("solver_rules.zig");

const Literal = solver_rules.Literal;
const OwnedFormula = solver_rules.OwnedFormula;

pub const SolveError = error{
    OutOfMemory,
    InvalidFormula,
    InvalidAssumption,
    InvalidDecisionPolicy,
    FormulaTooLarge,
    InternalSolverFailure,
};

pub const CandidateSolveError = SolveError || error{
    InvalidCandidatePolicy,
};

pub const DecisionPolicy = struct {
    /// Complete variable permutation in decision order.
    order: []const solver_model.PackageId = &.{},
    /// Preferred value per `PackageId`; defaults to false.
    preferred_values: []const bool = &.{},
};

pub const CandidateGroup = struct {
    clause_index: u32,
    candidates: solver_rules.PackageIdRange,
};

pub const CandidateDecisionPolicy = struct {
    fallback: DecisionPolicy = .{},
    groups: []const CandidateGroup = &.{},
    candidates: []const solver_model.PackageId = &.{},
};

const IncrementalState = enum {
    ready,
    preferred_completion,
    unsatisfiable,
    finished,
};

/// Persistent deterministic search used for optional package decisions.
///
/// `solveHard` stops once every hard clause is satisfied by the current
/// assignments plus the fallback policy's preferred values. Callers may then
/// try additional positive package decisions without rebuilding the solver.
pub const IncrementalSolver = struct {
    engine: Engine,
    state: IncrementalState = .ready,

    pub fn init(
        allocator: std.mem.Allocator,
        formula: *const OwnedFormula,
        assumptions: []const Literal,
        candidate_policy: CandidateDecisionPolicy,
    ) CandidateSolveError!IncrementalSolver {
        return .{
            .engine = try initializeEngine(
                allocator,
                formula,
                assumptions,
                candidate_policy,
                true,
            ),
        };
    }

    pub fn deinit(self: *IncrementalSolver) void {
        self.engine.deinit();
        self.* = undefined;
    }

    pub fn solveHard(self: *IncrementalSolver) SolveError!bool {
        if (self.state != .ready) return error.InternalSolverFailure;
        if (!try self.engine.run(.preferred_completion)) {
            self.state = .unsatisfiable;
            return false;
        }
        self.state = .preferred_completion;
        return true;
    }

    /// Return the current preferred completion value after `solveHard`.
    pub fn selected(
        self: *const IncrementalSolver,
        package_id: solver_model.PackageId,
    ) ?bool {
        if (self.state != .preferred_completion) return null;
        const variable: usize = @intFromEnum(package_id);
        if (variable >= self.engine.variable_count) return null;
        return switch (self.engine.assignments[variable]) {
            .true_value => true,
            .false_value => false,
            .unassigned => self.engine.preferred_values[variable],
        };
    }

    /// Try selecting one optional package on the live hard-solver trail.
    ///
    /// A rejected decision is a normal result; learned clauses and any
    /// necessary backtracking remain in the session.
    pub fn trySelect(
        self: *IncrementalSolver,
        package_id: solver_model.PackageId,
    ) SolveError!bool {
        if (self.state != .preferred_completion) {
            return error.InternalSolverFailure;
        }
        const variable: usize = @intFromEnum(package_id);
        if (variable >= self.engine.variable_count) {
            return error.InvalidAssumption;
        }
        switch (self.engine.assignments[variable]) {
            .true_value => {
                try self.engine.protectLiteral(
                    Literal.init(package_id, true),
                );
                return true;
            },
            .false_value => return false,
            .unassigned => {},
        }

        try self.engine.trail_limits.append(self.engine.trail.items.len);
        self.engine.statistics.decisions += 1;
        if (!try self.engine.enqueue(Literal.init(package_id, true), null)) {
            return false;
        }
        if (!try self.engine.run(.preferred_completion)) {
            return error.InternalSolverFailure;
        }
        const selected_value = self.selected(package_id) orelse
            return error.InternalSolverFailure;
        if (selected_value) {
            try self.engine.protectLiteral(Literal.init(package_id, true));
        }
        return selected_value;
    }

    /// Materialize the remaining preferred values into a complete model.
    pub fn finish(self: *IncrementalSolver) SolveError!Result {
        switch (self.state) {
            .ready => {
                if (!try self.engine.run(.complete)) {
                    self.state = .finished;
                    return .{ .unsatisfiable = {} };
                }
            },
            .preferred_completion => {
                if (!try self.engine.run(.complete)) {
                    return error.InternalSolverFailure;
                }
            },
            .unsatisfiable => {
                self.state = .finished;
                return .{ .unsatisfiable = {} };
            },
            .finished => return error.InternalSolverFailure,
        }
        if (!self.engine.validateModel()) {
            return error.InternalSolverFailure;
        }
        self.state = .finished;
        return .{ .satisfiable = try self.engine.makeModel() };
    }
};

/// A complete package assignment indexed by stable `PackageId`.
pub const Model = struct {
    allocator: std.mem.Allocator,
    values: []const bool,

    pub fn value(
        self: Model,
        package_id: solver_model.PackageId,
    ) ?bool {
        const package_index: usize = @intFromEnum(package_id);
        if (package_index >= self.values.len) return null;
        return self.values[package_index];
    }

    pub fn deinit(self: *Model) void {
        self.allocator.free(self.values);
        self.* = undefined;
    }
};

pub const Result = union(enum) {
    satisfiable: Model,
    unsatisfiable: void,

    pub fn deinit(self: *Result) void {
        switch (self.*) {
            .satisfiable => |model| {
                var owned_model = model;
                owned_model.deinit();
            },
            .unsatisfiable => {},
        }
        self.* = undefined;
    }
};

/// Solve every clause in `formula` as hard constraints.
pub fn solve(
    allocator: std.mem.Allocator,
    formula: *const OwnedFormula,
) SolveError!Result {
    return solveWithoutCandidates(allocator, formula, &.{}, .{});
}

/// Solve every formula clause plus the supplied level-zero assumptions.
pub fn solveAssuming(
    allocator: std.mem.Allocator,
    formula: *const OwnedFormula,
    assumptions: []const Literal,
) SolveError!Result {
    return solveWithoutCandidates(allocator, formula, assumptions, .{});
}

/// Solve with a complete deterministic variable order and polarity policy.
pub fn solveWithDecisionPolicy(
    allocator: std.mem.Allocator,
    formula: *const OwnedFormula,
    assumptions: []const Literal,
    decision_policy: DecisionPolicy,
) SolveError!Result {
    return solveWithoutCandidates(
        allocator,
        formula,
        assumptions,
        decision_policy,
    );
}

/// Solve with contextual best-first positive candidate groups.
pub fn solveWithCandidatePolicy(
    allocator: std.mem.Allocator,
    formula: *const OwnedFormula,
    assumptions: []const Literal,
    candidate_policy: CandidateDecisionPolicy,
) CandidateSolveError!Result {
    return solveInternal(
        allocator,
        formula,
        assumptions,
        candidate_policy,
        null,
    );
}

const Value = enum(u2) {
    unassigned,
    false_value,
    true_value,
};

const ClauseData = struct {
    start: usize,
    len: usize,
    watch_a: usize = 0,
    watch_b: usize = 0,
    scan_cursor: usize = 0,
};

const Statistics = struct {
    decisions: u64 = 0,
    propagations: u64 = 0,
    conflicts: u64 = 0,
    learned_clauses: u64 = 0,
    backjumps: u64 = 0,
    decision_probes: u64 = 0,
    watch_inspections: u64 = 0,
    candidate_probes: u64 = 0,
};

const Analysis = struct {
    literals: []const Literal,
    backtrack_level: u32,
};

const Decision = struct {
    variable: usize,
    positive: bool,
};

const RunMode = enum {
    preferred_completion,
    complete,
};

const CandidateOccurrence = struct {
    group: usize,
    candidate: bool,
    rank: usize = 0,
};

const CandidateGroupData = struct {
    clause: usize,
    candidates_start: usize,
    candidates_len: usize,
    control_count: usize,
    false_controls: usize = 0,
    true_candidates: usize = 0,
    unassigned_candidates: usize,
    candidate_cursor: usize = 0,
};

const ClauseList = std.array_list.Managed(ClauseData);
const LiteralList = std.array_list.Managed(Literal);
const IndexList = std.array_list.Managed(usize);
const OccurrenceList = std.array_list.Managed(CandidateOccurrence);

const Engine = struct {
    allocator: std.mem.Allocator,
    variable_count: usize,
    track_preferred_completion: bool,
    clauses: ClauseList,
    literals: LiteralList,
    watches: []IndexList,
    literal_occurrences: []IndexList,
    clause_true_counts: IndexList,
    clause_preferred_counts: IndexList,
    preferred_satisfied_clauses: usize = 0,
    assignments: []Value,
    levels: []u32,
    reasons: []?usize,
    seen: []bool,
    decision_order: []usize,
    decision_positions: []usize,
    preferred_values: []bool,
    candidate_groups: ?[]CandidateGroupData = null,
    candidate_packages: ?[]solver_model.PackageId = null,
    candidate_occurrences: ?[]OccurrenceList = null,
    candidate_heap_positions: ?[]?usize = null,
    candidate_heap: IndexList,
    trail: LiteralList,
    trail_limits: IndexList,
    propagation_head: usize = 0,
    decision_cursor: usize = 0,
    normalize_scratch: LiteralList,
    analysis_scratch: LiteralList,
    has_empty_clause: bool = false,
    root_initialized: bool = false,
    statistics: Statistics = .{},

    fn init(
        allocator: std.mem.Allocator,
        variable_count: usize,
        decision_policy: DecisionPolicy,
        track_preferred_completion: bool,
    ) SolveError!Engine {
        if (variable_count > std.math.maxInt(u32) or
            variable_count > std.math.maxInt(usize) / 2)
        {
            return error.FormulaTooLarge;
        }

        const assignments = try allocator.alloc(Value, variable_count);
        errdefer allocator.free(assignments);
        @memset(assignments, .unassigned);

        const levels = try allocator.alloc(u32, variable_count);
        errdefer allocator.free(levels);
        @memset(levels, 0);

        const reasons = try allocator.alloc(?usize, variable_count);
        errdefer allocator.free(reasons);
        @memset(reasons, null);

        const seen = try allocator.alloc(bool, variable_count);
        errdefer allocator.free(seen);
        @memset(seen, false);

        if (decision_policy.order.len != 0 and
            decision_policy.order.len != variable_count)
        {
            return error.InvalidDecisionPolicy;
        }
        if (decision_policy.preferred_values.len != 0 and
            decision_policy.preferred_values.len != variable_count)
        {
            return error.InvalidDecisionPolicy;
        }

        const decision_order = try allocator.alloc(usize, variable_count);
        errdefer allocator.free(decision_order);
        const decision_positions = try allocator.alloc(usize, variable_count);
        errdefer allocator.free(decision_positions);
        const preferred_values = try allocator.alloc(bool, variable_count);
        errdefer allocator.free(preferred_values);

        if (decision_policy.order.len == 0) {
            for (decision_order, decision_positions, 0..) |
                *package,
                *position,
                index,
            | {
                package.* = index;
                position.* = index;
            }
        } else {
            for (decision_policy.order, 0..) |package_id, position| {
                const package_index: usize = @intFromEnum(package_id);
                if (package_index >= variable_count or seen[package_index]) {
                    return error.InvalidDecisionPolicy;
                }
                seen[package_index] = true;
                decision_order[position] = package_index;
                decision_positions[package_index] = position;
            }
            @memset(seen, false);
        }
        if (decision_policy.preferred_values.len == 0) {
            @memset(preferred_values, false);
        } else {
            @memcpy(preferred_values, decision_policy.preferred_values);
        }

        const watches = try allocator.alloc(IndexList, variable_count * 2);
        errdefer allocator.free(watches);
        for (watches) |*watch| {
            watch.* = IndexList.init(allocator);
        }
        const literal_occurrences = try allocator.alloc(
            IndexList,
            if (track_preferred_completion) variable_count * 2 else 0,
        );
        errdefer allocator.free(literal_occurrences);
        for (literal_occurrences) |*occurrences| {
            occurrences.* = IndexList.init(allocator);
        }

        return .{
            .allocator = allocator,
            .variable_count = variable_count,
            .track_preferred_completion = track_preferred_completion,
            .clauses = ClauseList.init(allocator),
            .literals = LiteralList.init(allocator),
            .watches = watches,
            .literal_occurrences = literal_occurrences,
            .clause_true_counts = IndexList.init(allocator),
            .clause_preferred_counts = IndexList.init(allocator),
            .assignments = assignments,
            .levels = levels,
            .reasons = reasons,
            .seen = seen,
            .decision_order = decision_order,
            .decision_positions = decision_positions,
            .preferred_values = preferred_values,
            .candidate_heap = IndexList.init(allocator),
            .trail = LiteralList.init(allocator),
            .trail_limits = IndexList.init(allocator),
            .normalize_scratch = LiteralList.init(allocator),
            .analysis_scratch = LiteralList.init(allocator),
        };
    }

    fn deinit(self: *Engine) void {
        self.candidate_heap.deinit();
        if (self.candidate_heap_positions) |positions| {
            self.allocator.free(positions);
        }
        if (self.candidate_occurrences) |occurrences| {
            for (occurrences) |*list| list.deinit();
            self.allocator.free(occurrences);
        }
        if (self.candidate_packages) |packages| {
            self.allocator.free(packages);
        }
        if (self.candidate_groups) |groups| {
            self.allocator.free(groups);
        }
        self.analysis_scratch.deinit();
        self.normalize_scratch.deinit();
        self.trail_limits.deinit();
        self.trail.deinit();
        self.allocator.free(self.seen);
        self.allocator.free(self.preferred_values);
        self.allocator.free(self.decision_positions);
        self.allocator.free(self.decision_order);
        self.allocator.free(self.reasons);
        self.allocator.free(self.levels);
        self.allocator.free(self.assignments);
        self.clause_preferred_counts.deinit();
        self.clause_true_counts.deinit();
        for (self.literal_occurrences) |*occurrences| {
            occurrences.deinit();
        }
        self.allocator.free(self.literal_occurrences);
        for (self.watches) |*watch| {
            watch.deinit();
        }
        self.allocator.free(self.watches);
        self.literals.deinit();
        self.clauses.deinit();
        self.* = undefined;
    }

    fn addInputClause(
        self: *Engine,
        input_literals: []const Literal,
    ) SolveError!?usize {
        self.normalize_scratch.clearRetainingCapacity();
        try self.normalize_scratch.appendSlice(input_literals);
        std.sort.heap(
            Literal,
            self.normalize_scratch.items,
            {},
            literalLessThan,
        );

        var write_index: usize = 0;
        for (self.normalize_scratch.items) |literal| {
            if (!validLiteral(literal, self.variable_count)) {
                return error.InvalidFormula;
            }
            if (write_index != 0) {
                const previous = self.normalize_scratch.items[write_index - 1];
                if (literal == previous) continue;
                if (literal == previous.negated()) return null;
            }
            self.normalize_scratch.items[write_index] = literal;
            write_index += 1;
        }
        self.normalize_scratch.shrinkRetainingCapacity(write_index);
        return try self.addClause(self.normalize_scratch.items);
    }

    fn addAssumption(self: *Engine, literal: Literal) SolveError!void {
        if (!validLiteral(literal, self.variable_count)) {
            return error.InvalidAssumption;
        }
        _ = try self.addClause(&.{literal});
    }

    fn addClause(
        self: *Engine,
        input_literals: []const Literal,
    ) SolveError!usize {
        const literal_start = self.literals.items.len;
        try self.literals.appendSlice(input_literals);
        errdefer self.literals.shrinkRetainingCapacity(literal_start);

        const clause_id = self.clauses.items.len;
        try self.clauses.append(.{
            .start = literal_start,
            .len = input_literals.len,
            .watch_a = 0,
            .watch_b = if (input_literals.len > 1) 1 else 0,
            .scan_cursor = if (input_literals.len > 2) 2 else 0,
        });
        errdefer _ = self.clauses.pop();

        if (self.track_preferred_completion) {
            var true_count: usize = 0;
            var preferred_count: usize = 0;
            for (input_literals) |literal| {
                switch (self.literalValue(literal)) {
                    .true_value => true_count += 1,
                    .unassigned => {
                        const variable = literalVariable(literal);
                        if (literal.positive() ==
                            self.preferred_values[variable])
                        {
                            preferred_count += 1;
                        }
                    },
                    .false_value => {},
                }
            }
            try self.clause_true_counts.append(true_count);
            errdefer _ = self.clause_true_counts.pop();
            try self.clause_preferred_counts.append(preferred_count);
            errdefer _ = self.clause_preferred_counts.pop();
            const preferred_satisfied =
                true_count != 0 or preferred_count != 0;
            if (preferred_satisfied) self.preferred_satisfied_clauses += 1;
            errdefer if (preferred_satisfied) {
                self.preferred_satisfied_clauses -= 1;
            };

            var occurrences_added: usize = 0;
            errdefer for (input_literals[0..occurrences_added]) |literal| {
                _ = self.literal_occurrences[literalIndex(literal)].pop();
            };
            for (input_literals) |literal| {
                try self.literal_occurrences[literalIndex(literal)].append(
                    clause_id,
                );
                occurrences_added += 1;
            }
        }

        if (input_literals.len == 0) {
            self.has_empty_clause = true;
            return clause_id;
        }

        const first_watch = literalIndex(input_literals[0]);
        const first_len = self.watches[first_watch].items.len;
        try self.watches[first_watch].append(clause_id);
        errdefer self.watches[first_watch].shrinkRetainingCapacity(first_len);

        if (input_literals.len > 1) {
            const second_watch = literalIndex(input_literals[1]);
            const second_len = self.watches[second_watch].items.len;
            try self.watches[second_watch].append(clause_id);
            errdefer self.watches[second_watch].shrinkRetainingCapacity(
                second_len,
            );
        }

        return clause_id;
    }

    fn configureCandidateGroups(
        self: *Engine,
        formula: *const OwnedFormula,
        clause_mapping: []const ?usize,
        policy: CandidateDecisionPolicy,
    ) CandidateSolveError!void {
        if (policy.groups.len == 0) {
            if (policy.candidates.len != 0) {
                return error.InvalidCandidatePolicy;
            }
            return;
        }
        if (clause_mapping.len != formula.clauses.len) {
            return error.InternalSolverFailure;
        }

        const groups = try self.allocator.alloc(
            CandidateGroupData,
            policy.groups.len,
        );
        errdefer self.allocator.free(groups);
        const packages = try self.allocator.dupe(
            solver_model.PackageId,
            policy.candidates,
        );
        errdefer self.allocator.free(packages);
        const positions = try self.allocator.alloc(
            ?usize,
            policy.groups.len,
        );
        errdefer self.allocator.free(positions);
        @memset(positions, null);
        const occurrences = try self.allocator.alloc(
            OccurrenceList,
            self.variable_count,
        );
        errdefer self.allocator.free(occurrences);
        for (occurrences) |*list| list.* = OccurrenceList.init(self.allocator);
        errdefer for (occurrences) |*list| list.deinit();

        const used_clauses = try self.allocator.alloc(
            bool,
            formula.clauses.len,
        );
        defer self.allocator.free(used_clauses);
        @memset(used_clauses, false);
        const candidate_ranks = try self.allocator.alloc(
            usize,
            self.variable_count,
        );
        defer self.allocator.free(candidate_ranks);
        @memset(candidate_ranks, std.math.maxInt(usize));

        var candidate_cursor: usize = 0;
        for (policy.groups, groups, 0..) |input, *group, group_index| {
            const clause_index: usize = @intCast(input.clause_index);
            if (clause_index >= formula.clauses.len or
                used_clauses[clause_index])
            {
                return error.InvalidCandidatePolicy;
            }
            used_clauses[clause_index] = true;
            const internal_clause = clause_mapping[clause_index] orelse
                return error.InvalidCandidatePolicy;

            const start: usize = @intCast(input.candidates.start);
            const len: usize = @intCast(input.candidates.len);
            if (start != candidate_cursor or
                len == 0 or
                len > policy.candidates.len - start)
            {
                return error.InvalidCandidatePolicy;
            }
            candidate_cursor += len;

            for (policy.candidates[start .. start + len], 0..) |
                package_id,
                rank,
            | {
                const package_index: usize = @intFromEnum(package_id);
                if (package_index >= self.variable_count or
                    candidate_ranks[package_index] !=
                        std.math.maxInt(usize))
                {
                    return error.InvalidCandidatePolicy;
                }
                candidate_ranks[package_index] = rank;
            }

            var positive_count: usize = 0;
            const clause = self.clauses.items[internal_clause];
            for (self.clauseLiterals(clause)) |literal| {
                const variable = literalVariable(literal);
                if (literal.positive()) {
                    positive_count += 1;
                    if (candidate_ranks[variable] ==
                        std.math.maxInt(usize))
                    {
                        return error.InvalidCandidatePolicy;
                    }
                    try occurrences[variable].append(.{
                        .group = group_index,
                        .candidate = true,
                        .rank = candidate_ranks[variable],
                    });
                } else {
                    if (candidate_ranks[variable] !=
                        std.math.maxInt(usize))
                    {
                        return error.InvalidCandidatePolicy;
                    }
                    try occurrences[variable].append(.{
                        .group = group_index,
                        .candidate = false,
                    });
                }
            }
            if (positive_count != len) return error.InvalidCandidatePolicy;
            group.* = .{
                .clause = internal_clause,
                .candidates_start = start,
                .candidates_len = len,
                .control_count = clause.len - len,
                .unassigned_candidates = len,
            };
            for (policy.candidates[start .. start + len]) |package_id| {
                candidate_ranks[@intFromEnum(package_id)] =
                    std.math.maxInt(usize);
            }
        }
        if (candidate_cursor != policy.candidates.len) {
            return error.InvalidCandidatePolicy;
        }

        try self.candidate_heap.ensureTotalCapacity(policy.groups.len);
        self.candidate_groups = groups;
        self.candidate_packages = packages;
        self.candidate_occurrences = occurrences;
        self.candidate_heap_positions = positions;
        for (groups, 0..) |_, group_index| {
            self.refreshCandidateGroup(group_index);
        }
    }

    fn refreshCandidateGroup(self: *Engine, group_index: usize) void {
        const groups = self.candidate_groups orelse return;
        const positions = self.candidate_heap_positions.?;
        const group = groups[group_index];
        const eligible = group.false_controls == group.control_count and
            group.true_candidates == 0 and
            group.unassigned_candidates != 0;
        if (eligible and positions[group_index] == null) {
            self.candidateHeapInsert(group_index);
        } else if (!eligible and positions[group_index] != null) {
            self.candidateHeapRemove(group_index);
        }
    }

    fn updateCandidateOccurrences(
        self: *Engine,
        variable: usize,
        old: Value,
        new: Value,
    ) void {
        const occurrences = self.candidate_occurrences orelse return;
        const groups = self.candidate_groups.?;
        const packages = self.candidate_packages.?;
        for (occurrences[variable].items) |occurrence| {
            const group = &groups[occurrence.group];
            if (occurrence.candidate) {
                if (old == .unassigned) group.unassigned_candidates -= 1;
                if (new == .unassigned) group.unassigned_candidates += 1;
                if (old == .true_value) group.true_candidates -= 1;
                if (new == .true_value) group.true_candidates += 1;
                if (new == .unassigned and
                    occurrence.rank < group.candidate_cursor)
                {
                    group.candidate_cursor = occurrence.rank;
                } else if (old == .unassigned and
                    occurrence.rank == group.candidate_cursor)
                {
                    while (group.candidate_cursor <
                        group.candidates_len)
                    {
                        const package_id = packages[
                            group.candidates_start + group.candidate_cursor
                        ];
                        if (self.assignments[@intFromEnum(package_id)] ==
                            .unassigned)
                        {
                            break;
                        }
                        group.candidate_cursor += 1;
                    }
                }
            } else {
                if (old == .true_value) group.false_controls -= 1;
                if (new == .true_value) group.false_controls += 1;
            }
            self.refreshCandidateGroup(occurrence.group);
        }
    }

    fn candidateHeapInsert(self: *Engine, group_index: usize) void {
        const positions = self.candidate_heap_positions.?;
        var position = self.candidate_heap.items.len;
        self.candidate_heap.appendAssumeCapacity(group_index);
        positions[group_index] = position;
        while (position != 0) {
            const parent = (position - 1) / 2;
            if (self.candidate_heap.items[parent] < group_index) break;
            self.candidate_heap.items[position] =
                self.candidate_heap.items[parent];
            positions[self.candidate_heap.items[position]] = position;
            position = parent;
        }
        self.candidate_heap.items[position] = group_index;
        positions[group_index] = position;
    }

    fn candidateHeapRemove(self: *Engine, group_index: usize) void {
        const positions = self.candidate_heap_positions.?;
        var position = positions[group_index].?;
        positions[group_index] = null;
        const replacement = self.candidate_heap.pop().?;
        if (position == self.candidate_heap.items.len) return;
        self.candidate_heap.items[position] = replacement;
        positions[replacement] = position;

        while (position != 0) {
            const parent = (position - 1) / 2;
            if (self.candidate_heap.items[parent] < replacement) break;
            self.candidate_heap.items[position] =
                self.candidate_heap.items[parent];
            positions[self.candidate_heap.items[position]] = position;
            position = parent;
        }
        self.candidate_heap.items[position] = replacement;
        positions[replacement] = position;

        while (true) {
            const left = position * 2 + 1;
            if (left >= self.candidate_heap.items.len) break;
            const right = left + 1;
            const child = if (right < self.candidate_heap.items.len and
                self.candidate_heap.items[right] <
                    self.candidate_heap.items[left])
                right
            else
                left;
            if (self.candidate_heap.items[position] <
                self.candidate_heap.items[child])
            {
                break;
            }
            std.mem.swap(
                usize,
                &self.candidate_heap.items[position],
                &self.candidate_heap.items[child],
            );
            positions[self.candidate_heap.items[position]] = position;
            positions[self.candidate_heap.items[child]] = child;
            position = child;
        }
    }

    fn initializeRoot(self: *Engine) SolveError!bool {
        if (self.has_empty_clause) {
            self.statistics.conflicts += 1;
            return false;
        }
        for (self.clauses.items, 0..) |clause, clause_id| {
            if (clause.len != 1) continue;
            const literal = self.literals.items[clause.start];
            if (!try self.enqueue(literal, clause_id)) {
                self.statistics.conflicts += 1;
                return false;
            }
        }
        if (try self.propagate() != null) {
            self.statistics.conflicts += 1;
            return false;
        }
        return true;
    }

    fn run(self: *Engine, mode: RunMode) SolveError!bool {
        if (mode == .preferred_completion and
            !self.track_preferred_completion)
        {
            return error.InternalSolverFailure;
        }
        if (!self.root_initialized) {
            self.root_initialized = true;
            if (!try self.initializeRoot()) return false;
        }

        while (true) {
            if (try self.propagate()) |conflict_clause| {
                self.statistics.conflicts += 1;
                if (self.decisionLevel() == 0) return false;

                const analysis = try self.analyze(conflict_clause);
                const current_level = self.decisionLevel();
                self.backtrack(analysis.backtrack_level);
                if (analysis.backtrack_level < current_level) {
                    self.statistics.backjumps += 1;
                }

                const asserting_literal = analysis.literals[0];
                const learned_clause = try self.addClause(analysis.literals);
                self.statistics.learned_clauses += 1;
                if (!try self.enqueue(asserting_literal, learned_clause)) {
                    return error.InternalSolverFailure;
                }
                continue;
            }

            const decision = switch (mode) {
                .preferred_completion => self.chooseCandidateDecision() orelse
                    if (self.preferred_satisfied_clauses ==
                        self.clauses.items.len)
                        return true
                    else
                        self.chooseFallbackDecision() orelse
                            return error.InternalSolverFailure,
                .complete => self.chooseDecision() orelse return true,
            };
            try self.trail_limits.append(self.trail.items.len);
            self.statistics.decisions += 1;
            const decision_literal = Literal.init(
                @enumFromInt(@as(u32, @intCast(decision.variable))),
                decision.positive,
            );
            if (!try self.enqueue(decision_literal, null)) {
                return error.InternalSolverFailure;
            }
        }
    }

    fn propagate(self: *Engine) SolveError!?usize {
        while (self.propagation_head < self.trail.items.len) {
            const assigned_literal = self.trail.items[self.propagation_head];
            self.propagation_head += 1;
            self.statistics.propagations += 1;

            const false_literal = assigned_literal.negated();
            const false_watch = literalIndex(false_literal);
            var watch_index: usize = 0;
            while (watch_index < self.watches[false_watch].items.len) {
                const clause_id =
                    self.watches[false_watch].items[watch_index];
                if (clause_id >= self.clauses.items.len) {
                    return error.InternalSolverFailure;
                }
                const clause = &self.clauses.items[clause_id];
                const clause_literals = self.clauseLiterals(clause.*);
                if (clause_literals.len == 1) {
                    if (self.literalValue(clause_literals[0]) == .false_value) {
                        return clause_id;
                    }
                    watch_index += 1;
                    continue;
                }

                const false_is_a =
                    clause_literals[clause.watch_a] == false_literal;
                const false_is_b =
                    clause_literals[clause.watch_b] == false_literal;
                if (!false_is_a and !false_is_b) {
                    return error.InternalSolverFailure;
                }
                const false_position = if (false_is_a)
                    clause.watch_a
                else
                    clause.watch_b;
                const other_position = if (false_is_a)
                    clause.watch_b
                else
                    clause.watch_a;
                const other_literal = clause_literals[other_position];

                if (self.literalValue(other_literal) == .true_value) {
                    watch_index += 1;
                    continue;
                }

                var replacement: ?usize = null;
                var position = clause.scan_cursor;
                for (0..clause_literals.len) |_| {
                    self.statistics.watch_inspections += 1;
                    if (position != false_position and
                        position != other_position and
                        self.literalValue(clause_literals[position]) !=
                            .false_value)
                    {
                        replacement = position;
                        break;
                    }
                    position = if (position + 1 == clause_literals.len)
                        0
                    else
                        position + 1;
                }

                if (replacement) |new_position| {
                    const new_literal = clause_literals[new_position];
                    try self.watches[literalIndex(new_literal)].append(
                        clause_id,
                    );
                    if (false_is_a) {
                        clause.watch_a = new_position;
                    } else {
                        clause.watch_b = new_position;
                    }
                    clause.scan_cursor = if (new_position + 1 ==
                        clause_literals.len)
                        0
                    else
                        new_position + 1;
                    _ = self.watches[false_watch].swapRemove(watch_index);
                    continue;
                }

                switch (self.literalValue(other_literal)) {
                    .false_value => return clause_id,
                    .unassigned => {
                        if (!try self.enqueue(other_literal, clause_id)) {
                            return clause_id;
                        }
                    },
                    .true_value => unreachable,
                }
                watch_index += 1;
            }
        }
        return null;
    }

    fn analyze(
        self: *Engine,
        conflict_clause: usize,
    ) SolveError!Analysis {
        if (conflict_clause >= self.clauses.items.len or
            self.decisionLevel() == 0)
        {
            return error.InternalSolverFailure;
        }

        self.analysis_scratch.clearRetainingCapacity();
        const placeholder = Literal.init(@enumFromInt(0), true);
        try self.analysis_scratch.append(placeholder);
        @memset(self.seen, false);
        defer @memset(self.seen, false);

        const current_level = self.decisionLevel();
        var path_count: usize = 0;
        var clause_id = conflict_clause;
        var trail_index = self.trail.items.len;
        var resolved_variable: ?usize = null;

        while (true) {
            if (clause_id >= self.clauses.items.len) {
                return error.InternalSolverFailure;
            }
            for (self.clauseLiterals(self.clauses.items[clause_id])) |literal| {
                const variable = literalVariable(literal);
                if (resolved_variable != null and
                    variable == resolved_variable.?)
                {
                    continue;
                }
                if (self.seen[variable] or self.levels[variable] == 0) {
                    continue;
                }
                self.seen[variable] = true;
                if (self.levels[variable] == current_level) {
                    path_count += 1;
                } else {
                    try self.analysis_scratch.append(literal);
                }
            }

            var pivot: ?Literal = null;
            while (trail_index != 0) {
                trail_index -= 1;
                const candidate = self.trail.items[trail_index];
                if (self.seen[literalVariable(candidate)]) {
                    pivot = candidate;
                    break;
                }
            }
            const resolved = pivot orelse return error.InternalSolverFailure;
            const variable = literalVariable(resolved);
            self.seen[variable] = false;
            if (path_count == 0) return error.InternalSolverFailure;
            path_count -= 1;
            if (path_count == 0) {
                self.analysis_scratch.items[0] = resolved.negated();
                break;
            }

            clause_id = self.reasons[variable] orelse
                return error.InternalSolverFailure;
            resolved_variable = variable;
        }

        if (self.analysis_scratch.items.len > 2) {
            std.sort.heap(
                Literal,
                self.analysis_scratch.items[1..],
                {},
                literalLessThan,
            );
        }

        var backtrack_level: u32 = 0;
        var backtrack_position: usize = 1;
        for (self.analysis_scratch.items[1..], 1..) |literal, position| {
            const level = self.levels[literalVariable(literal)];
            if (level > backtrack_level) {
                backtrack_level = level;
                backtrack_position = position;
            }
        }
        if (self.analysis_scratch.items.len > 1 and backtrack_position != 1) {
            std.mem.swap(
                Literal,
                &self.analysis_scratch.items[1],
                &self.analysis_scratch.items[backtrack_position],
            );
        }

        return .{
            .literals = self.analysis_scratch.items,
            .backtrack_level = backtrack_level,
        };
    }

    fn backtrack(self: *Engine, target_level: u32) void {
        const current_level = self.decisionLevel();
        if (target_level >= current_level) return;

        const target_trail_len =
            self.trail_limits.items[@as(usize, @intCast(target_level))];
        var retained_trail_len = target_trail_len;
        for (self.trail.items[target_trail_len..]) |literal| {
            const variable = literalVariable(literal);
            if (self.levels[variable] <= target_level) {
                self.trail.items[retained_trail_len] = literal;
                retained_trail_len += 1;
                continue;
            }
            if (self.track_preferred_completion) {
                self.removeAssignmentCounts(literal);
            }
            self.updateCandidateOccurrences(
                variable,
                self.assignments[variable],
                .unassigned,
            );
            self.assignments[variable] = .unassigned;
            self.levels[variable] = 0;
            self.reasons[variable] = null;
            self.decision_cursor = @min(
                self.decision_cursor,
                self.decision_positions[variable],
            );
        }
        self.trail.shrinkRetainingCapacity(retained_trail_len);
        self.trail_limits.shrinkRetainingCapacity(
            @as(usize, @intCast(target_level)),
        );
        self.propagation_head = target_trail_len;
    }

    fn enqueue(
        self: *Engine,
        literal: Literal,
        reason: ?usize,
    ) SolveError!bool {
        const variable = literalVariable(literal);
        const wanted: Value = if (literal.positive())
            .true_value
        else
            .false_value;
        const assignment = self.assignments[variable];
        if (assignment != .unassigned) return assignment == wanted;

        try self.trail.append(literal);
        if (self.track_preferred_completion) {
            self.addAssignmentCounts(literal);
        }
        self.assignments[variable] = wanted;
        self.levels[variable] = self.decisionLevel();
        self.reasons[variable] = reason;
        self.updateCandidateOccurrences(variable, .unassigned, wanted);
        return true;
    }

    fn chooseDecision(self: *Engine) ?Decision {
        if (self.chooseCandidateDecision()) |decision| return decision;
        return self.chooseFallbackDecision();
    }

    fn chooseFallbackDecision(self: *Engine) ?Decision {
        while (self.decision_cursor < self.assignments.len) {
            self.statistics.decision_probes += 1;
            const decision = self.decision_order[self.decision_cursor];
            if (self.assignments[decision] == .unassigned) {
                self.decision_cursor += 1;
                return .{
                    .variable = decision,
                    .positive = self.preferred_values[decision],
                };
            }
            self.decision_cursor += 1;
        }
        return null;
    }

    fn chooseCandidateDecision(self: *Engine) ?Decision {
        const groups = self.candidate_groups orelse return null;
        const packages = self.candidate_packages.?;
        while (self.candidate_heap.items.len != 0) {
            const group_index = self.candidate_heap.items[0];
            const group = &groups[group_index];
            while (group.candidate_cursor < group.candidates_len) {
                self.statistics.candidate_probes += 1;
                const package_id = packages[
                    group.candidates_start + group.candidate_cursor
                ];
                const variable: usize = @intFromEnum(package_id);
                if (self.assignments[variable] == .unassigned) {
                    return .{ .variable = variable, .positive = true };
                }
                group.candidate_cursor += 1;
            }
            self.candidateHeapRemove(group_index);
        }
        return null;
    }

    fn decisionLevel(self: *const Engine) u32 {
        return @intCast(self.trail_limits.items.len);
    }

    fn literalValue(self: *const Engine, literal: Literal) Value {
        const assignment = self.assignments[literalVariable(literal)];
        return switch (assignment) {
            .unassigned => .unassigned,
            .true_value => if (literal.positive())
                .true_value
            else
                .false_value,
            .false_value => if (literal.positive())
                .false_value
            else
                .true_value,
        };
    }

    fn clausePreferredSatisfied(
        self: *const Engine,
        clause_id: usize,
    ) bool {
        return self.clause_true_counts.items[clause_id] != 0 or
            self.clause_preferred_counts.items[clause_id] != 0;
    }

    fn updatePreferredSatisfiedCount(
        self: *Engine,
        clause_id: usize,
        was_satisfied: bool,
    ) void {
        const is_satisfied = self.clausePreferredSatisfied(clause_id);
        if (was_satisfied == is_satisfied) return;
        if (is_satisfied) {
            self.preferred_satisfied_clauses += 1;
        } else {
            self.preferred_satisfied_clauses -= 1;
        }
    }

    fn addAssignmentCounts(self: *Engine, literal: Literal) void {
        for (self.literal_occurrences[literalIndex(literal)].items) |
            clause_id,
        | {
            const was_satisfied = self.clausePreferredSatisfied(clause_id);
            self.clause_true_counts.items[clause_id] += 1;
            self.updatePreferredSatisfiedCount(clause_id, was_satisfied);
        }
        const variable = literalVariable(literal);
        const preferred_literal = Literal.init(
            @enumFromInt(@as(u32, @intCast(variable))),
            self.preferred_values[variable],
        );
        for (self.literal_occurrences[
            literalIndex(preferred_literal)
        ].items) |clause_id| {
            const was_satisfied = self.clausePreferredSatisfied(clause_id);
            std.debug.assert(
                self.clause_preferred_counts.items[clause_id] != 0,
            );
            self.clause_preferred_counts.items[clause_id] -= 1;
            self.updatePreferredSatisfiedCount(clause_id, was_satisfied);
        }
    }

    fn removeAssignmentCounts(self: *Engine, literal: Literal) void {
        for (self.literal_occurrences[literalIndex(literal)].items) |
            clause_id,
        | {
            const was_satisfied = self.clausePreferredSatisfied(clause_id);
            std.debug.assert(self.clause_true_counts.items[clause_id] != 0);
            self.clause_true_counts.items[clause_id] -= 1;
            self.updatePreferredSatisfiedCount(clause_id, was_satisfied);
        }
        const variable = literalVariable(literal);
        const preferred_literal = Literal.init(
            @enumFromInt(@as(u32, @intCast(variable))),
            self.preferred_values[variable],
        );
        for (self.literal_occurrences[
            literalIndex(preferred_literal)
        ].items) |clause_id| {
            const was_satisfied = self.clausePreferredSatisfied(clause_id);
            self.clause_preferred_counts.items[clause_id] += 1;
            self.updatePreferredSatisfiedCount(clause_id, was_satisfied);
        }
    }

    fn protectLiteral(
        self: *Engine,
        literal: Literal,
    ) SolveError!void {
        const variable = literalVariable(literal);
        if (self.literalValue(literal) != .true_value) {
            return error.InternalSolverFailure;
        }
        if (self.levels[variable] == 0) return;

        const unit_clause = try self.addClause(&.{literal});
        self.levels[variable] = 0;
        self.reasons[variable] = unit_clause;
    }

    fn clauseLiterals(
        self: *const Engine,
        clause: ClauseData,
    ) []const Literal {
        return self.literals.items[clause.start .. clause.start + clause.len];
    }

    fn validateModel(self: *const Engine) bool {
        for (self.assignments) |assignment| {
            if (assignment == .unassigned) return false;
        }
        for (self.clauses.items) |clause| {
            var satisfied = false;
            for (self.clauseLiterals(clause)) |literal| {
                if (self.literalValue(literal) == .true_value) {
                    satisfied = true;
                    break;
                }
            }
            if (!satisfied) return false;
        }
        return true;
    }

    fn makeModel(self: *const Engine) SolveError!Model {
        const values = try self.allocator.alloc(bool, self.variable_count);
        errdefer self.allocator.free(values);
        for (self.assignments, values) |assignment, *value| {
            value.* = switch (assignment) {
                .false_value => false,
                .true_value => true,
                .unassigned => return error.InternalSolverFailure,
            };
        }
        return .{
            .allocator = self.allocator,
            .values = values,
        };
    }
};

fn solveWithoutCandidates(
    allocator: std.mem.Allocator,
    formula: *const OwnedFormula,
    assumptions: []const Literal,
    decision_policy: DecisionPolicy,
) SolveError!Result {
    return solveInternal(
        allocator,
        formula,
        assumptions,
        .{ .fallback = decision_policy },
        null,
    ) catch |err| switch (err) {
        error.InvalidCandidatePolicy => unreachable,
        else => |solve_error| return solve_error,
    };
}

fn solveInternal(
    allocator: std.mem.Allocator,
    formula: *const OwnedFormula,
    assumptions: []const Literal,
    candidate_policy: CandidateDecisionPolicy,
    statistics: ?*Statistics,
) CandidateSolveError!Result {
    var engine = try initializeEngine(
        allocator,
        formula,
        assumptions,
        candidate_policy,
        false,
    );
    defer engine.deinit();

    const satisfiable = try engine.run(.complete);
    if (statistics) |out| out.* = engine.statistics;
    if (!satisfiable) return .{ .unsatisfiable = {} };
    if (!engine.validateModel()) return error.InternalSolverFailure;
    return .{ .satisfiable = try engine.makeModel() };
}

fn initializeEngine(
    allocator: std.mem.Allocator,
    formula: *const OwnedFormula,
    assumptions: []const Literal,
    candidate_policy: CandidateDecisionPolicy,
    track_preferred_completion: bool,
) CandidateSolveError!Engine {
    const variable_count = formula.universe.packages.len;
    if (formula.package_states.len != variable_count) {
        return error.InvalidFormula;
    }

    var engine = try Engine.init(
        allocator,
        variable_count,
        candidate_policy.fallback,
        track_preferred_completion,
    );
    errdefer engine.deinit();

    const clause_mapping = if (candidate_policy.groups.len != 0)
        try allocator.alloc(?usize, formula.clauses.len)
    else
        null;
    defer if (clause_mapping) |mapping| allocator.free(mapping);

    for (formula.literals) |literal| {
        if (!validLiteral(literal, variable_count)) {
            return error.InvalidFormula;
        }
    }
    for (formula.clauses, 0..) |clause, clause_index| {
        const start: usize = @intCast(clause.literals.start);
        const len: usize = @intCast(clause.literals.len);
        if (start > formula.literals.len or
            len > formula.literals.len - start)
        {
            return error.InvalidFormula;
        }
        const internal_clause = try engine.addInputClause(
            formula.literals[start .. start + len],
        );
        if (clause_mapping) |mapping| {
            mapping[clause_index] = internal_clause;
        }
    }
    if (clause_mapping) |mapping| {
        try engine.configureCandidateGroups(
            formula,
            mapping,
            candidate_policy,
        );
    } else if (candidate_policy.candidates.len != 0) {
        return error.InvalidCandidatePolicy;
    }
    for (assumptions) |assumption| {
        try engine.addAssumption(assumption);
    }
    return engine;
}

fn validLiteral(literal: Literal, variable_count: usize) bool {
    return @intFromEnum(literal) >> 1 < variable_count;
}

fn literalVariable(literal: Literal) usize {
    return @intCast(@intFromEnum(literal) >> 1);
}

fn literalIndex(literal: Literal) usize {
    return @intCast(@intFromEnum(literal));
}

fn literalLessThan(_: void, left: Literal, right: Literal) bool {
    return @intFromEnum(left) < @intFromEnum(right);
}

fn testLiteral(variable: u32, positive: bool) Literal {
    return Literal.init(@enumFromInt(variable), positive);
}

fn testPackage(name: []const u8) metadata.Package {
    return .{
        .pkg_id = name,
        .nevra = .{
            .name = name,
            .version = "1",
            .release = "1",
            .arch = "noarch",
        },
        .checksum = .{ .kind = "sha256", .value = "" },
        .location = .{ .href = "" },
    };
}

fn testSolve(
    allocator: std.mem.Allocator,
    variable_count: usize,
    ranges: []const solver_rules.LiteralRange,
    literals: []const Literal,
    assumptions: []const Literal,
    statistics: ?*Statistics,
) CandidateSolveError!Result {
    return testSolvePolicy(
        allocator,
        variable_count,
        ranges,
        literals,
        assumptions,
        .{},
        statistics,
    );
}

fn testSolvePolicy(
    allocator: std.mem.Allocator,
    variable_count: usize,
    ranges: []const solver_rules.LiteralRange,
    literals: []const Literal,
    assumptions: []const Literal,
    decision_policy: DecisionPolicy,
    statistics: ?*Statistics,
) CandidateSolveError!Result {
    return testSolveCandidatePolicy(
        allocator,
        variable_count,
        ranges,
        literals,
        assumptions,
        .{ .fallback = decision_policy },
        statistics,
    );
}

fn testSolveCandidatePolicy(
    allocator: std.mem.Allocator,
    variable_count: usize,
    ranges: []const solver_rules.LiteralRange,
    literals: []const Literal,
    assumptions: []const Literal,
    candidate_policy: CandidateDecisionPolicy,
    statistics: ?*Statistics,
) CandidateSolveError!Result {
    const packages = try allocator.alloc(
        solver_model.UniversePackage,
        variable_count,
    );
    defer allocator.free(packages);
    const states = try allocator.alloc(
        solver_rules.PackageState,
        variable_count,
    );
    defer allocator.free(states);
    @memset(states, .{});
    const clauses = try allocator.alloc(solver_rules.Clause, ranges.len);
    defer allocator.free(clauses);
    for (ranges, clauses, 0..) |range, *clause, clause_index| {
        clause.* = .{
            .literals = range,
            .origin = .{
                .job = @enumFromInt(@as(u32, @intCast(clause_index))),
            },
        };
    }

    var universe = solver_model.Universe{
        .allocator = allocator,
        .repositories = &.{},
        .packages = packages,
        .input_to_repository = &.{},
    };
    const formula = OwnedFormula{
        .allocator = allocator,
        .universe = &universe,
        .clauses = clauses,
        .literals = literals,
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = states,
    };
    return solveInternal(
        allocator,
        &formula,
        assumptions,
        candidate_policy,
        statistics,
    );
}

fn testIncrementalSolve(
    allocator: std.mem.Allocator,
    variable_count: usize,
    ranges: []const solver_rules.LiteralRange,
    literals: []const Literal,
    assumptions: []const Literal,
) CandidateSolveError!Result {
    const packages = try allocator.alloc(
        solver_model.UniversePackage,
        variable_count,
    );
    defer allocator.free(packages);
    const states = try allocator.alloc(
        solver_rules.PackageState,
        variable_count,
    );
    defer allocator.free(states);
    @memset(states, .{});
    const clauses = try allocator.alloc(solver_rules.Clause, ranges.len);
    defer allocator.free(clauses);
    for (ranges, clauses, 0..) |range, *clause, clause_index| {
        clause.* = .{
            .literals = range,
            .origin = .{
                .job = @enumFromInt(@as(u32, @intCast(clause_index))),
            },
        };
    }
    var universe = solver_model.Universe{
        .allocator = allocator,
        .repositories = &.{},
        .packages = packages,
        .input_to_repository = &.{},
    };
    const formula = OwnedFormula{
        .allocator = allocator,
        .universe = &universe,
        .clauses = clauses,
        .literals = literals,
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = states,
    };
    var session = try IncrementalSolver.init(
        allocator,
        &formula,
        assumptions,
        .{},
    );
    defer session.deinit();
    _ = try session.solveHard();
    return session.finish();
}

fn assignmentSatisfies(
    variable_count: usize,
    ranges: []const solver_rules.LiteralRange,
    literals: []const Literal,
    assumptions: []const Literal,
    assignment: usize,
) bool {
    for (ranges) |range| {
        const start: usize = @intCast(range.start);
        const len: usize = @intCast(range.len);
        var satisfied = false;
        for (literals[start .. start + len]) |literal| {
            const selected = assignment &
                (@as(usize, 1) << @as(u6, @intCast(literalVariable(literal)))) != 0;
            if (selected == literal.positive()) {
                satisfied = true;
                break;
            }
        }
        if (!satisfied) return false;
    }
    for (assumptions) |literal| {
        if (literalVariable(literal) >= variable_count) return false;
        const selected = assignment &
            (@as(usize, 1) << @as(u6, @intCast(literalVariable(literal)))) != 0;
        if (selected != literal.positive()) return false;
    }
    return true;
}

fn bruteForceSatisfiable(
    variable_count: usize,
    ranges: []const solver_rules.LiteralRange,
    literals: []const Literal,
    assumptions: []const Literal,
) bool {
    for (0..(@as(usize, 1) << @as(u6, @intCast(variable_count)))) |assignment| {
        if (assignmentSatisfies(
            variable_count,
            ranges,
            literals,
            assumptions,
            assignment,
        )) return true;
    }
    return false;
}

fn expectResultMatchesBruteForce(
    variable_count: usize,
    ranges: []const solver_rules.LiteralRange,
    literals: []const Literal,
    assumptions: []const Literal,
) !void {
    const expected = bruteForceSatisfiable(
        variable_count,
        ranges,
        literals,
        assumptions,
    );
    var result = try testSolve(
        std.testing.allocator,
        variable_count,
        ranges,
        literals,
        assumptions,
        null,
    );
    defer result.deinit();
    var incremental = try testIncrementalSolve(
        std.testing.allocator,
        variable_count,
        ranges,
        literals,
        assumptions,
    );
    defer incremental.deinit();

    switch (result) {
        .satisfiable => |model| {
            try std.testing.expect(expected);
            const incremental_model = switch (incremental) {
                .satisfiable => |value| value,
                .unsatisfiable => return error.TestUnexpectedResult,
            };
            try std.testing.expectEqualSlices(
                bool,
                model.values,
                incremental_model.values,
            );
            var assignment: usize = 0;
            for (model.values, 0..) |selected, variable| {
                if (selected) {
                    assignment |= @as(usize, 1) <<
                        @as(u6, @intCast(variable));
                }
            }
            try std.testing.expect(assignmentSatisfies(
                variable_count,
                ranges,
                literals,
                assumptions,
                assignment,
            ));
        },
        .unsatisfiable => {
            try std.testing.expect(!expected);
            try std.testing.expect(
                std.meta.activeTag(incremental) == .unsatisfiable,
            );
        },
    }
}

test "empty formula selects no packages" {
    var result = try testSolve(
        std.testing.allocator,
        3,
        &.{},
        &.{},
        &.{},
        null,
    );
    defer result.deinit();

    const model = switch (result) {
        .satisfiable => |value| value,
        .unsatisfiable => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false, false },
        model.values,
    );
}

test "generated package rules solve end to end" {
    var relations = [_]metadata.Relation{
        .{ .name = "choice" },
        .{ .name = "choice" },
        .{ .name = "choice" },
    };
    var packages = [_]metadata.Package{
        testPackage("provider-a"),
        testPackage("provider-b"),
        testPackage("consumer"),
    };
    packages[0].provides = .{ .start = 0, .len = 1 };
    packages[1].provides = .{ .start = 1, .len = 1 };
    packages[2].requires = .{ .start = 2, .len = 1 };
    const repository = metadata.RepositoryModel{
        .packages = &packages,
        .relations = &relations,
    };
    var universe = try solver_model.Universe.init(
        std.testing.allocator,
        &.{.{
            .id = "available",
            .model = &repository,
        }},
    );
    defer universe.deinit();
    var formula = try solver_rules.generateBase(
        std.testing.allocator,
        &universe,
        .{ .jobs = &.{.{
            .action = .install,
            .selection = .{ .name = "consumer" },
        }} },
        .{ .native_arch = "x86_64" },
    );
    defer formula.deinit();

    var result = try solve(std.testing.allocator, &formula);
    defer result.deinit();
    const model = result.satisfiable;
    try std.testing.expect(!model.values[0]);
    try std.testing.expect(model.values[1]);
    try std.testing.expect(model.values[2]);
}

test "watched propagation moves repeatedly and forces the remaining literal" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(0, false),
        testLiteral(1, true),
        testLiteral(2, true),
        testLiteral(1, false),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 1 },
        .{ .start = 1, .len = 3 },
        .{ .start = 4, .len = 1 },
    };
    var result = try testSolve(
        std.testing.allocator,
        3,
        &ranges,
        &literals,
        &.{},
        null,
    );
    defer result.deinit();

    const model = result.satisfiable;
    try std.testing.expect(model.values[0]);
    try std.testing.expect(!model.values[1]);
    try std.testing.expect(model.values[2]);
}

test "empty and contradictory unit clauses are unsatisfiable" {
    var empty_result = try testSolve(
        std.testing.allocator,
        1,
        &.{.{ .start = 0, .len = 0 }},
        &.{},
        &.{},
        null,
    );
    defer empty_result.deinit();
    try std.testing.expect(empty_result == .unsatisfiable);

    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(0, false),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 1 },
        .{ .start = 1, .len = 1 },
    };
    var unit_result = try testSolve(
        std.testing.allocator,
        1,
        &ranges,
        &literals,
        &.{},
        null,
    );
    defer unit_result.deinit();
    try std.testing.expect(unit_result == .unsatisfiable);
}

test "assumptions constrain propagation and reject invalid literals" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
    };
    var result = try testSolve(
        std.testing.allocator,
        2,
        &ranges,
        &literals,
        &.{testLiteral(0, false)},
        null,
    );
    defer result.deinit();
    try std.testing.expect(!result.satisfiable.values[0]);
    try std.testing.expect(result.satisfiable.values[1]);

    var contradictory = try testSolve(
        std.testing.allocator,
        2,
        &ranges,
        &literals,
        &.{
            testLiteral(0, true),
            testLiteral(0, false),
        },
        null,
    );
    defer contradictory.deinit();
    try std.testing.expect(contradictory == .unsatisfiable);

    try std.testing.expectError(
        error.InvalidAssumption,
        testSolve(
            std.testing.allocator,
            2,
            &ranges,
            &literals,
            &.{testLiteral(2, true)},
            null,
        ),
    );
}

test "decision policy controls complete order and preferred polarity" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
        testLiteral(2, true),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 3 },
    };
    const order = [_]solver_model.PackageId{
        @enumFromInt(2),
        @enumFromInt(0),
        @enumFromInt(1),
    };
    const preferred = [_]bool{ false, false, false };
    var result = try testSolvePolicy(
        std.testing.allocator,
        3,
        &ranges,
        &literals,
        &.{},
        .{
            .order = &order,
            .preferred_values = &preferred,
        },
        null,
    );
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, false },
        result.satisfiable.values,
    );

    const installed_preference = [_]bool{ true, false, false };
    var preferred_result = try testSolvePolicy(
        std.testing.allocator,
        3,
        &.{},
        &.{},
        &.{},
        .{
            .order = &order,
            .preferred_values = &installed_preference,
        },
        null,
    );
    defer preferred_result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, false },
        preferred_result.satisfiable.values,
    );

    const duplicate_order = [_]solver_model.PackageId{
        @enumFromInt(0),
        @enumFromInt(0),
        @enumFromInt(2),
    };
    try std.testing.expectError(
        error.InvalidDecisionPolicy,
        testSolvePolicy(
            std.testing.allocator,
            3,
            &ranges,
            &literals,
            &.{},
            .{ .order = &duplicate_order },
            null,
        ),
    );
}

test "contextual group chooses its best positive candidate" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
        testLiteral(2, true),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 3 },
    };
    const candidates = [_]solver_model.PackageId{
        @enumFromInt(1),
        @enumFromInt(2),
        @enumFromInt(0),
    };
    var result = try testSolveCandidatePolicy(
        std.testing.allocator,
        3,
        &ranges,
        &literals,
        &.{},
        .{
            .groups = &.{.{
                .clause_index = 0,
                .candidates = .{ .start = 0, .len = 3 },
            }},
            .candidates = &candidates,
        },
        null,
    );
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, false },
        result.satisfiable.values,
    );
}

test "contextual requirement activates only after its owner is selected" {
    const literals = [_]Literal{
        testLiteral(0, false),
        testLiteral(1, true),
        testLiteral(2, true),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 3 },
    };
    const candidates = [_]solver_model.PackageId{
        @enumFromInt(2),
        @enumFromInt(1),
    };
    const policy = CandidateDecisionPolicy{
        .groups = &.{.{
            .clause_index = 0,
            .candidates = .{ .start = 0, .len = 2 },
        }},
        .candidates = &candidates,
    };
    var inactive = try testSolveCandidatePolicy(
        std.testing.allocator,
        3,
        &ranges,
        &literals,
        &.{},
        policy,
        null,
    );
    defer inactive.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, false, false },
        inactive.satisfiable.values,
    );

    var active = try testSolveCandidatePolicy(
        std.testing.allocator,
        3,
        &ranges,
        &literals,
        &.{testLiteral(0, true)},
        policy,
        null,
    );
    defer active.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, true },
        active.satisfiable.values,
    );
}

test "contextual group falls back after its preferred candidate conflicts" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
        testLiteral(0, false),
        testLiteral(2, true),
        testLiteral(0, false),
        testLiteral(2, false),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
        .{ .start = 2, .len = 2 },
        .{ .start = 4, .len = 2 },
    };
    const candidates = [_]solver_model.PackageId{
        @enumFromInt(0),
        @enumFromInt(1),
    };
    var statistics: Statistics = .{};
    var result = try testSolveCandidatePolicy(
        std.testing.allocator,
        3,
        &ranges,
        &literals,
        &.{},
        .{
            .groups = &.{.{
                .clause_index = 0,
                .candidates = .{ .start = 0, .len = 2 },
            }},
            .candidates = &candidates,
        },
        &statistics,
    );
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, false },
        result.satisfiable.values,
    );
    try std.testing.expect(statistics.conflicts != 0);
    try std.testing.expect(statistics.learned_clauses != 0);
}

test "contextual candidate rejection probes each rank once" {
    const candidate_count = 64;
    const variable_count = candidate_count * 2 - 1;
    const clause_count = 1 + 2 * (candidate_count - 1);
    const literal_count = candidate_count + 4 * (candidate_count - 1);
    const literals = try std.testing.allocator.alloc(Literal, literal_count);
    defer std.testing.allocator.free(literals);
    const ranges = try std.testing.allocator.alloc(
        solver_rules.LiteralRange,
        clause_count,
    );
    defer std.testing.allocator.free(ranges);
    const candidates = try std.testing.allocator.alloc(
        solver_model.PackageId,
        candidate_count,
    );
    defer std.testing.allocator.free(candidates);

    for (0..candidate_count) |candidate| {
        literals[candidate] = testLiteral(@intCast(candidate), true);
        candidates[candidate] = @enumFromInt(candidate);
    }
    ranges[0] = .{ .start = 0, .len = candidate_count };
    var next_literal: usize = candidate_count;
    var next_clause: usize = 1;
    for (0..candidate_count - 1) |candidate| {
        const helper = candidate_count + candidate;
        ranges[next_clause] = .{ .start = @intCast(next_literal), .len = 2 };
        literals[next_literal] = testLiteral(@intCast(candidate), false);
        literals[next_literal + 1] = testLiteral(@intCast(helper), true);
        next_literal += 2;
        next_clause += 1;

        ranges[next_clause] = .{ .start = @intCast(next_literal), .len = 2 };
        literals[next_literal] = testLiteral(@intCast(candidate), false);
        literals[next_literal + 1] = testLiteral(@intCast(helper), false);
        next_literal += 2;
        next_clause += 1;
    }

    var statistics: Statistics = .{};
    var result = try testSolveCandidatePolicy(
        std.testing.allocator,
        variable_count,
        ranges,
        literals,
        &.{},
        .{
            .groups = &.{.{
                .clause_index = 0,
                .candidates = .{ .start = 0, .len = candidate_count },
            }},
            .candidates = candidates,
        },
        &statistics,
    );
    defer result.deinit();

    for (result.satisfiable.values[0 .. candidate_count - 1]) |selected| {
        try std.testing.expect(!selected);
    }
    try std.testing.expect(
        result.satisfiable.values[candidate_count - 1],
    );
    try std.testing.expectEqual(
        candidate_count - 1,
        statistics.candidate_probes,
    );
}

test "contextual groups use stable input priority" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
        testLiteral(2, true),
        testLiteral(3, true),
        testLiteral(0, false),
        testLiteral(2, false),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
        .{ .start = 2, .len = 2 },
        .{ .start = 4, .len = 2 },
    };
    const first_candidates = [_]solver_model.PackageId{
        @enumFromInt(0),
        @enumFromInt(1),
        @enumFromInt(2),
        @enumFromInt(3),
    };
    var first = try testSolveCandidatePolicy(
        std.testing.allocator,
        4,
        &ranges,
        &literals,
        &.{},
        .{
            .groups = &.{
                .{
                    .clause_index = 0,
                    .candidates = .{ .start = 0, .len = 2 },
                },
                .{
                    .clause_index = 1,
                    .candidates = .{ .start = 2, .len = 2 },
                },
            },
            .candidates = &first_candidates,
        },
        null,
    );
    defer first.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, false, true },
        first.satisfiable.values,
    );

    const second_candidates = [_]solver_model.PackageId{
        @enumFromInt(2),
        @enumFromInt(3),
        @enumFromInt(0),
        @enumFromInt(1),
    };
    var second = try testSolveCandidatePolicy(
        std.testing.allocator,
        4,
        &ranges,
        &literals,
        &.{},
        .{
            .groups = &.{
                .{
                    .clause_index = 1,
                    .candidates = .{ .start = 0, .len = 2 },
                },
                .{
                    .clause_index = 0,
                    .candidates = .{ .start = 2, .len = 2 },
                },
            },
            .candidates = &second_candidates,
        },
        null,
    );
    defer second.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true, true, false },
        second.satisfiable.values,
    );
}

test "contextual rankings remain local to their clauses" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
        testLiteral(0, true),
        testLiteral(1, true),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
        .{ .start = 2, .len = 2 },
    };
    const first_candidates = [_]solver_model.PackageId{
        @enumFromInt(0),
        @enumFromInt(1),
        @enumFromInt(1),
        @enumFromInt(0),
    };
    var first = try testSolveCandidatePolicy(
        std.testing.allocator,
        2,
        &ranges,
        &literals,
        &.{},
        .{
            .groups = &.{
                .{
                    .clause_index = 0,
                    .candidates = .{ .start = 0, .len = 2 },
                },
                .{
                    .clause_index = 1,
                    .candidates = .{ .start = 2, .len = 2 },
                },
            },
            .candidates = &first_candidates,
        },
        null,
    );
    defer first.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false },
        first.satisfiable.values,
    );

    const second_candidates = [_]solver_model.PackageId{
        @enumFromInt(1),
        @enumFromInt(0),
        @enumFromInt(0),
        @enumFromInt(1),
    };
    var second = try testSolveCandidatePolicy(
        std.testing.allocator,
        2,
        &ranges,
        &literals,
        &.{},
        .{
            .groups = &.{
                .{
                    .clause_index = 1,
                    .candidates = .{ .start = 0, .len = 2 },
                },
                .{
                    .clause_index = 0,
                    .candidates = .{ .start = 2, .len = 2 },
                },
            },
            .candidates = &second_candidates,
        },
        null,
    );
    defer second.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ false, true },
        second.satisfiable.values,
    );
}

test "empty contextual policy preserves fallback model and statistics" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
        testLiteral(0, true),
        testLiteral(1, false),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
        .{ .start = 2, .len = 2 },
    };
    var fallback_statistics: Statistics = .{};
    var fallback = try testSolvePolicy(
        std.testing.allocator,
        2,
        &ranges,
        &literals,
        &.{},
        .{},
        &fallback_statistics,
    );
    defer fallback.deinit();

    var contextual_statistics: Statistics = .{};
    var contextual = try testSolveCandidatePolicy(
        std.testing.allocator,
        2,
        &ranges,
        &literals,
        &.{},
        .{},
        &contextual_statistics,
    );
    defer contextual.deinit();
    try std.testing.expectEqualSlices(
        bool,
        fallback.satisfiable.values,
        contextual.satisfiable.values,
    );
    try std.testing.expectEqualDeep(
        fallback_statistics,
        contextual_statistics,
    );
}

test "malformed contextual candidate groups are rejected" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
    };
    const duplicate = [_]solver_model.PackageId{
        @enumFromInt(0),
        @enumFromInt(0),
    };
    try std.testing.expectError(
        error.InvalidCandidatePolicy,
        testSolveCandidatePolicy(
            std.testing.allocator,
            2,
            &ranges,
            &literals,
            &.{},
            .{
                .groups = &.{.{
                    .clause_index = 0,
                    .candidates = .{ .start = 0, .len = 2 },
                }},
                .candidates = &duplicate,
            },
            null,
        ),
    );

    try std.testing.expectError(
        error.InvalidCandidatePolicy,
        testSolveCandidatePolicy(
            std.testing.allocator,
            2,
            &ranges,
            &literals,
            &.{},
            .{
                .groups = &.{.{
                    .clause_index = 0,
                    .candidates = .{ .start = 0, .len = 1 },
                }},
                .candidates = &.{@enumFromInt(0)},
            },
            null,
        ),
    );

    try std.testing.expectError(
        error.InvalidCandidatePolicy,
        testSolveCandidatePolicy(
            std.testing.allocator,
            2,
            &ranges,
            &literals,
            &.{},
            .{ .candidates = &.{@enumFromInt(0)} },
            null,
        ),
    );

    try std.testing.expectError(
        error.InvalidCandidatePolicy,
        testSolveCandidatePolicy(
            std.testing.allocator,
            2,
            &ranges,
            &literals,
            &.{},
            .{
                .groups = &.{.{
                    .clause_index = 1,
                    .candidates = .{ .start = 0, .len = 2 },
                }},
                .candidates = &.{ @enumFromInt(0), @enumFromInt(1) },
            },
            null,
        ),
    );

    try std.testing.expectError(
        error.InvalidCandidatePolicy,
        testSolveCandidatePolicy(
            std.testing.allocator,
            2,
            &ranges,
            &literals,
            &.{},
            .{
                .groups = &.{.{
                    .clause_index = 0,
                    .candidates = .{ .start = 1, .len = 2 },
                }},
                .candidates = &.{ @enumFromInt(0), @enumFromInt(1) },
            },
            null,
        ),
    );

    try std.testing.expectError(
        error.InvalidCandidatePolicy,
        testSolveCandidatePolicy(
            std.testing.allocator,
            2,
            &ranges,
            &literals,
            &.{},
            .{
                .groups = &.{.{
                    .clause_index = 0,
                    .candidates = .{ .start = 0, .len = 3 },
                }},
                .candidates = &.{ @enumFromInt(0), @enumFromInt(1) },
            },
            null,
        ),
    );

    try std.testing.expectError(
        error.InvalidCandidatePolicy,
        testSolveCandidatePolicy(
            std.testing.allocator,
            2,
            &ranges,
            &literals,
            &.{},
            .{
                .groups = &.{.{
                    .clause_index = 0,
                    .candidates = .{ .start = 0, .len = 2 },
                }},
                .candidates = &.{ @enumFromInt(0), @enumFromInt(2) },
            },
            null,
        ),
    );

    const duplicate_ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
        .{ .start = 0, .len = 2 },
    };
    try std.testing.expectError(
        error.InvalidCandidatePolicy,
        testSolveCandidatePolicy(
            std.testing.allocator,
            2,
            &duplicate_ranges,
            &literals,
            &.{},
            .{
                .groups = &.{
                    .{
                        .clause_index = 0,
                        .candidates = .{ .start = 0, .len = 2 },
                    },
                    .{
                        .clause_index = 0,
                        .candidates = .{ .start = 2, .len = 2 },
                    },
                },
                .candidates = &.{
                    @enumFromInt(0),
                    @enumFromInt(1),
                    @enumFromInt(0),
                    @enumFromInt(1),
                },
            },
            null,
        ),
    );

    const single_range = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 1 },
    };
    try std.testing.expectError(
        error.InvalidCandidatePolicy,
        testSolveCandidatePolicy(
            std.testing.allocator,
            2,
            &single_range,
            literals[0..1],
            &.{},
            .{
                .groups = &.{.{
                    .clause_index = 0,
                    .candidates = .{ .start = 0, .len = 1 },
                }},
                .candidates = &.{ @enumFromInt(0), @enumFromInt(1) },
            },
            null,
        ),
    );

    const controlled_literals = [_]Literal{
        testLiteral(0, false),
        testLiteral(1, true),
    };
    try std.testing.expectError(
        error.InvalidCandidatePolicy,
        testSolveCandidatePolicy(
            std.testing.allocator,
            2,
            &ranges,
            &controlled_literals,
            &.{},
            .{
                .groups = &.{.{
                    .clause_index = 0,
                    .candidates = .{ .start = 0, .len = 2 },
                }},
                .candidates = &.{ @enumFromInt(0), @enumFromInt(1) },
            },
            null,
        ),
    );
}

test "first UIP learning backjumps and flips a false-first decision" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
        testLiteral(0, true),
        testLiteral(1, false),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
        .{ .start = 2, .len = 2 },
    };
    var statistics: Statistics = .{};
    var result = try testSolve(
        std.testing.allocator,
        2,
        &ranges,
        &literals,
        &.{},
        &statistics,
    );
    defer result.deinit();

    try std.testing.expect(result.satisfiable.values[0]);
    try std.testing.expect(statistics.conflicts > 0);
    try std.testing.expect(statistics.learned_clauses > 0);
    try std.testing.expect(statistics.backjumps > 0);
}

test "duplicate literals collapse and tautological clauses are ignored" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(0, true),
        testLiteral(0, true),
        testLiteral(0, false),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
        .{ .start = 2, .len = 2 },
    };
    var result = try testSolve(
        std.testing.allocator,
        1,
        &ranges,
        &literals,
        &.{},
        null,
    );
    defer result.deinit();
    try std.testing.expect(result.satisfiable.values[0]);
}

test "malformed formula ranges and literals are rejected" {
    var packages: [1]solver_model.UniversePackage = undefined;
    var states: [1]solver_rules.PackageState = .{.{}};
    var universe = solver_model.Universe{
        .allocator = std.testing.allocator,
        .repositories = &.{},
        .packages = &packages,
        .input_to_repository = &.{},
    };
    const bad_range_clause = [_]solver_rules.Clause{.{
        .literals = .{ .start = 1, .len = 1 },
        .origin = .{ .job = @enumFromInt(0) },
    }};
    var formula = OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
        .clauses = &bad_range_clause,
        .literals = &.{testLiteral(0, true)},
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = &states,
    };
    try std.testing.expectError(
        error.InvalidFormula,
        solve(std.testing.allocator, &formula),
    );

    formula.clauses = &.{.{
        .literals = .{ .start = 0, .len = 1 },
        .origin = .{ .job = @enumFromInt(0) },
    }};
    formula.literals = &.{testLiteral(1, true)};
    try std.testing.expectError(
        error.InvalidFormula,
        solve(std.testing.allocator, &formula),
    );
}

test "relaxable clauses remain hard and weak metadata does not affect search" {
    var packages: [1]solver_model.UniversePackage = undefined;
    var states: [1]solver_rules.PackageState = .{.{}};
    var universe = solver_model.Universe{
        .allocator = std.testing.allocator,
        .repositories = &.{},
        .packages = &packages,
        .input_to_repository = &.{},
    };
    const empty_clause = [_]solver_rules.Clause{.{
        .literals = .{},
        .origin = .{ .job = @enumFromInt(0) },
        .disposition = .relaxable_job,
    }};
    const weak_request = [_]solver_rules.WeakRequest{.{
        .owner = @enumFromInt(0),
        .dependency = .{
            .package = @enumFromInt(0),
            .kind = .recommends,
            .index = 0,
        },
        .candidates = .{},
        .direction = .forward,
    }};
    var formula = OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
        .clauses = &empty_clause,
        .literals = &.{},
        .weak_requests = &weak_request,
        .weak_candidates = &.{},
        .package_states = &states,
    };
    var hard_result = try solve(std.testing.allocator, &formula);
    defer hard_result.deinit();
    try std.testing.expect(hard_result == .unsatisfiable);

    formula.clauses = &.{};
    var weak_only_result = try solve(std.testing.allocator, &formula);
    defer weak_only_result.deinit();
    try std.testing.expect(weak_only_result == .satisfiable);
    try std.testing.expect(!weak_only_result.satisfiable.values[0]);
}

test "search is deterministic" {
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
        testLiteral(0, true),
        testLiteral(1, false),
    };
    const ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
        .{ .start = 2, .len = 2 },
    };
    var first_statistics: Statistics = .{};
    var first = try testSolve(
        std.testing.allocator,
        2,
        &ranges,
        &literals,
        &.{},
        &first_statistics,
    );
    defer first.deinit();
    var second_statistics: Statistics = .{};
    var second = try testSolve(
        std.testing.allocator,
        2,
        &ranges,
        &literals,
        &.{},
        &second_statistics,
    );
    defer second.deinit();

    try std.testing.expectEqualSlices(
        bool,
        first.satisfiable.values,
        second.satisfiable.values,
    );
    try std.testing.expectEqualDeep(first_statistics, second_statistics);
}

test "all two-variable clause and assumption combinations match brute force" {
    var literal_storage: [4]Literal = undefined;
    var ranges: [2]solver_rules.LiteralRange = undefined;
    var assumptions: [2]Literal = undefined;

    for (0..9) |first_clause| {
        for (0..9) |second_clause| {
            var literal_count: usize = 0;
            for ([_]usize{ first_clause, second_clause }, 0..) |
                clause_code,
                clause_index,
            | {
                const start = literal_count;
                var code = clause_code;
                for (0..2) |variable| {
                    const state = code % 3;
                    code /= 3;
                    if (state == 0) continue;
                    literal_storage[literal_count] = testLiteral(
                        @intCast(variable),
                        state == 1,
                    );
                    literal_count += 1;
                }
                ranges[clause_index] = .{
                    .start = @intCast(start),
                    .len = @intCast(literal_count - start),
                };
            }

            for (0..9) |assumption_code| {
                var code = assumption_code;
                var assumption_count: usize = 0;
                for (0..2) |variable| {
                    const state = code % 3;
                    code /= 3;
                    if (state == 0) continue;
                    assumptions[assumption_count] = testLiteral(
                        @intCast(variable),
                        state == 1,
                    );
                    assumption_count += 1;
                }
                try expectResultMatchesBruteForce(
                    2,
                    &ranges,
                    literal_storage[0..literal_count],
                    assumptions[0..assumption_count],
                );
            }
        }
    }
}

test "legal contextual groups preserve exhaustive satisfiability" {
    var literal_storage: [6]Literal = undefined;
    var ranges: [3]solver_rules.LiteralRange = undefined;
    var assumptions: [2]Literal = undefined;
    const candidates = [_]solver_model.PackageId{
        @enumFromInt(1),
        @enumFromInt(0),
    };

    for (0..9) |second_clause| {
        for (0..9) |third_clause| {
            literal_storage[0] = testLiteral(0, true);
            literal_storage[1] = testLiteral(1, true);
            ranges[0] = .{ .start = 0, .len = 2 };
            var literal_count: usize = 2;
            for ([_]usize{ second_clause, third_clause }, 1..) |
                clause_code,
                clause_index,
            | {
                const start = literal_count;
                var code = clause_code;
                for (0..2) |variable| {
                    const state = code % 3;
                    code /= 3;
                    if (state == 0) continue;
                    literal_storage[literal_count] = testLiteral(
                        @intCast(variable),
                        state == 1,
                    );
                    literal_count += 1;
                }
                ranges[clause_index] = .{
                    .start = @intCast(start),
                    .len = @intCast(literal_count - start),
                };
            }

            for (0..9) |assumption_code| {
                var code = assumption_code;
                var assumption_count: usize = 0;
                for (0..2) |variable| {
                    const state = code % 3;
                    code /= 3;
                    if (state == 0) continue;
                    assumptions[assumption_count] = testLiteral(
                        @intCast(variable),
                        state == 1,
                    );
                    assumption_count += 1;
                }

                const expected = bruteForceSatisfiable(
                    2,
                    &ranges,
                    literal_storage[0..literal_count],
                    assumptions[0..assumption_count],
                );
                var result = try testSolveCandidatePolicy(
                    std.testing.allocator,
                    2,
                    &ranges,
                    literal_storage[0..literal_count],
                    assumptions[0..assumption_count],
                    .{
                        .groups = &.{.{
                            .clause_index = 0,
                            .candidates = .{ .start = 0, .len = 2 },
                        }},
                        .candidates = &candidates,
                    },
                    null,
                );
                defer result.deinit();
                switch (result) {
                    .satisfiable => |model| {
                        try std.testing.expect(expected);
                        var assignment: usize = 0;
                        for (model.values, 0..) |selected, variable| {
                            if (selected) {
                                assignment |= @as(usize, 1) <<
                                    @as(u6, @intCast(variable));
                            }
                        }
                        try std.testing.expect(assignmentSatisfies(
                            2,
                            &ranges,
                            literal_storage[0..literal_count],
                            assumptions[0..assumption_count],
                            assignment,
                        ));
                    },
                    .unsatisfiable => {
                        try std.testing.expect(!expected);
                    },
                }
            }
        }
    }
}

fn nextTestRandom(state: *u64) u64 {
    state.* = state.* *% 6364136223846793005 +% 1442695040888963407;
    return state.*;
}

test "generated four-variable formulas match brute force" {
    var random_state: u64 = 0x4d595df4d0f33173;
    var literal_storage: [40]Literal = undefined;
    var ranges: [8]solver_rules.LiteralRange = undefined;
    var assumptions: [3]Literal = undefined;

    for (0..256) |case_index| {
        const clause_count: usize =
            1 + @as(usize, @intCast(nextTestRandom(&random_state) % 8));
        var literal_count: usize = 0;
        for (ranges[0..clause_count], 0..) |*range, clause_index| {
            const start = literal_count;
            const clause_len: usize = if ((case_index + clause_index) % 31 == 0)
                0
            else
                1 + @as(
                    usize,
                    @intCast(nextTestRandom(&random_state) % 5),
                );
            for (0..clause_len) |_| {
                const random = nextTestRandom(&random_state);
                literal_storage[literal_count] = testLiteral(
                    @intCast((random >> 1) % 4),
                    random & 1 != 0,
                );
                literal_count += 1;
            }
            range.* = .{
                .start = @intCast(start),
                .len = @intCast(clause_len),
            };
        }

        const assumption_count: usize =
            @intCast(nextTestRandom(&random_state) % 4);
        for (assumptions[0..assumption_count]) |*assumption| {
            const random = nextTestRandom(&random_state);
            assumption.* = testLiteral(
                @intCast((random >> 1) % 4),
                random & 1 != 0,
            );
        }
        try expectResultMatchesBruteForce(
            4,
            ranges[0..clause_count],
            literal_storage[0..literal_count],
            assumptions[0..assumption_count],
        );
    }
}

test "wide clauses and unconstrained decisions advance linearly" {
    const variable_count = 512;
    const literals = try std.testing.allocator.alloc(
        Literal,
        variable_count,
    );
    defer std.testing.allocator.free(literals);
    for (literals, 0..) |*literal, variable| {
        literal.* = testLiteral(@intCast(variable), true);
    }
    const ranges = [_]solver_rules.LiteralRange{.{
        .start = 0,
        .len = variable_count,
    }};
    var statistics: Statistics = .{};
    var result = try testSolve(
        std.testing.allocator,
        variable_count,
        &ranges,
        literals,
        &.{},
        &statistics,
    );
    defer result.deinit();

    for (result.satisfiable.values[0 .. variable_count - 1]) |selected| {
        try std.testing.expect(!selected);
    }
    try std.testing.expect(result.satisfiable.values[variable_count - 1]);
    try std.testing.expect(statistics.decision_probes <= variable_count);
    try std.testing.expect(
        statistics.watch_inspections <= variable_count * 3,
    );
}

test "incremental optional decisions preserve the hard provider choice" {
    var packages: [3]solver_model.UniversePackage = undefined;
    var states = [_]solver_rules.PackageState{.{}} ** 3;
    var universe = solver_model.Universe{
        .allocator = std.testing.allocator,
        .repositories = &.{},
        .packages = &packages,
        .input_to_repository = &.{},
    };
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
        testLiteral(0, false),
        testLiteral(2, false),
    };
    const clauses = [_]solver_rules.Clause{
        .{
            .literals = .{ .start = 0, .len = 2 },
            .origin = .{ .job = @enumFromInt(0) },
        },
        .{
            .literals = .{ .start = 2, .len = 2 },
            .origin = .{ .job = @enumFromInt(1) },
        },
    };
    const formula = OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
        .clauses = &clauses,
        .literals = &literals,
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = &states,
    };
    var session = try IncrementalSolver.init(
        std.testing.allocator,
        &formula,
        &.{},
        .{
            .groups = &.{.{
                .clause_index = 0,
                .candidates = .{ .start = 0, .len = 2 },
            }},
            .candidates = &.{ @enumFromInt(0), @enumFromInt(1) },
        },
    );
    defer session.deinit();

    try std.testing.expect(try session.solveHard());
    try std.testing.expect(session.selected(@enumFromInt(0)).?);
    try std.testing.expect(!session.selected(@enumFromInt(1)).?);
    try std.testing.expect(!try session.trySelect(@enumFromInt(2)));
    try std.testing.expect(session.selected(@enumFromInt(0)).?);
    try std.testing.expect(!session.selected(@enumFromInt(1)).?);

    var result = try session.finish();
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, false },
        result.satisfiable.values,
    );
}

test "incremental optional packages activate contextual requirements" {
    var packages: [3]solver_model.UniversePackage = undefined;
    var states = [_]solver_rules.PackageState{.{}} ** 3;
    var universe = solver_model.Universe{
        .allocator = std.testing.allocator,
        .repositories = &.{},
        .packages = &packages,
        .input_to_repository = &.{},
    };
    const literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, false),
        testLiteral(2, true),
    };
    const clauses = [_]solver_rules.Clause{
        .{
            .literals = .{ .start = 0, .len = 1 },
            .origin = .{ .job = @enumFromInt(0) },
        },
        .{
            .literals = .{ .start = 1, .len = 2 },
            .origin = .{ .requirement = .{
                .package = @enumFromInt(1),
                .kind = .requires,
                .index = 0,
            } },
        },
    };
    const formula = OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
        .clauses = &clauses,
        .literals = &literals,
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = &states,
    };
    var session = try IncrementalSolver.init(
        std.testing.allocator,
        &formula,
        &.{},
        .{
            .groups = &.{.{
                .clause_index = 1,
                .candidates = .{ .start = 0, .len = 1 },
            }},
            .candidates = &.{@enumFromInt(2)},
        },
    );
    defer session.deinit();

    try std.testing.expect(try session.solveHard());
    try std.testing.expect(session.selected(@enumFromInt(0)).?);
    try std.testing.expect(!session.selected(@enumFromInt(1)).?);
    try std.testing.expect(!session.selected(@enumFromInt(2)).?);
    try std.testing.expect(try session.trySelect(@enumFromInt(1)));
    try std.testing.expect(session.selected(@enumFromInt(2)).?);

    var result = try session.finish();
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, true, true },
        result.satisfiable.values,
    );
}

test "rejected optional decisions preserve earlier accepted selections" {
    var packages: [4]solver_model.UniversePackage = undefined;
    var states = [_]solver_rules.PackageState{.{}} ** 4;
    var universe = solver_model.Universe{
        .allocator = std.testing.allocator,
        .repositories = &.{},
        .packages = &packages,
        .input_to_repository = &.{},
    };
    const literals = [_]Literal{
        testLiteral(0, false),
        testLiteral(1, true),
        testLiteral(2, false),
        testLiteral(3, true),
        testLiteral(2, false),
        testLiteral(3, false),
    };
    const clauses = [_]solver_rules.Clause{
        .{
            .literals = .{ .start = 0, .len = 2 },
            .origin = .{ .job = @enumFromInt(0) },
        },
        .{
            .literals = .{ .start = 2, .len = 2 },
            .origin = .{ .job = @enumFromInt(1) },
        },
        .{
            .literals = .{ .start = 4, .len = 2 },
            .origin = .{ .job = @enumFromInt(2) },
        },
    };
    const formula = OwnedFormula{
        .allocator = std.testing.allocator,
        .universe = &universe,
        .clauses = &clauses,
        .literals = &literals,
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = &states,
    };
    var session = try IncrementalSolver.init(
        std.testing.allocator,
        &formula,
        &.{},
        .{},
    );
    defer session.deinit();

    try std.testing.expect(try session.solveHard());
    try std.testing.expect(try session.trySelect(@enumFromInt(0)));
    try std.testing.expect(session.selected(@enumFromInt(1)).?);
    try std.testing.expect(!try session.trySelect(@enumFromInt(2)));
    try std.testing.expect(session.selected(@enumFromInt(0)).?);
    try std.testing.expect(session.selected(@enumFromInt(1)).?);

    var result = try session.finish();
    defer result.deinit();
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, true, false, false },
        result.satisfiable.values,
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    const satisfiable_literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
        testLiteral(0, true),
        testLiteral(1, false),
    };
    const satisfiable_ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
        .{ .start = 2, .len = 2 },
    };
    var satisfiable = try testSolve(
        allocator,
        2,
        &satisfiable_ranges,
        &satisfiable_literals,
        &.{},
        null,
    );
    defer satisfiable.deinit();

    const unsatisfiable_literals = [_]Literal{
        testLiteral(0, true),
        testLiteral(1, true),
        testLiteral(0, true),
        testLiteral(1, false),
        testLiteral(0, false),
        testLiteral(1, true),
        testLiteral(0, false),
        testLiteral(1, false),
    };
    const unsatisfiable_ranges = [_]solver_rules.LiteralRange{
        .{ .start = 0, .len = 2 },
        .{ .start = 2, .len = 2 },
        .{ .start = 4, .len = 2 },
        .{ .start = 6, .len = 2 },
    };
    var unsatisfiable = try testSolve(
        allocator,
        2,
        &unsatisfiable_ranges,
        &unsatisfiable_literals,
        &.{},
        null,
    );
    defer unsatisfiable.deinit();

    const candidates = [_]solver_model.PackageId{
        @enumFromInt(1),
        @enumFromInt(0),
    };
    var contextual = try testSolveCandidatePolicy(
        allocator,
        2,
        satisfiable_ranges[0..1],
        satisfiable_literals[0..2],
        &.{},
        .{
            .groups = &.{.{
                .clause_index = 0,
                .candidates = .{ .start = 0, .len = 2 },
            }},
            .candidates = &candidates,
        },
        null,
    );
    defer contextual.deinit();

    var packages: [2]solver_model.UniversePackage = undefined;
    var states = [_]solver_rules.PackageState{.{}} ** 2;
    var universe = solver_model.Universe{
        .allocator = allocator,
        .repositories = &.{},
        .packages = &packages,
        .input_to_repository = &.{},
    };
    const incremental_clauses = [_]solver_rules.Clause{.{
        .literals = .{ .start = 0, .len = 2 },
        .origin = .{ .job = @enumFromInt(0) },
    }};
    const incremental = OwnedFormula{
        .allocator = allocator,
        .universe = &universe,
        .clauses = &incremental_clauses,
        .literals = satisfiable_literals[0..2],
        .weak_requests = &.{},
        .weak_candidates = &.{},
        .package_states = &states,
    };
    var session = try IncrementalSolver.init(
        allocator,
        &incremental,
        &.{},
        .{
            .groups = &.{.{
                .clause_index = 0,
                .candidates = .{ .start = 0, .len = 2 },
            }},
            .candidates = &candidates,
        },
    );
    defer session.deinit();
    if (!try session.solveHard()) return error.TestUnexpectedResult;
    _ = try session.trySelect(@enumFromInt(0));
    var incremental_result = try session.finish();
    defer incremental_result.deinit();
}

test "search cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

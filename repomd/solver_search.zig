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

pub const DecisionPolicy = struct {
    /// Complete variable permutation in decision order.
    order: []const solver_model.PackageId = &.{},
    /// Preferred value per `PackageId`; defaults to false.
    preferred_values: []const bool = &.{},
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
    return solveInternal(allocator, formula, &.{}, .{}, null);
}

/// Solve every formula clause plus the supplied level-zero assumptions.
pub fn solveAssuming(
    allocator: std.mem.Allocator,
    formula: *const OwnedFormula,
    assumptions: []const Literal,
) SolveError!Result {
    return solveInternal(allocator, formula, assumptions, .{}, null);
}

/// Solve with a complete deterministic variable order and polarity policy.
pub fn solveWithDecisionPolicy(
    allocator: std.mem.Allocator,
    formula: *const OwnedFormula,
    assumptions: []const Literal,
    decision_policy: DecisionPolicy,
) SolveError!Result {
    return solveInternal(
        allocator,
        formula,
        assumptions,
        decision_policy,
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
};

const Analysis = struct {
    literals: []const Literal,
    backtrack_level: u32,
};

const ClauseList = std.array_list.Managed(ClauseData);
const LiteralList = std.array_list.Managed(Literal);
const IndexList = std.array_list.Managed(usize);

const Engine = struct {
    allocator: std.mem.Allocator,
    variable_count: usize,
    clauses: ClauseList,
    literals: LiteralList,
    watches: []IndexList,
    assignments: []Value,
    levels: []u32,
    reasons: []?usize,
    seen: []bool,
    decision_order: []usize,
    decision_positions: []usize,
    preferred_values: []bool,
    trail: LiteralList,
    trail_limits: IndexList,
    propagation_head: usize = 0,
    decision_cursor: usize = 0,
    normalize_scratch: LiteralList,
    analysis_scratch: LiteralList,
    has_empty_clause: bool = false,
    statistics: Statistics = .{},

    fn init(
        allocator: std.mem.Allocator,
        variable_count: usize,
        decision_policy: DecisionPolicy,
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

        return .{
            .allocator = allocator,
            .variable_count = variable_count,
            .clauses = ClauseList.init(allocator),
            .literals = LiteralList.init(allocator),
            .watches = watches,
            .assignments = assignments,
            .levels = levels,
            .reasons = reasons,
            .seen = seen,
            .decision_order = decision_order,
            .decision_positions = decision_positions,
            .preferred_values = preferred_values,
            .trail = LiteralList.init(allocator),
            .trail_limits = IndexList.init(allocator),
            .normalize_scratch = LiteralList.init(allocator),
            .analysis_scratch = LiteralList.init(allocator),
        };
    }

    fn deinit(self: *Engine) void {
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

    fn run(self: *Engine) SolveError!bool {
        if (!try self.initializeRoot()) return false;

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

            const decision_variable = self.chooseDecision() orelse return true;
            try self.trail_limits.append(self.trail.items.len);
            self.statistics.decisions += 1;
            const decision_literal = Literal.init(
                @enumFromInt(@as(u32, @intCast(decision_variable))),
                self.preferred_values[decision_variable],
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
        for (self.trail.items[target_trail_len..]) |literal| {
            const variable = literalVariable(literal);
            self.assignments[variable] = .unassigned;
            self.levels[variable] = 0;
            self.reasons[variable] = null;
            self.decision_cursor = @min(
                self.decision_cursor,
                self.decision_positions[variable],
            );
        }
        self.trail.shrinkRetainingCapacity(target_trail_len);
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
        self.assignments[variable] = wanted;
        self.levels[variable] = self.decisionLevel();
        self.reasons[variable] = reason;
        return true;
    }

    fn chooseDecision(self: *Engine) ?usize {
        while (self.decision_cursor < self.assignments.len) {
            self.statistics.decision_probes += 1;
            const decision = self.decision_order[self.decision_cursor];
            if (self.assignments[decision] == .unassigned) {
                self.decision_cursor += 1;
                return decision;
            }
            self.decision_cursor += 1;
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

fn solveInternal(
    allocator: std.mem.Allocator,
    formula: *const OwnedFormula,
    assumptions: []const Literal,
    decision_policy: DecisionPolicy,
    statistics: ?*Statistics,
) SolveError!Result {
    const variable_count = formula.universe.packages.len;
    if (formula.package_states.len != variable_count) {
        return error.InvalidFormula;
    }

    var engine = try Engine.init(
        allocator,
        variable_count,
        decision_policy,
    );
    defer engine.deinit();

    for (formula.literals) |literal| {
        if (!validLiteral(literal, variable_count)) {
            return error.InvalidFormula;
        }
    }
    for (formula.clauses) |clause| {
        const start: usize = @intCast(clause.literals.start);
        const len: usize = @intCast(clause.literals.len);
        if (start > formula.literals.len or
            len > formula.literals.len - start)
        {
            return error.InvalidFormula;
        }
        _ = try engine.addInputClause(formula.literals[start .. start + len]);
    }
    for (assumptions) |assumption| {
        try engine.addAssumption(assumption);
    }

    const satisfiable = try engine.run();
    if (statistics) |out| out.* = engine.statistics;
    if (!satisfiable) return .{ .unsatisfiable = {} };
    if (!engine.validateModel()) return error.InternalSolverFailure;
    return .{ .satisfiable = try engine.makeModel() };
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
) SolveError!Result {
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
) SolveError!Result {
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
        decision_policy,
        statistics,
    );
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
                variable_count,
                ranges,
                literals,
                assumptions,
                assignment,
            ));
        },
        .unsatisfiable => try std.testing.expect(!expected),
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
}

test "search cleans up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

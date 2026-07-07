// Copyright (C) 2015-2023 VMware, Inc. All Rights Reserved.
//
// Licensed under the GNU Lesser General Public License v2.1 (the "License");
// you may not use this file except in compliance with the License. The terms
// of the License are located in the COPYING file of this distribution.

// Pull the Zig-backed common component slices into one root module so their
// `export fn` declarations are reachable from C.
comptime {
    _ = @import("memory.zig");
    _ = @import("log.zig");
    _ = @import("lock.zig");
}

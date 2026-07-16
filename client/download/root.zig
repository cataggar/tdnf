const std = @import("std");
const tls = @import("tls");
const errors = @import("tdnf_error");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Uri = std.Uri;
const ResponseHead = std.http.Client.Response.Head;
const RedirectLimit: usize = 10;
const RequestHeadMaxLen: usize = 8192;
const StreamBufLen: usize = 8192;
const TestScratchDir = ".zig-cache/tdnf-download-tests";

pub const TDNF_ZIG_XFERINFOFUNCTION = *const fn (
    userdata: ?*anyopaque,
    dltotal: i64,
    dlnow: i64,
    ultotal: i64,
    ulnow: i64,
) callconv(.c) c_int;

pub const TDNF_ZIG_DOWNLOAD_REQUEST = extern struct {
    pszUrl: ?[*:0]const u8,
    pszDestination: ?[*:0]const u8,
    pfnProgress: ?TDNF_ZIG_XFERINFOFUNCTION,
    pProgressData: ?*anyopaque,
    pszUserAgent: ?[*:0]const u8,
    pszProxy: ?[*:0]const u8,
    pszProxyUserPwd: ?[*:0]const u8,
    pszUserName: ?[*:0]const u8,
    pszPassword: ?[*:0]const u8,
    pszSSLCaCert: ?[*:0]const u8,
    pszSSLClientCert: ?[*:0]const u8,
    pszSSLClientKey: ?[*:0]const u8,
    nSSLVerify: c_int,
    nConnectTimeout: c_long,
    nTimeout: c_long,
    nLowSpeedLimit: c_long,
    nLowSpeedTime: c_long,
    nMaxRecvSpeed: c_long,
};

const DownloadRequest = struct {
    url: []const u8,
    destination: []const u8,
    progress_fn: ?TDNF_ZIG_XFERINFOFUNCTION,
    progress_data: ?*anyopaque,
    user_agent: ?[]const u8,
    proxy_url: ?[]const u8,
    proxy_userpwd: ?[]const u8,
    username: ?[]const u8,
    password: ?[]const u8,
    ca_cert: ?[]const u8,
    client_cert: ?[]const u8,
    client_key: ?[]const u8,
    ssl_verify: bool,
    connect_timeout_secs: u32,
    total_timeout_secs: u32,
    low_speed_limit: u64,
    low_speed_time_secs: u32,
    max_recv_speed: u64,
};

const DownloadOutcome = union(enum) {
    status: u16,
    redirect: Uri,
};

const DownloadTransport = enum {
    file,
    std_http,
    tls_http,
};

const ParsedProxy = struct {
    uri: Uri,
    authorization: ?[]const u8,
};

const StdHttpTransport = struct {
    allocator: Allocator,
    io: Io,
    request: DownloadRequest,
    client: std.http.Client,
    proxy: ?*std.http.Client.Proxy = null,
    authorization: ?[]const u8 = null,
    custom_ca_loaded: bool = false,

    fn init(allocator: Allocator, io: Io, request: DownloadRequest) !StdHttpTransport {
        var transport = StdHttpTransport{
            .allocator = allocator,
            .io = io,
            .request = request,
            .client = .{
                .allocator = allocator,
                .io = io,
            },
        };
        if (request.proxy_url) |proxy_url| {
            const parsed = try parseProxy(allocator, proxy_url, request.proxy_userpwd);
            const host = try parsed.uri.getHostAlloc(allocator);
            const protocol = std.http.Client.Protocol.fromUri(parsed.uri) orelse return error.UnsupportedConfiguration;
            const proxy = try allocator.create(std.http.Client.Proxy);
            proxy.* = .{
                .protocol = protocol,
                .host = host,
                .authorization = parsed.authorization,
                .port = parsed.uri.port orelse switch (protocol) {
                    .plain => 80,
                    .tls => 443,
                },
                .supports_connect = true,
            };
            transport.proxy = proxy;
            transport.client.http_proxy = proxy;
            transport.client.https_proxy = proxy;
        }
        if (request.username != null and request.password != null) {
            transport.authorization = try buildBasicAuthorizationFromFields(
                allocator,
                request.username.?,
                request.password.?,
            );
        }
        return transport;
    }

    fn deinit(self: *StdHttpTransport) void {
        self.client.deinit();
    }

    fn ensureCustomCaLoaded(self: *StdHttpTransport) !void {
        if (self.request.ca_cert == null or self.custom_ca_loaded) {
            return;
        }
        const now = Io.Clock.real.now(self.io);
        self.client.ca_bundle.rescan(self.allocator, self.io, now) catch |err| {
            setError("failed to load system CA bundle: {}", .{err});
            return error.TlsConfiguration;
        };
        self.client.ca_bundle.addCertsFromFilePathAbsolute(self.allocator, self.io, now, self.request.ca_cert.?) catch |err| {
            setError("failed to add CA cert {s}: {}", .{ self.request.ca_cert.?, err });
            return error.TlsConfiguration;
        };
        self.client.now = now;
        self.custom_ca_loaded = true;
    }

    fn doRequest(self: *StdHttpTransport, arena: Allocator, uri: Uri) !DownloadOutcome {
        if (schemeEq(uri.scheme, "https") and self.request.ca_cert != null) {
            try self.ensureCustomCaLoaded();
        }

        const headers = try self.buildHeaders(arena, uri);
        var request = self.client.request(.GET, uri, .{
            .keep_alive = false,
            .redirect_behavior = .unhandled,
            .headers = headers,
        }) catch |err| {
            setError("std.http request init failed: {}", .{err});
            return mapStdHttpRequestError(err);
        };
        defer request.deinit();

        if (effectiveSocketTimeoutSecs(self.request)) |seconds| {
            try applySocketTimeouts(request.connection.?.stream_reader.stream, seconds);
        }

        request.sendBodiless() catch |err| {
            setError("std.http send failed: {}", .{err});
            return error.TransportWriteFailed;
        };

        var response = request.receiveHead(&.{}) catch |err| {
            if (err == error.ReadFailed) {
                if (request.connection) |conn| {
                    if (conn.getReadError()) |read_err| {
                        setError("std.http receive head failed: {}", .{read_err});
                    }
                }
            } else {
                setError("std.http receive head failed: {}", .{err});
            }
            return mapStdHttpHeadError(err);
        };

        const status = @as(u16, @intFromEnum(response.head.status));
        if (response.head.status.class() == .redirect) {
            const location = response.head.location orelse {
                setError("redirect missing location for {s}", .{self.request.url});
                return error.HttpRedirectMissing;
            };
            const next_uri = try resolveRedirect(arena, uri, location);
            try discardStdHttpBody(&response);
            return .{ .redirect = next_uri };
        }

        if (status >= 400) {
            try discardStdHttpBody(&response);
            return .{ .status = status };
        }

        var output = try openOutputFile(self.io, self.request.destination);
        defer output.close(self.io);

        var control = try TransferControl.init(self.io, self.request, response.head.content_length);
        defer control.finish() catch {};

        var transfer_buffer: [StreamBufLen]u8 = undefined;
        const reader = response.reader(&transfer_buffer);
        streamReaderToFile(
            self.io,
            reader,
            &output,
            &control,
        ) catch |err| {
            if (err == error.ReadFailed) {
                if (request.connection) |conn| {
                    if (conn.getReadError()) |read_err| {
                        setError("std.http body read failed: {}", .{read_err});
                    }
                } else if (response.bodyErr()) |body_err| {
                    setError("std.http body read failed: {}", .{body_err});
                }
            } else {
                setError("std.http body download failed: {}", .{err});
            }
            return err;
        };

        return .{ .status = status };
    }

    fn buildHeaders(self: *StdHttpTransport, arena: Allocator, uri: Uri) !std.http.Client.Request.Headers {
        var headers: std.http.Client.Request.Headers = .{
            .user_agent = if (self.request.user_agent) |user_agent| .{ .override = user_agent } else .omit,
            .authorization = .default,
            .accept_encoding = .omit,
        };
        if (self.authorization) |authorization| {
            headers.authorization = .{ .override = authorization };
        } else if (uri.user != null or uri.password != null) {
            const len = std.http.Client.basic_authorization.valueLengthFromUri(uri);
            const value = try arena.alloc(u8, len);
            _ = std.http.Client.basic_authorization.value(uri, value);
            headers.authorization = .{ .override = value };
        }
        return headers;
    }
};

const TlsHttpTransport = struct {
    allocator: Allocator,
    io: Io,
    request: DownloadRequest,
    proxy: ?ParsedProxy = null,
    authorization: ?[]const u8 = null,
    root_ca: tls.config.cert.Bundle = .empty,
    root_ca_loaded: bool = false,
    client_auth: ?tls.config.CertKeyPair = null,
    client_auth_loaded: bool = false,

    fn init(allocator: Allocator, io: Io, request: DownloadRequest) !TlsHttpTransport {
        var transport = TlsHttpTransport{
            .allocator = allocator,
            .io = io,
            .request = request,
        };
        if (request.proxy_url) |proxy_url| {
            transport.proxy = try parseProxy(allocator, proxy_url, request.proxy_userpwd);
        }
        if (request.username != null and request.password != null) {
            transport.authorization = try buildBasicAuthorizationFromFields(
                allocator,
                request.username.?,
                request.password.?,
            );
        }
        if (request.client_cert != null or request.client_key != null) {
            if (request.client_cert == null or request.client_key == null) {
                return error.UnsupportedConfiguration;
            }
            transport.client_auth = try tls.config.CertKeyPair.fromFilePathAbsolute(
                allocator,
                io,
                request.client_cert.?,
                request.client_key.?,
            );
            transport.client_auth_loaded = true;
        }
        return transport;
    }

    fn deinit(self: *TlsHttpTransport) void {
        if (self.client_auth_loaded) {
            self.client_auth.?.deinit(self.allocator);
        }
        if (self.root_ca_loaded) {
            self.root_ca.deinit(self.allocator);
        }
    }

    fn ensureRootCa(self: *TlsHttpTransport) !void {
        if (!self.request.ssl_verify or self.root_ca_loaded) {
            return;
        }
        self.root_ca = tls.config.cert.fromSystem(self.allocator, self.io) catch |err| {
            setError("failed to load system CA bundle: {}", .{err});
            return error.TlsConfiguration;
        };
        self.root_ca_loaded = true;
        if (self.request.ca_cert) |ca_cert| {
            self.root_ca.addCertsFromFilePathAbsolute(
                self.allocator,
                self.io,
                Io.Clock.real.now(self.io),
                ca_cert,
            ) catch |err| {
                setError("failed to add CA cert {s}: {}", .{ ca_cert, err });
                return error.TlsConfiguration;
            };
        }
    }

    fn doRequest(self: *TlsHttpTransport, arena: Allocator, uri: Uri) !DownloadOutcome {
        if (self.proxy) |proxy| {
            const protocol = std.http.Client.Protocol.fromUri(proxy.uri) orelse return error.UnsupportedConfiguration;
            if (protocol != .plain) {
                return error.UnsupportedConfiguration;
            }
        }
        try self.ensureRootCa();

        var host_buf: [Io.net.HostName.max_len]u8 = undefined;
        const host_name = uri.getHost(&host_buf) catch {
            setError("missing host in URL {s}", .{self.request.url});
            return error.InvalidUrl;
        };
        const port = uri.port orelse 443;
        const socket_timeout = effectiveSocketTimeoutSecs(self.request);

        var tcp = try connectTcp(self.io, host_name, port, self.request.connect_timeout_secs, self.proxy);
        defer tcp.close(self.io);
        if (socket_timeout) |seconds| {
            try applySocketTimeouts(tcp, seconds);
        }

        var tcp_reader_buf: [tls.input_buffer_len]u8 = undefined;
        var tcp_writer_buf: [tls.output_buffer_len]u8 = undefined;
        var tcp_reader = tcp.reader(self.io, &tcp_reader_buf);
        var tcp_writer = tcp.writer(self.io, &tcp_writer_buf);

        if (self.proxy) |proxy| {
            try sendConnectRequest(
                &tcp_reader.interface,
                &tcp_writer.interface,
                uri,
                proxy.authorization,
                self.request.user_agent,
            );
        }

        var rng_impl: std.Random.IoSource = .{ .io = self.io };
        var conn = tls.client(
            &tcp_reader.interface,
            &tcp_writer.interface,
            .{
                .host = host_name.bytes,
                .root_ca = if (self.request.ssl_verify) self.root_ca else .empty,
                .insecure_skip_verify = !self.request.ssl_verify,
                .auth = if (self.client_auth_loaded) &self.client_auth.? else null,
                .alpn_protocols = &.{"http/1.1"},
                .now = Io.Clock.real.now(self.io),
                .rng = rng_impl.interface(),
            },
        ) catch |err| {
            setError("tls handshake failed: {}", .{err});
            return error.TlsHandshakeFailed;
        };
        defer conn.close() catch {};

        try writeTlsRequest(
            &conn,
            uri,
            self.request.user_agent,
            self.authorization,
            arena,
        );

        var http_reader_buf: [RequestHeadMaxLen]u8 = undefined;
        var conn_reader = conn.reader(&http_reader_buf);
        var response = receiveResponseHead(&conn_reader.interface) catch |err| {
            setError("tls http receive head failed: {}", .{err});
            return err;
        };
        const status = @as(u16, @intFromEnum(response.head.status));

        if (response.head.status.class() == .redirect) {
            const location = response.head.location orelse {
                setError("redirect missing location for {s}", .{self.request.url});
                return error.HttpRedirectMissing;
            };
            const next_uri = try resolveRedirect(arena, uri, location);
            try discardHttpBody(&response.reader, response.head.transfer_encoding, response.head.content_length);
            return .{ .redirect = next_uri };
        }

        if (status >= 400) {
            try discardHttpBody(&response.reader, response.head.transfer_encoding, response.head.content_length);
            return .{ .status = status };
        }

        var output = try openOutputFile(self.io, self.request.destination);
        defer output.close(self.io);

        var control = try TransferControl.init(self.io, self.request, response.head.content_length);
        defer control.finish() catch {};

        var transfer_buffer: [StreamBufLen]u8 = undefined;
        const body_reader = response.reader.bodyReader(&transfer_buffer, response.head.transfer_encoding, response.head.content_length);
        streamReaderToFile(self.io, body_reader, &output, &control) catch |err| {
            if (err == error.ReadFailed) {
                if (tcp_reader.err) |read_err| {
                    setError("tls body read failed: {}", .{read_err});
                } else {
                    setError("tls body read failed", .{});
                }
            } else {
                setError("tls body download failed: {}", .{err});
            }
            return err;
        };

        return .{ .status = status };
    }
};

const ReceivedHead = struct {
    reader: std.http.Reader,
    head: ResponseHead,
};

const TransferControl = struct {
    io: Io,
    request: DownloadRequest,
    total_size: ?u64,
    downloaded: u64 = 0,
    overall_start: Io.Clock.Timestamp,
    low_speed_start: Io.Clock.Timestamp,
    throttle_start: Io.Clock.Timestamp,
    low_speed_bytes: u64 = 0,

    fn init(io: Io, request: DownloadRequest, total_size: ?u64) !TransferControl {
        const now = Io.Clock.Timestamp.now(io, .awake);
        var control = TransferControl{
            .io = io,
            .request = request,
            .total_size = total_size,
            .overall_start = now,
            .low_speed_start = now,
            .throttle_start = now,
        };
        try control.reportProgress();
        return control;
    }

    fn noteBytes(self: *TransferControl, bytes: usize) !void {
        self.downloaded += bytes;
        self.low_speed_bytes += bytes;
        try self.checkElapsed();
        try self.enforceLowSpeed();
        try self.enforceThrottle();
        try self.reportProgress();
    }

    fn checkElapsed(self: *TransferControl) !void {
        if (self.request.total_timeout_secs == 0) {
            return;
        }
        const elapsed_ns = timestampElapsedNs(self.io, self.overall_start);
        if (elapsed_ns > @as(u64, self.request.total_timeout_secs) * std.time.ns_per_s) {
            return error.Timeout;
        }
    }

    fn enforceLowSpeed(self: *TransferControl) !void {
        if (self.request.low_speed_limit == 0 or self.request.low_speed_time_secs == 0) {
            return;
        }
        const elapsed_ns = timestampElapsedNs(self.io, self.low_speed_start);
        const threshold_ns = @as(u64, self.request.low_speed_time_secs) * std.time.ns_per_s;
        if (elapsed_ns < threshold_ns) {
            return;
        }
        const required = (@as(u128, self.request.low_speed_limit) * @as(u128, elapsed_ns)) / std.time.ns_per_s;
        if (@as(u128, self.low_speed_bytes) < required) {
            return error.LowSpeedLimit;
        }
        self.low_speed_start = Io.Clock.Timestamp.now(self.io, .awake);
        self.low_speed_bytes = 0;
    }

    fn enforceThrottle(self: *TransferControl) !void {
        if (self.request.max_recv_speed == 0) {
            return;
        }
        const elapsed_ns = timestampElapsedNs(self.io, self.throttle_start);
        if (elapsed_ns == 0) {
            return;
        }
        const allowed = (@as(u128, self.request.max_recv_speed) * @as(u128, elapsed_ns)) / std.time.ns_per_s;
        if (@as(u128, self.downloaded) <= allowed) {
            return;
        }
        const excess = @as(u128, self.downloaded) - allowed;
        const sleep_ns = (excess * std.time.ns_per_s) / self.request.max_recv_speed;
        try Io.sleep(self.io, Io.Duration.fromNanoseconds(@intCast(sleep_ns)), .awake);
    }

    fn reportProgress(self: *TransferControl) !void {
        if (self.request.progress_fn == null) {
            return;
        }
        const total = if (self.total_size) |size|
            toCurlOff(size)
        else
            0;
        if (self.request.progress_fn.?(self.request.progress_data, total, toCurlOff(self.downloaded), 0, 0) != 0) {
            return error.OperationAborted;
        }
    }

    fn finish(self: *TransferControl) !void {
        try self.reportProgress();
    }
};

threadlocal var last_error_buf: [512]u8 = undefined;
threadlocal var last_error_len: usize = 0;

fn clearError() void {
    last_error_len = 0;
}

fn setError(comptime fmt: []const u8, args: anytype) void {
    const msg = std.fmt.bufPrint(&last_error_buf, fmt, args) catch blk: {
        const fallback = "(error message truncated)";
        @memcpy(last_error_buf[0..fallback.len], fallback);
        break :blk last_error_buf[0..fallback.len];
    };
    last_error_len = msg.len;
}

fn ensureErrorSet(comptime fmt: []const u8, args: anytype) void {
    if (last_error_len == 0) {
        setError(fmt, args);
    }
}

pub export fn TDNFZigDownloadLastError() [*:0]const u8 {
    if (last_error_len >= last_error_buf.len) {
        last_error_len = last_error_buf.len - 1;
    }
    last_error_buf[last_error_len] = 0;
    return @ptrCast(&last_error_buf);
}

pub export fn TDNFZigDownloadFile(
    raw_request: ?*const TDNF_ZIG_DOWNLOAD_REQUEST,
    out_status: ?*c_long,
) u32 {
    clearError();
    if (out_status) |status| {
        status.* = 0;
    }
    const request_ptr = raw_request orelse {
        setError("null download request", .{});
        return errors.ERROR_TDNF_INVALID_PARAMETER;
    };
    const request = parseRequest(request_ptr) catch |err| {
        if (err == error.InvalidParameter) {
            ensureErrorSet("invalid download request", .{});
            return errors.ERROR_TDNF_INVALID_PARAMETER;
        }
        ensureErrorSet("failed to parse request: {}", .{err});
        return errors.ERROR_TDNF_INVALID_PARAMETER;
    };

    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();

    var io_state: std.Io.Threaded = .init(std.heap.c_allocator, .{});
    defer io_state.deinit();
    const io = io_state.io();

    const status = downloadWithIo(arena_state.allocator(), io, request) catch |err| {
        if (err == error.UnsupportedConfiguration) {
            ensureErrorSet("download configuration not yet supported by zig transport", .{});
            return errors.ERROR_TDNF_CALL_NOT_SUPPORTED;
        }
        if (err == error.InvalidUrl) {
            ensureErrorSet("invalid URL: {s}", .{request.url});
            return errors.ERROR_TDNF_URL_INVALID;
        }
        if (err == error.TlsConfiguration) {
            ensureErrorSet("tls configuration failed", .{});
            return errors.ERROR_TDNF_SET_SSL_SETTINGS;
        }
        if (err == error.Timeout or err == error.LowSpeedLimit) {
            ensureErrorSet("download timed out", .{});
            return errors.ERROR_TDNF_TIMED_OUT;
        }
        if (err == error.OperationAborted) {
            ensureErrorSet("progress callback aborted download", .{});
            return errors.ERROR_TDNF_OPERATION_ABORTED;
        }
        if (err == error.OutOfMemory) {
            ensureErrorSet("out of memory", .{});
            return errors.ERROR_TDNF_OUT_OF_MEMORY;
        }
        ensureErrorSet("download failed: {}", .{err});
        return errors.ERROR_TDNF_REPO_PERFORM;
    };

    if (out_status) |status_out| {
        status_out.* = @intCast(status);
    }
    if (status >= 400) {
        setError("HTTP status {d} while downloading {s}", .{ status, request.url });
        return errors.ERROR_TDNF_INVALID_PARAMETER;
    }
    return 0;
}

fn parseRequest(raw_request: *const TDNF_ZIG_DOWNLOAD_REQUEST) !DownloadRequest {
    const url = requiredSpan(raw_request.pszUrl) orelse return error.InvalidParameter;
    const destination = requiredSpan(raw_request.pszDestination) orelse return error.InvalidParameter;

    return .{
        .url = url,
        .destination = destination,
        .progress_fn = raw_request.pfnProgress,
        .progress_data = raw_request.pProgressData,
        .user_agent = optionalSpan(raw_request.pszUserAgent),
        .proxy_url = optionalSpan(raw_request.pszProxy),
        .proxy_userpwd = optionalSpan(raw_request.pszProxyUserPwd),
        .username = optionalSpan(raw_request.pszUserName),
        .password = optionalSpan(raw_request.pszPassword),
        .ca_cert = optionalSpan(raw_request.pszSSLCaCert),
        .client_cert = optionalSpan(raw_request.pszSSLClientCert),
        .client_key = optionalSpan(raw_request.pszSSLClientKey),
        .ssl_verify = raw_request.nSSLVerify != 0,
        .connect_timeout_secs = try longToU32(raw_request.nConnectTimeout),
        .total_timeout_secs = try longToU32(raw_request.nTimeout),
        .low_speed_limit = try longToU64(raw_request.nLowSpeedLimit),
        .low_speed_time_secs = try longToU32(raw_request.nLowSpeedTime),
        .max_recv_speed = try longToU64(raw_request.nMaxRecvSpeed),
    };
}

fn downloadWithIo(allocator: Allocator, io: Io, request: DownloadRequest) !u16 {
    var current_uri = Uri.parse(request.url) catch {
        setError("invalid URL: {s}", .{request.url});
        return error.InvalidUrl;
    };

    var std_transport: ?StdHttpTransport = null;
    defer if (std_transport) |*transport| transport.deinit();

    var tls_transport: ?TlsHttpTransport = null;
    defer if (tls_transport) |*transport| transport.deinit();

    var redirects: usize = 0;
    while (true) {
        const outcome = switch (try chooseTransport(current_uri, request)) {
            .file => try downloadFileUri(io, request, current_uri),
            .std_http => blk: {
                if (std_transport == null) {
                    std_transport = try StdHttpTransport.init(allocator, io, request);
                }
                break :blk try std_transport.?.doRequest(allocator, current_uri);
            },
            .tls_http => blk: {
                if (tls_transport == null) {
                    tls_transport = try TlsHttpTransport.init(allocator, io, request);
                }
                break :blk try tls_transport.?.doRequest(allocator, current_uri);
            },
        };
        switch (outcome) {
            .status => |status| return status,
            .redirect => |next_uri| {
                redirects += 1;
                if (redirects > RedirectLimit) {
                    setError("too many redirects while downloading {s}", .{request.url});
                    return error.TooManyRedirects;
                }
                current_uri = next_uri;
            },
        }
    }
}

fn chooseTransport(uri: Uri, request: DownloadRequest) !DownloadTransport {
    if (schemeEq(uri.scheme, "file")) {
        return .file;
    }
    if (schemeEq(uri.scheme, "http")) {
        if (request.connect_timeout_secs != 0) {
            return error.UnsupportedConfiguration;
        }
        return .std_http;
    }
    if (schemeEq(uri.scheme, "https")) {
        const has_client_auth = request.client_cert != null and request.client_key != null;
        const has_partial_client_auth = (request.client_cert != null) != (request.client_key != null);
        if (has_partial_client_auth) {
            return error.UnsupportedConfiguration;
        }
        if (!request.ssl_verify or request.ca_cert != null or has_client_auth) {
            return .tls_http;
        }
        if (request.connect_timeout_secs != 0) {
            return error.UnsupportedConfiguration;
        }
        return .std_http;
    }
    return error.InvalidUrl;
}

fn downloadFileUri(io: Io, request: DownloadRequest, uri: Uri) !DownloadOutcome {
    const source_path = try filePathFromUri(std.heap.c_allocator, uri);
    defer std.heap.c_allocator.free(source_path);

    var source = try openInputFile(io, source_path);
    defer source.close(io);

    var output = try openOutputFile(io, request.destination);
    defer output.close(io);

    const source_stat = source.stat(io) catch null;
    const total_size = if (source_stat) |stat|
        if (stat.size == 0) null else stat.size
    else
        null;
    var control = try TransferControl.init(io, request, total_size);
    defer control.finish() catch {};

    var reader_buf: [StreamBufLen]u8 = undefined;
    var reader = source.reader(io, &reader_buf);
    try streamReaderToFile(io, &reader.interface, &output, &control);

    return .{ .status = 200 };
}

fn connectTcp(
    io: Io,
    host_name: Io.net.HostName,
    port: u16,
    connect_timeout_secs: u32,
    proxy: ?ParsedProxy,
) !Io.net.Stream {
    const timeout: Io.Timeout = if (connect_timeout_secs == 0)
        .none
    else
        .{ .duration = .{
            .clock = .awake,
            .raw = Io.Duration.fromSeconds(connect_timeout_secs),
        } };

    if (proxy) |parsed| {
        var proxy_host_buf: [Io.net.HostName.max_len]u8 = undefined;
        const proxy_host = parsed.uri.getHost(&proxy_host_buf) catch return error.InvalidUrl;
        const proxy_port = parsed.uri.port orelse 80;
        return proxy_host.connect(io, proxy_port, .{ .mode = .stream, .timeout = timeout });
    }
    return host_name.connect(io, port, .{ .mode = .stream, .timeout = timeout });
}

fn sendConnectRequest(
    reader: *Io.Reader,
    writer: *Io.Writer,
    uri: Uri,
    proxy_authorization: ?[]const u8,
    user_agent: ?[]const u8,
) !void {
    var host_buf: [Io.net.HostName.max_len]u8 = undefined;
    const host_name = uri.getHost(&host_buf) catch return error.InvalidUrl;
    const port = uri.port orelse 443;

    var req_buf: [2048]u8 = undefined;
    var req_writer: Io.Writer = .fixed(&req_buf);
    try req_writer.print("CONNECT {s}:{d} HTTP/1.1\r\nHost: {s}:{d}\r\n", .{ host_name.bytes, port, host_name.bytes, port });
    if (user_agent) |value| {
        try req_writer.print("User-Agent: {s}\r\n", .{value});
    }
    if (proxy_authorization) |value| {
        try req_writer.print("Proxy-Authorization: {s}\r\n", .{value});
    }
    try req_writer.writeAll("Connection: close\r\n\r\n");
    try writer.writeAll(req_writer.buffered());
    try writer.flush();

    var response = try receiveResponseHead(reader);
    const status = @as(u16, @intFromEnum(response.head.status));
    if (status != 200) {
        setError("proxy CONNECT failed with status {d}", .{status});
        return error.ProxyConnectFailed;
    }
    try discardHttpBody(&response.reader, response.head.transfer_encoding, response.head.content_length);
}

fn writeTlsRequest(
    conn: *tls.Connection,
    uri: Uri,
    user_agent: ?[]const u8,
    authorization: ?[]const u8,
    arena: Allocator,
) !void {
    var req_buf: [2048]u8 = undefined;
    var req_writer: Io.Writer = .fixed(&req_buf);
    try req_writer.writeAll("GET ");
    try writeRequestTarget(&req_writer, uri);
    try req_writer.writeAll(" HTTP/1.1\r\nHost: ");
    try writeAuthority(&req_writer, uri);
    try req_writer.writeAll("\r\nConnection: close\r\nAccept-Encoding:\r\n");
    if (user_agent) |value| {
        try req_writer.print("User-Agent: {s}\r\n", .{value});
    }
    if (authorization) |value| {
        try req_writer.print("Authorization: {s}\r\n", .{value});
    } else if (uri.user != null or uri.password != null) {
        const len = std.http.Client.basic_authorization.valueLengthFromUri(uri);
        const header = try arena.alloc(u8, len);
        _ = std.http.Client.basic_authorization.value(uri, header);
        try req_writer.print("Authorization: {s}\r\n", .{header});
    }
    try req_writer.writeAll("\r\n");
    try conn.writeAll(req_writer.buffered());
}

fn receiveResponseHead(reader: *Io.Reader) !ReceivedHead {
    var http_reader: std.http.Reader = .{
        .in = reader,
        .interface = undefined,
        .state = .ready,
        .max_head_len = RequestHeadMaxLen,
    };
    const head_bytes = http_reader.receiveHead() catch |err| switch (err) {
        error.ReadFailed => return error.ReadFailed,
        error.HttpRequestTruncated,
        error.HttpConnectionClosing,
        error.HttpHeadersOversize,
        => return error.HttpHeadersInvalid,
    };
    const head = ResponseHead.parse(head_bytes) catch return error.HttpHeadersInvalid;
    return .{ .reader = http_reader, .head = head };
}

fn discardStdHttpBody(response: *std.http.Client.Response) !void {
    var transfer_buffer: [256]u8 = undefined;
    const reader = response.reader(&transfer_buffer);
    _ = reader.discardRemaining() catch |err| switch (err) {
        error.ReadFailed => return error.ReadFailed,
        else => |e| return e,
    };
}

fn discardHttpBody(reader: *std.http.Reader, transfer_encoding: std.http.TransferEncoding, content_length: ?u64) !void {
    var transfer_buffer: [256]u8 = undefined;
    const body_reader = reader.bodyReader(&transfer_buffer, transfer_encoding, content_length);
    _ = body_reader.discardRemaining() catch |err| switch (err) {
        error.ReadFailed => return error.ReadFailed,
        else => |e| return e,
    };
}

fn streamReaderToFile(io: Io, reader: *Io.Reader, output: *Io.File, control: *TransferControl) !void {
    var output_buf: [StreamBufLen]u8 = undefined;
    var file_writer = output.writer(io, &output_buf);
    var chunk: [StreamBufLen]u8 = undefined;
    while (true) {
        try control.checkElapsed();
        const n = try reader.readSliceShort(&chunk);
        if (n == 0) {
            break;
        }
        try file_writer.interface.writeAll(chunk[0..n]);
        try control.noteBytes(n);
    }
    try file_writer.interface.flush();
}

fn writeRequestTarget(writer: *Io.Writer, uri: Uri) !void {
    if (uri.path.percent_encoded.len == 0) {
        try writer.writeAll("/");
    } else {
        try uri.path.formatRaw(writer);
    }
    if (uri.query) |query| {
        try writer.writeByte('?');
        try query.formatRaw(writer);
    }
}

fn writeAuthority(writer: *Io.Writer, uri: Uri) !void {
    const host = uri.host orelse return error.InvalidUrl;
    try host.formatRaw(writer);
    if (uri.port) |port| {
        try writer.print(":{d}", .{port});
    }
}

fn filePathFromUri(allocator: Allocator, uri: Uri) ![]u8 {
    if (!schemeEq(uri.scheme, "file")) {
        return error.InvalidUrl;
    }
    if (uri.path.percent_encoded.len == 0 or uri.path.percent_encoded[0] != '/') {
        return error.InvalidUrl;
    }
    const buffer = try allocator.alloc(u8, uri.path.percent_encoded.len);
    @memcpy(buffer, uri.path.percent_encoded);
    return Uri.percentDecodeInPlace(buffer);
}

fn resolveRedirect(allocator: Allocator, base: Uri, location: []const u8) !Uri {
    const extra = base.path.percent_encoded.len + location.len + 128;
    var buffer = try allocator.alloc(u8, extra);
    @memcpy(buffer[0..location.len], location);
    var aux = buffer;
    return Uri.resolveInPlace(base, location.len, &aux) catch {
        setError("failed to resolve redirect location {s}", .{location});
        return error.HttpRedirectInvalid;
    };
}

fn applySocketTimeouts(stream: Io.net.Stream, timeout_secs: u32) !void {
    if (timeout_secs == 0) {
        return;
    }
    const tv = std.posix.timeval{
        .sec = @intCast(timeout_secs),
        .usec = 0,
    };
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv));
}

fn effectiveSocketTimeoutSecs(request: DownloadRequest) ?u32 {
    var result: ?u32 = null;
    if (request.total_timeout_secs != 0) {
        result = request.total_timeout_secs;
    }
    if (request.low_speed_time_secs != 0) {
        result = if (result) |current| @min(current, request.low_speed_time_secs) else request.low_speed_time_secs;
    }
    return result;
}

fn parseProxy(allocator: Allocator, proxy_url: []const u8, proxy_userpwd: ?[]const u8) !ParsedProxy {
    const uri = Uri.parse(proxy_url) catch Uri.parseAfterScheme("http", proxy_url) catch {
        setError("invalid proxy URL: {s}", .{proxy_url});
        return error.InvalidUrl;
    };
    if (uri.host == null) {
        setError("proxy URL missing host: {s}", .{proxy_url});
        return error.InvalidUrl;
    }
    const authorization = if (proxy_userpwd) |combined|
        try buildBasicAuthorizationFromCombined(allocator, combined)
    else if (uri.user != null or uri.password != null) blk: {
        const len = std.http.Client.basic_authorization.valueLengthFromUri(uri);
        const header = try allocator.alloc(u8, len);
        _ = std.http.Client.basic_authorization.value(uri, header);
        break :blk header;
    } else null;
    return .{ .uri = uri, .authorization = authorization };
}

fn buildBasicAuthorizationFromFields(allocator: Allocator, username: []const u8, password: []const u8) ![]const u8 {
    const combined_len = username.len + 1 + password.len;
    const output_len = "Basic ".len + std.base64.standard.Encoder.calcSize(combined_len);
    const output = try allocator.alloc(u8, output_len);
    @memcpy(output[0.."Basic ".len], "Basic ");

    var temp = try allocator.alloc(u8, combined_len);
    defer allocator.free(temp);
    @memcpy(temp[0..username.len], username);
    temp[username.len] = ':';
    @memcpy(temp[username.len + 1 ..], password);

    _ = std.base64.standard.Encoder.encode(output["Basic ".len..], temp);
    return output;
}

fn buildBasicAuthorizationFromCombined(allocator: Allocator, combined: []const u8) ![]const u8 {
    const output_len = "Basic ".len + std.base64.standard.Encoder.calcSize(combined.len);
    const output = try allocator.alloc(u8, output_len);
    @memcpy(output[0.."Basic ".len], "Basic ");
    _ = std.base64.standard.Encoder.encode(output["Basic ".len..], combined);
    return output;
}

fn openOutputFile(io: Io, path: []const u8) !Io.File {
    if (std.fs.path.isAbsolute(path)) {
        return Io.Dir.createFileAbsolute(io, path, .{});
    }
    return Io.Dir.cwd().createFile(io, path, .{});
}

fn openInputFile(io: Io, path: []const u8) !Io.File {
    if (std.fs.path.isAbsolute(path)) {
        return Io.Dir.openFileAbsolute(io, path, .{});
    }
    return Io.Dir.cwd().openFile(io, path, .{});
}

fn optionalSpan(value: ?[*:0]const u8) ?[]const u8 {
    const ptr = value orelse return null;
    const span = std.mem.span(ptr);
    if (span.len == 0) {
        return null;
    }
    return span;
}

fn requiredSpan(value: ?[*:0]const u8) ?[]const u8 {
    const span = optionalSpan(value) orelse return null;
    return span;
}

fn longToU32(value: c_long) !u32 {
    if (value < 0) {
        return error.InvalidParameter;
    }
    return @intCast(value);
}

fn longToU64(value: c_long) !u64 {
    if (value < 0) {
        return error.InvalidParameter;
    }
    return @intCast(value);
}

fn toCurlOff(value: u64) i64 {
    return @intCast(@min(value, @as(u64, std.math.maxInt(i64))));
}

fn timestampElapsedNs(io: Io, start: Io.Clock.Timestamp) u64 {
    const now = Io.Clock.Timestamp.now(io, .awake);
    const duration = start.durationTo(now);
    return @intCast(duration.raw.toNanoseconds());
}

fn schemeEq(actual: []const u8, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(actual, expected);
}

fn mapStdHttpRequestError(err: anyerror) anyerror {
    return switch (err) {
        error.UnsupportedUriScheme,
        error.UriMissingHost,
        error.InvalidFormat,
        error.InvalidPort,
        error.InvalidHostName,
        => error.InvalidUrl,
        error.CertificateBundleLoadFailure => error.TlsConfiguration,
        else => err,
    };
}

fn mapStdHttpHeadError(err: anyerror) anyerror {
    return switch (err) {
        error.HttpHeadersInvalid,
        error.HttpContentEncodingUnsupported,
        error.HttpChunkInvalid,
        error.HttpChunkTruncated,
        error.HttpHeadersOversize,
        => error.TransportReadFailed,
        else => err,
    };
}

const ServerOptions = struct {
    tls_mode: bool,
    require_client_auth: bool = false,
    expected_authorization: ?[]const u8 = null,
    body: []const u8 = "hello from zig transport\n",
};

const ServerContext = struct {
    io: Io,
    server: *Io.net.Server,
    options: ServerOptions,
};

fn spawnServer(options: ServerOptions) !struct { thread: std.Thread, port: u16 } {
    const io = std.testing.io;
    const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    const server = try address.listen(io, .{ .reuse_address = true });
    const boxed = try std.testing.allocator.create(Io.net.Server);
    boxed.* = server;
    const ctx = try std.testing.allocator.create(ServerContext);
    ctx.* = .{ .io = io, .server = boxed, .options = options };
    const thread = try std.Thread.spawn(.{}, serverThreadMain, .{ctx});
    return .{ .thread = thread, .port = boxed.socket.address.getPort() };
}

fn serverThreadMain(ctx: *ServerContext) void {
    defer {
        ctx.server.deinit(ctx.io);
        std.testing.allocator.destroy(ctx.server);
        std.testing.allocator.destroy(ctx);
    }
    serveOne(ctx.io, ctx.server, ctx.options) catch |err| {
        std.debug.print("server error: {}\n", .{err});
    };
}

fn serveOne(io: Io, server: *Io.net.Server, options: ServerOptions) !void {
    const stream = try server.accept(io);
    defer stream.close(io);

    if (!options.tls_mode) {
        var reader_buf: [4096]u8 = undefined;
        var writer_buf: [4096]u8 = undefined;
        var reader = stream.reader(io, &reader_buf);
        var writer = stream.writer(io, &writer_buf);
        const auth_ok = try requestAuthorizationMatches(&reader.interface, options.expected_authorization);
        if (!auth_ok) {
            try writer.interface.writeAll("HTTP/1.1 401 Unauthorized\r\nContent-Length: 4\r\nConnection: close\r\n\r\nauth");
            try writer.interface.flush();
            return;
        }
        try writer.interface.print(
            "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
            .{ options.body.len, options.body },
        );
        try writer.interface.flush();
        return;
    }

    var server_auth = try tls.config.CertKeyPair.fromSlice(
        std.testing.allocator,
        io,
        @embedFile("fixtures/server-cert.pem"),
        @embedFile("fixtures/server-key.pem"),
    );
    defer server_auth.deinit(std.testing.allocator);

    var root_ca = try tls.config.cert.fromSlice(std.testing.allocator, io, @embedFile("fixtures/ca-cert.pem"));
    defer root_ca.deinit(std.testing.allocator);

    var rng_impl: std.Random.IoSource = .{ .io = io };
    var conn = try tls.serverFromStream(io, stream, .{
        .auth = &server_auth,
        .client_auth = if (options.require_client_auth) .{
            .auth_type = .require,
            .root_ca = root_ca,
        } else null,
        .now = Io.Clock.real.now(io),
        .rng = rng_impl.interface(),
    });
    defer conn.close() catch {};

    var conn_reader_buf: [4096]u8 = undefined;
    var conn_reader = conn.reader(&conn_reader_buf);
    const auth_ok = try requestAuthorizationMatches(&conn_reader.interface, options.expected_authorization);
    if (!auth_ok) {
        try conn.writeAll("HTTP/1.1 401 Unauthorized\r\nContent-Length: 4\r\nConnection: close\r\n\r\nauth");
        return;
    }

    var response_buf: [256]u8 = undefined;
    const response = try std.fmt.bufPrint(
        &response_buf,
        "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{options.body.len},
    );
    try conn.writeAll(response);
    try conn.writeAll(options.body);
}

fn requestAuthorizationMatches(reader: *Io.Reader, expected_authorization: ?[]const u8) !bool {
    var http_reader: std.http.Reader = .{
        .in = reader,
        .interface = undefined,
        .state = .ready,
        .max_head_len = RequestHeadMaxLen,
    };
    const head_bytes = try http_reader.receiveHead();
    if (expected_authorization == null) {
        return true;
    }
    var iter: std.http.HeaderIterator = .init(head_bytes);
    while (iter.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
            return std.mem.eql(u8, header.value, expected_authorization.?);
        }
    }
    return false;
}

fn ensureScratchDir(io: Io) !void {
    try Io.Dir.cwd().createDirPath(io, TestScratchDir);
}

fn scratchPath(allocator: Allocator, name: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ TestScratchDir, name });
}

fn dupeZ(allocator: Allocator, value: []const u8) ![:0]u8 {
    return allocator.dupeZ(u8, value);
}

fn writeScratchFile(io: Io, path: []const u8, data: []const u8) !void {
    if (std.fs.path.isAbsolute(path)) {
        return Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
    }
    return Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
}

fn readFileAlloc(allocator: Allocator, io: Io, path: []const u8) ![]u8 {
    var file = try openInputFile(io, path);
    defer file.close(io);
    var reader_buf: [256]u8 = undefined;
    var reader = file.reader(io, &reader_buf);
    return reader.interface.allocRemaining(allocator, .limited(64 * 1024));
}

fn deleteFileIfExists(io: Io, path: []const u8) void {
    if (std.fs.path.isAbsolute(path)) {
        Io.Dir.deleteFileAbsolute(io, path) catch {};
        return;
    }
    Io.Dir.cwd().deleteFile(io, path) catch {};
}

test "http fetch succeeds" {
    const io = std.testing.io;
    try ensureScratchDir(io);

    const server = try spawnServer(.{ .tls_mode = false, .body = "plain http body\n" });
    defer server.thread.join();

    const url = try std.fmt.allocPrint(std.testing.allocator, "http://127.0.0.1:{d}/payload", .{server.port});
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const dest = try scratchPath(std.testing.allocator, "http-fetch.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    const request: TDNF_ZIG_DOWNLOAD_REQUEST = .{
        .pszUrl = z_url.ptr,
        .pszDestination = z_dest.ptr,
        .pfnProgress = null,
        .pProgressData = null,
        .pszUserAgent = null,
        .pszProxy = null,
        .pszProxyUserPwd = null,
        .pszUserName = null,
        .pszPassword = null,
        .pszSSLCaCert = null,
        .pszSSLClientCert = null,
        .pszSSLClientKey = null,
        .nSSLVerify = 1,
        .nConnectTimeout = 0,
        .nTimeout = 0,
        .nLowSpeedLimit = 0,
        .nLowSpeedTime = 0,
        .nMaxRecvSpeed = 0,
    };
    var status: c_long = 0;
    try std.testing.expectEqual(@as(u32, 0), TDNFZigDownloadFile(&request, &status));
    try std.testing.expectEqual(@as(c_long, 200), status);

    const body = try readFileAlloc(std.testing.allocator, io, z_dest);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("plain http body\n", body);
}

test "http fetch supports basic auth" {
    const io = std.testing.io;
    try ensureScratchDir(io);

    const expected = try buildBasicAuthorizationFromFields(std.testing.allocator, "cassian", "andor");
    defer std.testing.allocator.free(expected);
    const server = try spawnServer(.{
        .tls_mode = false,
        .body = "authenticated\n",
        .expected_authorization = expected,
    });
    defer server.thread.join();

    const url = try std.fmt.allocPrint(std.testing.allocator, "http://127.0.0.1:{d}/secure", .{server.port});
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const dest = try scratchPath(std.testing.allocator, "http-auth.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    const request: TDNF_ZIG_DOWNLOAD_REQUEST = .{
        .pszUrl = z_url.ptr,
        .pszDestination = z_dest.ptr,
        .pfnProgress = null,
        .pProgressData = null,
        .pszUserAgent = null,
        .pszProxy = null,
        .pszProxyUserPwd = null,
        .pszUserName = "cassian",
        .pszPassword = "andor",
        .pszSSLCaCert = null,
        .pszSSLClientCert = null,
        .pszSSLClientKey = null,
        .nSSLVerify = 1,
        .nConnectTimeout = 0,
        .nTimeout = 0,
        .nLowSpeedLimit = 0,
        .nLowSpeedTime = 0,
        .nMaxRecvSpeed = 0,
    };
    var status: c_long = 0;
    try std.testing.expectEqual(@as(u32, 0), TDNFZigDownloadFile(&request, &status));
    try std.testing.expectEqual(@as(c_long, 200), status);

    const body = try readFileAlloc(std.testing.allocator, io, z_dest);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("authenticated\n", body);
}

test "verified https fetch succeeds with system CA" {
    const io = std.testing.io;
    try ensureScratchDir(io);

    const z_url = try dupeZ(std.testing.allocator, "https://example.com/");
    defer std.testing.allocator.free(z_url);
    const dest = try scratchPath(std.testing.allocator, "https-verified.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);
    const request: TDNF_ZIG_DOWNLOAD_REQUEST = .{
        .pszUrl = z_url.ptr,
        .pszDestination = z_dest.ptr,
        .pfnProgress = null,
        .pProgressData = null,
        .pszUserAgent = null,
        .pszProxy = null,
        .pszProxyUserPwd = null,
        .pszUserName = null,
        .pszPassword = null,
        .pszSSLCaCert = null,
        .pszSSLClientCert = null,
        .pszSSLClientKey = null,
        .nSSLVerify = 1,
        .nConnectTimeout = 0,
        .nTimeout = 0,
        .nLowSpeedLimit = 0,
        .nLowSpeedTime = 0,
        .nMaxRecvSpeed = 0,
    };
    var status: c_long = 0;
    try std.testing.expectEqual(@as(u32, 0), TDNFZigDownloadFile(&request, &status));
    try std.testing.expectEqual(@as(c_long, 200), status);

    const body = try readFileAlloc(std.testing.allocator, io, z_dest);
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "Example Domain") != null);
}

test "insecure https fetch succeeds" {
    const io = std.testing.io;
    try ensureScratchDir(io);

    const server = try spawnServer(.{ .tls_mode = true, .body = "insecure https body\n" });
    defer server.thread.join();

    const url = try std.fmt.allocPrint(std.testing.allocator, "https://127.0.0.1:{d}/payload", .{server.port});
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const dest = try scratchPath(std.testing.allocator, "https-insecure.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    const request: TDNF_ZIG_DOWNLOAD_REQUEST = .{
        .pszUrl = z_url.ptr,
        .pszDestination = z_dest.ptr,
        .pfnProgress = null,
        .pProgressData = null,
        .pszUserAgent = null,
        .pszProxy = null,
        .pszProxyUserPwd = null,
        .pszUserName = null,
        .pszPassword = null,
        .pszSSLCaCert = null,
        .pszSSLClientCert = null,
        .pszSSLClientKey = null,
        .nSSLVerify = 0,
        .nConnectTimeout = 0,
        .nTimeout = 0,
        .nLowSpeedLimit = 0,
        .nLowSpeedTime = 0,
        .nMaxRecvSpeed = 0,
    };
    var status: c_long = 0;
    try std.testing.expectEqual(@as(u32, 0), TDNFZigDownloadFile(&request, &status));
    try std.testing.expectEqual(@as(c_long, 200), status);

    const body = try readFileAlloc(std.testing.allocator, io, z_dest);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("insecure https body\n", body);
}

test "file uri copies data" {
    const io = std.testing.io;
    try ensureScratchDir(io);

    const src = try scratchPath(std.testing.allocator, "file-source.txt");
    defer std.testing.allocator.free(src);
    const dest = try scratchPath(std.testing.allocator, "file-dest.txt");
    defer std.testing.allocator.free(dest);
    deleteFileIfExists(io, src);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);
    try writeScratchFile(io, src, "file transport body\n");
    const src_abs = try Io.Dir.cwd().realPathFileAlloc(io, src, std.testing.allocator);
    defer std.testing.allocator.free(src_abs);
    const url = try std.fmt.allocPrint(std.testing.allocator, "file://{s}", .{src_abs});
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);

    const request: TDNF_ZIG_DOWNLOAD_REQUEST = .{
        .pszUrl = z_url.ptr,
        .pszDestination = z_dest.ptr,
        .pfnProgress = null,
        .pProgressData = null,
        .pszUserAgent = null,
        .pszProxy = null,
        .pszProxyUserPwd = null,
        .pszUserName = null,
        .pszPassword = null,
        .pszSSLCaCert = null,
        .pszSSLClientCert = null,
        .pszSSLClientKey = null,
        .nSSLVerify = 1,
        .nConnectTimeout = 0,
        .nTimeout = 0,
        .nLowSpeedLimit = 0,
        .nLowSpeedTime = 0,
        .nMaxRecvSpeed = 0,
    };
    var status: c_long = 0;
    try std.testing.expectEqual(@as(u32, 0), TDNFZigDownloadFile(&request, &status));
    try std.testing.expectEqual(@as(c_long, 200), status);

    const body = try readFileAlloc(std.testing.allocator, io, z_dest);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("file transport body\n", body);
}

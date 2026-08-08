const std = @import("std");
const tls = @import("tls");
const abi = @import("client_abi");
const errors = @import("tdnf_error");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Uri = std.Uri;
const ResponseHead = std.http.Client.Response.Head;
const RedirectLimit: usize = 10;
const RequestHeadMaxLen: usize = 8192;
const StreamBufLen: usize = 8192;
const TestScratchDir = ".zig-cache/tdnf-download-tests";

pub const TDNF_ZIG_XFERINFOFUNCTION = abi.DownloadProgressFn;
pub const TDNF_ZIG_DOWNLOAD_REQUEST = abi.DownloadRequest;

const DownloadRequest = struct {
    url: []const u8,
    destination: []const u8,
    destination_z: [*:0]const u8,
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
    custom_http,
};

const ParsedProxy = struct {
    uri: Uri,
    authorization: ?[]const u8,
};

const DeadlineGuard = struct {
    io: Io = undefined,
    stream: *const Io.net.Stream = undefined,
    total_timeout_secs: u32 = 0,
    low_speed_time_secs: u32 = 0,
    connect_timeout_secs: u32 = 0,
    started: Io.Clock.Timestamp = undefined,
    activity_sequence: std.atomic.Value(u64) = .init(0),
    connecting: std.atomic.Value(bool) = .init(true),
    expired: std.atomic.Value(bool) = .init(false),
    group: Io.Group = .init,
    active: bool = false,

    fn start(
        self: *DeadlineGuard,
        io: Io,
        stream: *const Io.net.Stream,
        request: DownloadRequest,
        started: Io.Clock.Timestamp,
    ) !void {
        self.* = .{
            .io = io,
            .stream = stream,
            .total_timeout_secs = request.total_timeout_secs,
            .low_speed_time_secs = if (request.low_speed_limit == 0)
                0
            else
                request.low_speed_time_secs,
            .connect_timeout_secs = request.connect_timeout_secs,
            .started = started,
        };
        if (self.total_timeout_secs == 0 and
            self.low_speed_time_secs == 0 and
            self.connect_timeout_secs == 0)
        {
            return;
        }
        try self.group.concurrent(io, DeadlineGuard.watch, .{self});
        self.active = true;
    }

    fn deinit(self: *DeadlineGuard) void {
        if (self.active) self.group.cancel(self.io);
    }

    fn activity(self: *DeadlineGuard) void {
        _ = self.activity_sequence.fetchAdd(1, .monotonic);
    }

    fn connected(self: *DeadlineGuard) void {
        self.connecting.store(false, .release);
        self.activity();
    }

    fn check(self: *const DeadlineGuard) !void {
        if (self.expired.load(.acquire)) return error.Timeout;
    }

    fn watch(self: *DeadlineGuard) Io.Cancelable!void {
        var observed = self.activity_sequence.load(.acquire);
        var low_speed_start = self.started;
        while (true) {
            const now = Io.Clock.Timestamp.now(self.io, .awake);
            const current = self.activity_sequence.load(.acquire);
            if (current != observed) {
                observed = current;
                low_speed_start = now;
            }

            var wait_ns: ?u64 = null;
            if (self.connect_timeout_secs != 0 and
                self.connecting.load(.acquire))
            {
                const limit = @as(u64, self.connect_timeout_secs) * std.time.ns_per_s;
                const elapsed = timestampElapsedNsAt(self.started, now);
                if (elapsed >= limit) return self.expire();
                wait_ns = limit - elapsed;
            }
            if (self.total_timeout_secs != 0) {
                const limit = @as(u64, self.total_timeout_secs) * std.time.ns_per_s;
                const elapsed = timestampElapsedNsAt(self.started, now);
                if (elapsed >= limit) return self.expire();
                wait_ns = limit - elapsed;
            }
            if (self.low_speed_time_secs != 0) {
                const limit = @as(u64, self.low_speed_time_secs) * std.time.ns_per_s;
                const elapsed = timestampElapsedNsAt(low_speed_start, now);
                if (elapsed >= limit) return self.expire();
                const remaining = limit - elapsed;
                wait_ns = if (wait_ns) |value| @min(value, remaining) else remaining;
            }
            const duration = wait_ns orelse return;
            try Io.sleep(
                self.io,
                Io.Duration.fromNanoseconds(@max(duration, 1)),
                .awake,
            );
        }
    }

    fn expire(self: *DeadlineGuard) void {
        self.expired.store(true, .release);
        self.stream.shutdown(self.io, .both) catch {};
    }
};

const StdHttpTransport = struct {
    allocator: Allocator,
    io: Io,
    request: DownloadRequest,
    origin: Uri,
    client: std.http.Client,
    proxy: ?*std.http.Client.Proxy = null,
    authorization: ?[]const u8 = null,
    custom_ca_loaded: bool = false,

    fn init(allocator: Allocator, io: Io, request: DownloadRequest) !StdHttpTransport {
        var transport = StdHttpTransport{
            .allocator = allocator,
            .io = io,
            .request = request,
            .origin = Uri.parse(request.url) catch return error.InvalidUrl,
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
                .supports_connect = false,
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

        var deadline: DeadlineGuard = .{};
        try deadline.start(
            self.io,
            &request.connection.?.stream_reader.stream,
            self.request,
            Io.Clock.Timestamp.now(self.io, .awake),
        );
        deadline.connected();
        defer deadline.deinit();

        request.sendBodiless() catch |err| {
            deadline.check() catch return error.Timeout;
            setError("std.http send failed: {}", .{err});
            return error.TransportWriteFailed;
        };
        deadline.activity();

        var response = request.receiveHead(&.{}) catch |err| {
            deadline.check() catch return error.Timeout;
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
        deadline.activity();

        const status = @as(u16, @intFromEnum(response.head.status));
        if (response.head.status.class() == .redirect) {
            const location = response.head.location orelse {
                setError("redirect response is missing Location", .{});
                return error.HttpRedirectMissing;
            };
            const next_uri = try resolveRedirect(arena, uri, location);
            discardStdHttpBody(&response) catch |err| {
                deadline.check() catch return error.Timeout;
                return err;
            };
            try deadline.check();
            return .{ .redirect = next_uri };
        }

        if (status >= 400) {
            discardStdHttpBody(&response) catch |err| {
                deadline.check() catch return error.Timeout;
                return err;
            };
            try deadline.check();
            return .{ .status = status };
        }

        var output = try openOutputFile(self.io, self.request.destination_z);
        defer output.close(self.io);

        var control = try TransferControl.init(
            self.io,
            self.request,
            response.head.content_length,
            &deadline,
        );

        var transfer_buffer: [StreamBufLen]u8 = undefined;
        const reader = response.reader(&transfer_buffer);
        streamReaderToFile(
            self.io,
            reader,
            &output,
            &control,
        ) catch |err| {
            deadline.check() catch return error.Timeout;
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
        try deadline.check();
        try control.finish();

        return .{ .status = status };
    }

    fn buildHeaders(self: *StdHttpTransport, arena: Allocator, uri: Uri) !std.http.Client.Request.Headers {
        var headers: std.http.Client.Request.Headers = .{
            .user_agent = if (self.request.user_agent) |user_agent| .{ .override = user_agent } else .omit,
            .authorization = .default,
            .accept_encoding = .omit,
        };
        if (self.authorization) |authorization| {
            if (!sameCredentialOrigin(self.origin, uri)) {
                return headers;
            }
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

const CustomHttpTransport = struct {
    allocator: Allocator,
    io: Io,
    request: DownloadRequest,
    origin: Uri,
    proxy: ?ParsedProxy = null,
    authorization: ?[]const u8 = null,
    root_ca: tls.config.cert.Bundle = .empty,
    root_ca_loaded: bool = false,
    client_auth: ?tls.config.CertKeyPair = null,
    client_auth_loaded: bool = false,

    fn init(allocator: Allocator, io: Io, request: DownloadRequest) !CustomHttpTransport {
        var transport = CustomHttpTransport{
            .allocator = allocator,
            .io = io,
            .request = request,
            .origin = Uri.parse(request.url) catch return error.InvalidUrl,
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

    fn deinit(self: *CustomHttpTransport) void {
        if (self.client_auth_loaded) {
            self.client_auth.?.deinit(self.allocator);
        }
        if (self.root_ca_loaded) {
            self.root_ca.deinit(self.allocator);
        }
    }

    fn ensureRootCa(self: *CustomHttpTransport, uri: Uri) !void {
        if (self.root_ca_loaded) return;
        const proxy_tls = if (self.proxy) |proxy|
            std.http.Client.Protocol.fromUri(proxy.uri) == .tls
        else
            false;
        const origin_tls = schemeEq(uri.scheme, "https");
        if ((!origin_tls or !self.request.ssl_verify) and !proxy_tls) return;
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

    fn doRequest(self: *CustomHttpTransport, arena: Allocator, uri: Uri) !DownloadOutcome {
        const operation_started = Io.Clock.Timestamp.now(self.io, .awake);
        try self.ensureRootCa(uri);

        var host_buf: [Io.net.HostName.max_len]u8 = undefined;
        const host_name = uri.getHost(&host_buf) catch {
            setError("download URL is missing a host", .{});
            return error.InvalidUrl;
        };
        const origin_tls = schemeEq(uri.scheme, "https");
        const port = uri.port orelse if (origin_tls) @as(u16, 443) else @as(u16, 80);
        const connect_timeout = try connectPhaseTimeout(
            self.io,
            self.request,
            operation_started,
        );
        var tcp = connectTcp(
            self.io,
            host_name,
            port,
            connect_timeout,
            self.proxy,
        ) catch |err| {
            if (err == error.Timeout) {
                setError("connection timed out", .{});
                return error.Timeout;
            }
            setError("connection failed: {}", .{err});
            return err;
        };
        defer tcp.close(self.io);

        var deadline: DeadlineGuard = .{};
        try deadline.start(self.io, &tcp, self.request, operation_started);
        defer deadline.deinit();
        try deadline.check();
        deadline.activity();

        var tcp_reader_buf: [tls.input_buffer_len]u8 = undefined;
        var tcp_writer_buf: [tls.output_buffer_len]u8 = undefined;
        var tcp_reader = tcp.reader(self.io, &tcp_reader_buf);
        var tcp_writer = tcp.writer(self.io, &tcp_writer_buf);

        var rng_impl: std.Random.IoSource = .{ .io = self.io };
        var proxy_tls: ?tls.Connection = null;
        defer if (proxy_tls) |*connection| connection.close() catch {};
        var proxy_tls_reader_buffer: [tls.input_buffer_len]u8 = undefined;
        var proxy_tls_writer_buffer: [tls.output_buffer_len]u8 = undefined;
        var proxy_tls_reader: ?tls.Connection.Reader = null;
        var proxy_tls_writer: ?tls.Connection.Writer = null;
        var tunnel_input: *Io.Reader = &tcp_reader.interface;
        var tunnel_output: *Io.Writer = &tcp_writer.interface;

        if (self.proxy) |proxy| {
            const protocol = std.http.Client.Protocol.fromUri(proxy.uri) orelse
                return error.UnsupportedConfiguration;
            if (protocol == .tls) {
                var proxy_host_buf: [Io.net.HostName.max_len]u8 = undefined;
                const proxy_host = proxy.uri.getHost(&proxy_host_buf) catch
                    return error.InvalidUrl;
                proxy_tls = tls.client(
                    tunnel_input,
                    tunnel_output,
                    .{
                        .host = proxy_host.bytes,
                        .root_ca = self.root_ca,
                        .insecure_skip_verify = false,
                        .alpn_protocols = &.{"http/1.1"},
                        .now = Io.Clock.real.now(self.io),
                        .rng = rng_impl.interface(),
                    },
                ) catch |err| {
                    deadline.check() catch return error.Timeout;
                    setError("proxy tls handshake failed: {}", .{err});
                    return error.TlsHandshakeFailed;
                };
                deadline.activity();
                proxy_tls_reader = proxy_tls.?.reader(&proxy_tls_reader_buffer);
                proxy_tls_writer = proxy_tls.?.writer(&proxy_tls_writer_buffer);
                tunnel_input = &proxy_tls_reader.?.interface;
                tunnel_output = &proxy_tls_writer.?.interface;
            }
            if (origin_tls) {
                sendConnectRequest(
                    tunnel_input,
                    tunnel_output,
                    uri,
                    proxy.authorization,
                    self.request.user_agent,
                ) catch |err| {
                    deadline.check() catch return error.Timeout;
                    return err;
                };
                deadline.activity();
            }
        }

        if (!origin_tls) {
            deadline.connected();
            writePlainRequest(
                tunnel_output,
                uri,
                self.proxy != null,
                if (self.proxy) |proxy| proxy.authorization else null,
                self.request.user_agent,
                if (sameCredentialOrigin(self.origin, uri))
                    self.authorization
                else
                    null,
                arena,
            ) catch |err| {
                deadline.check() catch return error.Timeout;
                return err;
            };
            deadline.activity();

            var response = receiveResponseHead(tunnel_input) catch |err| {
                deadline.check() catch return error.Timeout;
                setError("http receive head failed: {}", .{err});
                return err;
            };
            deadline.activity();
            return self.finishResponse(
                arena,
                uri,
                &response,
                &deadline,
                &tcp_reader,
                "http",
            );
        }

        var conn = tls.client(
            tunnel_input,
            tunnel_output,
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
            deadline.check() catch return error.Timeout;
            setError("tls handshake failed: {}", .{err});
            return error.TlsHandshakeFailed;
        };
        defer conn.close() catch {};
        deadline.connected();

        writeTlsRequest(
            &conn,
            uri,
            self.request.user_agent,
            if (sameCredentialOrigin(self.origin, uri))
                self.authorization
            else
                null,
            arena,
        ) catch |err| {
            deadline.check() catch return error.Timeout;
            return err;
        };
        deadline.activity();

        var http_reader_buf: [RequestHeadMaxLen]u8 = undefined;
        var conn_reader = conn.reader(&http_reader_buf);
        var response = receiveResponseHead(&conn_reader.interface) catch |err| {
            deadline.check() catch return error.Timeout;
            setError("tls http receive head failed: {}", .{err});
            return err;
        };
        deadline.activity();
        return self.finishResponse(
            arena,
            uri,
            &response,
            &deadline,
            &tcp_reader,
            "tls",
        );
    }

    fn finishResponse(
        self: *CustomHttpTransport,
        arena: Allocator,
        uri: Uri,
        response: *ReceivedHead,
        deadline: *DeadlineGuard,
        tcp_reader: *Io.net.Stream.Reader,
        transport_name: []const u8,
    ) !DownloadOutcome {
        const status = @as(u16, @intFromEnum(response.head.status));
        if (response.head.status.class() == .redirect) {
            const location = response.head.location orelse {
                setError("redirect response is missing Location", .{});
                return error.HttpRedirectMissing;
            };
            const next_uri = try resolveRedirect(arena, uri, location);
            discardHttpBody(
                &response.reader,
                response.head.transfer_encoding,
                response.head.content_length,
            ) catch |err| {
                deadline.check() catch return error.Timeout;
                return err;
            };
            try deadline.check();
            return .{ .redirect = next_uri };
        }

        if (status >= 400) {
            discardHttpBody(
                &response.reader,
                response.head.transfer_encoding,
                response.head.content_length,
            ) catch |err| {
                deadline.check() catch return error.Timeout;
                return err;
            };
            try deadline.check();
            return .{ .status = status };
        }

        var output = try openOutputFile(self.io, self.request.destination_z);
        defer output.close(self.io);

        var control = try TransferControl.init(
            self.io,
            self.request,
            response.head.content_length,
            deadline,
        );

        var transfer_buffer: [StreamBufLen]u8 = undefined;
        const body_reader = response.reader.bodyReader(&transfer_buffer, response.head.transfer_encoding, response.head.content_length);
        streamReaderToFile(self.io, body_reader, &output, &control) catch |err| {
            deadline.check() catch return error.Timeout;
            if (err == error.ReadFailed) {
                if (tcp_reader.err) |read_err| {
                    setError("{s} body read failed: {}", .{ transport_name, read_err });
                } else {
                    setError("{s} body read failed", .{transport_name});
                }
            } else {
                setError("{s} body download failed: {}", .{ transport_name, err });
            }
            return err;
        };
        try deadline.check();
        try control.finish();

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
    deadline: ?*DeadlineGuard,

    fn init(
        io: Io,
        request: DownloadRequest,
        total_size: ?u64,
        deadline: ?*DeadlineGuard,
    ) !TransferControl {
        const now = Io.Clock.Timestamp.now(io, .awake);
        var control = TransferControl{
            .io = io,
            .request = request,
            .total_size = total_size,
            .overall_start = now,
            .low_speed_start = now,
            .throttle_start = now,
            .deadline = deadline,
        };
        try control.reportProgress();
        return control;
    }

    fn noteBytes(self: *TransferControl, bytes: usize) !void {
        self.downloaded += bytes;
        self.low_speed_bytes += bytes;
        if (self.deadline) |deadline| deadline.activity();
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
        if (self.total_size) |expected| {
            if (self.downloaded != expected) {
                return error.ContentLengthMismatch;
            }
        }
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
            ensureErrorSet("invalid download URL", .{});
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
        setError("HTTP status {d} while downloading", .{status});
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
        .destination_z = raw_request.pszDestination.?,
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
        setError("invalid download URL", .{});
        return error.InvalidUrl;
    };

    var custom_transport: ?CustomHttpTransport = null;
    defer if (custom_transport) |*transport| transport.deinit();

    var redirects: usize = 0;
    while (true) {
        const outcome = switch (try chooseTransport(current_uri, request)) {
            .file => try downloadFileUri(io, request, current_uri),
            .custom_http => blk: {
                if (custom_transport == null) {
                    custom_transport = try CustomHttpTransport.init(allocator, io, request);
                }
                break :blk try custom_transport.?.doRequest(allocator, current_uri);
            },
        };
        switch (outcome) {
            .status => |status| return status,
            .redirect => |next_uri| {
                redirects += 1;
                if (redirects > RedirectLimit) {
                    setError("too many download redirects", .{});
                    return error.TooManyRedirects;
                }
                if (schemeEq(current_uri.scheme, "https") and
                    schemeEq(next_uri.scheme, "http"))
                {
                    setError("refusing HTTPS to HTTP redirect", .{});
                    return error.InsecureRedirect;
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
        return .custom_http;
    }
    if (schemeEq(uri.scheme, "https")) {
        const has_client_auth = request.client_cert != null and request.client_key != null;
        const has_partial_client_auth = (request.client_cert != null) != (request.client_key != null);
        if (has_partial_client_auth) {
            return error.UnsupportedConfiguration;
        }
        if (!request.ssl_verify or
            request.ca_cert != null or
            has_client_auth or
            request.proxy_url != null)
        {
            return .custom_http;
        }
        return .custom_http;
    }
    return error.InvalidUrl;
}

fn downloadFileUri(io: Io, request: DownloadRequest, uri: Uri) !DownloadOutcome {
    const source_path = try filePathFromUri(std.heap.c_allocator, uri);
    defer std.heap.c_allocator.free(source_path);

    var source = try openInputFile(io, source_path);
    defer source.close(io);

    var output = try openOutputFile(io, request.destination_z);
    defer output.close(io);

    const source_stat = source.stat(io) catch null;
    const total_size = if (source_stat) |stat|
        if (stat.size == 0) null else stat.size
    else
        null;
    var control = try TransferControl.init(io, request, total_size, null);

    var reader_buf: [StreamBufLen]u8 = undefined;
    var reader = source.reader(io, &reader_buf);
    try streamReaderToFile(io, &reader.interface, &output, &control);
    try control.finish();

    return .{ .status = 200 };
}

fn connectTcp(
    io: Io,
    host_name: Io.net.HostName,
    port: u16,
    timeout: Io.Timeout,
    proxy: ?ParsedProxy,
) !Io.net.Stream {
    if (proxy) |parsed| {
        var proxy_host_buf: [Io.net.HostName.max_len]u8 = undefined;
        const proxy_host = parsed.uri.getHost(&proxy_host_buf) catch return error.InvalidUrl;
        const protocol = std.http.Client.Protocol.fromUri(parsed.uri) orelse
            return error.UnsupportedConfiguration;
        const proxy_port: u16 = parsed.uri.port orelse switch (protocol) {
            .plain => @as(u16, 80),
            .tls => @as(u16, 443),
        };
        return connectHost(io, proxy_host, proxy_port, timeout);
    }
    return connectHost(io, host_name, port, timeout);
}

const ConnectLookupEvent = union(enum) {
    address: Io.net.IpAddress,
    finished: ?anyerror,
    timeout,
};

fn connectHost(
    io: Io,
    host_name: Io.net.HostName,
    port: u16,
    timeout: Io.Timeout,
) !Io.net.Stream {
    const deadline = timeout.toTimestamp(io) orelse
        return host_name.connect(io, port, .{ .mode = .stream });

    var event_buffer: [34]ConnectLookupEvent = undefined;
    var events: Io.Queue(ConnectLookupEvent) = .init(&event_buffer);
    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(
        io,
        lookupConnectEvents,
        .{ host_name, io, port, &events },
    );
    try group.concurrent(io, connectTimeoutEvent, .{ io, deadline, &events });

    var last_error: ?anyerror = null;
    while (events.getOne(io)) |event| switch (event) {
        .address => |address| {
            return connectAddressUntil(io, address, deadline) catch |err| {
                if (err == error.Timeout) return error.Timeout;
                last_error = err;
                continue;
            };
        },
        .finished => |lookup_error| {
            if (lookup_error) |err| return err;
            return last_error orelse error.UnknownHostName;
        },
        .timeout => return error.Timeout,
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => return last_error orelse error.UnknownHostName,
    }
}

fn lookupConnectEvents(
    host_name: Io.net.HostName,
    io: Io,
    port: u16,
    events: *Io.Queue(ConnectLookupEvent),
) Io.Cancelable!void {
    var lookup_buffer: [32]Io.net.HostName.LookupResult = undefined;
    var lookup_results: Io.Queue(Io.net.HostName.LookupResult) = .init(&lookup_buffer);
    var lookup = io.async(
        Io.net.HostName.lookup,
        .{ host_name, io, &lookup_results, .{ .port = port } },
    );
    defer lookup.cancel(io) catch {};

    while (lookup_results.getOne(io)) |result| switch (result) {
        .address => |address| events.putOne(io, .{ .address = address }) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => return,
        },
        .canonical_name => {},
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => {},
    }
    const result: ?anyerror = if (lookup.await(io)) null else |err| err;
    events.putOne(io, .{ .finished = result }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => return,
    };
}

fn connectTimeoutEvent(
    io: Io,
    deadline: Io.Clock.Timestamp,
    events: *Io.Queue(ConnectLookupEvent),
) Io.Cancelable!void {
    try deadline.wait(io);
    events.putOne(io, .timeout) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => return,
    };
}

fn connectAddressUntil(
    io: Io,
    address: Io.net.IpAddress,
    deadline: Io.Clock.Timestamp,
) !Io.net.Stream {
    const posix = std.posix;
    const family = std.Io.Threaded.posixAddressFamily(&address);
    const socket_result = posix.system.socket(
        family,
        posix.SOCK.STREAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
        0,
    );
    if (posix.errno(socket_result) != .SUCCESS) return error.ConnectFailed;
    const fd: posix.fd_t = @intCast(socket_result);
    errdefer _ = posix.system.close(fd);

    var storage: std.Io.Threaded.PosixAddress = undefined;
    const address_len = std.Io.Threaded.addressToPosix(&address, &storage);
    const connect_result = posix.system.connect(fd, &storage.any, address_len);
    switch (posix.errno(connect_result)) {
        .SUCCESS => {},
        .INPROGRESS => {
            const remaining_ns = timestampRemainingNs(io, deadline);
            if (remaining_ns == 0) return error.Timeout;
            const remaining_ms_u64 = @max(
                @as(u64, 1),
                (remaining_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms,
            );
            var poll_fds = [_]posix.pollfd{.{
                .fd = fd,
                .events = posix.POLL.OUT,
                .revents = 0,
            }};
            if (try posix.poll(
                &poll_fds,
                @intCast(@min(remaining_ms_u64, std.math.maxInt(i32))),
            ) == 0) return error.Timeout;
            var socket_error: c_int = 0;
            var socket_error_len: posix.socklen_t = @sizeOf(c_int);
            if (std.c.getsockopt(
                fd,
                posix.SOL.SOCKET,
                posix.SO.ERROR,
                &socket_error,
                &socket_error_len,
            ) != 0 or socket_error != 0) return error.ConnectFailed;
        },
        else => return error.ConnectFailed,
    }

    const flags_result = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (posix.errno(flags_result) != .SUCCESS) return error.ConnectFailed;
    const blocking_result = posix.system.fcntl(
        fd,
        posix.F.SETFL,
        @as(usize, @intCast(flags_result)) & ~@as(usize, posix.SOCK.NONBLOCK),
    );
    if (posix.errno(blocking_result) != .SUCCESS) return error.ConnectFailed;
    return .{ .socket = .{ .handle = fd, .address = address } };
}

fn timestampRemainingNs(io: Io, deadline: Io.Clock.Timestamp) u64 {
    const nanoseconds = deadline.durationFromNow(io).raw.toNanoseconds();
    return if (nanoseconds > 0) @intCast(nanoseconds) else 0;
}

fn connectPhaseTimeout(
    io: Io,
    request: DownloadRequest,
    started: Io.Clock.Timestamp,
) !Io.Timeout {
    const now = Io.Clock.Timestamp.now(io, .awake);
    const elapsed = timestampElapsedNsAt(started, now);
    var remaining: ?u64 = null;
    const limits = [_]u32{
        request.connect_timeout_secs,
        request.total_timeout_secs,
        if (request.low_speed_limit == 0) 0 else request.low_speed_time_secs,
    };
    for (limits) |seconds| {
        if (seconds == 0) continue;
        const limit = @as(u64, seconds) * std.time.ns_per_s;
        if (elapsed >= limit) return error.Timeout;
        const candidate = limit - elapsed;
        remaining = if (remaining) |value| @min(value, candidate) else candidate;
    }
    return if (remaining) |duration|
        .{ .duration = .{
            .clock = .awake,
            .raw = Io.Duration.fromNanoseconds(@max(duration, 1)),
        } }
    else
        .none;
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
    try req_writer.writeAll("Proxy-Connection: Keep-Alive\r\n\r\n");
    try writer.writeAll(req_writer.buffered());
    try writer.flush();

    const response = try receiveResponseHead(reader);
    const status = @as(u16, @intFromEnum(response.head.status));
    if (status < 200 or status >= 300) {
        setError("proxy CONNECT failed with status {d}", .{status});
        return error.ProxyConnectFailed;
    }
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

fn writePlainRequest(
    writer: *Io.Writer,
    uri: Uri,
    absolute_form: bool,
    proxy_authorization: ?[]const u8,
    user_agent: ?[]const u8,
    authorization: ?[]const u8,
    arena: Allocator,
) !void {
    var req_buf: [2048]u8 = undefined;
    var req_writer: Io.Writer = .fixed(&req_buf);
    try req_writer.writeAll("GET ");
    if (absolute_form) {
        try req_writer.print("{s}://", .{uri.scheme});
        try writeAuthority(&req_writer, uri);
    }
    try writeRequestTarget(&req_writer, uri);
    try req_writer.writeAll(" HTTP/1.1\r\nHost: ");
    try writeAuthority(&req_writer, uri);
    try req_writer.writeAll("\r\nConnection: close\r\nAccept-Encoding:\r\n");
    if (user_agent) |value| {
        try req_writer.print("User-Agent: {s}\r\n", .{value});
    }
    if (proxy_authorization) |value| {
        try req_writer.print("Proxy-Authorization: {s}\r\n", .{value});
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
    try writer.writeAll(req_writer.buffered());
    try writer.flush();
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
    while (true) {
        try control.checkElapsed();
        const bytes = reader.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        try file_writer.interface.writeAll(bytes);
        try control.noteBytes(bytes.len);
        reader.toss(bytes.len);
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
    if (uri.host) |host| {
        var host_buffer: [Io.net.HostName.max_len]u8 = undefined;
        const host_name = uri.getHost(&host_buffer) catch return error.InvalidUrl;
        if (!std.ascii.eqlIgnoreCase(host_name.bytes, "localhost")) {
            _ = host;
            return error.InvalidUrl;
        }
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
        setError("failed to resolve redirect location", .{});
        return error.HttpRedirectInvalid;
    };
}

fn parseProxy(allocator: Allocator, proxy_url: []const u8, proxy_userpwd: ?[]const u8) !ParsedProxy {
    const uri = Uri.parse(proxy_url) catch Uri.parseAfterScheme("http", proxy_url) catch {
        setError("invalid proxy URL", .{});
        return error.InvalidUrl;
    };
    if (uri.host == null) {
        setError("proxy URL missing host", .{});
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

fn openOutputFile(io: Io, path: [*:0]const u8) !Io.File {
    _ = io;
    const fd = std.c.open(
        path,
        .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
            .CLOEXEC = true,
            .NOFOLLOW = true,
        },
        @as(c_uint, 0o600),
    );
    if (fd < 0) return error.OutputOpenFailed;
    return .{ .handle = fd, .flags = .{ .nonblocking = false } };
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
    return timestampElapsedNsAt(start, now);
}

fn timestampElapsedNsAt(
    start: Io.Clock.Timestamp,
    now: Io.Clock.Timestamp,
) u64 {
    const duration = start.durationTo(now);
    return @intCast(duration.raw.toNanoseconds());
}

fn schemeEq(actual: []const u8, expected: []const u8) bool {
    return std.ascii.eqlIgnoreCase(actual, expected);
}

fn sameCredentialOrigin(left: Uri, right: Uri) bool {
    var left_host_buf: [Io.net.HostName.max_len]u8 = undefined;
    var right_host_buf: [Io.net.HostName.max_len]u8 = undefined;
    const left_host = left.getHost(&left_host_buf) catch return false;
    const right_host = right.getHost(&right_host_buf) catch return false;
    if (!std.ascii.eqlIgnoreCase(left_host.bytes, right_host.bytes)) {
        return false;
    }
    return effectivePort(left) == effectivePort(right) and
        (!schemeEq(left.scheme, "https") or schemeEq(right.scheme, "https"));
}

fn effectivePort(uri: Uri) ?u16 {
    if (uri.port) |port| return port;
    if (schemeEq(uri.scheme, "http")) return 80;
    if (schemeEq(uri.scheme, "https")) return 443;
    return null;
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
    authorization_must_be_absent: bool = false,
    expected_proxy_authorization: ?[]const u8 = null,
    body: []const u8 = "hello from zig transport\n",
    status: u16 = 200,
    redirect_location: ?[]const u8 = null,
    content_disposition: ?[]const u8 = null,
    declared_length: ?usize = null,
    response_delay_ns: u64 = 0,
    body_split_delay_ns: u64 = 0,
    stall_before_tls: bool = false,
    stall_before_headers: bool = false,
    stall_mid_body: bool = false,
};

const ServerContext = struct {
    io: Io,
    server: *Io.net.Server,
    options: ServerOptions,
};

const TunnelProxyOptions = struct {
    tls_mode: bool,
    upstream_port: u16,
    expected_proxy_authorization: ?[]const u8 = null,
    status: u16 = 200,
};

const TunnelProxyContext = struct {
    io: Io,
    server: *Io.net.Server,
    options: TunnelProxyOptions,
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

fn spawnTunnelProxy(
    options: TunnelProxyOptions,
) !struct { thread: std.Thread, port: u16 } {
    const io = std.testing.io;
    const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    const server = try address.listen(io, .{ .reuse_address = true });
    const boxed = try std.testing.allocator.create(Io.net.Server);
    boxed.* = server;
    const ctx = try std.testing.allocator.create(TunnelProxyContext);
    ctx.* = .{ .io = io, .server = boxed, .options = options };
    const thread = try std.Thread.spawn(.{}, tunnelProxyThreadMain, .{ctx});
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

fn tunnelProxyThreadMain(ctx: *TunnelProxyContext) void {
    defer {
        ctx.server.deinit(ctx.io);
        std.testing.allocator.destroy(ctx.server);
        std.testing.allocator.destroy(ctx);
    }
    serveTunnelProxy(ctx.io, ctx.server, ctx.options) catch |err| {
        std.debug.print("proxy error: {}\n", .{err});
    };
}

fn serveTunnelProxy(
    io: Io,
    server: *Io.net.Server,
    options: TunnelProxyOptions,
) !void {
    const client = try server.accept(io);
    defer client.close(io);

    var raw_reader_buffer: [tls.input_buffer_len]u8 = undefined;
    var raw_writer_buffer: [tls.output_buffer_len]u8 = undefined;
    var raw_reader = client.reader(io, &raw_reader_buffer);
    var raw_writer = client.writer(io, &raw_writer_buffer);
    var proxy_tls: ?tls.Connection = null;
    defer if (proxy_tls) |*connection| connection.close() catch {};
    var proxy_tls_reader_buffer: [4096]u8 = undefined;
    var proxy_tls_writer_buffer: [4096]u8 = undefined;
    var proxy_tls_reader: ?tls.Connection.Reader = null;
    var proxy_tls_writer: ?tls.Connection.Writer = null;
    var client_input: *Io.Reader = &raw_reader.interface;
    var client_output: *Io.Writer = &raw_writer.interface;

    var server_auth: ?tls.config.CertKeyPair = null;
    defer if (server_auth) |*auth| auth.deinit(std.testing.allocator);
    if (options.tls_mode) {
        server_auth = try tls.config.CertKeyPair.fromSlice(
            std.testing.allocator,
            io,
            @embedFile("fixtures/server-cert.pem"),
            @embedFile("fixtures/server-key.pem"),
        );
        var rng_impl: std.Random.IoSource = .{ .io = io };
        proxy_tls = try tls.server(
            client_input,
            client_output,
            .{
                .auth = &server_auth.?,
                .now = Io.Clock.real.now(io),
                .rng = rng_impl.interface(),
            },
        );
        proxy_tls_reader = proxy_tls.?.reader(&proxy_tls_reader_buffer);
        proxy_tls_writer = proxy_tls.?.writer(&proxy_tls_writer_buffer);
        client_input = &proxy_tls_reader.?.interface;
        client_output = &proxy_tls_writer.?.interface;
    }

    var request_reader: std.http.Reader = .{
        .in = client_input,
        .interface = undefined,
        .state = .ready,
        .max_head_len = RequestHeadMaxLen,
    };
    const head_bytes = try request_reader.receiveHead();
    var proxy_authorization: ?[]const u8 = null;
    var origin_authorization: ?[]const u8 = null;
    var headers = std.http.HeaderIterator.init(head_bytes);
    while (headers.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "proxy-authorization")) {
            proxy_authorization = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
            origin_authorization = header.value;
        }
    }
    const authorized = if (options.expected_proxy_authorization) |expected|
        proxy_authorization != null and
            std.mem.eql(u8, proxy_authorization.?, expected)
    else
        true;
    if (!authorized or origin_authorization != null) {
        try client_output.writeAll(
            "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
        );
        try client_output.flush();
        return;
    }
    if (options.status < 200 or options.status >= 300) {
        try client_output.print(
            "HTTP/1.1 {d} Proxy Error\r\nContent-Length: 0\r\n\r\n",
            .{options.status},
        );
        try client_output.flush();
        return;
    }

    const upstream_host = try Io.net.HostName.init("127.0.0.1");
    var upstream = try upstream_host.connect(
        io,
        options.upstream_port,
        .{ .mode = .stream },
    );
    defer upstream.close(io);
    try client_output.writeAll(
        "HTTP/1.1 200 Connection Established\r\n\r\n",
    );
    try client_output.flush();

    var upstream_reader_buffer: [8192]u8 = undefined;
    var upstream_writer_buffer: [8192]u8 = undefined;
    var upstream_reader = upstream.reader(io, &upstream_reader_buffer);
    var upstream_writer = upstream.writer(io, &upstream_writer_buffer);
    const relay_thread = try std.Thread.spawn(
        .{},
        relayStreamThread,
        .{ client_input, &upstream_writer.interface },
    );
    relayStream(&upstream_reader.interface, client_output) catch {};
    upstream.shutdown(io, .both) catch {};
    client.shutdown(io, .both) catch {};
    relay_thread.join();
}

fn relayStreamThread(reader: *Io.Reader, writer: *Io.Writer) void {
    relayStream(reader, writer) catch {};
}

fn relayStream(reader: *Io.Reader, writer: *Io.Writer) !void {
    while (true) {
        const bytes = reader.peekGreedy(1) catch return;
        try writer.writeAll(bytes);
        try writer.flush();
        reader.toss(bytes.len);
    }
}

fn serveOne(io: Io, server: *Io.net.Server, options: ServerOptions) !void {
    const stream = try server.accept(io);
    defer stream.close(io);

    if (!options.tls_mode) {
        var reader_buf: [4096]u8 = undefined;
        var writer_buf: [4096]u8 = undefined;
        var reader = stream.reader(io, &reader_buf);
        var writer = stream.writer(io, &writer_buf);
        const auth_ok = try requestHeadersMatch(&reader.interface, options);
        if (!auth_ok) {
            try writer.interface.writeAll("HTTP/1.1 401 Unauthorized\r\nContent-Length: 4\r\nConnection: close\r\n\r\nauth");
            try writer.interface.flush();
            return;
        }
        if (options.stall_before_headers) {
            waitForPeerClose(&reader.interface);
            return;
        }
        if (options.response_delay_ns != 0) {
            try Io.sleep(io, .fromNanoseconds(options.response_delay_ns), .awake);
        }
        if (options.redirect_location) |location| {
            try writer.interface.print(
                "HTTP/1.1 {d} Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                .{ options.status, location },
            );
            try writer.interface.flush();
            return;
        }
        const declared_length = options.declared_length orelse options.body.len;
        try writer.interface.print(
            "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\n",
            .{
                options.status,
                if (options.status >= 400) "Error" else "OK",
                declared_length,
            },
        );
        if (options.content_disposition) |value| {
            try writer.interface.print("Content-Disposition: {s}\r\n", .{value});
        }
        try writer.interface.writeAll("\r\n");
        if (options.stall_mid_body and options.body.len != 0) {
            try writer.interface.writeAll(options.body[0..1]);
            try writer.interface.flush();
            waitForPeerClose(&reader.interface);
            return;
        } else if (options.body_split_delay_ns != 0 and options.body.len > 1) {
            try writer.interface.writeAll(options.body[0..1]);
            try writer.interface.flush();
            try Io.sleep(io, .fromNanoseconds(options.body_split_delay_ns), .awake);
            try writer.interface.writeAll(options.body[1..]);
        } else {
            try writer.interface.writeAll(options.body);
        }
        try writer.interface.flush();
        return;
    }

    if (options.stall_before_tls) {
        var reader_buf: [256]u8 = undefined;
        var reader = stream.reader(io, &reader_buf);
        waitForPeerClose(&reader.interface);
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
    const auth_ok = try requestHeadersMatch(&conn_reader.interface, options);
    if (!auth_ok) {
        try conn.writeAll("HTTP/1.1 401 Unauthorized\r\nContent-Length: 4\r\nConnection: close\r\n\r\nauth");
        return;
    }
    if (options.stall_before_headers) {
        waitForPeerClose(&conn_reader.interface);
        return;
    }
    if (options.response_delay_ns != 0) {
        try Io.sleep(io, .fromNanoseconds(options.response_delay_ns), .awake);
    }
    if (options.redirect_location) |location| {
        var redirect_buf: [1024]u8 = undefined;
        const redirect = try std.fmt.bufPrint(
            &redirect_buf,
            "HTTP/1.1 {d} Found\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            .{ options.status, location },
        );
        try conn.writeAll(redirect);
        return;
    }

    var response_buf: [1024]u8 = undefined;
    var response_writer: Io.Writer = .fixed(&response_buf);
    const declared_length = options.declared_length orelse options.body.len;
    try response_writer.print(
        "HTTP/1.1 {d} {s}\r\nContent-Length: {d}\r\nConnection: close\r\n",
        .{
            options.status,
            if (options.status >= 400) "Error" else "OK",
            declared_length,
        },
    );
    if (options.content_disposition) |value| {
        try response_writer.print("Content-Disposition: {s}\r\n", .{value});
    }
    try response_writer.writeAll("\r\n");
    try conn.writeAll(response_writer.buffered());
    if (options.stall_mid_body and options.body.len != 0) {
        try conn.writeAll(options.body[0..1]);
        waitForPeerClose(&conn_reader.interface);
    } else if (options.body_split_delay_ns != 0 and options.body.len > 1) {
        try conn.writeAll(options.body[0..1]);
        try Io.sleep(io, .fromNanoseconds(options.body_split_delay_ns), .awake);
        try conn.writeAll(options.body[1..]);
    } else {
        try conn.writeAll(options.body);
    }
}

fn waitForPeerClose(reader: *Io.Reader) void {
    var buffer: [256]u8 = undefined;
    while (true) {
        const count = reader.readSliceShort(&buffer) catch return;
        if (count == 0) return;
    }
}

fn requestHeadersMatch(reader: *Io.Reader, options: ServerOptions) !bool {
    var http_reader: std.http.Reader = .{
        .in = reader,
        .interface = undefined,
        .state = .ready,
        .max_head_len = RequestHeadMaxLen,
    };
    const head_bytes = try http_reader.receiveHead();
    var authorization: ?[]const u8 = null;
    var proxy_authorization: ?[]const u8 = null;
    var iter: std.http.HeaderIterator = .init(head_bytes);
    while (iter.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
            authorization = header.value;
        } else if (std.ascii.eqlIgnoreCase(header.name, "proxy-authorization")) {
            proxy_authorization = header.value;
        }
    }
    if (options.authorization_must_be_absent and authorization != null) {
        return false;
    }
    if (options.expected_authorization) |expected| {
        if (authorization == null or
            !std.mem.eql(u8, authorization.?, expected))
        {
            return false;
        }
    }
    if (options.expected_proxy_authorization) |expected| {
        if (proxy_authorization == null or
            !std.mem.eql(u8, proxy_authorization.?, expected))
        {
            return false;
        }
    }
    return true;
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

fn testRequest(
    url: [*:0]const u8,
    destination: [*:0]const u8,
) TDNF_ZIG_DOWNLOAD_REQUEST {
    return .{
        .pszUrl = url,
        .pszDestination = destination,
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
}

fn shippedConnectTimeout(io: Io) !c_long {
    const contents = try readFileAlloc(
        std.testing.allocator,
        io,
        "etc/tdnf/tdnf.conf",
    );
    defer std.testing.allocator.free(contents);
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        const prefix = "connect_timeout=";
        if (std.mem.startsWith(u8, line, prefix)) {
            return try std.fmt.parseInt(c_long, line[prefix.len..], 10);
        }
    }
    return error.MissingConnectTimeout;
}

test "shipped connect timeout selects timed direct HTTP and HTTPS transports" {
    var raw = testRequest("https://repo.example/repodata/repomd.xml", "unused");
    raw.nConnectTimeout = try shippedConnectTimeout(std.testing.io);
    const request = try parseRequest(&raw);
    try std.testing.expectEqual(
        DownloadTransport.custom_http,
        try chooseTransport(
            try Uri.parse("http://repo.example/repodata/repomd.xml"),
            request,
        ),
    );
    try std.testing.expectEqual(
        DownloadTransport.custom_http,
        try chooseTransport(
            try Uri.parse("https://repo.example/repodata/repomd.xml"),
            request,
        ),
    );
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
        .nConnectTimeout = try shippedConnectTimeout(io),
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
        .nConnectTimeout = try shippedConnectTimeout(io),
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

test "verified local https fetch succeeds with configured CA" {
    const io = std.testing.io;
    try ensureScratchDir(io);

    const server = try spawnServer(.{ .tls_mode = true, .body = "verified https body\n" });
    defer server.thread.join();

    const url = try std.fmt.allocPrint(std.testing.allocator, "https://localhost:{d}/payload", .{server.port});
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const ca_path = try Io.Dir.cwd().realPathFileAlloc(
        io,
        "client/download/fixtures/ca-cert.pem",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(ca_path);
    const z_ca_path = try dupeZ(std.testing.allocator, ca_path);
    defer std.testing.allocator.free(z_ca_path);
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
        .pszSSLCaCert = z_ca_path.ptr,
        .pszSSLClientCert = null,
        .pszSSLClientKey = null,
        .nSSLVerify = 1,
        .nConnectTimeout = try shippedConnectTimeout(io),
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
    try std.testing.expectEqualStrings("verified https body\n", body);
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

test "redirects succeed and ignore content disposition filenames" {
    const io = std.testing.io;
    try ensureScratchDir(io);

    const target = try spawnServer(.{
        .tls_mode = false,
        .body = "redirected body\n",
        .content_disposition = "attachment; filename=../../escape.rpm",
    });
    defer target.thread.join();
    const target_url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://127.0.0.1:{d}/target",
        .{target.port},
    );
    defer std.testing.allocator.free(target_url);
    const redirect = try spawnServer(.{
        .tls_mode = false,
        .status = 302,
        .redirect_location = target_url,
    });
    defer redirect.thread.join();

    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://127.0.0.1:{d}/redirect",
        .{redirect.port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const dest = try scratchPath(std.testing.allocator, "redirect-final.rpm");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);
    deleteFileIfExists(io, "escape.rpm");

    var request = testRequest(z_url.ptr, z_dest.ptr);
    var status: c_long = 0;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFZigDownloadFile(&request, &status),
    );
    const body = try readFileAlloc(std.testing.allocator, io, z_dest);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("redirected body\n", body);
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().access(io, "escape.rpm", .{}),
    );
}

test "HTTPS redirects cannot downgrade to HTTP" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const redirect = try spawnServer(.{
        .tls_mode = true,
        .status = 302,
        .redirect_location = "http://127.0.0.1:9/plaintext",
    });
    defer redirect.thread.join();
    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "https://localhost:{d}/redirect",
        .{redirect.port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const ca_path = try Io.Dir.cwd().realPathFileAlloc(
        io,
        "client/download/fixtures/ca-cert.pem",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(ca_path);
    const z_ca = try dupeZ(std.testing.allocator, ca_path);
    defer std.testing.allocator.free(z_ca);
    const dest = try scratchPath(std.testing.allocator, "downgrade.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest(z_url.ptr, z_dest.ptr);
    request.pszSSLCaCert = z_ca.ptr;
    var status: c_long = 0;
    try std.testing.expectEqual(
        errors.ERROR_TDNF_REPO_PERFORM,
        TDNFZigDownloadFile(&request, &status),
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            std.mem.span(TDNFZigDownloadLastError()),
            "HTTPS to HTTP",
        ) != null,
    );
}

test "origin credentials are not forwarded across redirects" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const expected = try buildBasicAuthorizationFromFields(
        std.testing.allocator,
        "repo-user",
        "repo-secret",
    );
    defer std.testing.allocator.free(expected);
    const target = try spawnServer(.{
        .tls_mode = false,
        .body = "no leaked credentials\n",
        .authorization_must_be_absent = true,
    });
    defer target.thread.join();
    const target_url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://localhost:{d}/target",
        .{target.port},
    );
    defer std.testing.allocator.free(target_url);
    const redirect = try spawnServer(.{
        .tls_mode = false,
        .status = 302,
        .redirect_location = target_url,
        .expected_authorization = expected,
    });
    defer redirect.thread.join();
    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://127.0.0.1:{d}/redirect",
        .{redirect.port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const dest = try scratchPath(std.testing.allocator, "redirect-auth.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest(z_url.ptr, z_dest.ptr);
    request.pszUserName = "repo-user";
    request.pszPassword = "repo-secret";
    var status: c_long = 0;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFZigDownloadFile(&request, &status),
    );
}

test "HTTP proxy authentication is sent only to the proxy" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const expected = try buildBasicAuthorizationFromCombined(
        std.testing.allocator,
        "proxy-user:proxy-secret",
    );
    defer std.testing.allocator.free(expected);
    const proxy = try spawnServer(.{
        .tls_mode = false,
        .body = "proxied body\n",
        .authorization_must_be_absent = true,
        .expected_proxy_authorization = expected,
    });
    defer proxy.thread.join();
    const proxy_url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://127.0.0.1:{d}",
        .{proxy.port},
    );
    defer std.testing.allocator.free(proxy_url);
    const z_proxy = try dupeZ(std.testing.allocator, proxy_url);
    defer std.testing.allocator.free(z_proxy);
    const dest = try scratchPath(std.testing.allocator, "proxy.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest("http://origin.invalid/payload", z_dest.ptr);
    request.pszProxy = z_proxy.ptr;
    request.pszProxyUserPwd = "proxy-user:proxy-secret";
    var status: c_long = 0;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFZigDownloadFile(&request, &status),
    );
}

test "HTTPS origin tunnels through an authenticated HTTP proxy" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const proxy_authorization = try buildBasicAuthorizationFromCombined(
        std.testing.allocator,
        "proxy-user:proxy-secret",
    );
    defer std.testing.allocator.free(proxy_authorization);
    const origin_authorization = try buildBasicAuthorizationFromFields(
        std.testing.allocator,
        "repo-user",
        "repo-secret",
    );
    defer std.testing.allocator.free(origin_authorization);
    const origin = try spawnServer(.{
        .tls_mode = true,
        .body = "http proxy tunnel body\n",
        .expected_authorization = origin_authorization,
    });
    defer origin.thread.join();
    const proxy = try spawnTunnelProxy(.{
        .tls_mode = false,
        .upstream_port = origin.port,
        .expected_proxy_authorization = proxy_authorization,
    });
    defer proxy.thread.join();

    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "https://localhost:{d}/through-http-proxy",
        .{origin.port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const proxy_url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://127.0.0.1:{d}",
        .{proxy.port},
    );
    defer std.testing.allocator.free(proxy_url);
    const z_proxy = try dupeZ(std.testing.allocator, proxy_url);
    defer std.testing.allocator.free(z_proxy);
    const ca_path = try Io.Dir.cwd().realPathFileAlloc(
        io,
        "client/download/fixtures/ca-cert.pem",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(ca_path);
    const z_ca = try dupeZ(std.testing.allocator, ca_path);
    defer std.testing.allocator.free(z_ca);
    const dest = try scratchPath(std.testing.allocator, "http-connect.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest(z_url.ptr, z_dest.ptr);
    request.pszProxy = z_proxy.ptr;
    request.pszProxyUserPwd = "proxy-user:proxy-secret";
    request.pszUserName = "repo-user";
    request.pszPassword = "repo-secret";
    request.pszSSLCaCert = z_ca.ptr;
    var status: c_long = 0;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFZigDownloadFile(&request, &status),
    );
    const body = try readFileAlloc(std.testing.allocator, io, z_dest);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("http proxy tunnel body\n", body);
}

test "HTTPS origin tunnels through an authenticated HTTPS proxy" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const proxy_authorization = try buildBasicAuthorizationFromCombined(
        std.testing.allocator,
        "proxy-user:proxy-secret",
    );
    defer std.testing.allocator.free(proxy_authorization);
    const origin = try spawnServer(.{
        .tls_mode = true,
        .body = "https proxy tunnel body\n",
    });
    defer origin.thread.join();
    const proxy = try spawnTunnelProxy(.{
        .tls_mode = true,
        .upstream_port = origin.port,
        .expected_proxy_authorization = proxy_authorization,
    });
    defer proxy.thread.join();

    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "https://localhost:{d}/through-https-proxy",
        .{origin.port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const proxy_url = try std.fmt.allocPrint(
        std.testing.allocator,
        "https://localhost:{d}",
        .{proxy.port},
    );
    defer std.testing.allocator.free(proxy_url);
    const z_proxy = try dupeZ(std.testing.allocator, proxy_url);
    defer std.testing.allocator.free(z_proxy);
    const ca_path = try Io.Dir.cwd().realPathFileAlloc(
        io,
        "client/download/fixtures/ca-cert.pem",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(ca_path);
    const z_ca = try dupeZ(std.testing.allocator, ca_path);
    defer std.testing.allocator.free(z_ca);
    const dest = try scratchPath(std.testing.allocator, "https-connect.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest(z_url.ptr, z_dest.ptr);
    request.pszProxy = z_proxy.ptr;
    request.pszProxyUserPwd = "proxy-user:proxy-secret";
    request.pszSSLCaCert = z_ca.ptr;
    var status: c_long = 0;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFZigDownloadFile(&request, &status),
    );
    const body = try readFileAlloc(std.testing.allocator, io, z_dest);
    defer std.testing.allocator.free(body);
    try std.testing.expectEqualStrings("https proxy tunnel body\n", body);
}

test "CONNECT proxy authentication and failure statuses return promptly" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const expected = try buildBasicAuthorizationFromCombined(
        std.testing.allocator,
        "proxy-user:proxy-secret",
    );
    defer std.testing.allocator.free(expected);
    const dest = try scratchPath(std.testing.allocator, "connect-failure.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);

    const auth_proxy = try spawnTunnelProxy(.{
        .tls_mode = false,
        .upstream_port = 9,
        .expected_proxy_authorization = expected,
    });
    defer auth_proxy.thread.join();
    const auth_proxy_url = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "http://127.0.0.1:{d}",
        .{auth_proxy.port},
        0,
    );
    defer std.testing.allocator.free(auth_proxy_url);
    var auth_request = testRequest("https://localhost:9/auth", z_dest.ptr);
    auth_request.pszProxy = auth_proxy_url.ptr;
    auth_request.pszProxyUserPwd = "wrong:credentials";
    auth_request.nTimeout = 1;
    var status: c_long = 0;
    try std.testing.expectEqual(
        errors.ERROR_TDNF_REPO_PERFORM,
        TDNFZigDownloadFile(&auth_request, &status),
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            std.mem.span(TDNFZigDownloadLastError()),
            "407",
        ) != null,
    );

    const status_proxy = try spawnTunnelProxy(.{
        .tls_mode = false,
        .upstream_port = 9,
        .status = 502,
    });
    defer status_proxy.thread.join();
    const status_proxy_url = try std.fmt.allocPrintSentinel(
        std.testing.allocator,
        "http://127.0.0.1:{d}",
        .{status_proxy.port},
        0,
    );
    defer std.testing.allocator.free(status_proxy_url);
    var status_request = testRequest("https://localhost:9/status", z_dest.ptr);
    status_request.pszProxy = status_proxy_url.ptr;
    status_request.nTimeout = 1;
    try std.testing.expectEqual(
        errors.ERROR_TDNF_REPO_PERFORM,
        TDNFZigDownloadFile(&status_request, &status),
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            std.mem.span(TDNFZigDownloadLastError()),
            "502",
        ) != null,
    );
}

test "mutual TLS uses configured client certificate and key" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const server = try spawnServer(.{
        .tls_mode = true,
        .require_client_auth = true,
        .body = "mutual tls body\n",
    });
    defer server.thread.join();
    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "https://localhost:{d}/mtls",
        .{server.port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const ca_path = try Io.Dir.cwd().realPathFileAlloc(
        io,
        "client/download/fixtures/ca-cert.pem",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(ca_path);
    const cert_path = try Io.Dir.cwd().realPathFileAlloc(
        io,
        "client/download/fixtures/client-cert.pem",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(cert_path);
    const key_path = try Io.Dir.cwd().realPathFileAlloc(
        io,
        "client/download/fixtures/client-key.pem",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(key_path);
    const z_ca = try dupeZ(std.testing.allocator, ca_path);
    defer std.testing.allocator.free(z_ca);
    const z_cert = try dupeZ(std.testing.allocator, cert_path);
    defer std.testing.allocator.free(z_cert);
    const z_key = try dupeZ(std.testing.allocator, key_path);
    defer std.testing.allocator.free(z_key);
    const dest = try scratchPath(std.testing.allocator, "mtls.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest(z_url.ptr, z_dest.ptr);
    request.pszSSLCaCert = z_ca.ptr;
    request.pszSSLClientCert = z_cert.ptr;
    request.pszSSLClientKey = z_key.ptr;
    var status: c_long = 0;
    try std.testing.expectEqual(
        @as(u32, 0),
        TDNFZigDownloadFile(&request, &status),
    );
}

test "HTTP status and truncated bodies return errors" {
    const io = std.testing.io;
    try ensureScratchDir(io);

    const missing = try spawnServer(.{
        .tls_mode = false,
        .status = 404,
        .body = "missing",
    });
    defer missing.thread.join();
    const missing_url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://127.0.0.1:{d}/missing",
        .{missing.port},
    );
    defer std.testing.allocator.free(missing_url);
    const z_missing_url = try dupeZ(std.testing.allocator, missing_url);
    defer std.testing.allocator.free(z_missing_url);
    const missing_dest = try scratchPath(std.testing.allocator, "missing.txt");
    defer std.testing.allocator.free(missing_dest);
    const z_missing_dest = try dupeZ(std.testing.allocator, missing_dest);
    defer std.testing.allocator.free(z_missing_dest);
    var missing_request = testRequest(z_missing_url.ptr, z_missing_dest.ptr);
    var status: c_long = 0;
    try std.testing.expectEqual(
        errors.ERROR_TDNF_INVALID_PARAMETER,
        TDNFZigDownloadFile(&missing_request, &status),
    );
    try std.testing.expectEqual(@as(c_long, 404), status);

    const truncated = try spawnServer(.{
        .tls_mode = false,
        .body = "short",
        .declared_length = 1024,
    });
    defer truncated.thread.join();
    const truncated_url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://127.0.0.1:{d}/truncated",
        .{truncated.port},
    );
    defer std.testing.allocator.free(truncated_url);
    const z_truncated_url = try dupeZ(std.testing.allocator, truncated_url);
    defer std.testing.allocator.free(z_truncated_url);
    const truncated_dest = try scratchPath(std.testing.allocator, "truncated.txt");
    defer std.testing.allocator.free(truncated_dest);
    const z_truncated_dest = try dupeZ(std.testing.allocator, truncated_dest);
    defer std.testing.allocator.free(z_truncated_dest);
    var truncated_request = testRequest(
        z_truncated_url.ptr,
        z_truncated_dest.ptr,
    );
    try std.testing.expect(
        TDNFZigDownloadFile(&truncated_request, &status) != 0,
    );
}

test "slow responses honor the total timeout" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const server = try spawnServer(.{
        .tls_mode = false,
        .body = "too late",
        .body_split_delay_ns = 2 * std.time.ns_per_s,
    });
    defer server.thread.join();
    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://127.0.0.1:{d}/slow",
        .{server.port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const dest = try scratchPath(std.testing.allocator, "timeout.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest(z_url.ptr, z_dest.ptr);
    request.nTimeout = 1;
    var status: c_long = 0;
    try std.testing.expectEqual(
        errors.ERROR_TDNF_TIMED_OUT,
        TDNFZigDownloadFile(&request, &status),
    );
}

test "permanent TCP connect stalls honor connect timeout" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const address = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try address.listen(io, .{
        .reuse_address = true,
        .kernel_backlog = 1,
    });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    const host = try Io.net.HostName.init("127.0.0.1");
    var queued_one = try host.connect(io, port, .{ .mode = .stream });
    defer queued_one.close(io);
    var queued_two = try host.connect(io, port, .{ .mode = .stream });
    defer queued_two.close(io);

    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://127.0.0.1:{d}/never-connects",
        .{port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const dest = try scratchPath(std.testing.allocator, "connect-stall.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest(z_url.ptr, z_dest.ptr);
    request.nConnectTimeout = 1;
    const started = Io.Clock.Timestamp.now(io, .awake);
    var status: c_long = 0;
    try std.testing.expectEqual(
        errors.ERROR_TDNF_TIMED_OUT,
        TDNFZigDownloadFile(&request, &status),
    );
    try std.testing.expect(
        timestampElapsedNs(io, started) < 10 * std.time.ns_per_s,
    );
}

test "accepted TCP without a TLS handshake honors total timeout" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const server = try spawnServer(.{
        .tls_mode = true,
        .stall_before_tls = true,
    });
    defer server.thread.join();
    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "https://localhost:{d}/no-tls-handshake",
        .{server.port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const ca_path = try Io.Dir.cwd().realPathFileAlloc(
        io,
        "client/download/fixtures/ca-cert.pem",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(ca_path);
    const z_ca = try dupeZ(std.testing.allocator, ca_path);
    defer std.testing.allocator.free(z_ca);
    const dest = try scratchPath(std.testing.allocator, "tls-handshake-stall.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest(z_url.ptr, z_dest.ptr);
    request.pszSSLCaCert = z_ca.ptr;
    request.nConnectTimeout = try shippedConnectTimeout(io);
    request.nTimeout = 1;
    const started = Io.Clock.Timestamp.now(io, .awake);
    var status: c_long = 0;
    try std.testing.expectEqual(
        errors.ERROR_TDNF_TIMED_OUT,
        TDNFZigDownloadFile(&request, &status),
    );
    try std.testing.expect(
        timestampElapsedNs(io, started) < 10 * std.time.ns_per_s,
    );
}

test "accepted TCP without a TLS handshake honors minrate timeout" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const server = try spawnServer(.{
        .tls_mode = true,
        .stall_before_tls = true,
    });
    defer server.thread.join();
    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "https://localhost:{d}/no-tls-minrate",
        .{server.port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const ca_path = try Io.Dir.cwd().realPathFileAlloc(
        io,
        "client/download/fixtures/ca-cert.pem",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(ca_path);
    const z_ca = try dupeZ(std.testing.allocator, ca_path);
    defer std.testing.allocator.free(z_ca);
    const dest = try scratchPath(std.testing.allocator, "tls-handshake-minrate.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest(z_url.ptr, z_dest.ptr);
    request.pszSSLCaCert = z_ca.ptr;
    request.nConnectTimeout = try shippedConnectTimeout(io);
    request.nLowSpeedLimit = 1;
    request.nLowSpeedTime = 1;
    const started = Io.Clock.Timestamp.now(io, .awake);
    var status: c_long = 0;
    try std.testing.expectEqual(
        errors.ERROR_TDNF_TIMED_OUT,
        TDNFZigDownloadFile(&request, &status),
    );
    try std.testing.expect(
        timestampElapsedNs(io, started) < 10 * std.time.ns_per_s,
    );
}

test "permanent header stalls are canceled within the configured timeout" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const server = try spawnServer(.{
        .tls_mode = false,
        .stall_before_headers = true,
    });
    defer server.thread.join();
    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "http://127.0.0.1:{d}/stalled-head",
        .{server.port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const dest = try scratchPath(std.testing.allocator, "stalled-head.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest(z_url.ptr, z_dest.ptr);
    request.nTimeout = 1;
    const started = Io.Clock.Timestamp.now(io, .awake);
    var status: c_long = 0;
    try std.testing.expectEqual(
        errors.ERROR_TDNF_TIMED_OUT,
        TDNFZigDownloadFile(&request, &status),
    );
    try std.testing.expect(
        timestampElapsedNs(io, started) < 10 * std.time.ns_per_s,
    );
}

test "permanent TLS mid-body stalls are canceled within the minrate window" {
    const io = std.testing.io;
    try ensureScratchDir(io);
    const server = try spawnServer(.{
        .tls_mode = true,
        .body = "partial body that never resumes",
        .declared_length = 4096,
        .stall_mid_body = true,
    });
    defer server.thread.join();
    const url = try std.fmt.allocPrint(
        std.testing.allocator,
        "https://localhost:{d}/stalled-body",
        .{server.port},
    );
    defer std.testing.allocator.free(url);
    const z_url = try dupeZ(std.testing.allocator, url);
    defer std.testing.allocator.free(z_url);
    const ca_path = try Io.Dir.cwd().realPathFileAlloc(
        io,
        "client/download/fixtures/ca-cert.pem",
        std.testing.allocator,
    );
    defer std.testing.allocator.free(ca_path);
    const z_ca = try dupeZ(std.testing.allocator, ca_path);
    defer std.testing.allocator.free(z_ca);
    const dest = try scratchPath(std.testing.allocator, "stalled-body.txt");
    defer std.testing.allocator.free(dest);
    const z_dest = try dupeZ(std.testing.allocator, dest);
    defer std.testing.allocator.free(z_dest);
    deleteFileIfExists(io, z_dest);

    var request = testRequest(z_url.ptr, z_dest.ptr);
    request.pszSSLCaCert = z_ca.ptr;
    request.nLowSpeedLimit = 1;
    request.nLowSpeedTime = 1;
    const started = Io.Clock.Timestamp.now(io, .awake);
    var status: c_long = 0;
    try std.testing.expectEqual(
        errors.ERROR_TDNF_TIMED_OUT,
        TDNFZigDownloadFile(&request, &status),
    );
    try std.testing.expect(
        timestampElapsedNs(io, started) < 10 * std.time.ns_per_s,
    );
}

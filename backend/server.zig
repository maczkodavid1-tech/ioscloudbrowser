```zig
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const net = std.net;
const crypto = std.crypto;
const Sha1 = crypto.hash.Sha1;
const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const ChachaRng = crypto.random;
const base64 = std.base64;
const json = std.json;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const StringHashMap = std.StringHashMap;
const AutoHashMap = std.AutoHashMap;
const Mutex = std.Thread.Mutex;
const Atomic = std.atomic.Value;
const Thread = std.Thread;
const ChildProcess = std.process.Child;

const VERSION = "1.0.0";
const MAGIC_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const LogLevel = enum { debug, info, warn, @"error" };

var global_log_level: LogLevel = .info;
var log_mutex: Mutex = .{};

fn log(level: LogLevel, component: []const u8, msg: []const u8) void {
    if (@intFromEnum(level) < @intFromEnum(global_log_level)) return;
    log_mutex.lock();
    defer log_mutex.unlock();
    const stdout = std.io.getStdOut().writer();
    var buf: [64]u8 = undefined;
    const ts = iso8601Now(&buf);
    const lvl = switch (level) {
        .debug => "debug",
        .info => "info",
        .warn => "warn",
        .@"error" => "error",
    };
    stdout.print("{{\"ts\":\"{s}\",\"level\":\"{s}\",\"component\":\"{s}\",\"msg\":\"{s}\"}}\n", .{ ts, lvl, component, msg }) catch {};
}

fn iso8601Now(buf: []u8) []const u8 {
    const epoch_ms = std.time.milliTimestamp();
    const epoch_s: i64 = @divTrunc(epoch_ms, 1000);
    const ms_i: i64 = @mod(epoch_ms, 1000);
    const ms: u16 = @intCast(if (ms_i < 0) ms_i + 1000 else ms_i);
    const ed = epochDayFromUnix(epoch_s);
    const ymd = dayToYmd(ed);
    const day_secs_i: i64 = @mod(epoch_s, 86400);
    const day_secs: u32 = @intCast(if (day_secs_i < 0) day_secs_i + 86400 else day_secs_i);
    const h: u32 = day_secs / 3600;
    const m: u32 = (@mod(day_secs, 3600)) / 60;
    const s: u32 = @mod(day_secs, 60);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{ ymd.y, ymd.m, ymd.d, h, m, s, ms }) catch "1970-01-01T00:00:00.000Z";
}

fn epochDayFromUnix(unix: i64) i64 {
    return @divTrunc(unix, 86400);
}

fn dayToYmd(day: i64) struct { y: i32, m: u32, d: u32 } {
    const z: i64 = day + 719468;
    const era: i64 = @divTrunc(if (z >= 0) z else z - 146096, 146097);
    const doe: u32 = @intCast(z - era * 146097);
    const yoe: u32 = @divTrunc(doe - @divTrunc(doe, 1460) + @divTrunc(doe, 36524) - @divTrunc(doe, 146096), 365);
    const y: i64 = @as(i64, yoe) + era * 400;
    const doy: u32 = doe - (365 * yoe + @divTrunc(yoe, 4) - @divTrunc(yoe, 100));
    const mp: u32 = @divTrunc(5 * doy + 2, 153);
    const d: u32 = doy - @divTrunc(153 * mp + 2, 5) + 1;
    const m_raw: u32 = if (mp < 10) mp + 3 else mp - 9;
    const y_final: i32 = @intCast(y + @as(i64, if (m_raw <= 2) 1 else 0));
    return .{ .y = y_final, .m = m_raw, .d = d };
}

const Config = struct {
    host: []const u8 = "0.0.0.0",
    port: u16 = 8443,
    tls_enabled: bool = true,
    tls_cert_path: []const u8 = "/etc/cloudbrowser/cert.pem",
    tls_key_path: []const u8 = "/etc/cloudbrowser/key.pem",
    development_plain_http: bool = false,
    chromium_path: []const u8 = "/usr/bin/chromium",
    container_runtime: []const u8 = "bwrap",
    bwrap_path: []const u8 = "/usr/bin/bwrap",
    runc_path: []const u8 = "/usr/bin/runc",
    runc_bundle_path: []const u8 = "/var/lib/cloudbrowser/bundle",
    cgroup_base: []const u8 = "/sys/fs/cgroup/cloudbrowser",
    seccomp_profile_path: []const u8 = "/etc/cloudbrowser/seccomp.json",
    allow_no_sandbox: bool = false,
    base_data_dir: []const u8 = "/var/lib/cloudbrowser",
    max_sessions: u32 = 1000,
    max_tabs_per_session: u32 = 20,
    session_idle_seconds: u64 = 1800,
    tab_idle_seconds: u64 = 600,
    token_ttl_seconds: u64 = 30,
    download_max_size_bytes: u64 = 104857600,
    download_signed_url_ttl_seconds: u64 = 300,
    hmac_secret_hex: []const u8 = "0000000000000000000000000000000000000000000000000000000000000000",
    default_jpeg_quality: u8 = 78,
    min_jpeg_quality: u8 = 40,
    max_jpeg_quality: u8 = 92,
    target_fps: u8 = 30,
    frame_queue_capacity: u32 = 6,
    drop_threshold_percent: u8 = 80,
    ws_heartbeat_interval_seconds: u64 = 30,
    ws_max_message_bytes: u64 = 8388608,
    ws_backpressure_max_bytes: u64 = 16777216,
    cdp_command_timeout_ms: u64 = 10000,
    proxy_assignment_strategy: []const u8 = "round_robin",
    fingerprint_user_agent: []const u8 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    fingerprint_platform: []const u8 = "MacIntel",
    fingerprint_languages: []const []const u8 = &.{ "en-US", "en" },
    fingerprint_timezone: []const u8 = "America/New_York",
    fingerprint_webgl_vendor: []const u8 = "Google Inc. (Apple)",
    fingerprint_webgl_renderer: []const u8 = "ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)",
    fingerprint_screen_width: u32 = 1920,
    fingerprint_screen_height: u32 = 1080,
    fingerprint_color_depth: u32 = 24,
    metrics_enabled: bool = true,
    metrics_path: []const u8 = "/metrics",
    allowed_origins: []const []const u8 = &.{},
    log_level: []const u8 = "info",
    cleanup_interval_seconds: u64 = 30,
    accept_language_header: []const u8 = "en-US,en;q=0.9",
    clear_cookies_on_tab_close: bool = true,
    persistent_mode_enabled: bool = false,
    webrtc_policy: []const u8 = "disable_non_proxied_udp",
};

const ProxyEntry = struct {
    id: []const u8,
    scheme: []const u8,
    host: []const u8,
    port: u16,
    username: []const u8 = "",
    password: []const u8 = "",
    region: []const u8 = "unknown",
    enabled: bool = true,
};

const WireType = enum(u8) {
    frame = 0x01,
    tab_state = 0x02,
    session_state = 0x03,
    err = 0x04,
    download = 0x05,
    clipboard = 0x06,
    ping = 0x07,
    auth_renew = 0x08,
};

const InputType = enum(u8) {
    touch = 0x10,
    mouse = 0x11,
    key = 0x12,
    navigate = 0x13,
    tab_control = 0x14,
    viewport = 0x15,
    settings = 0x16,
    clipboard = 0x17,
    frame_ack = 0x18,
};

const TabAction = enum(u8) {
    create = 0x01,
    close = 0x02,
    switch_to = 0x03,
    reload = 0x04,
    stop = 0x05,
    back = 0x06,
    forward = 0x07,
    duplicate = 0x08,
    thumbnail = 0x09,
};

const Metrics = struct {
    active_sessions: Atomic(u64) = Atomic(u64).init(0),
    active_tabs: Atomic(u64) = Atomic(u64).init(0),
    ws_connections: Atomic(u64) = Atomic(u64).init(0),
    frames_emitted: Atomic(u64) = Atomic(u64).init(0),
    frames_dropped: Atomic(u64) = Atomic(u64).init(0),
    bytes_in: Atomic(u64) = Atomic(u64).init(0),
    bytes_out: Atomic(u64) = Atomic(u64).init(0),
    cdp_commands_total: Atomic(u64) = Atomic(u64).init(0),
    cdp_command_failures: Atomic(u64) = Atomic(u64).init(0),
    container_spawn_failures: Atomic(u64) = Atomic(u64).init(0),
    sessions_created: Atomic(u64) = Atomic(u64).init(0),
    tabs_created: Atomic(u64) = Atomic(u64).init(0),
    http_requests_total: Atomic(u64) = Atomic(u64).init(0),
    ws_upgrades_total: Atomic(u64) = Atomic(u64).init(0),
    ws_upgrade_failures: Atomic(u64) = Atomic(u64).init(0),
    downloads_served: Atomic(u64) = Atomic(u64).init(0),
    start_time_ns: i128 = 0,
};

fn inc(counter: *Atomic(u64), by: u64) void {
    _ = counter.fetchAdd(by, .monotonic);
}

fn dec(counter: *Atomic(u64), by: u64) void {
    _ = counter.fetchSub(by, .monotonic);
}

const SessionToken = struct {
    value: [32]u8,
    expires_at_ns: i128,
};

const DownloadEntry = struct {
    id: [32]u8,
    session_id: [32]u8,
    filename: []const u8,
    mime: []const u8,
    size: u64,
    state: u8,
    path: []const u8,
    created_ns: i128,
};

const Tab = struct {
    id: u32,
    session_id: [32]u8,
    profile_dir: []const u8,
    download_dir: []const u8,
    runtime_dir: []const u8,
    proxy: ?ProxyEntry,
    child: ?*ChildProcess,
    cdp_stdin: ?std.fs.File,
    cdp_stdout: ?std.fs.File,
    cdp_mutex: Mutex,
    cdp_msg_id: Atomic(u64),
    cdp_pending: std.AutoHashMap(u64, *CdpPendingCall),
    cdp_pending_mutex: Mutex,
    ws: ?*WebSocket,
    frame_seq: Atomic(u32),
    screencast_session_id: Atomic(u64),
    jpeg_quality: Atomic(u8),
    viewport_w: Atomic(u32),
    viewport_h: Atomic(u32),
    viewport_scale: f32,
    title: []const u8,
    url: []const u8,
    loading: bool,
    can_go_back: bool,
    can_go_forward: bool,
    security_state: []const u8,
    state_mutex: Mutex,
    last_activity_ns: Atomic(i128),
    frame_queue_depth: Atomic(u32),
    allocator: Allocator,
    cdp_reader_thread: ?Thread,
    cdp_running: Atomic(bool),
};

const CdpPendingCall = struct {
    done: Atomic(bool),
    result: ?json.Parsed(json.Value),
    allocator: Allocator,
    mutex: Mutex,
};

const Session = struct {
    id: [32]u8,
    tokens: ArrayList(SessionToken),
    token_mutex: Mutex,
    tabs: AutoHashMap(u32, *Tab),
    tabs_mutex: Mutex,
    ws: ?*WebSocket,
    ws_mutex: Mutex,
    created_ns: i128,
    last_activity_ns: Atomic(i128),
    active_tab_id: Atomic(u32),
    allocator: Allocator,
};

const WebSocket = struct {
    conn: net.Stream,
    closed: Atomic(bool),
    write_mutex: Mutex,
    send_queue: ArrayList([]const u8),
    send_queue_bytes: Atomic(u64),
    last_pong_ns: Atomic(i128),
    session: *Session,
    allocator: Allocator,
};

const ServerState = struct {
    config: Config,
    proxies: ArrayList(ProxyEntry),
    proxy_rr_index: Atomic(u64),
    sessions: StringHashMap(*Session),
    sessions_mutex: Mutex,
    downloads: StringHashMap(*DownloadEntry),
    downloads_mutex: Mutex,
    metrics: Metrics,
    allocator: Allocator,
    shutdown: Atomic(bool),
    hmac_key: [32]u8,
    listener: ?net.Server,
    next_tab_id: Atomic(u32),
};

fn hexDecode(out: []u8, src: []const u8) !void {
    if (src.len != out.len * 2) return error.InvalidLength;
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        const hi = hexNibble(src[i * 2]) orelse return error.InvalidHex;
        const lo = hexNibble(src[i * 2 + 1]) orelse return error.InvalidHex;
        out[i] = (hi << 4) | lo;
    }
}

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn hexEncode(out: []u8, src: []const u8) void {
    const chars = "0123456789abcdef";
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        out[i * 2] = chars[src[i] >> 4];
        out[i * 2 + 1] = chars[src[i] & 0x0F];
    }
}

fn secureId(out: *[32]u8) void {
    crypto.random.bytes(out);
}

fn idToHex(id: [32]u8) [64]u8 {
    var out: [64]u8 = undefined;
    hexEncode(&out, &id);
    return out;
}

fn hexToId(src: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    try hexDecode(&out, src);
    return out;
}

fn nowNs() i128 {
    return std.time.nanoTimestamp();
}

fn loadConfig(allocator: Allocator, path: []const u8) !Config {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    return try json.parseFromSliceLeaky(Config, allocator, content, .{ .ignore_unknown_fields = true });
}

fn loadProxies(allocator: Allocator, path: []const u8) !ArrayList(ProxyEntry) {
    var list = ArrayList(ProxyEntry).init(allocator);
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        if (err == error.FileNotFound) return list;
        return err;
    };
    defer file.close();
    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    const arr = try json.parseFromSliceLeaky([]ProxyEntry, allocator, content, .{ .ignore_unknown_fields = true });
    for (arr) |p| try list.append(p);
    return list;
}

fn selectProxy(state: *ServerState, session_id: [32]u8) ?ProxyEntry {
    if (state.proxies.items.len == 0) return null;
    var enabled_count: usize = 0;
    for (state.proxies.items) |p| {
        if (p.enabled) enabled_count += 1;
    }
    if (enabled_count == 0) return null;
    const strat = state.config.proxy_assignment_strategy;
    if (std.mem.eql(u8, strat, "random")) {
        var idx = crypto.random.int(u64) % state.proxies.items.len;
        var tries: usize = 0;
        while (tries < state.proxies.items.len) : (tries += 1) {
            if (state.proxies.items[idx].enabled) return state.proxies.items[idx];
            idx = (idx + 1) % state.proxies.items.len;
        }
        return null;
    }
    if (std.mem.eql(u8, strat, "sticky_per_session")) {
        var h: u64 = 0;
        for (session_id) |b| h = h *% 131 +% b;
        const idx = h % state.proxies.items.len;
        if (state.proxies.items[idx].enabled) return state.proxies.items[idx];
        return state.proxies.items[0];
    }
    const rr = state.proxy_rr_index.fetchAdd(1, .monotonic);
    return state.proxies.items[rr % state.proxies.items.len];
}

fn writeJsonResponse(writer: anytype, status: []const u8, body: []const u8, extra_headers: []const []const u8) !void {
    try writer.print("HTTP/1.1 {s}\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n", .{ status, body.len });
    for (extra_headers) |h| {
        try writer.print("{s}\r\n", .{h});
    }
    try writer.writeAll("\r\n");
    try writer.writeAll(body);
}

fn writePlainResponse(writer: anytype, status: []const u8, body: []const u8, content_type: []const u8) !void {
    try writer.print("HTTP/1.1 {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{ status, content_type, body.len });
    try writer.writeAll(body);
}

fn wsAccept(key: []const u8, allocator: Allocator) ![28]u8 {
    var concat = ArrayList(u8).init(allocator);
    defer concat.deinit();
    try concat.appendSlice(key);
    try concat.appendSlice(MAGIC_WS_GUID);
    var sha1: [20]u8 = undefined;
    Sha1.hash(concat.items, &sha1, .{});
    var out: [28]u8 = undefined;
    _ = base64.standard.Encoder.encode(&out, &sha1);
    return out;
}

fn trim(s: []const u8) []const u8 {
    return std.mem.trim(u8, s, " \t\r\n");
}

const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    headers: StringHashMap([]const u8),
    body: []const u8,
    allocator: Allocator,

    fn deinit(self: *HttpRequest) void {
        self.headers.deinit();
        self.allocator.free(self.method);
        self.allocator.free(self.path);
        if (self.body.len > 0) self.allocator.free(self.body);
    }
};

fn parseHttpRequest(reader: anytype, allocator: Allocator, buf: []u8) !HttpRequest {
    var headers = StringHashMap([]const u8).init(allocator);
    var method: []const u8 = "";
    var path: []const u8 = "";
    var total: usize = 0;
    var header_end: ?usize = null;

    while (total < buf.len) {
        const n = try reader.read(buf[total..]);
        if (n == 0) return error.Incomplete;
        total += n;
        if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n")) |idx| {
            header_end = idx + 4;
            break;
        }
    }
    if (header_end == null) return error.Incomplete;

    var it = std.mem.splitSequence(u8, buf[0 .. header_end.? - 2], "\r\n");
    const first_line = it.next() orelse return error.Malformed;
    var fl = std.mem.splitSequence(u8, first_line, " ");
    const m = fl.next() orelse return error.Malformed;
    const p = fl.next() orelse return error.Malformed;
    method = try allocator.dupe(u8, m);
    path = try allocator.dupe(u8, p);

    while (it.next()) |line| {
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const name = trim(line[0..colon]);
            const value = trim(line[colon + 1 ..]);
            var name_lc = try allocator.alloc(u8, name.len);
            for (name, 0..) |c, i| name_lc[i] = std.ascii.toLower(c);
            try headers.put(name_lc, try allocator.dupe(u8, value));
        }
    }

    var body: []const u8 = "";
    if (headers.get("content-length")) |cl| {
        const len = std.fmt.parseInt(usize, cl, 10) catch 0;
        const already_have = total - header_end.?;
        if (already_have < len) {
            const need = len - already_have;
            var initial = try allocator.alloc(u8, already_have);
            @memcpy(initial, buf[header_end.? .. header_end.? + already_have]);
            body = initial;
            while (body.len < need + already_have) {
                var tmp: [4096]u8 = undefined;
                const n = try reader.read(&tmp);
                if (n == 0) break;
                const slice = try allocator.alloc(u8, body.len + n);
                @memcpy(slice[0..body.len], body);
                @memcpy(slice[body.len .. body.len + n], tmp[0..n]);
                allocator.free(body);
                body = slice;
            }
        } else {
            body = try allocator.dupe(u8, buf[header_end.? .. header_end.? + len]);
        }
    }

    return HttpRequest{
        .method = method,
        .path = path,
        .headers = headers,
        .body = body,
        .allocator = allocator,
    };
}

fn handleHealth(state: *ServerState, writer: anytype) !void {
    const uptime_ns = nowNs() - state.metrics.start_time_ns;
    const uptime_s = @divTrunc(uptime_ns, std.time.ns_per_s);
    var body = ArrayList(u8).init(state.allocator);
    defer body.deinit();
    const w = body.writer();
    try w.print(
        \\{{"version":"{s}","uptime_seconds":{d},"active_sessions":{d},"active_tabs":{d},"timestamp":"{s}"}}
    , .{
        VERSION,
        uptime_s,
        state.metrics.active_sessions.load(.monotonic),
        state.metrics.active_tabs.load(.monotonic),
        "now",
    });
    try writeJsonResponse(writer, "200 OK", body.items, &.{});
}

fn handleMetrics(state: *ServerState, writer: anytype) !void {
    if (!state.config.metrics_enabled) {
        try writePlainResponse(writer, "404 Not Found", "metrics disabled", "text/plain");
        return;
    }
    var body = ArrayList(u8).init(state.allocator);
    defer body.deinit();
    const w = body.writer();
    try w.print("# HELP cloud_browser_active_sessions Current active sessions.\n", .{});
    try w.print("# TYPE cloud_browser_active_sessions gauge\n", .{});
    try w.print("cloud_browser_active_sessions {d}\n", .{state.metrics.active_sessions.load(.monotonic)});
    try w.print("# HELP cloud_browser_active_tabs Current active tabs.\n", .{});
    try w.print("# TYPE cloud_browser_active_tabs gauge\n", .{});
    try w.print("cloud_browser_active_tabs {d}\n", .{state.metrics.active_tabs.load(.monotonic)});
    try w.print("# HELP cloud_browser_ws_connections Current WebSocket connections.\n", .{});
    try w.print("# TYPE cloud_browser_ws_connections gauge\n", .{});
    try w.print("cloud_browser_ws_connections {d}\n", .{state.metrics.ws_connections.load(.monotonic)});
    try w.print("# HELP cloud_browser_frames_emitted_total Total frames emitted.\n", .{});
    try w.print("# TYPE cloud_browser_frames_emitted_total counter\n", .{});
    try w.print("cloud_browser_frames_emitted_total {d}\n", .{state.metrics.frames_emitted.load(.monotonic)});
    try w.print("# HELP cloud_browser_frames_dropped_total Total frames dropped.\n", .{});
    try w.print("# TYPE cloud_browser_frames_dropped_total counter\n", .{});
    try w.print("cloud_browser_frames_dropped_total {d}\n", .{state.metrics.frames_dropped.load(.monotonic)});
    try w.print("# HELP cloud_browser_bytes_in_total Total bytes received from clients.\n", .{});
    try w.print("# TYPE cloud_browser_bytes_in_total counter\n", .{});
    try w.print("cloud_browser_bytes_in_total {d}\n", .{state.metrics.bytes_in.load(.monotonic)});
    try w.print("# HELP cloud_browser_bytes_out_total Total bytes sent to clients.\n", .{});
    try w.print("# TYPE cloud_browser_bytes_out_total counter\n", .{});
    try w.print("cloud_browser_bytes_out_total {d}\n", .{state.metrics.bytes_out.load(.monotonic)});
    try w.print("# HELP cloud_browser_cdp_commands_total Total CDP commands issued.\n", .{});
    try w.print("# TYPE cloud_browser_cdp_commands_total counter\n", .{});
    try w.print("cloud_browser_cdp_commands_total {d}\n", .{state.metrics.cdp_commands_total.load(.monotonic)});
    try w.print("# HELP cloud_browser_cdp_command_failures_total Total CDP failures.\n", .{});
    try w.print("# TYPE cloud_browser_cdp_command_failures_total counter\n", .{});
    try w.print("cloud_browser_cdp_command_failures_total {d}\n", .{state.metrics.cdp_command_failures.load(.monotonic)});
    try w.print("# HELP cloud_browser_container_spawn_failures_total Total container spawn failures.\n", .{});
    try w.print("# TYPE cloud_browser_container_spawn_failures_total counter\n", .{});
    try w.print("cloud_browser_container_spawn_failures_total {d}\n", .{state.metrics.container_spawn_failures.load(.monotonic)});
    try w.print("# HELP cloud_browser_sessions_created_total Total sessions created.\n", .{});
    try w.print("# TYPE cloud_browser_sessions_created_total counter\n", .{});
    try w.print("cloud_browser_sessions_created_total {d}\n", .{state.metrics.sessions_created.load(.monotonic)});
    try w.print("# HELP cloud_browser_tabs_created_total Total tabs created.\n", .{});
    try w.print("# TYPE cloud_browser_tabs_created_total counter\n", .{});
    try w.print("cloud_browser_tabs_created_total {d}\n", .{state.metrics.tabs_created.load(.monotonic)});
    try w.print("# HELP cloud_browser_http_requests_total Total HTTP requests.\n", .{});
    try w.print("# TYPE cloud_browser_http_requests_total counter\n", .{});
    try w.print("cloud_browser_http_requests_total {d}\n", .{state.metrics.http_requests_total.load(.monotonic)});
    try w.print("# HELP cloud_browser_ws_upgrades_total Total WS upgrades.\n", .{});
    try w.print("# TYPE cloud_browser_ws_upgrades_total counter\n", .{});
    try w.print("cloud_browser_ws_upgrades_total {d}\n", .{state.metrics.ws_upgrades_total.load(.monotonic)});
    try w.print("# HELP cloud_browser_ws_upgrade_failures_total Total WS upgrade failures.\n", .{});
    try w.print("# TYPE cloud_browser_ws_upgrade_failures_total counter\n", .{});
    try w.print("cloud_browser_ws_upgrade_failures_total {d}\n", .{state.metrics.ws_upgrade_failures.load(.monotonic)});
    try w.print("# HELP cloud_browser_downloads_served_total Downloads served.\n", .{});
    try w.print("# TYPE cloud_browser_downloads_served_total counter\n", .{});
    try w.print("cloud_browser_downloads_served_total {d}\n", .{state.metrics.downloads_served.load(.monotonic)});
    try writePlainResponse(writer, "200 OK", body.items, "text/plain; version=0.0.4");
}

fn generateToken(out: *[32]u8, state: *ServerState) SessionToken {
    crypto.random.bytes(out);
    const expires = nowNs() + @as(i128, @intCast(state.config.token_ttl_seconds)) * std.time.ns_per_s;
    return SessionToken{ .value = out.*, .expires_at_ns = expires };
}

fn tokenValid(session: *Session, token_hex: []const u8) bool {
    if (token_hex.len != 64) return false;
    var candidate: [32]u8 = undefined;
    hexDecode(&candidate, token_hex) catch return false;
    session.token_mutex.lock();
    defer session.token_mutex.unlock();
    const now = nowNs();
    var i: usize = 0;
    while (i < session.tokens.items.len) {
        if (session.tokens.items[i].expires_at_ns < now) {
            _ = session.tokens.swapRemove(i);
            continue;
        }
        if (std.mem.eql(u8, &session.tokens.items[i].value, &candidate)) return true;
        i += 1;
    }
    return false;
}

fn handleCreateSession(state: *ServerState, writer: anytype) !void {
    if (state.metrics.active_sessions.load(.monotonic) >= state.config.max_sessions) {
        try writeJsonResponse(writer, "503 Service Unavailable", "{\"error\":\"max_sessions\"}", &.{});
        return;
    }
    var id: [32]u8 = undefined;
    secureId(&id);
    var tok_bytes: [32]u8 = undefined;
    const token = generateToken(&tok_bytes, state);
    const session = try state.allocator.create(Session);
    session.* = Session{
        .id = id,
        .tokens = ArrayList(SessionToken).init(state.allocator),
        .token_mutex = .{},
        .tabs = AutoHashMap(u32, *Tab).init(state.allocator),
        .tabs_mutex = .{},
        .ws = null,
        .ws_mutex = .{},
        .created_ns = nowNs(),
        .last_activity_ns = Atomic(i128).init(nowNs()),
        .active_tab_id = Atomic(u32).init(0),
        .allocator = state.allocator,
    };
    try session.tokens.append(token);
    const id_hex = idToHex(id);
    const tok_hex = idToHex(token.value);

    state.sessions_mutex.lock();
    const id_slice = try state.allocator.dupe(u8, &id_hex);
    try state.sessions.put(id_slice, session);
    state.sessions_mutex.unlock();

    inc(&state.metrics.active_sessions, 1);
    inc(&state.metrics.sessions_created, 1);
    log(.info, "http", "session created");

    var body = ArrayList(u8).init(state.allocator);
    defer body.deinit();
    try body.writer().print(
        \\{{"session_id":"{s}","ws_token":"{s}","token_ttl_seconds":{d}}}
    , .{ &id_hex, &tok_hex, state.config.token_ttl_seconds });
    try writeJsonResponse(writer, "201 Created", body.items, &.{});
}

fn handleRefreshSession(state: *ServerState, req: *HttpRequest, writer: anytype) !void {
    var parsed = json.parseFromSlice(json.Value, state.allocator, req.body, .{}) catch {
        try writeJsonResponse(writer, "400 Bad Request", "{\"error\":\"bad json\"}", &.{});
        return;
    };
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) {
        try writeJsonResponse(writer, "400 Bad Request", "{\"error\":\"not object\"}", &.{});
        return;
    }
    const sid = root.object.get("session_id") orelse {
        try writeJsonResponse(writer, "400 Bad Request", "{\"error\":\"missing session_id\"}", &.{});
        return;
    };
    const tok = root.object.get("ws_token") orelse {
        try writeJsonResponse(writer, "400 Bad Request", "{\"error\":\"missing ws_token\"}", &.{});
        return;
    };
    if (sid != .string or tok != .string) {
        try writeJsonResponse(writer, "400 Bad Request", "{\"error\":\"bad types\"}", &.{});
        return;
    }
    state.sessions_mutex.lock();
    const session = state.sessions.get(sid.string);
    state.sessions_mutex.unlock();
    if (session == null) {
        try writeJsonResponse(writer, "404 Not Found", "{\"error\":\"unknown session\"}", &.{});
        return;
    }
    if (!tokenValid(session.?, tok.string)) {
        try writeJsonResponse(writer, "401 Unauthorized", "{\"error\":\"invalid token\"}", &.{});
        return;
    }
    var tok_bytes: [32]u8 = undefined;
    const new_token = generateToken(&tok_bytes, state);
    session.?.token_mutex.lock();
    try session.?.tokens.append(new_token);
    session.?.token_mutex.unlock();
    const tok_hex = idToHex(new_token.value);
    var body = ArrayList(u8).init(state.allocator);
    defer body.deinit();
    try body.writer().print(
        \\{{"ws_token":"{s}","token_ttl_seconds":{d}}}
    , .{ &tok_hex, state.config.token_ttl_seconds });
    try writeJsonResponse(writer, "200 OK", body.items, &.{});
}

fn handleDeleteSession(state: *ServerState, session_id_hex: []const u8, writer: anytype) !void {
    state.sessions_mutex.lock();
    const owned_key = state.sessions.getKey(session_id_hex);
    const session = state.sessions.fetchRemove(session_id_hex);
    state.sessions_mutex.unlock();
    if (session == null) {
        try writeJsonResponse(writer, "404 Not Found", "{\"error\":\"unknown session\"}", &.{});
        return;
    }
    terminateSession(state, session.?.value);
    if (owned_key) |k| state.allocator.free(k);
    dec(&state.metrics.active_sessions, 1);
    try writeJsonResponse(writer, "200 OK", "{\"status\":\"deleted\"}", &.{});
}

fn terminateSession(state: *ServerState, session: *Session) void {
    session.tabs_mutex.lock();
    var it = session.tabs.valueIterator();
    while (it.next()) |tab_ptr| {
        terminateTab(state, tab_ptr.*);
    }
    session.tabs.deinit();
    session.tabs_mutex.unlock();
    session.token_mutex.lock();
    session.tokens.deinit();
    session.token_mutex.unlock();
    if (session.ws) |ws| {
        _ = ws.closed.swap(true, .monotonic);
        ws.conn.close();
    }
    state.allocator.destroy(session);
}

fn terminateTab(state: *ServerState, tab: *Tab) void {
    tab.cdp_running.store(false, .monotonic);
    if (tab.child) |child| {
        _ = child.kill() catch std.process.Child.Term{ .Unknown = 0 };
        state.allocator.destroy(child);
    }
    if (tab.cdp_stdin) |f| f.close();
    if (tab.cdp_stdout) |f| f.close();
    std.fs.cwd().deleteTree(tab.profile_dir) catch {};
    std.fs.cwd().deleteTree(tab.download_dir) catch {};
    std.fs.cwd().deleteTree(tab.runtime_dir) catch {};
    tab.allocator.free(tab.profile_dir);
    tab.allocator.free(tab.download_dir);
    tab.allocator.free(tab.runtime_dir);
    tab.allocator.free(tab.title);
    tab.allocator.free(tab.url);
    tab.allocator.free(tab.security_state);
    tab.cdp_pending_mutex.lock();
    var pit = tab.cdp_pending.valueIterator();
    while (pit.next()) |pc| {
        pc.*.done.store(true, .monotonic);
    }
    tab.cdp_pending.deinit();
    tab.cdp_pending_mutex.unlock();
    dec(&state.metrics.active_tabs, 1);
    tab.allocator.destroy(tab);
}

fn handleDownload(state: *ServerState, download_id: []const u8, sig: []const u8, writer: anytype) !void {
    _ = sig;
    state.downloads_mutex.lock();
    const entry = state.downloads.get(download_id);
    state.downloads_mutex.unlock();
    if (entry == null) {
        try writeJsonResponse(writer, "404 Not Found", "{\"error\":\"unknown download\"}", &.{});
        return;
    }
    const d = entry.?;
    const file = std.fs.cwd().openFile(d.path, .{}) catch {
        try writeJsonResponse(writer, "410 Gone", "{\"error\":\"file missing\"}", &.{});
        return;
    };
    defer file.close();
    const stat = try file.stat();
    if (stat.size > state.config.download_max_size_bytes) {
        try writeJsonResponse(writer, "413 Payload Too Large", "{\"error\":\"too large\"}", &.{});
        return;
    }
    const header = try std.fmt.allocPrint(state.allocator, "HTTP/1.1 200 OK\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nContent-Disposition: attachment; filename=\"{s}\"\r\nConnection: close\r\n\r\n", .{ d.mime, stat.size, d.filename });
    defer state.allocator.free(header);
    try writer.writeAll(header);
    var buf: [65536]u8 = undefined;
    var remaining = stat.size;
    while (remaining > 0) {
        const n = try file.read(&buf);
        if (n == 0) break;
        try writer.writeAll(buf[0..n]);
        remaining -= @min(remaining, n);
    }
    inc(&state.metrics.downloads_served, 1);
}

const WsOpcode = enum(u4) {
    cont = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

fn wsReadFrame(stream: net.Stream, allocator: Allocator) !struct { opcode: WsOpcode, payload: []const u8, fin: bool } {
    var hdr: [2]u8 = undefined;
    try stream.reader().readNoEof(&hdr);
    const fin = (hdr[0] & 0x80) != 0;
    const op: u4 = @intCast(hdr[0] & 0x0F);
    const masked = (hdr[1] & 0x80) != 0;
    if (!masked) return error.UnmaskedClientFrame;
    var length: u64 = @intCast(hdr[1] & 0x7F);
    if (length == 126) {
        var ext: [2]u8 = undefined;
        try stream.reader().readNoEof(&ext);
        length = (@as(u64, ext[0]) << 8) | ext[1];
    } else if (length == 127) {
        var ext: [8]u8 = undefined;
        try stream.reader().readNoEof(&ext);
        length = 0;
        for (ext) |b| length = (length << 8) | b;
    }
    if (length > 32 * 1024 * 1024) return error.FrameTooLarge;
    var mask: [4]u8 = undefined;
    try stream.reader().readNoEof(&mask);
    var payload = try allocator.alloc(u8, @intCast(length));
    var read_total: usize = 0;
    while (read_total < payload.len) {
        const n = try stream.read(payload[read_total..]);
        if (n == 0) return error.Closed;
        read_total += n;
    }
    for (payload, 0..) |*b, i| {
        b.* ^= mask[i % 4];
    }
    const opcode: WsOpcode = @enumFromInt(op);
    return .{ .opcode = opcode, .payload = payload, .fin = fin };
}

fn wsWriteFrame(stream: net.Stream, mutex: *Mutex, opcode: WsOpcode, payload: []const u8) !void {
    mutex.lock();
    defer mutex.unlock();
    var hdr: [14]u8 = undefined;
    var pos: usize = 0;
    hdr[0] = 0x80 | @as(u8, @intFromEnum(opcode));
    pos = 1;
    if (payload.len < 126) {
        hdr[1] = @intCast(payload.len);
        pos = 2;
    } else if (payload.len < 65536) {
        hdr[1] = 126;
        hdr[2] = @intCast((payload.len >> 8) & 0xFF);
        hdr[3] = @intCast(payload.len & 0xFF);
        pos = 4;
    } else {
        hdr[1] = 127;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            hdr[2 + i] = @intCast((payload.len >> @intCast(8 * (7 - i))) & 0xFF);
        }
        pos = 10;
    }
    try stream.writeAll(hdr[0..pos]);
    try stream.writeAll(payload);
}

fn sendWsMessage(ws: *WebSocket, payload: []const u8) !void {
    if (ws.closed.load(.monotonic)) return error.Closed;
    const queued = ws.send_queue_bytes.load(.monotonic);
    if (queued > 16 * 1024 * 1024) {
        return error.BackpressureOverflow;
    }
    try wsWriteFrame(ws.conn, &ws.write_mutex, .binary, payload);
}

fn buildFrameMessage(allocator: Allocator, tab_id: u32, frame_seq: u32, w: u32, h: u32, ts_ns: u64, jpeg: []const u8) ![]u8 {
    const total = 1 + 4 + 4 + 4 + 4 + 8 + 4 + jpeg.len;
    var buf = try allocator.alloc(u8, total);
    var p: usize = 0;
    buf[p] = @intFromEnum(WireType.frame);
    p += 1;
    std.mem.writeInt(u32, buf[p .. p + 4][0..4], tab_id, .little);
    p += 4;
    std.mem.writeInt(u32, buf[p .. p + 4][0..4], frame_seq, .little);
    p += 4;
    std.mem.writeInt(u32, buf[p .. p + 4][0..4], w, .little);
    p += 4;
    std.mem.writeInt(u32, buf[p .. p + 4][0..4], h, .little);
    p += 4;
    std.mem.writeInt(u64, buf[p .. p + 8][0..8], ts_ns, .little);
    p += 8;
    std.mem.writeInt(u32, buf[p .. p + 4][0..4], @intCast(jpeg.len), .little);
    p += 4;
    @memcpy(buf[p .. p + jpeg.len], jpeg);
    return buf;
}

fn sendTabState(ws: *WebSocket, tab: *Tab) !void {
    tab.state_mutex.lock();
    defer tab.state_mutex.unlock();
    var buf = ArrayList(u8).init(ws.allocator);
    defer buf.deinit();
    try buf.append(@intFromEnum(WireType.tab_state));
    var tmp4: [4]u8 = undefined;
    std.mem.writeInt(u32, &tmp4, tab.id, .little);
    try buf.appendSlice(&tmp4);
    try buf.append(if (tab.loading) @as(u8, 1) else @as(u8, 0));
    var tmp2: [2]u8 = undefined;
    std.mem.writeInt(u16, &tmp2, @intCast(tab.title.len), .little);
    try buf.appendSlice(&tmp2);
    try buf.appendSlice(tab.title);
    std.mem.writeInt(u16, &tmp2, @intCast(tab.url.len), .little);
    try buf.appendSlice(&tmp2);
    try buf.appendSlice(tab.url);
    var nav_flags: u8 = 0;
    if (tab.can_go_back) nav_flags |= 0x01;
    if (tab.can_go_forward) nav_flags |= 0x02;
    try buf.append(nav_flags);
    std.mem.writeInt(u16, &tmp2, @intCast(tab.security_state.len), .little);
    try buf.appendSlice(&tmp2);
    try buf.appendSlice(tab.security_state);
    try wsWriteFrame(ws.conn, &ws.write_mutex, .binary, buf.items);
}

fn sendSessionState(ws: *WebSocket) !void {
    const session = ws.session;
    session.tabs_mutex.lock();
    defer session.tabs_mutex.unlock();
    var buf = ArrayList(u8).init(ws.allocator);
    defer buf.deinit();
    try buf.append(@intFromEnum(WireType.session_state));
    var tmp2: [2]u8 = undefined;
    std.mem.writeInt(u16, &tmp2, @intCast(session.tabs.count()), .little);
    try buf.appendSlice(&tmp2);
    var it = session.tabs.iterator();
    while (it.next()) |entry| {
        const tab = entry.value_ptr.*;
        var tmp4: [4]u8 = undefined;
        std.mem.writeInt(u32, &tmp4, tab.id, .little);
        try buf.appendSlice(&tmp4);
        std.mem.writeInt(u16, &tmp2, @intCast(tab.title.len), .little);
        try buf.appendSlice(&tmp2);
        try buf.appendSlice(tab.title);
        std.mem.writeInt(u16, &tmp2, @intCast(tab.url.len), .little);
        try buf.appendSlice(&tmp2);
        try buf.appendSlice(tab.url);
        try buf.append(if (tab.proxy != null) @as(u8, 1) else 0);
        if (tab.proxy) |px| {
            std.mem.writeInt(u16, &tmp2, @intCast(px.region.len), .little);
            try buf.appendSlice(&tmp2);
            try buf.appendSlice(px.region);
        }
    }
    var tmp4: [4]u8 = undefined;
    std.mem.writeInt(u32, &tmp4, session.active_tab_id.load(.monotonic), .little);
    try buf.appendSlice(&tmp4);
    try wsWriteFrame(ws.conn, &ws.write_mutex, .binary, buf.items);
}

fn sendError(ws: *WebSocket, code: u32, message: []const u8) !void {
    var buf = ArrayList(u8).init(ws.allocator);
    defer buf.deinit();
    try buf.append(@intFromEnum(WireType.err));
    var tmp4: [4]u8 = undefined;
    std.mem.writeInt(u32, &tmp4, code, .little);
    try buf.appendSlice(&tmp4);
    var tmp2: [2]u8 = undefined;
    std.mem.writeInt(u16, &tmp2, @intCast(message.len), .little);
    try buf.appendSlice(&tmp2);
    try buf.appendSlice(message);
    try wsWriteFrame(ws.conn, &ws.write_mutex, .binary, buf.items);
}

fn sendPing(ws: *WebSocket) !void {
    var buf: [9]u8 = undefined;
    buf[0] = @intFromEnum(WireType.ping);
    std.mem.writeInt(u64, buf[1..9][0..8], @intCast(nowNs()), .little);
    try wsWriteFrame(ws.conn, &ws.write_mutex, .binary, &buf);
}

fn sendAuthRenew(ws: *WebSocket, deadline_seconds: u32) !void {
    var buf: [5]u8 = undefined;
    buf[0] = @intFromEnum(WireType.auth_renew);
    std.mem.writeInt(u32, buf[1..5][0..4], deadline_seconds, .little);
    try wsWriteFrame(ws.conn, &ws.write_mutex, .binary, &buf);
}

fn sendDownload(ws: *WebSocket, d: *DownloadEntry) !void {
    var buf = ArrayList(u8).init(ws.allocator);
    defer buf.deinit();
    try buf.append(@intFromEnum(WireType.download));
    try buf.appendSlice(&d.id);
    var tmp2: [2]u8 = undefined;
    std.mem.writeInt(u16, &tmp2, @intCast(d.filename.len), .little);
    try buf.appendSlice(&tmp2);
    try buf.appendSlice(d.filename);
    std.mem.writeInt(u16, &tmp2, @intCast(d.mime.len), .little);
    try buf.appendSlice(&tmp2);
    try buf.appendSlice(d.mime);
    var tmp8: [8]u8 = undefined;
    std.mem.writeInt(u64, &tmp8, d.size, .little);
    try buf.appendSlice(&tmp8);
    try buf.append(d.state);
    try wsWriteFrame(ws.conn, &ws.write_mutex, .binary, buf.items);
}

fn cdpSendCommand(tab: *Tab, method: []const u8, params: json.Value) !json.Value {
    const id = tab.cdp_msg_id.fetchAdd(1, .monotonic) + 1;
    var payload = ArrayList(u8).init(tab.allocator);
    defer payload.deinit();
    try json.stringify(.{ .id = id, .method = method, .params = params }, .{}, payload.writer());
    try payload.append('\x00');

    const pending = try tab.allocator.create(CdpPendingCall);
    pending.* = CdpPendingCall{
        .done = Atomic(bool).init(false),
        .result = null,
        .allocator = tab.allocator,
        .mutex = .{},
    };
    tab.cdp_pending_mutex.lock();
    try tab.cdp_pending.put(id, pending);
    tab.cdp_pending_mutex.unlock();

    if (tab.cdp_stdin) |stdin| {
        try stdin.writeAll(payload.items);
    } else return error.NoCdpPipe;

    const deadline = nowNs() + @as(i128, @intCast(10_000)) * 1_000_000;
    while (!pending.done.load(.acquire)) {
        if (nowNs() > deadline) return error.CdpTimeout;
        std.time.sleep(1_000_000);
    }
    tab.cdp_pending_mutex.lock();
    _ = tab.cdp_pending.remove(id);
    tab.cdp_pending_mutex.unlock();
    if (pending.result) |r| {
        const val = r.value;
        tab.allocator.destroy(pending);
        return val;
    }
    tab.allocator.destroy(pending);
    return json.Value{ .null = {} };
}

fn cdpReaderThreadFn(ctx: ?*anyopaque) u8 {
    _ = ctx;
    return 0;
}

fn ensureTabDirs(tab: *Tab) !void {
    std.fs.cwd().makePath(tab.profile_dir) catch {};
    std.fs.cwd().makePath(tab.download_dir) catch {};
    std.fs.cwd().makePath(tab.runtime_dir) catch {};
}

fn spawnChromium(state: *ServerState, tab: *Tab) !void {
    try ensureTabDirs(tab);
    var args = ArrayList([]const u8).init(state.allocator);
    defer args.deinit();
    if (std.mem.eql(u8, state.config.container_runtime, "bwrap")) {
        try args.append(state.config.bwrap_path);
        try args.append("--dev-bind");
        try args.append("/");
        try args.append("/");
        try args.append("--tmpfs");
        try args.append(tab.runtime_dir);
        try args.append("--bind");
        try args.append(tab.profile_dir);
        try args.append(tab.profile_dir);
        try args.append("--bind");
        try args.append(tab.download_dir);
        try args.append(tab.download_dir);
        try args.append("--unshare-net");
        try args.append("--die-with-parent");
        try args.append("--new-session");
        try args.append("--");
    }
    try args.append(state.config.chromium_path);
    try args.append("--headless=new");
    try args.append("--remote-debugging-pipe");
    var udb = ArrayList(u8).init(state.allocator);
    try udb.writer().print("--user-data-dir={s}", .{tab.profile_dir});
    try args.append(try state.allocator.dupe(u8, udb.items));
    udb.deinit();
    var wszb = ArrayList(u8).init(state.allocator);
    try wszb.writer().print("--window-size={d},{d}", .{ tab.viewport_w.load(.monotonic), tab.viewport_h.load(.monotonic) });
    try args.append(try state.allocator.dupe(u8, wszb.items));
    wszb.deinit();
    var scb = ArrayList(u8).init(state.allocator);
    try scb.writer().print("--force-device-scale-factor={d:.2}", .{tab.viewport_scale});
    try args.append(try state.allocator.dupe(u8, scb.items));
    scb.deinit();
    try args.append("--disable-background-networking");
    try args.append("--disable-sync");
    try args.append("--disable-translate");
    try args.append("--disable-default-apps");
    try args.append("--disable-extensions");
    try args.append("--disable-component-update");
    try args.append("--disable-features=Translate,InterestFeedContentSuggestions,MediaRouter");
    try args.append("--mute-audio");
    try args.append("--hide-scrollbars");
    try args.append("--no-first-run");
    try args.append("--no-default-browser-check");
    try args.append("--password-store=basic");
    try args.append("--use-mock-keychain");
    var wrb = ArrayList(u8).init(state.allocator);
    try wrb.writer().print("--force-webrtc-ip-handling-policy={s}", .{state.config.webrtc_policy});
    try args.append(try state.allocator.dupe(u8, wrb.items));
    wrb.deinit();
    if (tab.proxy) |px| {
        var pb = ArrayList(u8).init(state.allocator);
        if (px.username.len > 0) {
            try pb.writer().print("--proxy-server={s}://{s}:{s}@{s}:{d}", .{ px.scheme, px.username, px.password, px.host, px.port });
        } else {
            try pb.writer().print("--proxy-server={s}://{s}:{d}", .{ px.scheme, px.host, px.port });
        }
        try args.append(try state.allocator.dupe(u8, pb.items));
        pb.deinit();
        var hrb = ArrayList(u8).init(state.allocator);
        try hrb.writer().print("--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE {s}", .{px.host});
        try args.append(try state.allocator.dupe(u8, hrb.items));
        hrb.deinit();
    }
    if (state.config.allow_no_sandbox) {
        try args.append("--no-sandbox");
    }
    const child = try state.allocator.create(ChildProcess);
    child.* = ChildProcess.init(args.items, state.allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;
    child.spawn() catch |err| {
        inc(&state.metrics.container_spawn_failures, 1);
        state.allocator.destroy(child);
        return err;
    };
    tab.child = child;
    tab.cdp_stdin = child.stdin;
    tab.cdp_stdout = child.stdout;
    tab.cdp_running.store(true, .monotonic);
    log(.info, "tab", "chromium spawned");
}

fn startScreencast(state: *ServerState, tab: *Tab) !void {
    _ = state;
    var params = std.json.ObjectMap.init(tab.allocator);
    try params.put("format", json.Value{ .string = "jpeg" });
    try params.put("quality", json.Value{ .integer = tab.jpeg_quality.load(.monotonic) });
    try params.put("maxWidth", json.Value{ .integer = tab.viewport_w.load(.monotonic) });
    try params.put("maxHeight", json.Value{ .integer = tab.viewport_h.load(.monotonic) });
    try params.put("everyNthFrame", json.Value{ .integer = 1 });
    _ = cdpSendCommand(tab, "Page.startScreencast", json.Value{ .object = params }) catch json.Value{ .null = {} };
}

fn applyFingerprint(state: *ServerState, tab: *Tab) !void {
    var script = ArrayList(u8).init(state.allocator);
    defer script.deinit();
    try script.writer().print(
        \\Object.defineProperty(navigator,'userAgent',{{get:() => '{s}'}});
        \\Object.defineProperty(navigator,'platform',{{get:() => '{s}'}});
        \\Object.defineProperty(navigator,'languages',{{get:() => ['{s}','{s}']}});
        \\Object.defineProperty(navigator,'webdriver',{{get:() => false}});
        \\Object.defineProperty(screen,'width',{{get:() => {d}}});
        \\Object.defineProperty(screen,'height',{{get:() => {d}}});
        \\Object.defineProperty(screen,'colorDepth',{{get:() => {d}}});
        \\Object.defineProperty(screen,'pixelDepth',{{get:() => {d}}});
    , .{
        state.config.fingerprint_user_agent,
        state.config.fingerprint_platform,
        state.config.fingerprint_languages[0],
        if (state.config.fingerprint_languages.len > 1) state.config.fingerprint_languages[1] else "en",
        state.config.fingerprint_screen_width,
        state.config.fingerprint_screen_height,
        state.config.fingerprint_color_depth,
        state.config.fingerprint_color_depth,
    });
    var params = std.json.ObjectMap.init(state.allocator);
    try params.put("source", json.Value{ .string = script.items });
    _ = cdpSendCommand(tab, "Page.addScriptToEvaluateOnNewDocument", json.Value{ .object = params }) catch json.Value{ .null = {} };

    var hdr = std.json.ObjectMap.init(state.allocator);
    var headers = std.json.ObjectMap.init(state.allocator);
    try headers.put("Accept-Language", json.Value{ .string = state.config.accept_language_header });
    try headers.put("User-Agent", json.Value{ .string = state.config.fingerprint_user_agent });
    try hdr.put("headers", json.Value{ .object = headers });
    _ = cdpSendCommand(tab, "Network.setExtraHTTPHeaders", json.Value{ .object = hdr }) catch json.Value{ .null = {} };
}

fn handleNewTab(state: *ServerState, session: *Session) !*Tab {
    if (session.tabs.count() >= state.config.max_tabs_per_session) return error.TooManyTabs;
    const tab_id = state.next_tab_id.fetchAdd(1, .monotonic) + 1;
    const id_hex = idToHex(session.id);
    const tab = try state.allocator.create(Tab);
    tab.* = Tab{
        .id = tab_id,
        .session_id = session.id,
        .profile_dir = try std.fmt.allocPrint(state.allocator, "{s}/sessions/{s}/tabs/{d}/profile", .{ state.config.base_data_dir, &id_hex, tab_id }),
        .download_dir = try std.fmt.allocPrint(state.allocator, "{s}/sessions/{s}/tabs/{d}/downloads", .{ state.config.base_data_dir, &id_hex, tab_id }),
        .runtime_dir = try std.fmt.allocPrint(state.allocator, "{s}/sessions/{s}/tabs/{d}/runtime", .{ state.config.base_data_dir, &id_hex, tab_id }),
        .proxy = selectProxy(state, session.id),
        .child = null,
        .cdp_stdin = null,
        .cdp_stdout = null,
        .cdp_mutex = .{},
        .cdp_msg_id = Atomic(u64).init(0),
        .cdp_pending = std.AutoHashMap(u64, *CdpPendingCall).init(state.allocator),
        .cdp_pending_mutex = .{},
        .ws = session.ws,
        .frame_seq = Atomic(u32).init(0),
        .screencast_session_id = Atomic(u64).init(0),
        .jpeg_quality = Atomic(u8).init(state.config.default_jpeg_quality),
        .viewport_w = Atomic(u32).init(1280),
        .viewport_h = Atomic(u32).init(800),
        .viewport_scale = 2.0,
        .title = try state.allocator.dupe(u8, "New Tab"),
        .url = try state.allocator.dupe(u8, "about:blank"),
        .loading = false,
        .can_go_back = false,
        .can_go_forward = false,
        .security_state = try state.allocator.dupe(u8, "unknown"),
        .state_mutex = .{},
        .last_activity_ns = Atomic(i128).init(nowNs()),
        .frame_queue_depth = Atomic(u32).init(0),
        .allocator = state.allocator,
        .cdp_reader_thread = null,
        .cdp_running = Atomic(bool).init(false),
    };
    spawnChromium(state, tab) catch |err| {
        state.allocator.free(tab.profile_dir);
        state.allocator.free(tab.download_dir);
        state.allocator.free(tab.runtime_dir);
        state.allocator.free(tab.title);
        state.allocator.free(tab.url);
        state.allocator.free(tab.security_state);
        tab.cdp_pending.deinit();
        state.allocator.destroy(tab);
        return err;
    };
    session.tabs_mutex.lock();
    try session.tabs.put(tab_id, tab);
    session.tabs_mutex.unlock();
    session.active_tab_id.store(tab_id, .monotonic);
    inc(&state.metrics.active_tabs, 1);
    inc(&state.metrics.tabs_created, 1);
    std.time.sleep(50_000_000);
    applyFingerprint(state, tab) catch {};
    startScreencast(state, tab) catch {};
    return tab;
}

fn decodeJpegBase64(allocator: Allocator, encoded: []const u8) ![]u8 {
    const size = base64.standard.Decoder.calcSizeForSlice(encoded) catch return error.BadBase64;
    var out = try allocator.alloc(u8, size);
    base64.standard.Decoder.decode(out, encoded) catch return error.BadBase64;
    return out;
}

fn emitFrame(state: *ServerState, tab: *Tab, jpeg_b64: []const u8, w: u32, h: u32, ts_us: f64) void {
    const ws = tab.ws orelse return;
    if (ws.closed.load(.monotonic)) return;
    const depth = tab.frame_queue_depth.load(.monotonic);
    if (depth >= state.config.frame_queue_capacity) {
        inc(&state.metrics.frames_dropped, 1);
        return;
    }
    _ = tab.frame_queue_depth.fetchAdd(1, .monotonic);
    const jpeg = decodeJpegBase64(state.allocator, jpeg_b64) catch {
        _ = tab.frame_queue_depth.fetchSub(1, .monotonic);
        return;
    };
    defer state.allocator.free(jpeg);
    const ts_ns: u64 = @intFromFloat(ts_us * 1000.0);
    const seq = tab.frame_seq.fetchAdd(1, .monotonic) + 1;
    const frame = buildFrameMessage(state.allocator, tab.id, seq, w, h, ts_ns, jpeg) catch {
        _ = tab.frame_queue_depth.fetchSub(1, .monotonic);
        return;
    };
    defer state.allocator.free(frame);
    wsWriteFrame(ws.conn, &ws.write_mutex, .binary, frame) catch {
        _ = tab.frame_queue_depth.fetchSub(1, .monotonic);
        return;
    };
    _ = tab.frame_queue_depth.fetchSub(1, .monotonic);
    inc(&state.metrics.frames_emitted, 1);
    inc(&state.metrics.bytes_out, @intCast(frame.len));
}

fn handleClientMessage(state: *ServerState, ws: *WebSocket, payload: []const u8) !void {
    if (payload.len < 1) return;
    const kind: InputType = @enumFromInt(payload[0]);
    inc(&state.metrics.bytes_in, @intCast(payload.len));
    ws.session.last_activity_ns.store(nowNs(), .monotonic);
    switch (kind) {
        .navigate => {
            if (payload.len < 3) return;
            const url_len = std.mem.readInt(u16, payload[1..3][0..2], .little);
            if (payload.len < 3 + url_len) return;
            const url = payload[3 .. 3 + url_len];
            const tab_id = ws.session.active_tab_id.load(.monotonic);
            ws.session.tabs_mutex.lock();
            const tab = ws.session.tabs.get(tab_id);
            ws.session.tabs_mutex.unlock();
            if (tab) |t| {
                var params = std.json.ObjectMap.init(state.allocator);
                try params.put("url", json.Value{ .string = url });
                _ = cdpSendCommand(t, "Page.navigate", json.Value{ .object = params }) catch json.Value{ .null = {} };
            }
        },
        .tab_control => {
            if (payload.len < 2) return;
            const action: TabAction = @enumFromInt(payload[1]);
            switch (action) {
                .create => {
                    const tab = handleNewTab(state, ws.session) catch |err| {
                        sendError(ws, 1, @errorName(err)) catch {};
                        return;
                    };
                    if (ws.session.ws) |w| sendTabState(w, tab) catch {};
                    sendSessionState(ws) catch {};
                },
                .close => {
                    if (payload.len < 6) return;
                    const tab_id = std.mem.readInt(u32, payload[2..6][0..4], .little);
                    ws.session.tabs_mutex.lock();
                    const tab = ws.session.tabs.fetchRemove(tab_id);
                    ws.session.tabs_mutex.unlock();
                    if (tab) |kv| terminateTab(state, kv.value);
                    sendSessionState(ws) catch {};
                },
                .switch_to => {
                    if (payload.len < 6) return;
                    const tab_id = std.mem.readInt(u32, payload[2..6][0..4], .little);
                    ws.session.active_tab_id.store(tab_id, .monotonic);
                    sendSessionState(ws) catch {};
                },
                .reload => {
                    const tab_id = ws.session.active_tab_id.load(.monotonic);
                    ws.session.tabs_mutex.lock();
                    const tab = ws.session.tabs.get(tab_id);
                    ws.session.tabs_mutex.unlock();
                    if (tab) |t| {
                        _ = cdpSendCommand(t, "Page.reload", json.Value{ .null = {} }) catch json.Value{ .null = {} };
                    }
                },
                .stop => {
                    const tab_id = ws.session.active_tab_id.load(.monotonic);
                    ws.session.tabs_mutex.lock();
                    const tab = ws.session.tabs.get(tab_id);
                    ws.session.tabs_mutex.unlock();
                    if (tab) |t| {
                        _ = cdpSendCommand(t, "Page.stopLoading", json.Value{ .null = {} }) catch json.Value{ .null = {} };
                    }
                },
                .back => {
                    const tab_id = ws.session.active_tab_id.load(.monotonic);
                    ws.session.tabs_mutex.lock();
                    const tab = ws.session.tabs.get(tab_id);
                    ws.session.tabs_mutex.unlock();
                    if (tab) |t| {
                        _ = cdpSendCommand(t, "Page.navigateToHistoryEntry", json.Value{ .null = {} }) catch json.Value{ .null = {} };
                    }
                },
                .forward => {
                    const tab_id = ws.session.active_tab_id.load(.monotonic);
                    ws.session.tabs_mutex.lock();
                    const tab = ws.session.tabs.get(tab_id);
                    ws.session.tabs_mutex.unlock();
                    if (tab) |t| {
                        _ = cdpSendCommand(t, "Page.navigateToHistoryEntry", json.Value{ .null = {} }) catch json.Value{ .null = {} };
                    }
                },
                .duplicate, .thumbnail => {},
            }
        },
        .viewport => {
            if (payload.len < 13) return;
            const w = std.mem.readInt(u32, payload[1..5][0..4], .little);
            const h = std.mem.readInt(u32, payload[5..9][0..4], .little);
            const scale_raw = std.mem.readInt(u32, payload[9..13][0..4], .little);
            const scale: f32 = @bitCast(scale_raw);
            const tab_id = ws.session.active_tab_id.load(.monotonic);
            ws.session.tabs_mutex.lock();
            const tab = ws.session.tabs.get(tab_id);
            ws.session.tabs_mutex.unlock();
            if (tab) |t| {
                t.viewport_w.store(w, .monotonic);
                t.viewport_h.store(h, .monotonic);
                t.viewport_scale = scale;
                var params = std.json.ObjectMap.init(state.allocator);
                try params.put("width", json.Value{ .integer = @intCast(w) });
                try params.put("height", json.Value{ .integer = @intCast(h) });
                try params.put("deviceScaleFactor", json.Value{ .float = @as(f64, scale) });
                try params.put("mobile", json.Value{ .bool = false });
                _ = cdpSendCommand(t, "Emulation.setDeviceMetricsOverride", json.Value{ .object = params }) catch json.Value{ .null = {} };
                _ = cdpSendCommand(t, "Page.stopScreencast", json.Value{ .null = {} }) catch json.Value{ .null = {} };
                startScreencast(state, t) catch {};
            }
        },
        .touch => {
            if (payload.len < 25) return;
            const phase = payload[1];
            const touch_id = std.mem.readInt(u32, payload[2..6][0..4], .little);
            const x_raw = std.mem.readInt(u32, payload[6..10][0..4], .little);
            const y_raw = std.mem.readInt(u32, payload[10..14][0..4], .little);
            const radius_raw = std.mem.readInt(u32, payload[14..18][0..4], .little);
            const force_raw = std.mem.readInt(u32, payload[18..22][0..4], .little);
            const modifiers = std.mem.readInt(u16, payload[22..24][0..2], .little);
            _ = payload[24];
            const x: f64 = @floatFromInt(x_raw);
            const y: f64 = @floatFromInt(y_raw);
            const radius: f64 = @as(f64, @floatFromInt(radius_raw)) / 10.0;
            const force: f64 = @as(f64, @floatFromInt(force_raw)) / 1000.0;
            const tab_id = ws.session.active_tab_id.load(.monotonic);
            ws.session.tabs_mutex.lock();
            const tab = ws.session.tabs.get(tab_id);
            ws.session.tabs_mutex.unlock();
            if (tab) |t| {
                const type_str: []const u8 = switch (phase) {
                    0 => "touchStart",
                    1 => "touchEnd",
                    2 => "touchMove",
                    else => "touchMove",
                };
                var params = std.json.ObjectMap.init(state.allocator);
                try params.put("type", json.Value{ .string = type_str });
                var tp = std.json.ObjectMap.init(state.allocator);
                try tp.put("x", json.Value{ .float = x });
                try tp.put("y", json.Value{ .float = y });
                try tp.put("id", json.Value{ .integer = @intCast(touch_id) });
                try tp.put("radiusX", json.Value{ .float = radius });
                try tp.put("radiusY", json.Value{ .float = radius });
                try tp.put("force", json.Value{ .float = force });
                var touches = json.Array.init(state.allocator);
                try touches.append(json.Value{ .object = tp });
                try params.put("touchPoints", json.Value{ .array = touches });
                try params.put("modifiers", json.Value{ .integer = modifiers });
                _ = cdpSendCommand(t, "Input.dispatchTouchEvent", json.Value{ .object = params }) catch json.Value{ .null = {} };
            }
        },
        .mouse => {
            if (payload.len < 13) return;
            const type_byte = payload[1];
            const button = payload[2];
            const x = std.mem.readInt(u32, payload[3..7][0..4], .little);
            const y = std.mem.readInt(u32, payload[7..11][0..4], .little);
            const modifiers = std.mem.readInt(u16, payload[11..13][0..2], .little);
            const tab_id = ws.session.active_tab_id.load(.monotonic);
            ws.session.tabs_mutex.lock();
            const tab = ws.session.tabs.get(tab_id);
            ws.session.tabs_mutex.unlock();
            if (tab) |t| {
                const type_str: []const u8 = switch (type_byte) {
                    0 => "mousePressed",
                    1 => "mouseReleased",
                    2 => "mouseMoved",
                    3 => "mouseWheel",
                    else => "mouseMoved",
                };
                const button_str: []const u8 = switch (button) {
                    0 => "none",
                    1 => "left",
                    2 => "middle",
                    3 => "right",
                    else => "none",
                };
                var params = std.json.ObjectMap.init(state.allocator);
                try params.put("type", json.Value{ .string = type_str });
                try params.put("x", json.Value{ .integer = @intCast(x) });
                try params.put("y", json.Value{ .integer = @intCast(y) });
                try params.put("button", json.Value{ .string = button_str });
                try params.put("clickCount", json.Value{ .integer = 1 });
                try params.put("modifiers", json.Value{ .integer = modifiers });
                _ = cdpSendCommand(t, "Input.dispatchMouseEvent", json.Value{ .object = params }) catch json.Value{ .null = {} };
            }
        },
        .key => {
            if (payload.len < 10) return;
            const type_byte = payload[1];
            const modifiers = std.mem.readInt(u16, payload[2..4][0..2], .little);
            const key_code = std.mem.readInt(u32, payload[4..8][0..4], .little);
            const text_len = std.mem.readInt(u16, payload[8..10][0..2], .little);
            const text = if (payload.len >= 10 + text_len) payload[10 .. 10 + text_len] else "";
            const tab_id = ws.session.active_tab_id.load(.monotonic);
            ws.session.tabs_mutex.lock();
            const tab = ws.session.tabs.get(tab_id);
            ws.session.tabs_mutex.unlock();
            if (tab) |t| {
                const type_str: []const u8 = switch (type_byte) {
                    0 => "keyDown",
                    1 => "keyUp",
                    2 => "char",
                    else => "keyDown",
                };
                var params = std.json.ObjectMap.init(state.allocator);
                try params.put("type", json.Value{ .string = type_str });
                try params.put("modifiers", json.Value{ .integer = modifiers });
                try params.put("windowsVirtualKeyCode", json.Value{ .integer = @intCast(key_code) });
                try params.put("nativeVirtualKeyCode", json.Value{ .integer = @intCast(key_code) });
                if (text.len > 0) try params.put("text", json.Value{ .string = text });
                _ = cdpSendCommand(t, "Input.dispatchKeyEvent", json.Value{ .object = params }) catch json.Value{ .null = {} };
            }
        },
        .settings => {
            if (payload.len < 3) return;
            const json_len = std.mem.readInt(u16, payload[1..3][0..2], .little);
            if (payload.len < 3 + json_len) return;
            const json_text = payload[3 .. 3 + json_len];
            var parsed = json.parseFromSlice(json.Value, state.allocator, json_text, .{}) catch return;
            defer parsed.deinit();
            if (parsed.value == .object) {
                if (parsed.value.object.get("jpeg_quality")) |q| {
                    if (q == .integer) {
                        const raw_u8: u8 = @intCast(q.integer);
                        const clamped = @max(state.config.min_jpeg_quality, @min(state.config.max_jpeg_quality, raw_u8));
                        const tab_id = ws.session.active_tab_id.load(.monotonic);
                        ws.session.tabs_mutex.lock();
                        const tab = ws.session.tabs.get(tab_id);
                        ws.session.tabs_mutex.unlock();
                        if (tab) |t| t.jpeg_quality.store(clamped, .monotonic);
                    }
                }
            }
        },
        .clipboard => {
            if (payload.len < 2) return;
            const sub = payload[1];
            if (sub == 0) {} else if (sub == 1) {
                if (payload.len < 4) return;
                const text_len = std.mem.readInt(u16, payload[2..4][0..2], .little);
                const text = if (payload.len >= 4 + text_len) payload[4 .. 4 + text_len] else "";
                const tab_id = ws.session.active_tab_id.load(.monotonic);
                ws.session.tabs_mutex.lock();
                const tab = ws.session.tabs.get(tab_id);
                ws.session.tabs_mutex.unlock();
                if (tab) |t| {
                    var params = std.json.ObjectMap.init(state.allocator);
                    try params.put("text", json.Value{ .string = text });
                    _ = cdpSendCommand(t, "Input.insertText", json.Value{ .object = params }) catch json.Value{ .null = {} };
                }
            }
        },
        .frame_ack => {
            if (payload.len < 13) return;
            const seq = std.mem.readInt(u32, payload[1..5][0..4], .little);
            const client_ts = std.mem.readInt(u64, payload[5..13][0..8], .little);
            _ = seq;
            _ = client_ts;
            const tab_id = ws.session.active_tab_id.load(.monotonic);
            ws.session.tabs_mutex.lock();
            const tab = ws.session.tabs.get(tab_id);
            ws.session.tabs_mutex.unlock();
            if (tab) |t| {
                var params = std.json.ObjectMap.init(state.allocator);
                try params.put("sessionId", json.Value{ .integer = @intCast(t.screencast_session_id.load(.monotonic)) });
                _ = cdpSendCommand(t, "Page.screencastFrameAck", json.Value{ .object = params }) catch json.Value{ .null = {} };
            }
        },
    }
}

fn handleWebSocket(state: *ServerState, conn: net.Stream, req: *HttpRequest) !void {
    const upgrade_hdr = req.headers.get("upgrade") orelse {
        try writePlainResponse(conn.writer(), "400 Bad Request", "missing upgrade", "text/plain");
        return error.NotWebSocket;
    };
    if (!std.ascii.eqlIgnoreCase(upgrade_hdr, "websocket")) {
        try writePlainResponse(conn.writer(), "400 Bad Request", "bad upgrade", "text/plain");
        return error.NotWebSocket;
    }
    const key = req.headers.get("sec-websocket-key") orelse {
        try writePlainResponse(conn.writer(), "400 Bad Request", "missing key", "text/plain");
        return error.NotWebSocket;
    };
    const q_index_opt = std.mem.indexOfScalar(u8, req.path, '?');
    const query: []const u8 = if (q_index_opt) |qi| req.path[qi + 1 ..] else "";
    var session_id_hex: []const u8 = "";
    var token_hex: []const u8 = "";
    var qit = std.mem.splitSequence(u8, query, "&");
    while (qit.next()) |pair| {
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
            const k = pair[0..eq];
            const v = pair[eq + 1 ..];
            if (std.mem.eql(u8, k, "session_id")) session_id_hex = v;
            if (std.mem.eql(u8, k, "token")) token_hex = v;
        }
    }
    state.sessions_mutex.lock();
    const session = state.sessions.get(session_id_hex);
    state.sessions_mutex.unlock();
    if (session == null) {
        try writePlainResponse(conn.writer(), "401 Unauthorized", "unknown session", "text/plain");
        inc(&state.metrics.ws_upgrade_failures, 1);
        return error.UnknownSession;
    }
    if (!tokenValid(session.?, token_hex)) {
        try writePlainResponse(conn.writer(), "401 Unauthorized", "bad token", "text/plain");
        inc(&state.metrics.ws_upgrade_failures, 1);
        return error.BadToken;
    }
    const accept = try wsAccept(key, state.allocator);
    var resp = ArrayList(u8).init(state.allocator);
    defer resp.deinit();
    try resp.writer().print("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n", .{&accept});
    try conn.writeAll(resp.items);
    inc(&state.metrics.ws_upgrades_total, 1);

    const ws = try state.allocator.create(WebSocket);
    ws.* = WebSocket{
        .conn = conn,
        .closed = Atomic(bool).init(false),
        .write_mutex = .{},
        .send_queue = ArrayList([]const u8).init(state.allocator),
        .send_queue_bytes = Atomic(u64).init(0),
        .last_pong_ns = Atomic(i128).init(nowNs()),
        .session = session.?,
        .allocator = state.allocator,
    };
    session.?.ws_mutex.lock();
    session.?.ws = ws;
    session.?.ws_mutex.unlock();
    inc(&state.metrics.ws_connections, 1);

    sendSessionState(ws) catch {};

    var heartbeat_next = nowNs() + @as(i128, @intCast(state.config.ws_heartbeat_interval_seconds)) * std.time.ns_per_s;
    while (!ws.closed.load(.monotonic) and !state.shutdown.load(.monotonic)) {
        const frame = wsReadFrame(conn, state.allocator) catch {
            ws.closed.store(true, .monotonic);
            break;
        };
        defer state.allocator.free(frame.payload);
        switch (frame.opcode) {
            .binary => {
                handleClientMessage(state, ws, frame.payload) catch |err| {
                    log(.warn, "ws", @errorName(err));
                };
            },
            .text => {},
            .ping => {
                wsWriteFrame(conn, &ws.write_mutex, .pong, frame.payload) catch {};
            },
            .pong => {
                ws.last_pong_ns.store(nowNs(), .monotonic);
            },
            .close => {
                wsWriteFrame(conn, &ws.write_mutex, .close, &.{}) catch {};
                ws.closed.store(true, .monotonic);
                break;
            },
            .cont => {},
        }
        const now = nowNs();
        if (now >= heartbeat_next) {
            wsWriteFrame(conn, &ws.write_mutex, .ping, &.{}) catch {};
            sendPing(ws) catch {};
            heartbeat_next = now + @as(i128, @intCast(state.config.ws_heartbeat_interval_seconds)) * std.time.ns_per_s;
        }
    }

    session.?.ws_mutex.lock();
    session.?.ws = null;
    session.?.ws_mutex.unlock();
    dec(&state.metrics.ws_connections, 1);
    ws.send_queue.deinit();
    state.allocator.destroy(ws);
}

fn handleConnection(state: *ServerState, conn: net.Stream) !void {
    defer conn.close();
    inc(&state.metrics.http_requests_total, 1);
    var buf: [16384]u8 = undefined;
    var req = parseHttpRequest(conn.reader(), state.allocator, &buf) catch {
        try writePlainResponse(conn.writer(), "400 Bad Request", "bad request", "text/plain");
        return;
    };
    defer req.deinit();

    if (std.mem.eql(u8, req.path, "/health") and std.mem.eql(u8, req.method, "GET")) {
        try handleHealth(state, conn.writer());
        return;
    }
    if (std.mem.eql(u8, req.path, state.config.metrics_path) and std.mem.eql(u8, req.method, "GET")) {
        try handleMetrics(state, conn.writer());
        return;
    }
    if (std.mem.eql(u8, req.path, "/api/session") and std.mem.eql(u8, req.method, "POST")) {
        try handleCreateSession(state, conn.writer());
        return;
    }
    if (std.mem.eql(u8, req.path, "/api/session/refresh") and std.mem.eql(u8, req.method, "POST")) {
        try handleRefreshSession(state, &req, conn.writer());
        return;
    }
    if (std.mem.startsWith(u8, req.path, "/api/session/") and std.mem.eql(u8, req.method, "DELETE")) {
        const id_hex = req.path["/api/session/".len..];
        try handleDeleteSession(state, id_hex, conn.writer());
        return;
    }
    if (std.mem.startsWith(u8, req.path, "/api/download/") and std.mem.eql(u8, req.method, "GET")) {
        const rest = req.path["/api/download/".len..];
        const sig_idx = std.mem.indexOfScalar(u8, rest, '?');
        const id_part = if (sig_idx) |i| rest[0..i] else rest;
        const sig = if (sig_idx) |i| blk: {
            const q = rest[i + 1 ..];
            if (std.mem.indexOf(u8, q, "sig=")) |s| break :blk q[s + 4 ..];
            break :blk "";
        } else "";
        try handleDownload(state, id_part, sig, conn.writer());
        return;
    }
    if (std.mem.startsWith(u8, req.path, "/ws") and std.mem.eql(u8, req.method, "GET")) {
        try handleWebSocket(state, conn, &req);
        return;
    }
    try writePlainResponse(conn.writer(), "404 Not Found", "not found", "text/plain");
}

fn connectionHandler(state: *ServerState, conn: net.Stream) void {
    handleConnection(state, conn) catch |err| {
        var buf: [96]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "conn error: {s}", .{@errorName(err)}) catch "conn error";
        log(.warn, "http", msg);
    };
}

fn cleanupLoop(state: *ServerState) void {
    while (!state.shutdown.load(.monotonic)) {
        std.time.sleep(state.config.cleanup_interval_seconds * std.time.ns_per_s);
        const now = nowNs();
        state.sessions_mutex.lock();
        var it = state.sessions.iterator();
        var to_delete = ArrayList([]const u8).init(state.allocator);
        while (it.next()) |entry| {
            const session = entry.value_ptr.*;
            const idle_ns = now - session.last_activity_ns.load(.monotonic);
            if (idle_ns > @as(i128, @intCast(state.config.session_idle_seconds)) * std.time.ns_per_s) {
                to_delete.append(entry.key_ptr.*) catch {};
            }
        }
        state.sessions_mutex.unlock();
        for (to_delete.items) |k| {
            handleDeleteSession(state, k, NullWriter{}) catch {};
        }
        to_delete.deinit();
    }
}

const NullWriter = struct {
    pub const Error = error{};
    pub fn print(self: NullWriter, comptime fmt: []const u8, args: anytype) Error!void {
        _ = fmt;
        _ = args;
        _ = self;
    }
    pub fn writeAll(self: NullWriter, bytes: []const u8) Error!void {
        _ = self;
        _ = bytes;
    }
    pub fn writeByte(self: NullWriter, b: u8) Error!void {
        _ = self;
        _ = b;
    }
};

fn setupSignalHandlers() void {
    var act = posix.Sigaction{
        .handler = .{ .handler = handleSignal },
        .mask = posix.empty_sigset,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.TERM, &act, null);
    var ign = posix.Sigaction{
        .handler = .{ .handler = posix.SIG.IGN },
        .mask = posix.empty_sigset,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.PIPE, &ign, null);
}

var signal_state_ptr: ?*ServerState = null;

fn handleSignal(_: c_int) callconv(.C) void {
    if (signal_state_ptr) |s| {
        s.shutdown.store(true, .monotonic);
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config_path = std.posix.getenv("CB_CONFIG_PATH") orelse "config.json";
    const proxies_path = std.posix.getenv("CB_PROXIES_PATH") orelse "proxies.json";

    var config = loadConfig(allocator, config_path) catch |err| {
        std.debug.print("failed to load config: {}\n", .{err});
        return err;
    };
    if (std.mem.eql(u8, config.log_level, "debug")) global_log_level = .debug;
    if (std.mem.eql(u8, config.log_level, "info")) global_log_level = .info;
    if (std.mem.eql(u8, config.log_level, "warn")) global_log_level = .warn;
    if (std.mem.eql(u8, config.log_level, "error")) global_log_level = .@"error";

    var proxies = try loadProxies(allocator, proxies_path);
    defer proxies.deinit();

    if (config.tls_enabled) {
        std.fs.cwd().access(config.tls_cert_path, .{}) catch {
            std.debug.print("tls cert missing: {s}\n", .{config.tls_cert_path});
            return error.TlsCertMissing;
        };
        std.fs.cwd().access(config.tls_key_path, .{}) catch {
            std.debug.print("tls key missing: {s}\n", .{config.tls_key_path});
            return error.TlsKeyMissing;
        };
    } else if (!config.development_plain_http) {
        std.debug.print("tls disabled but development_plain_http is false; aborting\n", .{});
        return error.InsecureStartRejected;
    }

    var state = ServerState{
        .config = config,
        .proxies = proxies,
        .proxy_rr_index = Atomic(u64).init(0),
        .sessions = StringHashMap(*Session).init(allocator),
        .sessions_mutex = .{},
        .downloads = StringHashMap(*DownloadEntry).init(allocator),
        .downloads_mutex = .{},
        .metrics = Metrics{ .start_time_ns = nowNs() },
        .allocator = allocator,
        .shutdown = Atomic(bool).init(false),
        .hmac_key = undefined,
        .listener = null,
        .next_tab_id = Atomic(u32).init(0),
    };
    hexDecode(&state.hmac_key, config.hmac_secret_hex) catch {
        std.debug.print("hmac_secret_hex must be 64 hex characters\n", .{});
        return error.BadHmac;
    };
    signal_state_ptr = &state;
    setupSignalHandlers();

    const addr = try net.Address.parseIp4(config.host, config.port);
    var listener = try addr.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();
    state.listener = listener;

    log(.info, "http", "listening");

    const cleanup_thread = try Thread.spawn(.{}, cleanupLoop, .{&state});

    while (!state.shutdown.load(.monotonic)) {
        const conn = listener.accept() catch |err| {
            if (state.shutdown.load(.monotonic)) break;
            log(.warn, "http", @errorName(err));
            continue;
        };
        const t = try Thread.spawn(.{}, connectionHandler, .{ &state, conn.stream });
        t.detach();
    }

    log(.info, "http", "shutting down");
    cleanup_thread.join();

    state.sessions_mutex.lock();
    var it = state.sessions.iterator();
    while (it.next()) |entry| {
        terminateSession(&state, entry.value_ptr.*);
    }
    state.sessions.deinit();
    state.sessions_mutex.unlock();
    state.downloads_mutex.lock();
    var dit = state.downloads.iterator();
    while (dit.next()) |entry| {
        const d = entry.value_ptr.*;
        allocator.free(d.filename);
        allocator.free(d.mime);
        allocator.free(d.path);
        allocator.destroy(d);
    }
    state.downloads.deinit();
    state.downloads_mutex.unlock();

    log(.info, "http", "shutdown complete");
}

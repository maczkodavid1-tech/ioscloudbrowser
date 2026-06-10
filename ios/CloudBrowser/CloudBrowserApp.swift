import SwiftUI
import UIKit
import Network
import CoreGraphics
import ImageIO
import Metal
import MetalKit
import QuartzCore
import Security
import UniformTypeIdentifiers
import Combine

let defaultBackendURL = "https://cloudbrowser.local:8443"
let appVersion = "1.0.0"

@main
struct CloudBrowserApp: App {
    @StateObject private var state = AppState.shared

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(state)
                .preferredColorScheme(state.settings.theme == .dark ? .dark : (state.settings.theme == .light ? .light : nil))
        }
    }
}

enum ConnectionState: String, Codable {
    case disconnected
    case connecting
    case connected
    case authenticated
    case failed
}

enum Screen: Hashable {
    case launch
    case home
    case browser
    case tabs
    case settings
    case history
    case bookmarks
    case downloads
    case diagnostics
    case error
}

enum ThemePreference: String, Codable, CaseIterable {
    case system
    case light
    case dark
}

enum JpegQualityMode: String, Codable, CaseIterable {
    case auto
    case manual
}

struct SettingsModel: Codable {
    var backendURL: String = defaultBackendURL
    var trustInsecureLocalhost: Bool = false
    var jpegQualityMode: JpegQualityMode = .auto
    var jpegQualityManual: Int = 78
    var targetFPS: Int = 30
    var preferredProxyRegion: String = "auto"
    var preferredLanguage: String = "en-US"
    var preferredTimezone: String = "America/New_York"
    var theme: ThemePreference = .system
    var showDiagnostics: Bool = false
}

struct TabInfo: Identifiable, Hashable, Codable {
    var id: UInt32
    var title: String
    var url: String
    var loading: Bool
    var proxyRegion: String
}

struct HistoryItem: Identifiable, Hashable, Codable {
    var id: UUID = UUID()
    var title: String
    var url: String
    var visitedAt: Date
}

struct BookmarkItem: Identifiable, Hashable, Codable {
    var id: UUID = UUID()
    var title: String
    var url: String
    var order: Int
}

struct DownloadItem: Identifiable, Hashable {
    var id: String
    var filename: String
    var mime: String
    var size: UInt64
    var state: UInt8
    var signedURL: String
}

struct DiagnosticsModel {
    var wsState: ConnectionState = .disconnected
    var reconnectAttempts: Int = 0
    var rttMs: Double = 0
    var fps: Double = 0
    var droppedFrames: UInt64 = 0
    var activeTabId: UInt32 = 0
    var serverVersion: String = ""
    var lastError: String = ""
    var proxyRegion: String = ""
    var renderWidth: UInt32 = 0
    var renderHeight: UInt32 = 0
    var bytesIn: UInt64 = 0
    var bytesOut: UInt64 = 0
}

final class KeychainStore {
    static let service = "cloudbrowser.session"

    static func save(key: String, value: String) {
        guard let data = value.data(using: .utf8) else { return }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(query as CFDictionary)
        var newQuery = query
        newQuery[kSecValueData as String] = data
        newQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        SecItemAdd(newQuery as CFDictionary, nil)
    }

    static func load(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func delete(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(query as CFDictionary)
    }
}

final class BinaryBuffer {
    var data = Data()

    func writeU8(_ v: UInt8) { data.append(v) }
    func writeU16(_ v: UInt16) { var x = v.littleEndian; data.append(Data(bytes: &x, count: 2)) }
    func writeU32(_ v: UInt32) { var x = v.littleEndian; data.append(Data(bytes: &x, count: 4)) }
    func writeU64(_ v: UInt64) { var x = v.littleEndian; data.append(Data(bytes: &x, count: 8)) }
    func writeF32(_ v: Float) { writeU32(v.bitPattern) }
    func writeString(_ s: String) {
        let bytes = Array(s.utf8)
        writeU16(UInt16(bytes.count))
        data.append(contentsOf: bytes)
    }
    func writeRaw(_ bytes: [UInt8]) { data.append(contentsOf: bytes) }
    func writeData(_ d: Data) { data.append(d) }
}

final class BinaryReader {
    let data: Data
    var offset: Int = 0

    init(_ data: Data) { self.data = data }

    var remaining: Int { data.count - offset }

    func readU8() -> UInt8? {
        guard offset + 1 <= data.count else { return nil }
        let v = data[data.startIndex + offset]
        offset += 1
        return v
    }

    func readU16() -> UInt16? {
        guard offset + 2 <= data.count else { return nil }
        let v = data.subdata(in: (data.startIndex + offset)..<(data.startIndex + offset + 2)).withUnsafeBytes { $0.load(as: UInt16.self) }
        offset += 2
        return UInt16(littleEndian: v)
    }

    func readU32() -> UInt32? {
        guard offset + 4 <= data.count else { return nil }
        let v = data.subdata(in: (data.startIndex + offset)..<(data.startIndex + offset + 4)).withUnsafeBytes { $0.load(as: UInt32.self) }
        offset += 4
        return UInt32(littleEndian: v)
    }

    func readU64() -> UInt64? {
        guard offset + 8 <= data.count else { return nil }
        let v = data.subdata(in: (data.startIndex + offset)..<(data.startIndex + offset + 8)).withUnsafeBytes { $0.load(as: UInt64.self) }
        offset += 8
        return UInt64(littleEndian: v)
    }

    func readString() -> String? {
        guard let len = readU16() else { return nil }
        guard offset + Int(len) <= data.count else { return nil }
        let slice = data.subdata(in: (data.startIndex + offset)..<(data.startIndex + offset + Int(len)))
        offset += Int(len)
        return String(data: slice, encoding: .utf8)
    }

    func readBytes(_ count: Int) -> Data? {
        guard offset + count <= data.count else { return nil }
        let slice = data.subdata(in: (data.startIndex + offset)..<(data.startIndex + offset + count))
        offset += count
        return slice
    }
}

actor FrameCache {
    private var latest: (UInt32, Data, UInt32, UInt32, UInt64)? = nil

    func update(tabId: UInt32, jpeg: Data, width: UInt32, height: UInt32, ts: UInt64) {
        latest = (tabId, jpeg, width, height, ts)
    }

    func fetch() -> (UInt32, Data, UInt32, UInt32, UInt64)? {
        return latest
    }
}

final class PixelStreamLayer: CAMetalLayer {
    var latestImage: CGImage?
    var ciContext: CIContext?

    override init() {
        super.init()
        commonInit()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        commonInit()
    }

    override init(layer: Any) {
        super.init(layer: layer)
        commonInit()
    }

    private func commonInit() {
        framebufferOnly = true
        contentsGravity = .resizeAspect
        isOpaque = true
        backgroundColor = CGColor(red: 0, green: 0, blue: 0, alpha: 1)
    }

    func updateWithJPEG(_ jpeg: Data) {
        guard let provider = CGDataProvider(data: jpeg as CFData),
              let image = CGImage(jpegDataProviderSource: provider, decode: nil, shouldInterpolate: true, intent: .defaultIntent) else {
            return
        }
        latestImage = image
        DispatchQueue.main.async {
            self.contents = image
            self.setNeedsDisplay()
        }
    }
}

struct PixelStreamView: UIViewRepresentable {
    @ObservedObject var state: AppState

    final class Coordinator {
        weak var layer: PixelStreamLayer?
        var cancellable: AnyCancellable?
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> UIView {
        let view = TouchCaptureView()
        view.state = state
        view.backgroundColor = .black
        let layer = PixelStreamLayer()
        layer.frame = view.bounds
        layer.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.layer.addSublayer(layer)
        context.coordinator.layer = layer
        context.coordinator.cancellable = state.$latestFrame
            .receive(on: DispatchQueue.main)
            .sink { frame in
                guard let frame = frame else { return }
                layer.updateWithJPEG(frame.jpeg)
            }
        return view
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        if let v = uiView as? TouchCaptureView {
            v.state = state
        }
    }
}

final class TouchCaptureView: UIView {
    weak var state: AppState?
    private var nextTouchId: UInt32 = 1
    private var activeTouches: [UITouch: UInt32] = [:]

    override init(frame: CGRect) {
        super.init(frame: frame)
        isMultipleTouchEnabled = true
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
        isMultipleTouchEnabled = true
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent?) {
        for t in touches {
            let id = nextTouchId
            nextTouchId &+= 1
            activeTouches[t] = id
            send(phase: 0, touch: t, id: id)
        }
    }

    override func touchesMoved(_ touches: Set<UITouch>, with event: UIEvent?) {
        for t in touches {
            if let id = activeTouches[t] {
                send(phase: 2, touch: t, id: id)
            }
        }
    }

    override func touchesEnded(_ touches: Set<UITouch>, with event: UIEvent?) {
        for t in touches {
            if let id = activeTouches[t] {
                send(phase: 1, touch: t, id: id)
                activeTouches.removeValue(forKey: t)
            }
        }
    }

    override func touchesCancelled(_ touches: Set<UITouch>, with event: UIEvent?) {
        for t in touches {
            if let id = activeTouches[t] {
                send(phase: 1, touch: t, id: id)
                activeTouches.removeValue(forKey: t)
            }
        }
    }

    private func send(phase: UInt8, touch: UITouch, id: UInt32) {
        let p = touch.location(in: self)
        let x = UInt32(max(0, min(Float(bounds.width), Float(p.x))))
        let y = UInt32(max(0, min(Float(bounds.height), Float(p.y))))
        let radius = UInt32(max(1, touch.majorRadius) * 10)
        let force = UInt32(max(0, min(1, touch.force / max(1, touch.maximumPossibleForce))) * 1000)
        let modifiers: UInt16 = 0
        let buf = BinaryBuffer()
        buf.writeU8(0x10)
        buf.writeU8(phase)
        buf.writeU32(id)
        buf.writeU32(x)
        buf.writeU32(y)
        buf.writeU32(radius)
        buf.writeU32(force)
        buf.writeU16(modifiers)
        buf.writeU8(0)
        state?.transport.send(buf.data)
    }
}

final class HiddenKeyField: UITextField, UITextFieldDelegate {
    var onKey: ((UInt8, UInt16, UInt32, String) -> Void)?

    override init(frame: CGRect) {
        super.init(frame: frame)
        delegate = self
        autocorrectionType = .no
        autocapitalizationType = .none
        spellCheckingType = .no
        isSecureTextEntry = false
        inputAssistantItem.leadingBarButtonGroups = []
        inputAssistantItem.trailingBarButtonGroups = []
    }

    required init?(coder: NSCoder) { super.init(coder: coder) }

    func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool {
        if string == "\n" {
            onKey?(0, 0, 13, "")
        } else if string == "\t" {
            onKey?(0, 0, 9, "")
        } else if string.count > 0 {
            onKey?(2, 0, 0, string)
        } else if range.length > 0 {
            onKey?(0, 0, 8, "")
        }
        return false
    }
}

struct KeyboardHost: UIViewRepresentable {
    @Binding var active: Bool
    var onKey: (UInt8, UInt16, UInt32, String) -> Void

    final class Coordinator {
        var field: HiddenKeyField?
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIView(context: Context) -> UIView {
        let v = UIView()
        let field = HiddenKeyField(frame: .zero)
        field.onKey = onKey
        v.addSubview(field)
        context.coordinator.field = field
        return v
    }

    func updateUIView(_ uiView: UIView, context: Context) {
        if let field = context.coordinator.field {
            if active && !field.isFirstResponder {
                DispatchQueue.main.async { field.becomeFirstResponder() }
            } else if !active && field.isFirstResponder {
                field.resignFirstResponder()
            }
        }
    }
}

final class Transport: NSObject, ObservableObject, URLSessionWebSocketDelegate {
    @Published var state: ConnectionState = .disconnected
    private var task: URLSessionWebSocketTask?
    private var session: URLSession?
    private var appState: AppState?
    private var reconnectAttempt = 0
    private let reconnectQueue = DispatchQueue(label: "cloudbrowser.reconnect")
    private let decodeQueue = DispatchQueue(label: "cloudbrowser.decode", qos: .userInteractive)
    private var pingTimer: Timer?

    func attach(_ appState: AppState) {
        self.appState = appState
    }

    func connect() {
        guard let appState = appState else { return }
        guard let baseURL = URL(string: appState.settings.backendURL) else {
            DispatchQueue.main.async { appState.errorMessage = "Invalid backend URL" }
            return
        }
        var comps = URLComponents()
        comps.scheme = baseURL.scheme == "https" ? "wss" : "ws"
        comps.host = baseURL.host
        comps.port = baseURL.port
        comps.path = "/ws"
        comps.queryItems = [
            URLQueryItem(name: "session_id", value: appState.sessionId),
            URLQueryItem(name: "token", value: appState.wsToken),
        ]
        guard let url = comps.url else { return }
        DispatchQueue.main.async { self.state = .connecting; appState.diagnostics.wsState = .connecting }

        let config = URLSessionConfiguration.default
        config.waitsForConnectivity = true
        config.timeoutIntervalForRequest = 30
        let s = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        self.session = s
        let t = s.webSocketTask(with: url)
        t.maximumMessageSize = 16 * 1024 * 1024
        self.task = t
        t.resume()
        self.startReceiving()
        self.startPing()
    }

    func disconnect() {
        task?.cancel(with: .goingAway, reason: nil)
        task = nil
        pingTimer?.invalidate()
        pingTimer = nil
        DispatchQueue.main.async { self.state = .disconnected }
    }

    func send(_ data: Data) {
        task?.send(.data(data)) { [weak self] err in
            if let err = err {
                self?.appState?.diagnostics.lastError = err.localizedDescription
            } else {
                self?.appState?.diagnostics.bytesOut += UInt64(data.count)
            }
        }
    }

    private func startReceiving() {
        guard let task = task else { return }
        task.receive { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .success(let msg):
                switch msg {
                case .data(let d):
                    self.decodeQueue.async { self.handle(d) }
                case .string: break
                @unknown default: break
                }
                self.startReceiving()
            case .failure(let err):
                DispatchQueue.main.async {
                    self.state = .disconnected
                    self.appState?.diagnostics.wsState = .disconnected
                    self.appState?.diagnostics.lastError = err.localizedDescription
                }
                self.scheduleReconnect()
            }
        }
    }

    private func startPing() {
        pingTimer?.invalidate()
        pingTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            self?.task?.sendPing { err in
                if let err = err {
                    self?.appState?.diagnostics.lastError = err.localizedDescription
                }
            }
        }
    }

    private func scheduleReconnect() {
        reconnectAttempt += 1
        let delay = min(30.0, pow(2.0, Double(reconnectAttempt)))
        DispatchQueue.main.async { self.appState?.diagnostics.reconnectAttempts = self.reconnectAttempt }
        reconnectQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self = self, self.appState?.sessionId.isEmpty == false else { return }
            self.connect()
        }
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if appState?.settings.trustInsecureLocalhost == true,
           challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
            return
        }
        completionHandler(.performDefaultHandling, nil)
    }

    private func handle(_ data: Data) {
        guard let appState = appState else { return }
        appState.diagnostics.bytesIn += UInt64(data.count)
        let r = BinaryReader(data)
        guard let kind = r.readU8() else { return }
        switch kind {
        case 0x01: handleFrame(r, appState: appState)
        case 0x02: handleTabState(r, appState: appState)
        case 0x03: handleSessionState(r, appState: appState)
        case 0x04: handleError(r, appState: appState)
        case 0x05: handleDownload(r, appState: appState)
        case 0x06: handleClipboard(r, appState: appState)
        case 0x07: handlePing(r, appState: appState)
        case 0x08: handleAuthRenew(r, appState: appState)
        default: break
        }
    }

    private func handleFrame(_ r: BinaryReader, appState: AppState) {
        guard let tabId = r.readU32(),
              let frameSeq = r.readU32(),
              let w = r.readU32(),
              let h = r.readU32(),
              let ts = r.readU64(),
              let jpegLen = r.readU32(),
              let jpeg = r.readBytes(Int(jpegLen)) else { return }

        appState.frameCount += 1
        let now = Date().timeIntervalSince1970
        let delta = now - appState.lastFpsWindowStart
        if delta >= 1.0 {
            appState.diagnostics.fps = Double(appState.frameCount) / delta
            appState.frameCount = 0
            appState.lastFpsWindowStart = now
        }

        let frame = FrameMessage(tabId: tabId, frameSeq: frameSeq, width: w, height: h, timestampNs: ts, jpeg: jpeg)
        DispatchQueue.main.async {
            appState.latestFrame = frame
            appState.diagnostics.renderWidth = w
            appState.diagnostics.renderHeight = h
            appState.diagnostics.activeTabId = tabId
        }

        let ack = BinaryBuffer()
        ack.writeU8(0x18)
        ack.writeU32(frameSeq)
        ack.writeU64(UInt64(Date().timeIntervalSince1970 * 1_000_000_000))
        send(ack.data)
    }

    private func handleTabState(_ r: BinaryReader, appState: AppState) {
        guard let tabId = r.readU32(),
              let loadingByte = r.readU8(),
              let title = r.readString(),
              let url = r.readString(),
              let navFlags = r.readU8(),
              let security = r.readString() else { return }
        DispatchQueue.main.async {
            if let idx = appState.tabs.firstIndex(where: { $0.id == tabId }) {
                appState.tabs[idx].title = title
                appState.tabs[idx].url = url
                appState.tabs[idx].loading = loadingByte != 0
            } else {
                appState.tabs.append(TabInfo(id: tabId, title: title, url: url, loading: loadingByte != 0, proxyRegion: ""))
            }
            appState.activeNavigationFlags[tabId] = navFlags
            appState.securityStates[tabId] = security
        }
    }

    private func handleSessionState(_ r: BinaryReader, appState: AppState) {
        guard let count = r.readU16() else { return }
        var tabs: [TabInfo] = []
        for _ in 0..<count {
            guard let id = r.readU32(),
                  let title = r.readString(),
                  let url = r.readString(),
                  let hasProxy = r.readU8() else { continue }
            var region = ""
            if hasProxy == 1 { region = r.readString() ?? "" }
            tabs.append(TabInfo(id: id, title: title, url: url, loading: false, proxyRegion: region))
        }
        let active = r.readU32() ?? 0
        DispatchQueue.main.async {
            appState.tabs = tabs
            appState.activeTabId = active
            if let t = tabs.first(where: { $0.id == active }) {
                appState.diagnostics.proxyRegion = t.proxyRegion
            }
        }
    }

    private func handleError(_ r: BinaryReader, appState: AppState) {
        guard let code = r.readU32(), let msg = r.readString() else { return }
        DispatchQueue.main.async { appState.errorMessage = "(\(code)) \(msg)" }
    }

    private func handleDownload(_ r: BinaryReader, appState: AppState) {
        guard let idBytes = r.readBytes(32) else { return }
        let id = idBytes.map { String(format: "%02x", $0) }.joined()
        guard let filename = r.readString(),
              let mime = r.readString(),
              let size = r.readU64(),
              let stateByte = r.readU8() else { return }
        DispatchQueue.main.async {
            if let idx = appState.downloads.firstIndex(where: { $0.id == id }) {
                appState.downloads[idx].state = stateByte
                appState.downloads[idx].size = size
            } else {
                appState.downloads.append(DownloadItem(id: id, filename: filename, mime: mime, size: size, state: stateByte, signedURL: ""))
            }
        }
    }

    private func handleClipboard(_ r: BinaryReader, appState: AppState) {
        guard let text = r.readString() else { return }
        DispatchQueue.main.async { appState.lastClipboard = text }
    }

    private func handlePing(_ r: BinaryReader, appState: AppState) {
        guard let serverTs = r.readU64() else { return }
        let now = UInt64(Date().timeIntervalSince1970 * 1_000_000_000)
        let rtt = now >= serverTs ? Double(now - serverTs) / 1_000_000.0 : 0
        DispatchQueue.main.async { appState.diagnostics.rttMs = rtt }
    }

    private func handleAuthRenew(_ r: BinaryReader, appState: AppState) {
        guard let _ = r.readU32() else { return }
        DispatchQueue.main.async { appState.refreshToken() }
    }
}

struct FrameMessage {
    var tabId: UInt32
    var frameSeq: UInt32
    var width: UInt32
    var height: UInt32
    var timestampNs: UInt64
    var jpeg: Data
}

final class AppState: ObservableObject {
    static let shared = AppState()

    @Published var connectionState: ConnectionState = .disconnected
    @Published var sessionId: String = ""
    @Published var wsToken: String = ""
    @Published var activeTabId: UInt32 = 0
    @Published var tabs: [TabInfo] = []
    @Published var thumbnails: [UInt32: UIImage] = [:]
    @Published var settings: SettingsModel = SettingsModel() { didSet { persistSettings() } }
    @Published var history: [HistoryItem] = [] { didSet { persistHistory() } }
    @Published var bookmarks: [BookmarkItem] = [] { didSet { persistBookmarks() } }
    @Published var downloads: [DownloadItem] = []
    @Published var diagnostics = DiagnosticsModel()
    @Published var errorMessage: String? = nil
    @Published var currentScreen: Screen = .launch
    @Published var latestFrame: FrameMessage? = nil
    @Published var addressBarText: String = ""
    @Published var activeNavigationFlags: [UInt32: UInt8] = [:]
    @Published var securityStates: [UInt32: String] = [:]
    @Published var lastClipboard: String? = nil
    @Published var showPasteConfirm: Bool = false
    @Published var showAddressBar: Bool = false
    @Published var keyboardActive: Bool = false
    @Published var insecureLocalhostWarning: Bool = false

    var frameCount: Int = 0
    var lastFpsWindowStart: TimeInterval = Date().timeIntervalSince1970

    let transport: Transport = Transport()
    private let defaults = UserDefaults.standard

    init() {
        transport.attach(self)
        loadPersisted()
    }

    private func loadPersisted() {
        if let data = defaults.data(forKey: "settings"),
           let s = try? JSONDecoder().decode(SettingsModel.self, from: data) {
            settings = s
        }
        if let data = defaults.data(forKey: "bookmarks"),
           let b = try? JSONDecoder().decode([BookmarkItem].self, from: data) {
            bookmarks = b
        }
        if let data = defaults.data(forKey: "history"),
           let h = try? JSONDecoder().decode([HistoryItem].self, from: data) {
            history = h
        }
        if let sid = KeychainStore.load(key: "sessionId") { sessionId = sid }
        if let tok = KeychainStore.load(key: "wsToken") { wsToken = tok }
    }

    private func persistSettings() {
        if let data = try? JSONEncoder().encode(settings) {
            defaults.set(data, forKey: "settings")
        }
    }

    private func persistBookmarks() {
        if let data = try? JSONEncoder().encode(bookmarks) {
            defaults.set(data, forKey: "bookmarks")
        }
    }

    private func persistHistory() {
        let trimmed = Array(history.prefix(500))
        if let data = try? JSONEncoder().encode(trimmed) {
            defaults.set(data, forKey: "history")
        }
    }

    func createSession() {
        guard let url = URL(string: settings.backendURL + "/api/session") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = "{}".data(using: .utf8)
        connectionState = .connecting
        diagnostics.wsState = .connecting
        URLSession.shared.dataTask(with: req) { [weak self] data, resp, err in
            guard let self = self else { return }
            if let err = err {
                DispatchQueue.main.async { self.errorMessage = err.localizedDescription; self.connectionState = .failed }
                return
            }
            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let sid = json["session_id"] as? String,
                  let tok = json["ws_token"] as? String else {
                DispatchQueue.main.async { self.errorMessage = "Invalid session response"; self.connectionState = .failed }
                return
            }
            DispatchQueue.main.async {
                self.sessionId = sid
                self.wsToken = tok
                KeychainStore.save(key: "sessionId", value: sid)
                KeychainStore.save(key: "wsToken", value: tok)
                self.transport.connect()
                self.currentScreen = .home
                self.connectionState = .connected
            }
            self.fetchHealth()
        }.resume()
    }

    func refreshToken() {
        guard let url = URL(string: settings.backendURL + "/api/session/refresh") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let body: [String: Any] = ["session_id": sessionId, "ws_token": wsToken]
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        URLSession.shared.dataTask(with: req) { [weak self] data, _, _ in
            guard let self = self, let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let tok = json["ws_token"] as? String else { return }
            DispatchQueue.main.async {
                self.wsToken = tok
                KeychainStore.save(key: "wsToken", value: tok)
            }
        }.resume()
    }

    func fetchHealth() {
        guard let url = URL(string: settings.backendURL + "/health") else { return }
        URLSession.shared.dataTask(with: url) { [weak self] data, _, _ in
            guard let self = self, let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let v = json["version"] as? String else { return }
            DispatchQueue.main.async { self.diagnostics.serverVersion = v }
        }.resume()
    }

    func endSession() {
        guard !sessionId.isEmpty,
              let url = URL(string: settings.backendURL + "/api/session/" + sessionId) else {
            transport.disconnect()
            clearSession()
            return
        }
        var req = URLRequest(url: url)
        req.httpMethod = "DELETE"
        URLSession.shared.dataTask(with: req) { [weak self] _, _, _ in
            DispatchQueue.main.async {
                self?.transport.disconnect()
                self?.clearSession()
            }
        }.resume()
    }

    func clearSession() {
        sessionId = ""
        wsToken = ""
        tabs = []
        activeTabId = 0
        KeychainStore.delete(key: "sessionId")
        KeychainStore.delete(key: "wsToken")
        currentScreen = .launch
        connectionState = .disconnected
    }

    func createTab() {
        let buf = BinaryBuffer()
        buf.writeU8(0x14)
        buf.writeU8(0x01)
        transport.send(buf.data)
    }

    func closeTab(_ id: UInt32) {
        let buf = BinaryBuffer()
        buf.writeU8(0x14)
        buf.writeU8(0x02)
        buf.writeU32(id)
        transport.send(buf.data)
    }

    func switchTab(_ id: UInt32) {
        let buf = BinaryBuffer()
        buf.writeU8(0x14)
        buf.writeU8(0x03)
        buf.writeU32(id)
        transport.send(buf.data)
        activeTabId = id
    }

    func reloadTab() {
        let buf = BinaryBuffer()
        buf.writeU8(0x14)
        buf.writeU8(0x04)
        transport.send(buf.data)
    }

    func stopLoading() {
        let buf = BinaryBuffer()
        buf.writeU8(0x14)
        buf.writeU8(0x05)
        transport.send(buf.data)
    }

    func goBack() {
        let buf = BinaryBuffer()
        buf.writeU8(0x14)
        buf.writeU8(0x06)
        transport.send(buf.data)
    }

    func goForward() {
        let buf = BinaryBuffer()
        buf.writeU8(0x14)
        buf.writeU8(0x07)
        transport.send(buf.data)
    }

    func navigate(_ raw: String) {
        var target = raw.trimmingCharacters(in: .whitespaces)
        if target.isEmpty { return }
        if !target.contains("://") {
            if target.contains(".") && !target.contains(" ") {
                target = "https://" + target
            } else {
                let q = target.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
                target = "https://duckduckgo.com/?q=" + q
            }
        }
        let buf = BinaryBuffer()
        buf.writeU8(0x13)
        buf.writeString(target)
        transport.send(buf.data)
        history.insert(HistoryItem(title: target, url: target, visitedAt: Date()), at: 0)
        addressBarText = target
    }

    func sendViewport(width: UInt32, height: UInt32, scale: Float) {
        let buf = BinaryBuffer()
        buf.writeU8(0x15)
        buf.writeU32(width)
        buf.writeU32(height)
        buf.writeF32(scale)
        transport.send(buf.data)
    }

    func sendSettings(_ json: String) {
        let buf = BinaryBuffer()
        buf.writeU8(0x16)
        buf.writeString(json)
        transport.send(buf.data)
    }

    func requestClipboard() {
        let buf = BinaryBuffer()
        buf.writeU8(0x17)
        buf.writeU8(0)
        transport.send(buf.data)
    }

    func pasteClipboard(_ text: String) {
        let buf = BinaryBuffer()
        buf.writeU8(0x17)
        buf.writeU8(1)
        buf.writeString(text)
        transport.send(buf.data)
    }

    func addBookmark(title: String, url: String) {
        bookmarks.append(BookmarkItem(title: title, url: url, order: bookmarks.count))
    }

    func deleteHistory(_ item: HistoryItem) {
        history.removeAll { $0.id == item.id }
    }

    func clearHistory() { history.removeAll() }
    func clearBookmarks() { bookmarks.removeAll() }
    func clearAllData() {
        clearHistory()
        clearBookmarks()
        downloads.removeAll()
    }
}

struct RootView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        NavigationStack {
            Group {
                switch state.currentScreen {
                case .launch: LaunchView()
                case .home: HomeView()
                case .browser: BrowserView()
                case .tabs: TabsOverviewView()
                case .settings: SettingsView()
                case .history: HistoryView()
                case .bookmarks: BookmarksView()
                case .downloads: DownloadsView()
                case .diagnostics: DiagnosticsView()
                case .error: ErrorView()
                }
            }
            .navigationTitle("")
            .navigationBarHidden(true)
            .alert("Connection Error", isPresented: Binding(
                get: { state.errorMessage != nil },
                set: { if !$0 { state.errorMessage = nil } }
            )) {
                Button("OK") { state.errorMessage = nil }
            } message: {
                Text(state.errorMessage ?? "")
            }
        }
    }
}

struct LaunchView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "cloud.fill")
                .font(.system(size: 96))
                .foregroundStyle(.blue)
            Text("Cloud Browser")
                .font(.largeTitle.bold())
            Text("v\(appVersion)")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Text("Backend: \(state.settings.backendURL)")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Spacer()
            Button {
                state.createSession()
            } label: {
                HStack {
                    if state.connectionState == .connecting {
                        ProgressView().tint(.white)
                    }
                    Text(state.connectionState == .connecting ? "Connecting..." : "Create Session")
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.blue)
                .foregroundStyle(.white)
                .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            .disabled(state.connectionState == .connecting)
            .padding(.horizontal)

            Button {
                state.currentScreen = .diagnostics
            } label: {
                Text("Diagnostics")
                    .foregroundStyle(.secondary)
            }

            Button {
                state.currentScreen = .settings
            } label: {
                Text("Settings")
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding()
    }
}

struct HomeView: View {
    @EnvironmentObject var state: AppState
    @State private var query: String = ""

    let speedDial: [(String, String)] = [
        ("DuckDuckGo", "https://duckduckgo.com"),
        ("Wikipedia", "https://wikipedia.org"),
        ("Hacker News", "https://news.ycombinator.com"),
        ("Reddit", "https://reddit.com"),
        ("GitHub", "https://github.com"),
        ("Apple", "https://apple.com"),
    ]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("Search or enter URL", text: $query)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onSubmit {
                            state.navigate(query)
                            state.createTab()
                            state.currentScreen = .browser
                            query = ""
                        }
                }
                .padding(12)
                .background(Color(.secondarySystemBackground))
                .clipShape(RoundedRectangle(cornerRadius: 14))

                Text("Speed Dial").font(.headline)
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 100))], spacing: 12) {
                    ForEach(speedDial, id: \.1) { item in
                        Button {
                            state.createTab()
                            state.navigate(item.1)
                            state.currentScreen = .browser
                        } label: {
                            VStack {
                                Image(systemName: "globe")
                                    .font(.title2)
                                Text(item.0)
                                    .font(.caption)
                                    .lineLimit(1)
                            }
                            .frame(maxWidth: .infinity, minHeight: 80)
                            .background(Color(.secondarySystemBackground))
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                        }
                        .buttonStyle(.plain)
                    }
                }

                HStack {
                    Text("Recent").font(.headline)
                    Spacer()
                    if !state.history.isEmpty {
                        Button("Clear") { state.clearHistory() }.font(.caption)
                    }
                }
                ForEach(state.history.prefix(8)) { item in
                    Button {
                        state.createTab()
                        state.navigate(item.url)
                        state.currentScreen = .browser
                    } label: {
                        HStack {
                            VStack(alignment: .leading) {
                                Text(item.title).lineLimit(1).font(.subheadline)
                                Text(item.url).lineLimit(1).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                        }
                        .padding(.vertical, 6)
                    }
                    .buttonStyle(.plain)
                }

                Button {
                    state.createTab()
                    state.currentScreen = .browser
                } label: {
                    HStack {
                        Image(systemName: "plus.square.on.square")
                        Text("New Isolated Tab")
                    }
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.green)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
                }
            }
            .padding()
        }
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button { state.currentScreen = .tabs } label: { Image(systemName: "square.on.square") }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button("Bookmarks") { state.currentScreen = .bookmarks }
                    Button("History") { state.currentScreen = .history }
                    Button("Downloads") { state.currentScreen = .downloads }
                    Button("Settings") { state.currentScreen = .settings }
                    Button("Diagnostics") { state.currentScreen = .diagnostics }
                    Divider()
                    Button("End Session", role: .destructive) { state.endSession() }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .navigationBarHidden(false)
        .navigationTitle("Home")
    }
}

struct BrowserView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        GeometryReader { geo in
            ZStack(alignment: .top) {
                PixelStreamView(state: state)
                    .ignoresSafeArea()
                    .onAppear {
                        let scale = Float(UIScreen.main.scale)
                        state.sendViewport(width: UInt32(geo.size.width), height: UInt32(geo.size.height), scale: scale)
                    }
                    .onChange(of: geo.size) { newSize in
                        let scale = Float(UIScreen.main.scale)
                        state.sendViewport(width: UInt32(newSize.width), height: UInt32(newSize.height), scale: scale)
                    }

                if state.showAddressBar {
                    VStack {
                        HStack {
                            Button { state.goBack() } label: { Image(systemName: "chevron.left") }
                                .disabled((state.activeNavigationFlags[state.activeTabId] ?? 0) & 0x01 == 0)
                            Button { state.goForward() } label: { Image(systemName: "chevron.right") }
                                .disabled((state.activeNavigationFlags[state.activeTabId] ?? 0) & 0x02 == 0)
                            HStack {
                                if let sec = state.securityStates[state.activeTabId] {
                                    Image(systemName: sec == "secure" ? "lock.fill" : "lock.open.fill")
                                        .foregroundStyle(sec == "secure" ? .green : .red)
                                }
                                TextField("Address", text: $state.addressBarText)
                                    .textInputAutocapitalization(.never)
                                    .autocorrectionDisabled()
                                    .onSubmit {
                                        state.navigate(state.addressBarText)
                                        state.showAddressBar = false
                                    }
                            }
                            .padding(8)
                            .background(Color(.systemBackground))
                            .clipShape(RoundedRectangle(cornerRadius: 10))
                            Button {
                                let tab = state.tabs.first(where: { $0.id == state.activeTabId })
                                if tab?.loading == true { state.stopLoading() } else { state.reloadTab() }
                            } label: {
                                let tab = state.tabs.first(where: { $0.id == state.activeTabId })
                                Image(systemName: tab?.loading == true ? "xmark" : "arrow.clockwise")
                            }
                        }
                        .padding(8)
                        .background(.ultraThinMaterial)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                        .padding(.horizontal)
                        Spacer()
                    }
                    .transition(.move(edge: .top))
                }

                VStack {
                    Spacer()
                    HStack(spacing: 20) {
                        Button { state.showAddressBar.toggle() } label: {
                            Image(systemName: state.showAddressBar ? "xmark" : "text.magnifyingglass")
                                .frame(width: 44, height: 44)
                        }
                        Button { state.keyboardActive.toggle() } label: {
                            Image(systemName: "keyboard")
                                .frame(width: 44, height: 44)
                        }
                        Button { state.showPasteConfirm = true } label: {
                            Image(systemName: "doc.on.clipboard")
                                .frame(width: 44, height: 44)
                        }
                        Button {
                            if let tab = state.tabs.first(where: { $0.id == state.activeTabId }) {
                                state.addBookmark(title: tab.title, url: tab.url)
                            }
                        } label: {
                            Image(systemName: "star")
                                .frame(width: 44, height: 44)
                        }
                        Button { state.currentScreen = .tabs } label: {
                            ZStack {
                                Image(systemName: "square.on.square")
                                    .frame(width: 44, height: 44)
                                Text("\(state.tabs.count)")
                                    .font(.caption2.bold())
                                    .padding(4)
                                    .background(Color.blue)
                                    .foregroundStyle(.white)
                                    .clipShape(Circle())
                                    .offset(x: 12, y: -12)
                            }
                        }
                        Button {
                            let tab = state.tabs.first(where: { $0.id == state.activeTabId })
                            if let tab = tab {
                                let av = UIActivityViewController(activityItems: [URL(string: tab.url) as Any], applicationActivities: nil)
                                UIApplication.shared.connectedScenes
                                    .compactMap { ($0 as? UIWindowScene)?.keyWindow }
                                    .first?
                                    .rootViewController?
                                    .present(av, animated: true)
                            }
                        } label: {
                            Image(systemName: "square.and.arrow.up")
                                .frame(width: 44, height: 44)
                        }
                    }
                    .padding(.vertical, 8)
                    .padding(.horizontal, 16)
                    .background(.ultraThinMaterial)
                    .clipShape(Capsule())
                    .padding()
                }
            }
            .overlay(alignment: .bottom) {
                if state.keyboardActive {
                    KeyboardHost(active: $state.keyboardActive) { type, modifiers, keyCode, text in
                        let buf = BinaryBuffer()
                        buf.writeU8(0x12)
                        buf.writeU8(type)
                        buf.writeU16(modifiers)
                        buf.writeU32(keyCode)
                        buf.writeString(text)
                        state.transport.send(buf.data)
                    }
                    .frame(height: 0)
                }
            }
            .confirmationDialog("Paste from clipboard?", isPresented: $state.showPasteConfirm) {
                Button("Paste") {
                    if let text = UIPasteboard.general.string {
                        state.pasteClipboard(text)
                    }
                }
                Button("Cancel", role: .cancel) {}
            }
        }
        .navigationBarHidden(true)
        .onAppear {
            if let tab = state.tabs.first(where: { $0.id == state.activeTabId }) {
                state.addressBarText = tab.url
            }
        }
    }
}

struct TabsOverviewView: View {
    @EnvironmentObject var state: AppState
    let columns = [GridItem(.adaptive(minimum: 180), spacing: 12)]

    var body: some View {
        ScrollView {
            LazyVGrid(columns: columns, spacing: 12) {
                ForEach(state.tabs) { tab in
                    VStack(alignment: .leading, spacing: 6) {
                        ZStack(alignment: .topTrailing) {
                            Rectangle()
                                .fill(Color(.secondarySystemBackground))
                                .aspectRatio(16.0/10.0, contentMode: .fit)
                                .overlay(
                                    Group {
                                        if let img = state.thumbnails[tab.id] {
                                            Image(uiImage: img).resizable().scaledToFill()
                                        } else {
                                            Image(systemName: "globe").font(.largeTitle).foregroundStyle(.secondary)
                                        }
                                    }
                                )
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                .onTapGesture {
                                    state.switchTab(tab.id)
                                    state.currentScreen = .browser
                                }
                            Button {
                                state.closeTab(tab.id)
                            } label: {
                                Image(systemName: "xmark.circle.fill")
                                    .foregroundStyle(.white, .black)
                                    .font(.title3)
                            }
                            .offset(x: 6, y: -6)
                        }
                        Text(tab.title).font(.caption).lineLimit(1)
                        Text(tab.url).font(.caption2).foregroundStyle(.secondary).lineLimit(1)
                        if !tab.proxyRegion.isEmpty {
                            Text(tab.proxyRegion).font(.caption2).foregroundStyle(.blue)
                        }
                    }
                }
            }
            .padding()
        }
        .overlay(alignment: .bottomTrailing) {
            Button {
                state.createTab()
            } label: {
                Image(systemName: "plus")
                    .font(.title2)
                    .padding(20)
                    .background(Color.blue)
                    .foregroundStyle(.white)
                    .clipShape(Circle())
                    .shadow(radius: 4)
            }
            .padding()
        }
        .navigationTitle("Tabs (\(state.tabs.count))")
        .navigationBarHidden(false)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button("Back") { state.currentScreen = state.tabs.isEmpty ? .home : .browser }
            }
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        Form {
            Section("Backend") {
                TextField("Backend URL", text: $state.settings.backendURL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Toggle("Trust insecure localhost (DEBUG only)", isOn: Binding(
                    get: { state.settings.trustInsecureLocalhost },
                    set: { new in
                        #if DEBUG
                        state.settings.trustInsecureLocalhost = new
                        #else
                        _ = new
                        state.insecureLocalhostWarning = true
                        #endif
                    }
                ))
            }

            Section("Streaming") {
                Picker("JPEG quality", selection: $state.settings.jpegQualityMode) {
                    ForEach(JpegQualityMode.allCases, id: \.self) { Text($0.rawValue.capitalized).tag($0) }
                }
                if state.settings.jpegQualityMode == .manual {
                    Slider(value: Binding(
                        get: { Double(state.settings.jpegQualityManual) },
                        set: { state.settings.jpegQualityManual = Int($0); state.sendSettings("{\"jpeg_quality\":\(Int($0))}") }
                    ), in: 40...92, step: 1) {
                        Text("Quality")
                    }
                    Text("Quality: \(state.settings.jpegQualityManual)").font(.caption).foregroundStyle(.secondary)
                }
                Picker("FPS", selection: $state.settings.targetFPS) {
                    Text("15").tag(15)
                    Text("30").tag(30)
                    Text("60").tag(60)
                }
            }

            Section("Appearance") {
                Picker("Theme", selection: $state.settings.theme) {
                    ForEach(ThemePreference.allCases, id: \.self) { Text($0.rawValue.capitalized).tag($0) }
                }
                Picker("Language", selection: $state.settings.preferredLanguage) {
                    Text("English (US)").tag("en-US")
                    Text("English (UK)").tag("en-GB")
                    Text("German").tag("de-DE")
                    Text("French").tag("fr-FR")
                    Text("Spanish").tag("es-ES")
                    Text("Hungarian").tag("hu-HU")
                }
                Picker("Timezone", selection: $state.settings.preferredTimezone) {
                    Text("New York").tag("America/New_York")
                    Text("Los Angeles").tag("America/Los_Angeles")
                    Text("London").tag("Europe/London")
                    Text("Berlin").tag("Europe/Berlin")
                    Text("Budapest").tag("Europe/Budapest")
                    Text("Tokyo").tag("Asia/Tokyo")
                }
            }

            Section("Proxy") {
                Picker("Preferred region", selection: $state.settings.preferredProxyRegion) {
                    Text("Auto").tag("auto")
                    Text("US East").tag("us-east")
                    Text("US West").tag("us-west")
                    Text("EU").tag("eu")
                    Text("Asia").tag("asia")
                }
            }

            Section("Data") {
                Button("Clear history") { state.clearHistory() }
                Button("Clear bookmarks") { state.clearBookmarks() }
                Button("Clear all local data", role: .destructive) { state.clearAllData() }
            }

            Section("Session") {
                Button("End session", role: .destructive) { state.endSession() }
            }
        }
        .navigationTitle("Settings")
        .navigationBarHidden(false)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button("Back") { state.currentScreen = .home }
            }
        }
        .alert("Insecure mode unavailable", isPresented: $state.insecureLocalhostWarning) {
            Button("OK") {}
        } message: {
            Text("Release builds cannot disable TLS verification. Use a trusted certificate.")
        }
    }
}

struct HistoryView: View {
    @EnvironmentObject var state: AppState
    @State private var search: String = ""

    var filtered: [HistoryItem] {
        if search.isEmpty { return state.history }
        return state.history.filter { $0.title.localizedCaseInsensitiveContains(search) || $0.url.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        List {
            ForEach(filtered) { item in
                Button {
                    state.createTab()
                    state.navigate(item.url)
                    state.currentScreen = .browser
                } label: {
                    VStack(alignment: .leading) {
                        Text(item.title).lineLimit(1)
                        Text(item.url).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        Text(item.visitedAt.formatted(date: .abbreviated, time: .shortened)).font(.caption2).foregroundStyle(.tertiary)
                    }
                }
                .swipeActions {
                    Button("Delete", role: .destructive) { state.deleteHistory(item) }
                    Button("New tab") {
                        state.createTab()
                        state.navigate(item.url)
                    }
                    Button("Copy") { UIPasteboard.general.string = item.url }
                }
            }
        }
        .searchable(text: $search)
        .navigationTitle("History")
        .navigationBarHidden(false)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) { Button("Back") { state.currentScreen = .home } }
            ToolbarItem(placement: .topBarTrailing) {
                if !state.history.isEmpty {
                    Button("Clear", role: .destructive) { state.clearHistory() }
                }
            }
        }
    }
}

struct BookmarksView: View {
    @EnvironmentObject var state: AppState
    @State private var showAdd = false
    @State private var newTitle = ""
    @State private var newURL = ""

    var body: some View {
        List {
            ForEach(state.bookmarks.sorted(by: { $0.order < $1.order })) { item in
                Button {
                    state.createTab()
                    state.navigate(item.url)
                    state.currentScreen = .browser
                } label: {
                    VStack(alignment: .leading) {
                        Text(item.title).lineLimit(1)
                        Text(item.url).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                .swipeActions {
                    Button("Delete", role: .destructive) {
                        state.bookmarks.removeAll { $0.id == item.id }
                    }
                }
            }
            .onMove { from, to in
                var items = state.bookmarks.sorted(by: { $0.order < $1.order })
                items.move(fromOffsets: from, toOffset: to)
                for (idx, item) in items.enumerated() {
                    if let i = state.bookmarks.firstIndex(where: { $0.id == item.id }) {
                        state.bookmarks[i].order = idx
                    }
                }
            }
        }
        .navigationTitle("Bookmarks")
        .navigationBarHidden(false)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) { Button("Back") { state.currentScreen = .home } }
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    showAdd = true
                } label: { Image(systemName: "plus") }
            }
        }
        .sheet(isPresented: $showAdd) {
            NavigationStack {
                Form {
                    TextField("Title", text: $newTitle)
                    TextField("URL", text: $newURL)
                        .textInputAutocapitalization(.never)
                }
                .navigationTitle("Add Bookmark")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) { Button("Cancel") { showAdd = false } }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Save") {
                            state.addBookmark(title: newTitle, url: newURL)
                            newTitle = ""; newURL = ""; showAdd = false
                        }
                    }
                }
            }
        }
    }
}

struct DownloadsView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        List(state.downloads) { item in
            VStack(alignment: .leading, spacing: 4) {
                Text(item.filename).font(.headline).lineLimit(1)
                Text(item.mime).font(.caption).foregroundStyle(.secondary)
                Text(formatSize(item.size)).font(.caption2).foregroundStyle(.tertiary)
                ProgressView(value: Double(min(item.size, 100)), total: 100)
                    .opacity(item.state == 2 ? 0 : 1)
            }
            .swipeActions {
                Button("Delete", role: .destructive) {
                    state.downloads.removeAll { $0.id == item.id }
                }
                Button("Share") {
                    if let url = URL(string: state.settings.backendURL + "/api/download/" + item.id) {
                        let av = UIActivityViewController(activityItems: [url], applicationActivities: nil)
                        UIApplication.shared.connectedScenes
                            .compactMap { ($0 as? UIWindowScene)?.keyWindow }
                            .first?
                            .rootViewController?
                            .present(av, animated: true)
                    }
                }
            }
        }
        .navigationTitle("Downloads")
        .navigationBarHidden(false)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) { Button("Back") { state.currentScreen = .home } }
        }
    }

    private func formatSize(_ bytes: UInt64) -> String {
        let units = ["B", "KB", "MB", "GB"]
        var value = Double(bytes)
        var idx = 0
        while value >= 1024 && idx < units.count - 1 {
            value /= 1024
            idx += 1
        }
        return String(format: "%.1f %@", value, units[idx])
    }
}

struct DiagnosticsView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        List {
            Section("Connection") {
                row("WebSocket", state.diagnostics.wsState.rawValue)
                row("Reconnect attempts", "\(state.diagnostics.reconnectAttempts)")
                row("RTT", String(format: "%.1f ms", state.diagnostics.rttMs))
            }
            Section("Streaming") {
                row("FPS", String(format: "%.1f", state.diagnostics.fps))
                row("Dropped frames", "\(state.diagnostics.droppedFrames)")
                row("Render size", "\(state.diagnostics.renderWidth)×\(state.diagnostics.renderHeight)")
                row("Active tab ID", "\(state.diagnostics.activeTabId)")
                row("Proxy region", state.diagnostics.proxyRegion)
            }
            Section("Server") {
                row("Version", state.diagnostics.serverVersion)
                row("Last error", state.diagnostics.lastError.isEmpty ? "—" : state.diagnostics.lastError)
            }
            Section("Traffic") {
                row("Bytes in", "\(state.diagnostics.bytesIn)")
                row("Bytes out", "\(state.diagnostics.bytesOut)")
            }
        }
        .navigationTitle("Diagnostics")
        .navigationBarHidden(false)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button("Back") { state.currentScreen = state.sessionId.isEmpty ? .launch : .home }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button("Refresh") { state.fetchHealth() }
            }
        }
    }

    private func row(_ k: String, _ v: String) -> some View {
        HStack { Text(k); Spacer(); Text(v).foregroundStyle(.secondary).lineLimit(1) }
    }
}

struct ErrorView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 64))
                .foregroundStyle(.orange)
            Text("Something went wrong")
                .font(.title2.bold())
            Text(state.errorMessage ?? "Unknown error")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
            Spacer()
            Button {
                state.errorMessage = nil
                state.transport.connect()
            } label: {
                Text("Retry")
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 14))
            }
            Button("Reset session", role: .destructive) {
                state.endSession()
            }
            .padding(.horizontal)
            Spacer()
        }
        .padding()
    }
}

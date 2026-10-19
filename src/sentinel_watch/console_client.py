"""Optional normal-user, single-origin Sentinel Qt 6.10 client.

Qt imports are confined to create_window/main. There is no general browser,
certificate exception, credential storage API, privileged action or subprocess.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit
import uuid

CONFIG_PATH = Path('/etc/sentinel-console-client/config.json')
CA_PATH = Path('/etc/sentinel-console-client/ca.der')
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_CA_BYTES = 16384
UNSAFE_ENVIRONMENT = ('QTWEBENGINE_CHROMIUM_FLAGS', 'QTWEBENGINE_DISABLE_SANDBOX',
    'QTWEBENGINE_REMOTE_DEBUGGING', 'QTWEBENGINEPROCESS_PATH', 'CHROMIUM_FLAGS',
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy')


class ClientError(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise ClientError(code)


def prepare_process_environment(environment):
    """A process-local Qt Quick backend, with no Chromium/sandbox/TLS flags."""
    need(not any(environment.get(key) for key in UNSAFE_ENVIRONMENT), 'E_CLIENT_ENVIRONMENT')
    environment['QT_QUICK_BACKEND'] = 'software'


def _split(value):
    need(isinstance(value, str) and 0 < len(value) <= 8192
         and all(ord(c) >= 32 and ord(c) != 127 for c in value)
         and '\\' not in value, 'E_CLIENT_URL')
    try:
        parsed = urlsplit(value)
        need(parsed.scheme == 'https' and parsed.hostname is not None
             and parsed.username is None and parsed.password is None, 'E_CLIENT_URL')
        port = parsed.port
    except (ValueError, TypeError):
        raise ClientError('E_CLIENT_URL') from None
    need(port is not None and parsed.netloc == parsed.hostname + ':' + str(port), 'E_CLIENT_URL')
    return parsed


def validate_config(value):
    need(isinstance(value, dict) and set(value) == {'schema_version', 'origin', 'ca_der_sha256'}
         and type(value['schema_version']) is int and value['schema_version'] == 1, 'E_CLIENT_CONFIG')
    parsed = _split(value['origin'])
    try:
        address = ipaddress.IPv4Address(parsed.hostname)
    except ValueError:
        raise ClientError('E_CLIENT_CONFIG') from None
    allowed = any(address in ipaddress.IPv4Network(network) for network in
                  ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
    need(allowed and str(address) == parsed.hostname and parsed.port == 8443
         and not parsed.path and not parsed.query and not parsed.fragment
         and isinstance(value['ca_der_sha256'], str)
         and re.fullmatch(r'[0-9a-f]{64}', value['ca_der_sha256']), 'E_CLIENT_CONFIG')
    return dict(value)


def same_origin(url, origin):
    try:
        parsed, expected = _split(url), _split(origin)
        return parsed.scheme == expected.scheme and parsed.netloc == expected.netloc
    except ClientError:
        return False


def report_blob(url, origin):
    if not isinstance(url, str) or not url.startswith('blob:'):
        return False
    inner = url[5:]
    try:
        parsed = _split(inner)
        # Chromium blob identifiers are opaque UUIDs; no nested schemes or paths.
        return (same_origin(inner, origin) and not parsed.query and not parsed.fragment
                and re.fullmatch(r'/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', parsed.path) is not None)
    except ClientError:
        return False


def download_allowed(url, page_url, origin, mime_type, total_bytes, *, save_page=False):
    return (save_page is False and report_blob(url, origin) and same_origin(page_url, origin)
            and mime_type == 'application/json' and type(total_bytes) is int
            and 0 < total_bytes <= MAX_REPORT_BYTES)


def gate_request(info, origin):
    """Block before inspecting any Qt metadata; API/policy errors remain denied."""
    try:
        info.block(True)
        target = info.requestUrl().toString()
        allowed = same_origin(target, origin) or (info.isDownload() and report_blob(target, origin)
            and same_origin(info.firstPartyUrl().toString(), origin))
        if allowed:
            info.block(False)
            return True
    except Exception:
        pass
    return False


def validate_ca_der(raw, expected_hash):
    need(isinstance(raw, bytes) and 64 <= len(raw) <= MAX_CA_BYTES
         and isinstance(expected_hash, str) and re.fullmatch(r'[0-9a-f]{64}', expected_hash)
         and hashlib.sha256(raw).hexdigest() == expected_hash, 'E_CLIENT_CA')
    # Require one complete, canonical outer DER SEQUENCE, not a PEM/bundle prefix.
    need(raw[0] == 0x30, 'E_CLIENT_CA')
    size, header = raw[1], 2
    if size & 0x80:
        length_bytes = size & 0x7f
        need(1 <= length_bytes <= 3 and len(raw) > 2 + length_bytes
             and raw[2] != 0, 'E_CLIENT_CA')
        size = int.from_bytes(raw[2:2 + length_bytes], 'big')
        need(size >= 128, 'E_CLIENT_CA')
        header += length_bytes
    need(size + header == len(raw), 'E_CLIENT_CA')
    return raw


def _metadata(meta, owner, *, directory=False, private=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    need(kind(meta.st_mode) and meta.st_uid == owner and not meta.st_mode & 0o022
         and (directory or meta.st_nlink == 1)
         and (not private or stat.S_IMODE(meta.st_mode) == 0o700), 'E_CLIENT_PATH')


def _read_file(path, maximum, owner):
    before = path.lstat()
    _metadata(before, owner)
    need(before.st_size <= maximum, 'E_CLIENT_SIZE')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    need(len(raw) <= maximum and identity(before) == identity(opened) == identity(after), 'E_CLIENT_PATH')
    return raw


def load_fixed_config():
    _metadata(CONFIG_PATH.parent.lstat(), 0, directory=True)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'E_CLIENT_CONFIG')
            result[key] = value
        return result
    config = validate_config(json.loads(_read_file(CONFIG_PATH, 4096, 0), object_pairs_hook=unique))
    return config, validate_ca_der(_read_file(CA_PATH, MAX_CA_BYTES, 0), config['ca_der_sha256'])


def private_directory(path, owner, *, create=False):
    if create:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
    _metadata(path.lstat(), owner, directory=True, private=True)
    return path


def user_directories():
    import pwd
    owner = os.getuid()
    need(owner != 0, 'E_CLIENT_NORMAL_USER')
    home = Path(pwd.getpwuid(owner).pw_dir)
    _metadata(home.lstat(), owner, directory=True)
    parent = home
    for component in ('.local', 'share'):
        parent = parent / component
        try:
            parent.mkdir(mode=0o700)
        except FileExistsError:
            pass
        _metadata(parent.lstat(), owner, directory=True)
    state = private_directory(parent / 'sentinel-console-client', owner, create=True)
    return state, private_directory(state / 'reports', owner, create=True)


def validate_report(raw):
    need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_REPORT_BYTES, 'E_CLIENT_REPORT_SIZE')
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise ClientError('E_CLIENT_REPORT_JSON') from None
    need(isinstance(value, dict) and set(value) == {'snapshot', 'annotations'}
         and isinstance(value['snapshot'], dict) and isinstance(value['annotations'], dict), 'E_CLIENT_REPORT_JSON')
    return raw


def publish_report(directory, raw):
    """Only generated names, a bounded validated body and exclusive publication."""
    raw = validate_report(raw)
    private_directory(directory, os.getuid())
    name = 'sentinel-report-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex + '.json'
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def create_window(app, origin, ca_der, expected_sha256, private_state, reports):
    """Qt factory for the launcher and isolated engine fixtures; does not load a URL.

    Only main reads the fixed root configuration. This in-process fixture seam
    accepts an exact HTTPS loopback origin; no launcher URL/CA override exists.
    """
    import PySide6
    from PySide6.QtCore import QTemporaryDir, QUrl, Qt, qVersion
    from PySide6.QtGui import QAction
    from PySide6.QtNetwork import QNetworkProxy, QSsl, QSslCertificate
    from PySide6.QtWidgets import QMainWindow, QToolBar, QLabel
    from PySide6.QtWebEngineCore import (QWebEnginePage, QWebEngineProfile,
        QWebEngineProfileBuilder, QWebEngineSettings, QWebEngineUrlRequestInterceptor)
    from PySide6.QtWebEngineWidgets import QWebEngineView
    import shiboken6

    need(re.fullmatch(r'6\.10\.\d+', PySide6.__version__) and re.fullmatch(r'6\.10\.\d+', qVersion()), 'E_CLIENT_QT_VERSION')
    _split(origin)
    validate_ca_der(ca_der, expected_sha256)
    certificates = QSslCertificate.fromData(ca_der, QSsl.EncodingFormat.Der)
    need(len(certificates) == 1 and bytes(certificates[0].toDer()) == ca_der, 'E_CLIENT_CA')
    owner = os.getuid()
    private_directory(private_state, owner)
    private_directory(reports, owner)
    QNetworkProxy.setApplicationProxy(QNetworkProxy(QNetworkProxy.ProxyType.NoProxy))

    class Interceptor(QWebEngineUrlRequestInterceptor):
        def interceptRequest(self, info):
            # QWebEngineUrlRequestInfo.isDownload exists in the versioned 6.10 API.
            try:
                if not gate_request(info, origin):
                    self.parent().policy_rejections += 1
            except Exception:
                pass

    class Page(QWebEnginePage):
        def acceptNavigationRequest(self, url, kind, main_frame):
            try:
                allowed = same_origin(url.toString(), origin)
                if not allowed:
                    self.parent().policy_rejections += 1
                return allowed
            except Exception:
                return False

        def createWindow(self, kind):
            try:
                self.parent().policy_rejections += 1
            except Exception:
                pass
            return None

        def chooseFiles(self, mode, old_files, accepted_mime_types):
            return []

        def javaScriptConsoleMessage(self, level, message, line, source):
            pass  # Never log page data, credentials or response bodies.

    class Window(QMainWindow):
        def __init__(self):
            super().__init__()
            self.origin, self.report_directory = origin, reports
            self.policy_rejections = 0
            self.download_counts = {'accepted': 0, 'rejected': 0, 'published': 0}
            self.downloads = {}
            self.closed = False
            self.temporary = QTemporaryDir(str(private_state / 'session-XXXXXX'))
            self.temporary.setAutoRemove(False)
            need(self.temporary.isValid(), 'E_CLIENT_STATE')
            self.session = private_directory(Path(self.temporary.path()), owner)
            builder = QWebEngineProfileBuilder()
            builder.setPersistentStoragePath(str(self.session / 'storage'))
            builder.setCachePath(str(self.session / 'cache'))
            builder.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
            builder.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)
            builder.setPersistentPermissionsPolicy(QWebEngineProfile.PersistentPermissionsPolicy.StoreInMemory)
            builder.setAdditionalTrustedCertificates(certificates)
            # The static createOffTheRecordProfile would discard builder settings.
            self.profile = builder.createProfile('', self)
            need(self.profile is not None and self.profile.isOffTheRecord(), 'E_CLIENT_PROFILE')
            extra = self.profile.additionalTrustedCertificates()
            need(len(extra) == 1 and hashlib.sha256(bytes(extra[0].toDer())).hexdigest() == expected_sha256, 'E_CLIENT_CA')
            self.profile.setPushServiceEnabled(False)
            self.profile.setSpellCheckEnabled(False)
            self.interceptor = Interceptor(self)
            self.profile.setUrlRequestInterceptor(self.interceptor)
            self.profile.downloadRequested.connect(self.download)
            self.page = Page(self.profile, self)
            self.page.certificateError.connect(lambda error: self.deny(error, 'rejectCertificate'))
            self.page.permissionRequested.connect(lambda permission: self.deny(permission, 'deny'))
            self.page.selectClientCertificate.connect(lambda selection: self.deny(selection, 'selectNone'))
            self.page.fileSystemAccessRequested.connect(lambda request: self.deny(request, 'reject'))
            self.page.quotaRequested.connect(lambda request: self.deny(request, 'reject'))
            self.page.registerProtocolHandlerRequested.connect(lambda request: self.deny(request, 'reject'))
            self.page.fullScreenRequested.connect(lambda request: self.deny(request, 'reject'))
            settings = self.page.settings()
            for attribute in ('JavascriptCanOpenWindows', 'JavascriptCanAccessClipboard', 'JavascriptCanPaste',
                              'LocalContentCanAccessFileUrls', 'LocalContentCanAccessRemoteUrls', 'PluginsEnabled',
                              'PdfViewerEnabled', 'DnsPrefetchEnabled', 'HyperlinkAuditingEnabled', 'ScreenCaptureEnabled',
                              'NavigateOnDropEnabled', 'WebGLEnabled', 'AllowRunningInsecureContent',
                              'AllowGeolocationOnInsecureOrigins', 'LocalStorageEnabled'):
                settings.setAttribute(getattr(QWebEngineSettings.WebAttribute, attribute), False)
            settings.setUnknownUrlSchemePolicy(QWebEngineSettings.UnknownUrlSchemePolicy.DisallowUnknownUrlSchemes)
            self.view = QWebEngineView(self)
            self.view.setPage(self.page)
            self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
            self.view.setAcceptDrops(False)
            self.setCentralWidget(self.view)
            self.setWindowTitle('Sentinel Network Watch')
            self.resize(1200, 850)
            toolbar = QToolBar('Sentinel', self)
            toolbar.setMovable(False)
            self.addToolBar(toolbar)
            for label, callback in (('Home', lambda: self.view.setUrl(QUrl(origin + '/'))), ('Reload', self.view.reload)):
                action = QAction(label, self)
                action.triggered.connect(callback)
                toolbar.addAction(action)
            self.status = QLabel('Sentinel only - sign in with your dashboard login', self)
            toolbar.addWidget(self.status)
            self.view.loadStarted.connect(lambda: self.status.setText('Connecting to Sentinel...'))
            self.view.loadFinished.connect(lambda ok: self.status.setText('Sentinel loaded' if ok else 'Connection failed - no certificate bypass available'))

        def deny(self, request, method):
            try:
                getattr(request, method)()
            except Exception:
                self.view.stop()
                app.quit()  # A missing denial API cannot fall back to browsing.

        def download(self, request):
            try:
                page = request.page()
                allowed = (page is self.page and len(self.downloads) < 2
                    and download_allowed(request.url().toString(), page.url().toString(), origin,
                        request.mimeType(), request.totalBytes(), save_page=request.isSavePageDownload()))
                if not allowed:
                    self.download_counts['rejected'] += 1
                    request.cancel()
                    return
                folder = private_directory(self.session / ('download-' + uuid.uuid4().hex), owner, create=True)
                path = folder / 'report.json'
                self.downloads[request.id()] = (request, path)
                request.setDownloadDirectory(str(folder))
                request.setDownloadFileName(path.name)
                request.receivedBytesChanged.connect(lambda: self.check_download(request))
                request.totalBytesChanged.connect(lambda: self.check_download(request))
                request.isFinishedChanged.connect(lambda: self.finish_download(request))
                self.download_counts['accepted'] += 1
                request.accept()
            except Exception:
                self.download_counts['rejected'] += 1
                request.cancel()

        def check_download(self, request):
            if request.receivedBytes() > MAX_REPORT_BYTES or request.totalBytes() > MAX_REPORT_BYTES:
                request.cancel()

        def finish_download(self, request):
            if not request.isFinished() or request.id() not in self.downloads:
                return
            _, path = self.downloads.pop(request.id())
            try:
                need(request.state() == request.DownloadState.DownloadCompleted, 'E_CLIENT_DOWNLOAD')
                raw = _read_file(path, MAX_REPORT_BYTES, owner)
                publish_report(reports, raw)
                self.download_counts['published'] += 1
                self.status.setText('Private JSON report saved in Sentinel reports')
            except Exception:
                self.status.setText('Report not saved: blocked, incomplete or invalid JSON')

        def shutdown(self):
            if self.closed:
                return
            self.closed = True
            for request, _ in list(self.downloads.values()):
                request.cancel()
            self.view.stop()
            shiboken6.delete(self.view)
            if shiboken6.isValid(self.page):
                shiboken6.delete(self.page)
            shiboken6.delete(self.profile)
            try:
                private_directory(self.session, owner)
                need(self.session.parent == private_state and self.session.name.startswith('session-'), 'E_CLIENT_STATE')
                self.temporary.remove()  # Only this Qt-created and verified private per-run path.
            except Exception:
                pass  # Interrupted cleanup leaves private transient files; never broad-delete.

    return Window()


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        need(sys.platform.startswith('linux') and os.getuid() != 0 and not args, 'E_CLIENT_LAUNCH')
        prepare_process_environment(os.environ)
        os.umask(0o077)
        config, ca_der = load_fixed_config()
        state, reports = user_directories()
        from PySide6.QtCore import QUrl
        from PySide6.QtWidgets import QApplication
        app = QApplication(['Sentinel Network Watch'])
        window = create_window(app, config['origin'], ca_der, config['ca_der_sha256'], state, reports)
        try:
            window.show()
            window.view.setUrl(QUrl(config['origin'] + '/'))
            return app.exec()
        finally:
            window.shutdown()
    except Exception:
        print('Sentinel client could not start; review installation, certificate and runtime checks.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

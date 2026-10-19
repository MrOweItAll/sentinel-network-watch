"""Real Qt + HTTPS report workflow with synthetic data only; no production access."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import ssl
import sys
import tempfile
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', required=True)
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    report = {'ok': False, 'synthetic_only': True, 'production_contacted': False,
              'checks': {}, 'started_at': time.time()}
    server = thread = harness = None
    phase = 'environment'
    try:
        assert sys.platform.startswith('linux') and os.geteuid() != 0
        signal.alarm(90)
        os.umask(0o077)
        sys.path.insert(0, str(Path(args.source_root).resolve()))
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from sentinel_watch import console_client
        from sentinel_watch.console import ReviewStore
        from sentinel_watch.console_server import create_server
        from sentinel_watch.dashboard import write_password_file
        import linux_console_client_acceptance as engine
        console_client.prepare_process_environment(os.environ)
        os.environ['QT_QPA_PLATFORM'] = 'offscreen'
        from PySide6.QtWidgets import QApplication
        app = QApplication(['sentinel-report-synthetic-acceptance'])
        app.setQuitOnLastWindowClosed(False)
        with ExitStack() as resources:
            tmp = resources.enter_context(tempfile.TemporaryDirectory(prefix='sentinel-report-acceptance-'))
            root = Path(tmp)
            root.chmod(0o700)
            engine.PROGRESS_ROOT = root
            ca_der, fixtures = engine.certificates(root)
            certificate, key = fixtures['good']
            auth = root / 'synthetic-auth.json'
            write_password_file(auth, engine.FIXTURE_PASSWORD)
            store = ReviewStore(root / 'reviews.sqlite3')
            network_id = '12345678-1234-5678-1234-567812345678'
            binding = 'a' * 64
            def row(index):
                return {'id': 'fixture-history-' + str(index).zfill(4), 'source': 'router', 'state': 'history',
                    'direction': 'vendor_outgoing', 'network_id': network_id,
                    'source_address': '192.0.2.20', 'source_port': None,
                    'destination_address': '198.51.100.10', 'destination_port': 443,
                    'summary': 'fixture-destination-' + str(index) + '.example', 'application': 'Unreported by router',
                    'observed_at': time.time(), 'severity': 'INFO', 'flags': [], 'transport': 'unknown',
                    'reason': 'Synthetic retained observation; contents and outcome unknown.',
                    'next_step': 'Review this synthetic evidence.', 'rx_bytes': None, 'tx_bytes': None}
            rows = [row(index) for index in range(700)]
            class History:
                def __init__(self): self.calls = []
                def summary(self, snapshot, annotations):
                    return {'available': True, 'state': 'ok', 'generated_at': time.time(),
                        'collector_checked_at': time.time(), 'raw_retained_count': 700,
                        'total_observations': 700, 'row_errors': 0, 'reason': 'Synthetic retained history only.'}
                def page(self, query, annotations, snapshot):
                    self.calls.append(dict(query))
                    found = [r for r in rows if (query['direction'] == 'all' or query['direction'] == r['direction'])
                        and query['search'].lower() in json.dumps(r).lower()
                        and (query['review'] == 'all' or (query['review'] == 'pending' and r['id'] not in annotations)
                             or annotations.get(r['id'], {}).get('decision') == query['review'])]
                    offset, limit = query['offset'], query['limit']
                    return dict(self.summary(snapshot, annotations), rows=found[offset:offset+limit],
                        total_matches=len(found), offset=offset, limit=limit, has_more=offset+limit<len(found))
                def contains(self, ident, snapshot): return any(r['id'] == ident for r in rows)
            history = History()
            def snapshot():
                return {'schema_version': 1, 'generated_at': time.time(), 'connections': rows[:500],
                    'network_id': network_id, 'network_binding_sha256': binding,
                    'sources': {'guard': {'matches': True, 'state': 'ok', 'network_id': network_id,
                        'binding_sha256': binding, 'checked_at': time.time()}},
                    'devices': [], 'counters': [], 'capabilities': {},
                    'truncation': {'connections_omitted': 200}}
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.minimum_version = ssl.TLSVersion.TLSv1_2
            tls.load_cert_chain(certificate, key)
            server = create_server({'bind': '127.0.0.1', 'port': 8443, 'allowed_cidr': '127.0.0.0/8',
                                    'auth_path': str(auth)}, snapshot, store, tls, history_provider=history)
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
            thread.start()
            harness = engine.EngineHarness(app, console_client, root, ca_der)
            def close_windows():
                for item in list(harness.windows):
                    harness.close(item)
            resources.callback(close_windows)
            window = harness.window('https://127.0.0.1:8443')
            def check(name, value):
                report['checks'][name] = bool(value)
                assert value
            def js(value): return harness.js(window, value)
            def wait(expression):
                return harness.spin(lambda: bool(js(expression)))
            def change(ident, value):
                js("(()=>{const e=document.getElementById("+json.dumps(ident)+");e.value="+json.dumps(value)+
                   ";e.dispatchEvent(new Event('"+('input' if ident=='search' else 'change')+"'));return true})()")
            phase = 'login'
            check('real_login_page', harness.load(window, 'https://127.0.0.1:8443/login'))
            js("document.getElementById('password').value="+json.dumps(engine.FIXTURE_PASSWORD)+
               ";document.getElementById('login').requestSubmit();true")
            check('real_report_loaded', wait("document.getElementById('rows')?.children.length>0"))
            check('pending_default', js("document.getElementById('review').value==='pending'"))
            check('info_is_not_approval', js("document.querySelector('#rows strong')?.textContent==='Not reviewed' && document.querySelector('#rows strong')?.className.includes('REVIEW')"))
            phase = 'history_paging'
            js("document.getElementById('browse-history').click();true")
            check('full_history_mode', wait("document.getElementById('source').value==='history' && document.getElementById('rows').children.length===50"))
            check('full_history_total_visible', js("document.getElementById('count').textContent.includes('700') || document.getElementById('history-status').textContent.includes('700')"))
            js("document.getElementById('history-next').click();true")
            check('next_page_uses_server', harness.spin(lambda: any(q['offset']==50 for q in history.calls)))
            phase = 'search_beyond_500'
            change('search', 'fixture-destination-699.example')
            check('search_finds_beyond_first500', wait("document.getElementById('rows').children.length===1 && document.getElementById('rows').textContent.includes('fixture-destination-699.example')"))
            check('filter_resets_page', history.calls[-1]['offset']==0)
            js("document.querySelector('#rows button').click();document.getElementById('note').value='Synthetic note survives refresh';document.getElementById('refresh').click();true")
            harness.spin(lambda: False, .25)
            check('refresh_preserves_note', js("document.getElementById('note').value==='Synthetic note survives refresh' && document.getElementById('detail').open"))
            phase = 'review_history_only_identity'
            js("document.querySelector('[data-decision=investigate]').click();true")
            check('review_beyond_first500_saved', harness.spin(lambda: store.annotations().get(rows[699]['id'],{}).get('decision')=='investigate'))
            check('pending_queue_removes_reviewed', wait("!document.getElementById('detail').open && document.getElementById('rows').children.length===0"))
            change('review', 'investigate')
            check('investigate_filter_finds_saved', wait("document.getElementById('rows').children.length===1 && document.querySelector('#rows strong')?.textContent==='Investigate'"))
            phase = 'export'
            js("document.getElementById('export').click();true")
            check('page_report_saved_by_real_client', harness.spin(lambda: len(list(window._fixture_reports.glob('*.json')))==1))
            exported = json.loads(next(window._fixture_reports.glob('*.json')).read_bytes())
            check('export_shape_and_page_scope', set(exported)=={'snapshot','annotations'} and len(exported['snapshot']['connections'])==1)
            check('export_has_explicit_scope', 'page' in json.dumps(exported['snapshot']).lower())
            check('no_automatic_recognition', all(a['decision']!='recognize' for a in store.annotations().values()))
            check('session_is_off_record', window.profile.isOffTheRecord())
            phase = 'screenshot'
            image = window.grab()
            image_path = Path(args.report).with_suffix('.png')
            check('synthetic_report_screenshot', image.save(str(image_path), 'PNG'))
            report['ok'] = all(report['checks'].values())
    except Exception:
        report['error_code'] = 'E_REPORT_ACCEPTANCE'
        report['failure_phase'] = phase
    finally:
        if harness is not None:
            for window in list(harness.windows): harness.close(window)
        if server is not None:
            server.shutdown(); server.server_close()
        if thread is not None: thread.join(timeout=3)
        signal.alarm(0)
        report['finished_at'] = time.time()
        fd = os.open(args.report, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd,'wb') as stream: stream.write((json.dumps(report,sort_keys=True)+'\n').encode())
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Start and operate Sentinel without an AI session or Windows controller."""
from __future__ import annotations

import json
import contextlib
import os
from pathlib import Path
import signal
import sys
import threading
import time
import uuid

from .arguments import SafeArgumentParser
from .hub import Hub, HubError, DEFAULT_CONFIG, DEFAULT_STATE, gateway_context, host_fingerprint, private_dir, write_private, load_config


def initialize(config_path, *, state_dir=DEFAULT_STATE, network_label, router_state_dir=None, alerts_config=None,
               password_prompt=None):
    from .dashboard import initialize_password_file, PasswordAuth
    config_path = Path(config_path)
    if config_path.exists() or config_path.is_symlink(): raise HubError('E_CONFIG_EXISTS')
    private_dir(config_path.parent)
    private_dir(state_dir)
    gateway = gateway_context()
    if not gateway.get('fingerprint'): raise HubError('E_NETWORK_HINT_UNAVAILABLE')
    if (not isinstance(network_label,str) or not 1 <= len(network_label.strip()) <= 128 or
            any(ord(c)<32 or ord(c)==127 for c in network_label)):
        raise HubError('E_NETWORK_LABEL')
    host = host_fingerprint()
    auth = config_path.parent / 'dashboard-auth.json'
    reused_auth = auth.exists()
    if reused_auth:
        PasswordAuth(auth)  # Recover an interrupted setup without resetting its credential.
    else:
        initialize_password_file(auth, **({'password_prompt':password_prompt} if password_prompt is not None else {}))
    value = {'schema_version':1,'state_dir':str(Path(state_dir).absolute()),
             'network_id':str(uuid.uuid4()),'network_label':network_label.strip(),
             'actor_key':'linux:'+host,'expected_host_fingerprint':host,
             'expected_gateway_fingerprint':gateway['fingerprint'],
             'collection_interval_seconds':60,'linux_enabled':True,'port':8765,'auth_path':str(auth.absolute())}
    if router_state_dir is not None:
        value.update(router_state_dir=str(Path(router_state_dir).absolute()),router_expected_gateway=gateway['gateway'])
    if alerts_config is not None: value['alerts_config_path'] = str(Path(alerts_config).absolute())
    write_private(config_path,value,exclusive=True)
    Hub(config_path)
    return {'ok':True,'configured':True,'services_started':False,'network_settings_changed':False,
            'dashboard_credentials_reused':reused_auth}


def run_server(hub):
    from .dashboard import create_server
    from .alerts import _FileLock
    stop = threading.Event()
    port = hub.config.get('port',8765)
    server = create_server(hub,hub.config.get('auth_path','/etc/sentinel-hub/dashboard-auth.json'),port=port)
    interval = hub.config.get('collection_interval_seconds',60)
    def worker():
        while not stop.is_set():
            started = time.monotonic()
            try:
                hub.tick()
            except Exception:
                # A full/unavailable queue is an explicit degraded state, never an all-clear.
                try:
                    write_private(hub.state/'worker-error.json',{'ok':False,'code':'E_HUB_CYCLE','checked_at':time.time()})
                    engine = hub._engine({'hub_collection':False})
                    if engine is not None: engine.tick()
                except Exception: pass
            stop.wait(max(1,interval-(time.monotonic()-started)))
    def shutdown(signum, frame):
        stop.set()
        threading.Thread(target=server.shutdown,daemon=True).start()
    for sig in (signal.SIGTERM,signal.SIGINT): signal.signal(sig,shutdown)
    try:
        with _FileLock(hub.state/'daemon.lock'):
            thread = threading.Thread(target=worker,name='sentinel-collector',daemon=True)
            thread.start()
            try: server.serve_forever(poll_interval=0.5)
            finally: stop.set(); thread.join(timeout=90)
    finally:
        server.server_close()


def watchdog(config_path):
    """Independent systemd invocation can report a stopped hub; no AI or UI required."""
    from .alerts import AlertEngine, load_config as alert_config, _subprocess_ok
    c = load_config(config_path)
    state = private_dir(c['state_dir'])
    if not c.get('alerts_config_path'): raise HubError('E_ALERTS_NOT_CONFIGURED')
    active = _subprocess_ok(['/usr/bin/systemctl','is-active','--quiet','sentinel-hub.service'])
    try:
        observed = Hub(config_path).overview()
        healthy = bool(active and observed['ok'])
    except Exception:
        healthy = False
    from .alerts import service_checks
    checks = {'hub_collection':healthy, **service_checks(state_dir=state)}
    engine = AlertEngine(state/'alerts',alert_config(Path(c['alerts_config_path'])),check_provider=lambda:checks)
    result = engine.tick()
    write_private(state/'watchdog-status.json',{'checked_at':time.time(),'hub_service_active':active,
                                             'hub_checks_healthy':healthy,'delivery_state':result.get('delivery_state')})
    return {'ok':result.get('ok',False),'hub_service_active':active,'hub_checks_healthy':healthy,
            'complete_host_outage_detectable':False}


def main(argv=None):
    p = SafeArgumentParser(description=__doc__)
    p.add_argument('command',choices=('init','serve','tick','status','report','test-alert','watchdog'))
    p.add_argument('--config',type=Path,default=DEFAULT_CONFIG)
    p.add_argument('--state-dir',type=Path,default=DEFAULT_STATE)
    p.add_argument('--network-label')
    p.add_argument('--router-state-dir',type=Path)
    p.add_argument('--alerts-config',type=Path)
    args = p.parse_args(argv)
    try:
        if args.command in ('serve','init') and (not sys.platform.startswith('linux') or os.geteuid()!=0):
            raise HubError('E_LINUX_ROOT_REQUIRED')
        if args.command=='init':
            result = initialize(args.config,state_dir=args.state_dir,network_label=args.network_label,
                                router_state_dir=args.router_state_dir,alerts_config=args.alerts_config)
        elif args.command=='watchdog':
            result = watchdog(args.config)
        else:
            config = load_config(args.config)
            state = private_dir(config['state_dir'])
            from .alerts import _FileLock
            # The service owns this lock for its lifetime. Local mutating CLI
            # commands must not race its collector or a migration/import.
            guard = _FileLock(state/'daemon.lock') if args.command in ('tick','test-alert') else contextlib.nullcontext()
            with guard:
                hub = Hub(args.config)
                if args.command=='serve':
                    run_server(hub); return 0
                result = {'tick':hub.tick,'status':hub.overview,'report':hub.report,'test-alert':hub.test_alert}[args.command]()
        print(json.dumps(result,sort_keys=True))
        return 0 if result.get('ok',True) else 1
    except (HubError,ValueError) as error:
        code = str(error)
        if not code.startswith('E_') or len(code)>64 or not all(c.isupper() or c.isdigit() or c=='_' for c in code):
            code = 'E_HUB'
        print(json.dumps({'ok':False,'error':code})); return 1
    except Exception:
        print(json.dumps({'ok':False,'error':'E_HUB'})); return 1


if __name__=='__main__':
    raise SystemExit(main())

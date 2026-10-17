#!/usr/bin/env python3
"""Run the fixed read-only collector and durably hand generic intents to ntfy."""
import argparse
from .arguments import SafeArgumentParser
import json
import os
from pathlib import Path
import sys
import time
import uuid

from . import router as router_logs


def load_alerts():
    from . import alerts
    return alerts


def run(config_path=router_logs.DEFAULT_CONFIG, *, alerts_config=None,
        state_dir=None, alert_state_dir=None):
    if getattr(os, "geteuid", lambda: -1)()!=0:
        return 1
    store=None
    status=None
    try:
        config=router_logs.load_config(config_path)
        store=router_logs.Store(router_logs.DEFAULT_STATE if state_dir is None else state_dir)
        status=router_logs.collect(store, **config)
        module=load_alerts()
        engine=module.AlertEngine(module.DEFAULT_STATE if alert_state_dir is None else alert_state_dir,
                                  module.load_config(module.DEFAULT_CONFIG if alerts_config is None else alerts_config))
        handed=0
        for notice in store.pending_notices():
            engine.enqueue_router_notice(notice['id'],notice['category'])
            store.acknowledge_notice(notice['id'])
            handed+=1
        status['notices_handed_to_persistent_outbox']=handed
        status['pending_generic_notices']=len(store.pending_notices())
        status['alert_queue_handoff_ok']=True
        result=0 if status['ok'] else 1
    except Exception:
        status=status or {'checked_at':time.time(),'complete_stream_visibility':False}
        status.update(ok=False,error='E_ROUTER_COLLECTOR_OR_ALERT_HANDOFF',alert_queue_handoff_ok=False)
        result=1
    finally:
        if store is not None:
            try:
                tmp=store.path/(uuid.uuid4().hex+'.status.tmp')
                router_logs.private_write(tmp,(router_logs.canonical(status)+'\n').encode())
                os.replace(tmp,store.path/'status.json')
            finally:
                store.close()
    return result


def main(argv=None):
    parser=SafeArgumentParser(description='Read-only router observations and persistent alert handoff.')
    parser.add_argument('--config',type=Path,default=router_logs.DEFAULT_CONFIG)
    parser.add_argument('--alerts-config',type=Path)
    parser.add_argument('--state-dir',type=Path)
    parser.add_argument('--alert-state-dir',type=Path)
    args=parser.parse_args(argv)
    result=run(args.config,alerts_config=args.alerts_config,state_dir=args.state_dir,
               alert_state_dir=args.alert_state_dir)
    status={'ok':result==0,'complete_stream_visibility':False}
    if result:
        status['error']='E_ROUTER_COLLECTOR_OR_ALERT_HANDOFF'
    print(json.dumps(status,sort_keys=True))
    return result


if __name__=='__main__':
    raise SystemExit(main())

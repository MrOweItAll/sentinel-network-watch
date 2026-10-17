"""Exercise crash-sensitive queue handoff without networking or real state."""
import json
import os
import io
from contextlib import redirect_stdout
import pathlib
import tempfile
import types
import unittest
from unittest.mock import patch
from sentinel_watch import router_runner as r

class HandoffTests(unittest.TestCase):
    def setUp(self):
        if os.name == 'nt':
            original = os.mkdir
            def inherited(path, mode=0o777, *, dir_fd=None):
                return original(path, 0o777 if mode == 0o700 else mode) if dir_fd is None else original(path, mode, dir_fd=dir_fd)
            shim = patch('os.mkdir', side_effect=inherited)
            shim.start(); self.addCleanup(shim.stop)
        self.temp=tempfile.TemporaryDirectory(prefix='router-runner-fixture-',dir=pathlib.Path(__file__).resolve().parent)
        self.addCleanup(self.temp.cleanup)
        self.calls=[]
        self.pending=[{'id':'a'*32,'category':'inventory_change'}]
        test=self
        class Store:
            path=pathlib.Path(test.temp.name)
            def pending_notices(self):return list(test.pending)
            def acknowledge_notice(self,ident):
                test.calls.append(('ack',ident));test.pending.clear()
            def close(self):test.calls.append(('close',))
        self.store=Store()
        self.collect={'ok':True,'checked_at':123,'logging_enabled':True,'complete_stream_visibility':False}
        self.module=types.SimpleNamespace(DEFAULT_STATE=None,DEFAULT_CONFIG=None,
            load_config=lambda path:None,AlertEngine=lambda *args:self)
        self.failure=False
    def enqueue_router_notice(self,ident,category):
        self.calls.append(('enqueue',ident,category))
        if self.failure:raise RuntimeError('private error content must not escape')
        return 'deterministic-id'
    def run_job(self):
        with patch.object(r.os,'geteuid',return_value=0,create=True),\
             patch.object(r.router_logs,'load_config',return_value={'gateway':'192.0.2.1','profile':r.router_logs.SUPPORTED_PROFILE}),\
             patch.object(r.router_logs,'Store',return_value=self.store),\
             patch.object(r.router_logs,'collect',return_value=self.collect.copy()),\
             patch.object(r,'load_alerts',return_value=self.module):
            return r.run()
    def test_durable_enqueue_precedes_ack_and_state_is_written(self):
        self.assertEqual(self.run_job(),0)
        self.assertEqual(self.calls[:2],[('enqueue','a'*32,'inventory_change'),('ack','a'*32)])
        self.assertEqual(self.pending,[])
        state=json.loads((self.store.path/'status.json').read_text())
        self.assertTrue(state['alert_queue_handoff_ok'])
        self.assertEqual(state['notices_handed_to_persistent_outbox'],1)
    def test_failed_enqueue_preserves_source_notice_and_safe_status(self):
        self.failure=True
        self.assertEqual(self.run_job(),1)
        self.assertEqual(len(self.pending),1)
        self.assertFalse(any(c[0]=='ack' for c in self.calls))
        text=(self.store.path/'status.json').read_text()
        self.assertNotIn('private error content',text)
        self.assertEqual(json.loads(text)['logging_enabled'],True)
        self.assertFalse(json.loads(text)['alert_queue_handoff_ok'])

    def test_main_passes_configuration_options_and_prints_safe_result(self):
        stdout=io.StringIO()
        with patch.object(r,'run',return_value=0) as run,redirect_stdout(stdout):
            result=r.main(['--config','fixture-router.json','--alerts-config','fixture-alerts.json',
                           '--state-dir','fixture-router-state','--alert-state-dir','fixture-alert-state'])
        self.assertEqual(result,0)
        self.assertEqual(json.loads(stdout.getvalue()),{'ok':True,'complete_stream_visibility':False})
        run.assert_called_once_with(pathlib.Path('fixture-router.json'),
             alerts_config=pathlib.Path('fixture-alerts.json'),state_dir=pathlib.Path('fixture-router-state'),
             alert_state_dir=pathlib.Path('fixture-alert-state'))

if __name__=='__main__':unittest.main()

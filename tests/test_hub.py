"""Autonomous lifecycle fixtures: no discovery, traffic or real notifications."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

from sentinel_watch import hub
from sentinel_watch.review import ReviewQueue


class Engine:
    def __init__(self): self.ids={}; self.tests=[]
    def enqueue_hub_notice(self,n,c): self.ids.setdefault(n,c);return n
    def tick(self): return {'ok':True,'delivery_state':'verified','outbox':{'verified':len(self.ids)}}
    def enqueue_test(self): self.tests.append('fixture');return 'fixture'


class HubTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.cfg=self.root/'config.json'
        self.root.chmod(0o700)
        self.now=2_000_000_000.0;self.net='b'*64;self.engine=Engine()
        self.config={'schema_version':1,'state_dir':str(self.state),'network_id':str(uuid.uuid4()),
                     'network_label':'Fixture network','actor_key':'linux:fixture',
                     'expected_host_fingerprint':'a'*64,'expected_gateway_fingerprint':self.net,
                     'collection_interval_seconds':60,'linux_enabled':True}
        hub.write_private(self.cfg,self.config,exclusive=True)
        self.seq=0;self.complete=True
        self.h=hub.Hub(self.cfg,clock=lambda:self.now,host_provider=lambda:'a'*64,
                       network_provider=lambda:{'fingerprint':self.net,'gateway':'192.0.2.1'},
                       linux_provider=self.capture,alert_factory=lambda checks:self.engine)

    def tearDown(self): self.temp.cleanup()

    def capture(self,actor_key,observed_at):
        self.seq+=1
        return {'records':[{'actor_key':actor_key,'app_context_key':'binary:fixture','kind':'native_tcp',
                 'transport':'TCP','destination_address':'192.0.2.20','destination_port':443,
                 'observed_at':observed_at,'observation_id':'capture:'+str(self.seq),
                 'evidence':{'application_name':'fixture','app_identity_complete':self.complete,
                             'binary_sha256':'c'*64,'endpoint_complete':True}}],
                'coverage':{'ok':True,'scope':'own_host_tcp'}}

    def test_autonomous_ingest_flags_once_and_repeats_accumulate(self):
        self.h.tick();self.h.tick()
        row=self.h.relationships()[0]
        self.assertEqual(row['sightings'],2)
        self.assertEqual(row['status'],'pending')
        self.assertEqual(list(self.engine.ids.values()),['review_needed'])
        self.assertFalse(self.h.overview()['complete_network_visibility'])

    def test_recognition_never_approves_and_identity_changes_do_not_inherit(self):
        self.h.tick();r=self.h.relationships()[0]
        self.h.recognize(r['review_id'],expected_app_context_key=r['app_context_key'])
        self.assertTrue(self.h.relationships()[0]['application_recognized'])
        self.assertEqual(self.h.relationships()[0]['status'],'pending')
        self.complete=False;self.h.tick()
        self.assertFalse(self.h.relationships()[0]['application_recognized'])
        self.assertEqual(self.h.relationships()[0]['status'],'pending_more_evidence')

    def test_fixed_expiry_survives_restart_and_reflags_on_expiry(self):
        self.h.tick();r=self.h.relationships()[0]
        self.h.decide(r['review_id'],'approve',86400,expected_relationship_key=r['relationship_key'])
        expires=self.h.relationships()[0]['decision']['expires_at']
        self.h.tick();self.assertEqual(len(self.engine.ids),1)
        self.now+=86400
        self.h.tick()
        self.assertEqual(self.h.relationships()[0]['status'],'pending')
        self.assertEqual(self.h.relationships()[0]['decision']['expires_at'],expires)
        self.assertEqual(len(self.engine.ids),2)
        self.assertEqual(self.h.overview()['queue']['counts']['pending'],1)

    def test_unknown_identity_linklocal_and_stale_ui_cannot_approve(self):
        self.complete=False;self.h.tick();r=self.h.relationships()[0]
        with self.assertRaisesRegex(hub.HubError,'E_APPLICATION_EVIDENCE_REQUIRED'):
            self.h.decide(r['review_id'],'approve',86400,expected_relationship_key=r['relationship_key'])
        with self.assertRaisesRegex(hub.HubError,'E_STALE_REVIEW'):
            self.h.decide(r['review_id'],'reject',86400,expected_relationship_key='wrong')

    def test_revoke_returns_pending_without_blocking(self):
        self.h.tick();r=self.h.relationships()[0]
        self.h.decide(r['review_id'],'approve',86400,expected_relationship_key=r['relationship_key'])
        result=self.h.decide(r['review_id'],'revoke',expected_relationship_key=r['relationship_key'])
        self.assertEqual(result['status'],'pending');self.assertFalse(result['blocking_action'])

    def test_network_change_pauses_intake_then_explicit_new_profile_inherits_nothing(self):
        self.h.tick();r=self.h.relationships()[0]
        self.h.decide(r['review_id'],'approve',86400,expected_relationship_key=r['relationship_key'])
        original=self.h.overview()['network']['network_id']
        self.net='d'*64
        result=self.h.tick()
        self.assertFalse(result['ok']);self.assertEqual(result['observations_processed'],0)
        self.h.onboard_network('Other fixture')
        self.assertEqual(self.h.relationships(),[])
        self.h.tick();r2=self.h.relationships()[0]
        self.assertNotEqual(r['relationship_key'],r2['relationship_key'])
        self.assertEqual(r2['status'],'pending')
        with self.assertRaisesRegex(hub.HubError,'E_STALE_REVIEW'):
            self.h.decide(r2['review_id'],'approve',86400,expected_relationship_key=r['relationship_key'])
        self.net='b'*64;self.h.activate_network(original)
        self.assertEqual(self.h.relationships()[0]['status'],'approved')

    def test_stale_data_and_missing_alert_configuration_do_not_show_healthy(self):
        self.h.tick();self.now+=181
        self.assertFalse(self.h.overview()['ok']);self.assertTrue(self.h.overview()['collection_stale'])
        self.h.alert_factory=None
        result=self.h.tick();self.assertFalse(result['ok'])
        self.assertIn('E_ALERTS_NOT_CONFIGURED',[g['code'] for g in result['gaps']])

    def test_crash_before_handoff_keeps_notice_for_retry(self):
        class Failed(Engine):
            def enqueue_hub_notice(self,n,c): raise RuntimeError('FAKE_PRIVATE_ERROR')
        self.h.alert_factory=lambda checks:Failed()
        self.assertFalse(self.h.tick()['ok'])
        self.assertEqual(self.h.overview()['pending_notification_handoffs'],1)
        self.h.alert_factory=lambda checks:self.engine
        self.h.tick()
        self.assertEqual(self.h.overview()['pending_notification_handoffs'],0)
        self.assertEqual(list(self.engine.ids.values()),['review_needed'])

    def test_import_preserves_exact_ids_decisions_and_24h_expiry(self):
        source=self.root/'import.sqlite3'
        with ReviewQueue(source,clock=lambda:1234) as q:
            record=self.capture('windows:original',1234)['records'][0]
            row=q.ingest(record)
            q.decide(row['review_id'],'approve',scope_endpoint=True,expires_seconds=86400)
        sha=hashlib.sha256(source.read_bytes()).hexdigest()
        result=self.h.import_case(source,expected_sha256=sha)
        self.assertEqual(result['decisions'],1)
        imported=self.h.relationships()[0]
        self.assertEqual(imported['actor_key'],'windows:original')
        self.assertEqual(imported['decision']['expires_at'],1234+86400)
        self.assertEqual(imported['status'],'pending')
        with self.assertRaisesRegex(hub.HubError,'E_IMPORT_TARGET_NOT_EMPTY'):
            self.h.import_case(source,expected_sha256=sha)

    def test_local_test_alert_is_queued_without_assuming_phone_delivery(self):
        self.assertFalse(self.h.test_alert()['human_receipt_confirmed'])
        self.assertEqual(self.engine.tests,['fixture'])

    def test_existing_service_summary_never_returns_private_fields(self):
        value={'checked_at':self.now,'checks':{'docker_service':True,'password_value':'FAKE_SECRET'},
               'health_state':'healthy','delivery_state':'verified','topic':'FAKE_PRIVATE_TOPIC'}
        with patch.object(hub.Path,'exists',return_value=True),patch.object(hub,'read_private',return_value=value):
            result=self.h.existing_services()
        self.assertEqual(result['alerts_and_adguard']['checks'],{'docker_service':True})
        self.assertNotIn('FAKE_',json.dumps(result))

    def test_failed_later_signature_cannot_inherit_recognition_or_approval(self):
        self.h.tick();r=self.h.relationships()[0]
        self.h.recognize(r['review_id'],expected_app_context_key=r['app_context_key'])
        self.h.decide(r['review_id'],'approve',86400,expected_relationship_key=r['relationship_key'])
        original_provider=self.h.linux_provider
        def invalid_signature(**kwargs):
            capture=original_provider(**kwargs)
            capture['records'][0]['evidence']['signature_status']='Invalid'
            return capture
        self.h.linux_provider=invalid_signature
        self.h.tick()
        row=self.h.relationships()[0]
        self.assertEqual(row['status'],'pending_more_evidence')
        self.assertFalse(row['application_recognized'])
        self.assertFalse(row['decision']['active'])
        self.assertTrue(row['effective_approval_suspended'])
        self.assertEqual(len(self.engine.ids),2)


if __name__=='__main__':unittest.main()

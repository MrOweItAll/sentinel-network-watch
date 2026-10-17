"""Synthetic repeat/capacity/crash fixtures; no host collection or network."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

from sentinel_watch import hub
from sentinel_watch.review import ReviewQueue, ReviewError


class Engine:
    def __init__(self): self.ids={}
    def enqueue_hub_notice(self,notice_id,category): self.ids.setdefault(notice_id,category)
    def tick(self): return {'ok':True,'delivery_state':'verified'}


class HubAutonomyRetentionTests(unittest.TestCase):
    def setUp(self):
        if os.name=='nt':
            mkdir=os.mkdir
            patcher=mock.patch.object(os,'mkdir',side_effect=lambda p,mode=0o777,**kw:mkdir(p,0o777 if mode==0o700 else mode,**kw))
            patcher.start();self.addCleanup(patcher.stop)
        # Keep synthetic private state out of Documents sync/hardlink staging.
        temp=tempfile.TemporaryDirectory(prefix='.test-hub-retention-')
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name);self.root.chmod(0o700)
        self.state=self.root/'state';self.state.mkdir(mode=0o700)
        self.cfg=self.root/'config.json'
        self.now=2_000_000_000.0;self.sequence=0;self.unknown=True;self.engine=Engine()
        hub.write_private(self.cfg,{'schema_version':1,'state_dir':str(self.state),'network_id':str(uuid.uuid4()),
            'network_label':'Synthetic','actor_key':'linux:fixture','expected_host_fingerprint':'a'*64,
            'expected_gateway_fingerprint':'b'*64,'collection_interval_seconds':60},exclusive=True)
        self.h=hub.Hub(self.cfg,clock=lambda:self.now,host_provider=lambda:'a'*64,
            network_provider=lambda:{'fingerprint':'b'*64,'gateway':'192.0.2.1'},
            linux_provider=self.capture,alert_factory=lambda checks:self.engine)

    def capture(self,actor_key,observed_at):
        self.sequence+=1
        context=('linux-unattributed-v1:'+str(self.sequence)) if self.unknown else 'linux-ordinary_binary-v1:fixture'
        return {'records':[{'actor_key':actor_key,'app_context_key':context,'kind':'listener','transport':'TCP',
            'destination_address':'0.0.0.0','destination_port':5355,'observed_at':observed_at,
            'observation_id':'linux:synthetic:'+str(self.sequence),
            'evidence':{'source':'linux_proc_tcp_snapshot','app_identity_complete':not self.unknown,
                        'endpoint_complete':True,'socket_uid':1000,'socket_inode':100+self.sequence,
                        'local_address':'0.0.0.0','local_port':5355,'executable_sha256':'c'*64}}],
            'coverage':{'ok':True}}

    def router(self,poll='1',observed=None):
        observed=self.now if observed is None else observed
        return {'actor_key':'network:'+self.h.config['network_id']+'/router-source:192.0.2.10',
            'app_context_key':'router:outgoing:application-unreported','kind':'router_record','transport':'unknown',
            'destination_address':'198.51.100.20','destination_port':443,'observed_at':observed,
            'observation_id':'router:outgoing:'+('d'*64)+':'+poll,
            'evidence':{'source':'router retained observation','app_identity_complete':False,
                        'router_kind':'outgoing','router_record_hash':'d'*64,'router_last_poll_id':poll}}

    def use_router(self,records,*,linux=False):
        self.h.config['linux_enabled']=linux
        profiles=hub.read_private(self.h.profiles_path)
        profiles['profiles'][0]['router_enabled']=True
        hub.write_private(self.h.profiles_path,profiles)
        self.h._router_records=lambda:(records,{'collection_ok':True})

    def test_repeated_unknown_capture_is_one_unapprovable_bucket_with_counts(self):
        with mock.patch.object(hub,'OWN_OBSERVATION_WINDOW',3):
            for _ in range(12):
                self.assertTrue(self.h.tick()['ok']);self.now+=60
            rows=self.h.relationships();self.assertEqual(len(rows),1)
            row=rows[0]
            self.assertTrue(row['app_context_key'].startswith('unattributed-linux-endpoint:'))
            self.assertEqual(row['status'],'pending_more_evidence')
            self.assertFalse(row['approval_available']);self.assertFalse(row['application_recognized'])
            self.assertEqual(row['sightings'],12)
            self.assertEqual(row['last_seen']-row['first_seen'],11*60)
            self.assertEqual(row['evidence']['capture_app_context_key'],'linux-unattributed-v1:12')
            self.assertEqual(row['evidence']['grouping_note'],hub.UNKNOWN_GROUPING_NOTE)
            retained=self.h.overview()['observation_retention']
            self.assertEqual(retained['own_replay_ids_retained'],3)
            self.assertEqual(retained['own_replay_ids_compacted_total'],9)
        with self.assertRaisesRegex(hub.HubError,'E_APPLICATION_EVIDENCE_REQUIRED'):
            self.h.decide(row['review_id'],'approve',86400,expected_relationship_key=row['relationship_key'])
        with self.assertRaisesRegex(hub.HubError,'E_APPLICATION_EVIDENCE_REQUIRED'):
            self.h.recognize(row['review_id'],expected_app_context_key=row['app_context_key'])
        self.assertEqual(list(self.engine.ids.values()),['review_needed'])

    def test_bucket_dimensions_are_isolated_and_known_contexts_are_unchanged(self):
        base=self.capture('network:fixture/linux:fixture',self.now)['records'][0]
        original=hub.Hub._bucket_linux(base)['app_context_key']
        for field,value in [('actor_key','another-actor'),('kind','native_tcp'),('transport','unknown'),
                            ('destination_address','192.0.2.2'),('destination_port',443)]:
            changed={**base,field:value}
            self.assertNotEqual(hub.Hub._bucket_linux(changed)['app_context_key'],original,field)
        for field,value in [('socket_uid',1001),('local_port',5356),('local_address','::')]:
            changed={**base,'evidence':{**base['evidence'],field:value}}
            self.assertNotEqual(hub.Hub._bucket_linux(changed)['app_context_key'],original,field)
        for context,source,complete in [('linux-ordinary_binary-v1:known','linux_proc_tcp_snapshot',False),
                ('linux-unattributed-v1:manual','manual_import',False),('known-binary','linux_proc_tcp_snapshot',True)]:
            changed={**base,'app_context_key':context,'evidence':{**base['evidence'],'source':source,'app_identity_complete':complete}}
            self.assertEqual(hub.Hub._bucket_linux(changed)['app_context_key'],context)

    def test_known_application_contexts_never_merge_or_lose_decisions(self):
        self.unknown=False
        self.h.tick();first=self.h.relationships()[0]
        self.h.decide(first['review_id'],'approve',86400,expected_relationship_key=first['relationship_key'])
        expiry=self.h.relationships()[0]['decision']['expires_at']
        with mock.patch.object(hub,'OWN_OBSERVATION_WINDOW',2):
            for _ in range(6):self.now+=60;self.h.tick()
        row=self.h.relationships()[0]
        self.assertEqual(row['app_context_key'],'linux-ordinary_binary-v1:fixture')
        self.assertEqual(row['sightings'],7);self.assertEqual(row['status'],'approved')
        self.assertEqual(row['decision']['expires_at'],expiry)

    def test_imported_owned_ids_and_case_aggregates_are_protected(self):
        source=self.root/'historical.sqlite3'
        old_id='linux:hub-v1:'+('e'*64)
        with ReviewQueue(source,clock=lambda:1234) as q:
            hub.Hub._schema(q)
            record=self.capture('windows:historical',1234)['records'][0]
            record['observation_id']=old_id
            record['evidence']['app_identity_complete']=True
            row=q.ingest(record)
            q.decide(row['review_id'],'approve',scope_endpoint=True,expires_seconds=86400)
            with q.db:q.db.execute('INSERT INTO hub_observation_ids(observation_id) VALUES(?)',(old_id,))
        digest=hashlib.sha256(source.read_bytes()).hexdigest()
        self.h.import_case(source,expected_sha256=digest)
        with mock.patch.object(hub,'OWN_OBSERVATION_WINDOW',2):
            for _ in range(7):self.h.tick();self.now+=60
        with self.h._queue() as q:
            old=q.db.execute('SELECT * FROM relationships WHERE actor_key=?',('windows:historical',)).fetchone()
            self.assertEqual((old['first_seen'],old['last_seen'],old['sightings']),(1234,1234,1))
            self.assertIsNotNone(q.db.execute('SELECT 1 FROM observations WHERE observation_id=?',(old_id,)).fetchone())
            self.assertEqual(q.db.execute('SELECT eligible FROM hub_observation_ids WHERE observation_id=?',(old_id,)).fetchone()[0],0)
            self.assertEqual(q.db.execute('SELECT expires_at FROM decisions').fetchone()[0],1234+86400)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),digest)

    def test_router_watermark_survives_id_compaction_and_new_poll_counts_once(self):
        records=[self.router()];self.use_router(records,linux=True)
        with mock.patch.object(hub,'OWN_OBSERVATION_WINDOW',2):
            for _ in range(7):self.h.tick();self.now+=60
            with self.h._queue() as q:
                self.assertEqual(q.db.execute("SELECT sightings FROM relationships WHERE kind='router_record'").fetchone()[0],1)
                self.assertEqual(q.db.execute("SELECT COUNT(*) FROM observations WHERE observation_id LIKE 'router:%'").fetchone()[0],0)
            result=self.h.tick()
            self.assertEqual(result['router_rows_skipped_unchanged'],1)
            records[0]=self.router('2')
            self.h.tick();self.h.tick()
        with self.h._queue() as q:
            self.assertEqual(q.db.execute("SELECT sightings FROM relationships WHERE kind='router_record'").fetchone()[0],2)
            self.assertEqual(q.db.execute('SELECT last_poll_id FROM hub_router_watermarks').fetchone()[0],'2')

    def test_crash_after_core_commit_replays_without_inflated_router_count(self):
        records=[self.router()];self.use_router(records)
        with mock.patch.object(self.h,'_ack_observation',side_effect=RuntimeError('synthetic crash')):
            result=self.h.tick()
        self.assertFalse(result['ok'])
        with self.h._queue() as q:
            self.assertEqual(q.db.execute('SELECT sightings FROM relationships').fetchone()[0],1)
            self.assertEqual(self.h._retention_status(q)['pending_observation_records'],1)
            self.assertEqual(q.db.execute('SELECT COUNT(*) FROM hub_router_watermarks').fetchone()[0],0)
        result=self.h.tick();self.assertTrue(result['ok'])
        self.assertEqual(result['recovered_pending_observations'],1)
        with self.h._queue() as q:
            self.assertEqual(q.db.execute('SELECT sightings FROM relationships').fetchone()[0],1)
            self.assertEqual(self.h._retention_status(q)['pending_observation_records'],0)

    def test_crash_before_core_commit_replays_staged_record(self):
        self.use_router([self.router()])
        with mock.patch.object(ReviewQueue,'ingest',side_effect=RuntimeError('synthetic crash')):
            self.assertFalse(self.h.tick()['ok'])
        with self.h._queue() as q:
            self.assertEqual(q.db.execute('SELECT COUNT(*) FROM relationships').fetchone()[0],0)
            self.assertEqual(self.h._retention_status(q)['pending_observation_records'],1)
        self.assertTrue(self.h.tick()['ok'])
        self.assertEqual(self.h.relationships()[0]['sightings'],1)

    def test_watermark_capacity_failure_preserves_replay_and_core_count(self):
        self.use_router([self.router()])
        original=ReviewQueue._check_capacity
        def check(q):
            original(q)
            if q.db.execute('SELECT COUNT(*) FROM hub_router_watermarks').fetchone()[0]:
                raise ReviewError('E_QUEUE_CAP')
        with mock.patch.object(ReviewQueue,'_check_capacity',check):
            self.assertFalse(self.h.tick()['ok'])
        with self.h._queue() as q:
            self.assertEqual(q.db.execute('SELECT sightings FROM relationships').fetchone()[0],1)
            self.assertEqual(q.db.execute('SELECT COUNT(*) FROM hub_router_watermarks').fetchone()[0],0)
            self.assertEqual(self.h._retention_status(q)['pending_observation_records'],1)
        self.assertTrue(self.h.tick()['ok'])
        self.assertEqual(self.h.relationships()[0]['sightings'],1)

    def test_compaction_capacity_rollback_keeps_ids_and_all_counts(self):
        self.h.tick();self.now+=60;self.h.tick()
        with self.h._queue() as q,mock.patch.object(hub,'OWN_OBSERVATION_WINDOW',1):
            with mock.patch.object(q,'_check_capacity',side_effect=ReviewError('E_QUEUE_CAP')):
                with self.assertRaisesRegex(ReviewError,'E_QUEUE_CAP'):self.h._compact_observations(q)
            self.assertEqual(q.db.execute('SELECT COUNT(*) FROM observations').fetchone()[0],2)
            self.assertEqual(self.h._retention_status(q)['own_replay_ids_compacted_total'],0)
            self.h._compact_observations(q)
            self.assertEqual(q.db.execute('SELECT COUNT(*) FROM observations').fetchone()[0],1)
            self.assertEqual(q.db.execute('SELECT sightings FROM relationships').fetchone()[0],2)


if __name__=='__main__':unittest.main()

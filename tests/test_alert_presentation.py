"""Synthetic phone-presentation and old-outbox compatibility fixtures; no network."""
from contextlib import closing
import json
import sqlite3
import uuid
import unittest
from unittest import mock

from sentinel_watch import alerts as sut
import test_alerts as fixtures


class PresentationTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.AlertEngineTests('test_pending_event_survives_restart_and_is_sent_once')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.engine=self.fixture.engine
        self.http=self.fixture.http

    def event(self,event_id,engine=None):
        with closing(sqlite3.connect((engine or self.engine).db_path)) as db:
            db.row_factory=sqlite3.Row
            return dict(db.execute('SELECT * FROM events WHERE event_id=?',(event_id,)).fetchone())

    def test_every_category_has_fixed_severity_reason_action_and_no_visible_identifiers(self):
        kinds={'boot','down','recovery','test'}|sut.ROUTER_NOTICE_CATEGORIES|sut.HUB_NOTICE_CATEGORIES
        self.assertEqual(set(sut.EVENT_PRESENTATIONS),kinds)
        warnings={'down','router_collection_degraded','monitoring_gap'}
        reviews={'inventory_change','review_needed'}
        for kind in sorted(kinds):
            with self.subTest(kind=kind),self.engine._locked_connection() as db,sut._transaction(db):
                event_id=self.engine._enqueue(db,kind,self.fixture.clock())
                row=dict(db.execute('SELECT * FROM events WHERE event_id=?',(event_id,)).fetchone())
                self.assertEqual(row['sequence_id'],event_id)
                self.assertEqual(str(uuid.UUID(row['event_id'])),event_id)
                severity='WARNING' if kind in warnings else 'REVIEW' if kind in reviews else 'INFO'
                self.assertTrue(row['title'].startswith('Sentinel '+severity+': '))
                self.assertTrue(row['body'].startswith('Reason: '));self.assertIn('\nAction: ',row['body'])
                self.assertEqual(len(row['body'].splitlines()),2)
                rendered=row['title']+' '+row['body']
                for private in (event_id,self.fixture.config.topic,self.fixture.config.token,'Ref:','Event ','.py','/var/','C:\\'):
                    self.assertNotIn(private,rendered)
                self.assertNotRegex(rendered,r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b')
                self.assertEqual(row['priority'],4 if kind in warnings else 3)
                if kind in ('boot','down'):
                    self.assertIn('local health report',row['body'])
                    self.assertNotIn('dashboard',row['body'])
                if kind in ('router_collection_recovered','monitoring_recovered'):
                    self.assertIn('checks passed again.',row['body'])
                    self.assertNotIn('producing',row['body'])
        self.assertEqual(self.http.calls,[])

    def test_down_includes_only_allowlisted_failed_check_reasons(self):
        self.fixture.health={'docker_service':False,'dns_udp':False,'private_context_fixture':False}
        self.engine.tick();self.engine.tick()
        post=self.http.posts()[0];body=post['body'].decode()
        self.assertIn('the Docker service check failed',body)
        self.assertIn('local UDP DNS test failed',body)
        self.assertNotIn('private_context_fixture',body)
        self.assertIn('Action: ',body)
        self.assertTrue(post['headers']['Title'].startswith('Sentinel WARNING:'))

    def test_title_body_and_sequence_survive_restart_and_template_change(self):
        event_id=self.engine.enqueue_test();before=self.event(event_id)
        with mock.patch.dict(sut.EVENT_PRESENTATIONS,{'test':('WARNING','different','different','different')}):
            self.engine=self.fixture.new_engine();self.engine.tick()
        post=self.http.posts()[0]
        self.assertEqual(post['headers']['Title'],before['title'])
        self.assertEqual(post['headers']['X-Sequence-ID'],event_id)
        self.assertEqual(post['body'],before['body'].encode())
        self.assertEqual(self.event(event_id)['state'],'verified')

    def test_identical_visible_text_keeps_distinct_full_internal_sequence_ids(self):
        first=self.engine.enqueue_test();second=self.engine.enqueue_test()
        one,two=self.event(first),self.event(second)
        self.assertEqual(one['body'],two['body']);self.assertEqual(one['title'],two['title'])
        self.assertNotEqual(one['event_id'],two['event_id'])
        self.assertNotEqual(one['sequence_id'],two['sequence_id'])
        record={'id':'fixture-server','event':'message','topic':self.fixture.config.topic,
                'message':one['body'],'sequence_id':two['sequence_id']}
        self.assertFalse(self.engine._message_matches(record,one))
        record['sequence_id']=one['sequence_id']
        self.assertTrue(self.engine._message_matches(record,one))

    def test_missing_or_wrong_publish_sequence_never_verifies_or_skips_recovery_get(self):
        for index,sequence in enumerate((None,str(uuid.uuid4()))):
            with self.subTest(sequence_present=sequence is not None):
                # Separate states keep both attempted intents inspectable.
                engine=self.fixture.new_engine(state=self.fixture.state.parent/('sequence-'+str(index)))
                engine.boot_id_provider=lambda:'unknown'
                event_id=engine.enqueue_test()
                def wrong_sequence(method,url,headers,body):
                    return self.http.accept(body,sequence)
                self.http.calls.clear();self.http.messages.clear()
                self.http.actions.append(('POST',wrong_sequence))
                result=engine.tick()
                self.assertIn('E_PUBLISH_RESPONSE',json.dumps(result))
                self.assertEqual(self.event(event_id,engine)['state'],'posting')
                self.fixture.clock.advance(86401);engine.tick()
                self.assertEqual(self.http.methods(),['POST','GET'])
                self.assertNotEqual(self.event(event_id,engine)['state'],'verified')

    def test_accepted_wrong_readback_sequence_never_causes_another_post(self):
        event_id=self.engine.enqueue_test()
        def wrong_sequence(method,url,headers,body):
            record=dict(self.http.messages[-1],sequence_id=str(uuid.uuid4()))
            return self.http.response(200,json.dumps(record).encode()+b'\n')
        self.http.actions.extend([('POST',None),('GET',wrong_sequence)])
        self.engine.tick()
        self.assertEqual(self.event(event_id)['state'],'accepted')
        self.engine=self.fixture.new_engine();self.fixture.clock.advance(86401);self.engine.tick()
        self.assertEqual(self.http.methods(),['POST','GET','GET'])
        self.assertEqual(self.event(event_id)['state'],'verified')

    def test_ambiguous_cache_with_same_text_wrong_sequence_cannot_confirm_intent(self):
        event_id=self.engine.enqueue_test()
        def accept_then_timeout(method,url,headers,body):
            self.http.accept(body,str(uuid.uuid4()))
            raise sut.TransportError('E_NETWORK')
        self.http.actions.append(('POST',accept_then_timeout))
        self.engine.tick();self.engine=self.fixture.new_engine()
        self.fixture.clock.advance(86401);self.engine.tick()
        self.assertEqual(self.http.methods(),['POST','GET'])
        self.assertEqual(self.event(event_id)['state'],'pending')

    def test_legacy_schema_pending_posting_and_accepted_rows_keep_exact_identity_and_body(self):
        for state in ('pending','posting','accepted'):
            with self.subTest(state=state):
                folder=self.fixture.state.parent/('legacy-'+state);folder.mkdir()
                path=folder/'outbox.sqlite3';event_id=str(uuid.uuid4())
                body='Sentinel alert delivery test. Event '+event_id
                server_id='legacy-'+state if state=='accepted' else None
                with closing(sqlite3.connect(path)) as db:
                    db.row_factory=sqlite3.Row
                    db.executescript('''CREATE TABLE events(
                        event_id TEXT PRIMARY KEY,kind TEXT NOT NULL,body TEXT NOT NULL,
                        priority INTEGER NOT NULL,created REAL NOT NULL,state TEXT NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0,next_attempt REAL NOT NULL,
                        server_id TEXT,accepted_at REAL,verified_at REAL,last_error TEXT);''')
                    db.execute('INSERT INTO events(event_id,kind,body,priority,created,state,next_attempt,server_id) VALUES(?,?,?,?,?,?,?,?)',
                               (event_id,'test',body,3,self.fixture.clock()-60,state,self.fixture.clock()-1,server_id))
                    db.commit();before=dict(db.execute('SELECT * FROM events').fetchone())
                engine=sut.AlertEngine(folder,self.fixture.config,transport=self.http,clock=self.fixture.clock,
                                       check_provider=lambda:{},boot_id_provider=lambda:'unknown')
                migrated=self.event(event_id,engine)
                self.assertIsNone(migrated.pop('title'));self.assertIsNone(migrated.pop('sequence_id'))
                self.assertEqual(migrated,before)
                self.http.calls.clear();self.http.messages.clear()
                if state!='pending':
                    self.http.messages.append({'id':server_id or 'legacy-posting','event':'message',
                        'topic':self.fixture.config.topic,'message':body})
                engine.tick()
                self.assertEqual(self.event(event_id,engine)['state'],'verified')
                self.assertEqual(self.event(event_id,engine)['body'],body)
                if state=='pending':
                    self.assertEqual(self.http.methods(),['POST','GET'])
                    self.assertEqual(self.http.posts()[0]['body'],body.encode())
                    self.assertEqual(self.http.posts()[0]['headers']['Title'],'Sentinel')
                    self.assertNotIn('X-Sequence-ID',self.http.posts()[0]['headers'])
                else:self.assertEqual(self.http.methods(),['GET'])
                engine=sut.AlertEngine(folder,self.fixture.config,transport=self.http,clock=self.fixture.clock,
                                       check_provider=lambda:{},boot_id_provider=lambda:'unknown')
                self.fixture.clock.advance(86401);engine.tick()
                self.assertEqual(len(self.http.posts()),1 if state=='pending' else 0)


if __name__=='__main__':unittest.main()

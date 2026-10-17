"""Socket-free dashboard security fixtures; only synthetic in-memory hub data."""
import contextlib
from email.message import Message
import getpass
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import warnings

from sentinel_watch import dashboard as d


class FakeAuth:
    def verify(self,username,password):
        return username=='sentinel' and password=='FAKE_ONLY_password'


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.now=1000
        self.hub=Mock()
        self.row={'review_id':'C0001','actor_key':'fixture-device','app_context_key':'fixture-app',
                  'relationship_key':'a'*64,'kind':'native_tcp','transport':'TCP',
                  'destination_address':'192.0.2.10','destination_port':443,'status':'pending',
                  'evidence':{'application_name':'<img src=x onerror=alert(1)>'}}
        self.hub.overview.return_value={'health':'fixture','network':{'label':'fixture-network'}}
        self.hub.relationships.return_value=[self.row]
        self.hub.report.return_value={'relationships':[self.row],'token':'FAKE_ONLY_hidden'}
        for name in ('decide','recognize','tick','test_alert','onboard_network','activate_network'):
            getattr(self.hub,name).return_value={'ok':True}
        self.app=d.DashboardApp(self.hub,FakeAuth(),clock=lambda:self.now)
        self.cookie='';self.csrf=''

    def request(self,path,*,method='GET',data=None,headers=None,raw=None,client='127.0.0.1'):
        values={'Host':'127.0.0.1:8765'}
        if self.cookie:values['Cookie']=self.cookie
        if method=='POST':values.update({'Origin':self.app.origin,'Content-Type':'application/json',
                                        'X-CSRF-Token':self.csrf})
        values.update(headers or {})
        body=raw if raw is not None else json.dumps(data).encode() if data is not None else b''
        return self.app.dispatch(method,path,values,body,client_ip=client)

    def login(self):
        result=self.request('/api/login',method='POST',data={'username':'sentinel','password':'FAKE_ONLY_password'})
        self.assertEqual(result.status,200)
        self.cookie=result.headers['Set-Cookie'].split(';')[0]
        self.csrf=json.loads(result.body)['csrf_token']
        return result

    def test_all_private_reads_require_authentication(self):
        for path in ('/api/overview','/api/relationships','/api/report.json','/api/report.csv','/api/session'):
            with self.subTest(path=path):self.assertEqual(self.request(path).status,401)
        self.hub.assert_not_called()
        self.assertEqual(self.hub.mock_calls,[])

    def test_login_cookie_is_httponly_strict_and_password_never_echoed(self):
        response=self.login()
        self.assertIn('HttpOnly',response.headers['Set-Cookie'])
        self.assertIn('SameSite=Strict',response.headers['Set-Cookie'])
        self.assertNotIn(b'FAKE_ONLY_password',response.body)
        self.assertEqual(self.request('/api/session').status,200)

    def test_cross_origin_host_rebinding_nonlocal_and_duplicate_host_rejected(self):
        self.login()
        for headers in ({'Origin':'https://evil.test.invalid'},{'Host':'evil.test.invalid:8765'},
                        {'Sec-Fetch-Site':'cross-site'}):
            with self.subTest(headers=headers):self.assertEqual(self.request('/api/overview',headers=headers).status,403)
        self.assertEqual(self.request('/api/overview',client='192.0.2.5').status,403)
        response=self.app.dispatch('GET','/',[('Host','127.0.0.1:8765'),('Host','evil.test.invalid')])
        self.assertEqual(response.status,400)
        self.hub.overview.assert_not_called()

    def test_mutations_require_origin_and_csrf(self):
        self.login()
        for headers in ({'X-CSRF-Token':''},{'X-CSRF-Token':'wrong'},
                        {'Origin':'null'},{'Origin':'http://localhost:8765'}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request('/api/tick',method='POST',data={},headers=headers).status,403)
        self.hub.tick.assert_not_called()

    def test_exact_decision_scope_and_explicit_duration_pass_unchanged(self):
        self.login()
        value={'review_id':'C0001','decision':'approve','duration_seconds':86400,'until_revoked':False,
               'expected_relationship_key':'a'*64}
        self.assertEqual(self.request('/api/decide',method='POST',data=value).status,200)
        self.hub.decide.assert_called_once_with('C0001','approve',86400,until_revoked=False,
                                                expected_relationship_key='a'*64)
        self.hub.decide.reset_mock()
        for change in ({'duration_seconds':None},{'duration_seconds':0},{'duration_seconds':86401},
                       {'duration_seconds':True},{'expected_relationship_key':''},
                       {'until_revoked':True},{'review_id':'../config'}):
            with self.subTest(change=change):
                self.assertEqual(self.request('/api/decide',method='POST',data={**value,**change}).status,400)
        self.hub.decide.assert_not_called()

    def test_until_revoked_is_deliberate_and_recognition_is_separate(self):
        self.login()
        data={'review_id':'C0001','decision':'reject','duration_seconds':None,'until_revoked':True,
              'expected_relationship_key':'a'*64}
        self.assertEqual(self.request('/api/decide',method='POST',data=data).status,200)
        self.assertEqual(self.request('/api/recognize',method='POST',data={
            'review_id':'C0001','expected_app_context_key':'fixture-app'}).status,200)
        self.hub.recognize.assert_called_once_with('C0001',expected_app_context_key='fixture-app')
        self.assertEqual(self.hub.decide.call_count,1)

    def test_network_onboarding_activation_and_test_alert_are_authenticated_posts(self):
        self.login()
        self.assertEqual(self.request('/api/network/onboard',method='POST',data={'label':' Fixture network '}).status,200)
        self.hub.onboard_network.assert_called_once_with('Fixture network')
        self.assertEqual(self.request('/api/network/activate',method='POST',data={'network_id':'fixture-profile'}).status,200)
        self.hub.activate_network.assert_called_once_with('fixture-profile')
        self.assertEqual(self.request('/api/test-alert',method='POST',data={}).status,200)
        self.hub.test_alert.assert_called_once_with()
        self.assertEqual(self.request('/api/network/onboard',method='POST',data={'label':'bad\nlabel'}).status,400)
        self.assertEqual(self.request('/api/network/activate',method='POST',data={'network_id':'../file'}).status,400)

    def test_pagination_is_bounded_and_does_not_accept_extra_query_fields(self):
        self.login()
        self.assertEqual(self.request('/api/relationships?limit=20&offset=40').status,200)
        self.hub.relationships.assert_called_once_with(limit=20,offset=40)
        for query in ('limit=201','offset=-1','offset=50001','limit=1&limit=2','path=secret','limit=not-a-number'):
            with self.subTest(query=query):self.assertEqual(self.request('/api/relationships?'+query).status,400)

    def test_request_bounds_and_no_generic_file_or_command_routes(self):
        self.login()
        self.assertEqual(self.request('/api/tick',method='POST',raw=b'x'*(d.MAX_BODY+1)).status,413)
        self.assertEqual(self.request('/api/tick',method='POST',data={},headers={'Content-Type':'text/plain'}).status,415)
        self.assertEqual(self.request('/api/tick?token=FAKE',method='POST',data={}).status,403)
        for path in ('/etc/passwd','/api/command','/api/config','/api/../../private','/api/apply'):
            with self.subTest(path=path):self.assertEqual(self.request(path).status,404)
        self.assertEqual(self.request('/api/tick',method='GET').status,404)
        self.assertEqual(self.request('/api/tick',method='PUT').status,405)

    def test_login_rate_limit_session_expiry_and_logout(self):
        for _ in range(5):
            self.assertEqual(self.request('/api/login',method='POST',data={'username':'sentinel','password':'wrong'}).status,401)
        self.assertEqual(self.request('/api/login',method='POST',data={'username':'sentinel','password':'FAKE_ONLY_password'}).status,429)
        self.now+=61;self.login();self.now+=d.IDLE_SECONDS
        self.assertEqual(self.request('/api/overview').status,401)
        self.login()
        self.assertEqual(self.request('/api/logout',method='POST',data={}).status,200)
        self.assertEqual(self.request('/api/overview').status,401)

    def test_reports_redact_credentials_and_csv_cells_are_formula_safe(self):
        self.login()
        self.hub.report.return_value={'relationships':[dict(self.row,actor_key=' \t=FAKE_FORMULA',app_context_key='@FAKE')],
                                     'password':'FAKE_ONLY_PRIVATE','token':'FAKE_ONLY_PRIVATE','topic':'FAKE_ONLY_PRIVATE'}
        response=self.request('/api/report.json')
        self.assertNotIn(b'FAKE_ONLY_PRIVATE',response.body)
        self.assertIn('attachment',response.headers['Content-Disposition'])
        csv=self.request('/api/report.csv')
        self.assertIn(b"' \t=FAKE_FORMULA",csv.body)
        self.assertIn(b"'@FAKE",csv.body)
        self.assertEqual(csv.headers['X-Content-Type-Options'],'nosniff')

    def test_hub_errors_and_malicious_labels_are_not_html_or_raw_error_output(self):
        self.login()
        self.hub.tick.side_effect=RuntimeError('FAKE_ONLY_PRIVATE_ERROR')
        result=self.request('/api/tick',method='POST',data={})
        self.assertEqual(result.status,400);self.assertNotIn(b'FAKE_ONLY_PRIVATE_ERROR',result.body)
        page=self.request('/')
        self.assertNotIn(b'onerror=alert(1)',page.body)
        self.assertNotIn(b'innerHTML',page.body)
        self.assertIn(b'textContent=',page.body)
        self.assertIn("frame-ancestors 'none'",page.headers['Content-Security-Policy'])
        self.assertIn("script-src 'nonce-",page.headers['Content-Security-Policy'])
        self.assertNotIn(b'__NONCE__',page.body)

    def test_explicit_hub_failure_cannot_be_reported_as_success(self):
        self.login()
        self.hub.test_alert.return_value={'ok':False,'error':'FAKE_ONLY_PRIVATE_ERROR'}
        response=self.request('/api/test-alert',method='POST',data={})
        self.assertEqual(response.status,409)
        self.assertEqual(json.loads(response.body),{'error':'E_OPERATION'})

    def test_backup_requires_session_origin_csrf_and_matching_hidden_input(self):
        data={'passphrase':'FAKE_ONLY_backup_password','confirmation':'FAKE_ONLY_backup_password'}
        self.assertEqual(self.request('/api/backups',method='POST',data=data).status,401)
        self.assertEqual(self.request('/api/backups/'+'a'*32).status,401)
        self.login()
        for headers in ({'X-CSRF-Token':'wrong'},{'Origin':'https://evil.test.invalid'}):
            self.assertEqual(self.request('/api/backups',method='POST',data=data,headers=headers).status,403)
        for invalid in ({'passphrase':'short','confirmation':'short'},
                        dict(data,confirmation='different'),dict(data,path='/etc/passwd'),
                        {'passphrase':'FAKE_ONLY\n_backup_password','confirmation':'FAKE_ONLY\n_backup_password'}):
            response=self.request('/api/backups',method='POST',data=invalid)
            self.assertEqual(response.status,400);self.assertNotIn(b'FAKE_ONLY',response.body)
        self.hub.create_backup.assert_not_called();self.hub.backup_download.assert_not_called()

    def test_backup_result_is_verified_metadata_only_and_failure_never_echoes_phrase(self):
        self.login();phrase='FAKE_ONLY_backup_password'
        self.hub.create_backup.return_value={'ok':True,'backup_id':'a'*32,'filename':'a'*32+'.tar.gpg',
            'sha256':'b'*64,'bytes':42,'integrity_verified':True,'restore_verified':False,
            'local_only':True,'offhost_copy_verified':False,'system_backup_complete':False,
            'missing_components':['fixture excluded component'],'manifest':{'file':phrase},'unexpected':phrase}
        response=self.request('/api/backups',method='POST',data={'passphrase':phrase,'confirmation':phrase})
        self.assertEqual(response.status,200);self.assertNotIn(phrase.encode(),response.body)
        result=json.loads(response.body);self.assertFalse(result['restore_verified']);self.assertFalse(result['offhost_copy_verified'])
        self.assertNotIn('manifest',result);self.assertNotIn('unexpected',result)
        self.hub.create_backup.assert_called_once_with(phrase)
        self.hub.create_backup.return_value={'ok':False,'error':phrase}
        self.assertEqual(self.request('/api/backups',method='POST',data={'passphrase':phrase,'confirmation':phrase}).status,409)
        self.hub.create_backup.side_effect=RuntimeError(phrase)
        failed=self.request('/api/backups',method='POST',data={'passphrase':phrase,'confirmation':phrase})
        self.assertEqual(failed.status,400);self.assertNotIn(phrase.encode(),failed.body)

    def test_backup_download_accepts_only_exact_generated_id_and_no_paths(self):
        self.login()
        for ident in ('../private','a'*32+'.tar.gpg','A'*32,'a'*31,'a'*33,'%2e%2e%2fprivate'):
            with self.subTest(ident=ident):self.assertEqual(self.request('/api/backups/'+ident).status,400)
        self.assertEqual(self.request('/api/backups/'+'a'*32+'?path=secret').status,404)
        self.hub.backup_download.assert_not_called()
        stream=io.BytesIO(b'FAKE_ONLY_ciphertext')
        self.hub.backup_download.return_value=Path('fixture-backup-only')
        with patch.object(d,'_open_backup',return_value=(stream,20)) as opened:
            response=self.request('/api/backups/'+'a'*32)
        self.assertEqual(response.status,200);self.assertIs(response.stream,stream);self.assertEqual(response.body,b'')
        self.assertEqual(response.content_length,20);self.assertIn('a'*32+'.tar.gpg',response.headers['Content-Disposition'])
        self.hub.backup_download.assert_called_once_with('a'*32);opened.assert_called_once_with(Path('fixture-backup-only'))
        stream.close()

    @unittest.skipUnless(shutil.which('node'),'Optional JavaScript runtime is unavailable')
    def test_browser_summary_uses_hub_schema_and_fails_closed_on_incomplete_scope(self):
        # Execute only rendering functions in a synthetic DOM: no browser, sockets,
        # credentials, timers, fetches or application startup are involved.
        source=d.HTML.split('<script nonce="__NONCE__">',1)[1].split('</script>',1)[0]
        source=source.split("$('loginform').onsubmit=",1)[0]
        harness=r"""
const assert=require('node:assert/strict');
class Node {
 constructor(){this.children=[];this.textContent='';this.value='';this.disabled=false;this.open=false;}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=[...nodes];}
 get options(){return this.children;}
 showModal(){this.open=true;} close(){this.open=false;}
}
const nodes=new Map();
const document={getElementById(id){if(!nodes.has(id))nodes.set(id,new Node());return nodes.get(id);},createElement(){return new Node();}};
function content(node){return node.textContent+node.children.map(content).join(' ');}
"""+source+r"""
const row={review_id:'C0001',actor_key:'fixture actor',app_context_key:'fixture app',relationship_key:'fixture key',
 kind:'native_tcp',transport:'TCP',destination_address:'192.0.2.10',destination_port:443,status:'pending',
 application_recognized:true,approval_available:true,evidence:{executable_name:'fixture-program',app_identity_complete:true,executable_sha256:'a'.repeat(64)}};
assert.equal(appName(row),'fixture-program');
assert.equal(approvalReady(row),true);
assert.equal(approvalReady({...row,approval_available:false}),false);
assert.equal(approvalReady({...row,transport:'unknown'}),false);
assert.equal(approvalReady({...row,destination_address:null}),false);
assert.equal(approvalReady({...row,evidence:{...row.evidence,app_identity_complete:false}}),false);
renderOverview({ok:true,network:{label:'Fixture network',network_id:'fixture-profile-id',context_matches:true,current_gateway_hint:'192.0.2.1'},
 profiles:[{network_id:'fixture-profile-id',label:'Fixture network'}],queue:{relationships:213,counts:{pending:7,pending_more_evidence:2,approved:4,not_approved:3}},
 last_collection:{checked_at:1700000000,alerts:{delivery_state:'pending',outbox:{pending:1,posting:1,accepted:1,verified:3}},sources:{linux:{unattributed:2},router:{configured:false}},gaps:[]},
 collection_age_seconds:30,application_recognition_count:1,coverage_limits:['Fixture coverage limit.'],
 existing_services:{alerts_and_adguard:{available:true,fresh:true,health_state:'down',delivery_state:'verified',checks:{docker_service:true,dns_tcp:false}}}});
assert.equal($('networks').children[0].value,'fixture-profile-id');
assert.equal($('networks').children[0].textContent,'Fixture network');
assert.ok(!content($('networkcontext')).includes('fixture-profile-id'));
assert.ok(content($('overview')).includes('Needs review 7'));
assert.ok(content($('overview')).includes('More evidence 2'));
assert.ok(content($('delivery')).includes('3 awaiting readback or retry'));
assert.ok(content($('gaps')).includes('2 local observations'));
assert.ok(content($('reportnote')).includes('up to 200 of 213'));
assert.equal($('services').hidden,false);assert.ok(content($('servicestatus')).includes('checks need attention'));
assert.ok(content($('servicechecks')).includes('Local DNS over TCP: needs attention'));
openRecord(row);assert.equal($('approve').disabled,false);assert.equal($('recognize').disabled,true);
openRecord({...row,approval_available:false});assert.equal($('approve').disabled,true);
currentOverview.network.context_matches=false;openRecord(row);
assert.equal($('approve').disabled,true);assert.equal($('reject').disabled,true);assert.equal($('recognize').disabled,true);
records=[row];renderRows();assert.ok(content($('rows')).includes('Captured identity recognized'));
"""
        result=subprocess.run([shutil.which('node'),'-'],input=harness,text=True,encoding='utf-8',
                              capture_output=True,timeout=10)
        # Do not echo the DOM even in a failing fixture: assertions report only
        # public synthetic test data, but the production UI is a private view.
        self.assertEqual(result.returncode,0,'Synthetic browser rendering assertions failed')

    def test_absolute_session_expiry_survives_intermediate_reads(self):
        self.login()
        for _ in range(16):
            self.now+=d.IDLE_SECONDS-1
            self.request('/api/session')
        self.now+=20
        self.assertEqual(self.request('/api/overview').status,401)


class PasswordFileTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(__file__).parent/('fixture-dashboard-'+os.urandom(8).hex())
        self.root.mkdir(mode=0o777 if os.name=='nt' else 0o700)
        self.path=self.root/'auth.json'

    def tearDown(self):
        assert self.root.resolve().parent==Path(__file__).resolve().parent
        assert self.root.name.startswith('fixture-dashboard-')
        shutil.rmtree(self.root)

    def test_password_is_salted_hashed_and_existing_file_never_overwritten(self):
        password='FAKE_ONLY_dashboard_password_123'
        d.write_password_file(self.path,password)
        self.assertNotIn(password,self.path.read_text())
        auth=d.PasswordAuth(self.path)
        self.assertTrue(auth.verify('sentinel',password))
        self.assertFalse(auth.verify('sentinel','wrong'))
        self.assertFalse(auth.verify('other',password))
        self.assertFalse(auth.verify('nonASCII\u00e9',password))
        before=self.path.read_bytes()
        # A sync client may add a hardlink in this Windows workspace between
        # calls; either exclusive-create or the stronger link guard must refuse.
        with self.assertRaises((FileExistsError,d.DashboardError)):d.write_password_file(self.path,password)
        self.assertEqual(self.path.read_bytes(),before)
        self.assertEqual(json.loads(before)['iterations'],600000)
        if os.name=='posix':self.assertEqual(self.path.stat().st_mode&0o777,0o600)

    def test_hidden_prompt_fallback_and_confirmation_failure_create_no_file(self):
        def echo_fallback(_):
            warnings.warn('fixture no terminal',getpass.GetPassWarning)
            self.fail('must fail before echo fallback')
        with self.assertRaisesRegex(d.DashboardError,'E_HIDDEN_INPUT'):
            d.initialize_password_file(self.path,password_prompt=echo_fallback)
        with self.assertRaisesRegex(d.DashboardError,'E_AUTH_CONFIRMATION'):
            d.initialize_password_file(self.path,password_prompt=Mock(side_effect=['FAKE_ONLY_password','different']))
        self.assertFalse(self.path.exists())

    def test_bad_hash_file_and_unsafe_permissions_are_rejected(self):
        self.path.write_text('{}');self.path.chmod(0o600)
        with self.assertRaises(d.DashboardError):d.PasswordAuth(self.path)
        if os.name=='posix':
            self.path.chmod(0o644)
            with self.assertRaisesRegex(d.DashboardError,'E_AUTH_PERMISSIONS'):d.PasswordAuth(self.path)

    def test_lan_binding_is_rejected_before_reading_auth_or_opening_socket(self):
        with patch.object(d,'PasswordAuth',side_effect=AssertionError('auth read')), \
             patch.object(d,'HTTPServer',side_effect=AssertionError('socket bind')):
            for host in ('0.0.0.0','192.0.2.1','localhost','::'):
                with self.subTest(host=host),self.assertRaisesRegex(d.DashboardError,'E_LOOPBACK_BIND'):
                    d.create_server(Mock(),self.path,host=host)

    def test_http_adapter_rejects_chunked_or_duplicate_lengths_without_dispatch(self):
        server=SimpleNamespace(server_port=8765)
        with patch.object(d,'PasswordAuth',return_value=FakeAuth()),patch.object(d,'HTTPServer',return_value=server) as factory:
            d.create_server(Mock(),self.path)
        handler_type=factory.call_args.args[1]
        for headers in ([('Transfer-Encoding','chunked')],[('Content-Length','1'),('Content-Length','2')]):
            handler=handler_type.__new__(handler_type);handler.headers=Message()
            for key,value in headers:handler.headers[key]=value
            handler.command='POST';handler.path='/api/tick';handler.rfile=io.BytesIO(b'{}');handler.wfile=io.BytesIO()
            handler.server=SimpleNamespace(app=Mock());handler.client_address=('127.0.0.1',123)
            handler.send_response=Mock();handler.send_header=Mock();handler.end_headers=Mock()
            handler._handle()
            handler.server.app.dispatch.assert_not_called();handler.send_response.assert_called_once_with(400)
            self.assertNotIn(b'Transfer-Encoding',handler.wfile.getvalue())

    def test_private_backup_file_guards_and_bounded_descriptor(self):
        self.path.write_bytes(b'FAKE_ONLY_ciphertext');self.path.chmod(0o600)
        stream,size=d._open_backup(self.path)
        try:self.assertEqual(size,20);self.assertEqual(stream.read(),b'FAKE_ONLY_ciphertext')
        finally:stream.close()
        meta=self.path.stat()
        for changes in ({'st_nlink':2},{'st_size':d.MAX_BACKUP+1},{'st_ino':meta.st_ino+1}):
            values={key:getattr(meta,key) for key in ('st_mode','st_nlink','st_size','st_dev','st_ino','st_uid')}
            with patch.object(d.os,'fstat',return_value=SimpleNamespace(**{**values,**changes})),self.assertRaises(d.DashboardError):
                d._open_backup(self.path)
        if os.name=='posix':
            self.path.chmod(0o644)
            with self.assertRaises(d.DashboardError):d._open_backup(self.path)

    def test_http_backup_stream_has_fixed_length_chunks_and_closes_on_disconnect(self):
        server=SimpleNamespace(server_port=8765)
        with patch.object(d,'PasswordAuth',return_value=FakeAuth()),patch.object(d,'HTTPServer',return_value=server) as factory:
            d.create_server(Mock(),self.path)
        handler_type=factory.call_args.args[1]
        for disconnect in (False,True):
            stream=io.BytesIO(b'x'*131073)
            response=d.Response(200,b'',{'Content-Type':'application/octet-stream'},stream,131073)
            handler=handler_type.__new__(handler_type);handler.headers=Message()
            handler.command='GET';handler.path='/api/backups/'+'a'*32;handler.rfile=io.BytesIO()
            handler.wfile=Mock() if disconnect else io.BytesIO()
            if disconnect:handler.wfile.write.side_effect=OSError('fixture disconnect')
            handler.server=SimpleNamespace(app=Mock());handler.server.app.dispatch.return_value=response
            handler.client_address=('127.0.0.1',123);handler.send_response=Mock();handler.send_header=Mock();handler.end_headers=Mock()
            handler._handle();self.assertTrue(stream.closed)
            handler.send_header.assert_any_call('Content-Length','131073')
            if not disconnect:self.assertEqual(len(handler.wfile.getvalue()),131073)


if __name__=='__main__':unittest.main()

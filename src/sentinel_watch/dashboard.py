"""Authenticated loopback dashboard. No commands, arbitrary files or settings API.

The local browser and applications on this host must be trusted. HTTP is confined
to loopback; this is not a LAN/reverse-proxy deployment. Password initialization
is a separate local, hidden-prompt setup action, never an HTTP endpoint.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import base64
import csv
import getpass
import hashlib
import hmac
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from urllib.parse import parse_qs, urlsplit
import warnings

DEFAULT_AUTH = Path('/etc/sentinel-hub/dashboard-auth.json')
ITERATIONS = 600_000
MAX_BODY = 16_384
MAX_RESPONSE = 4 * 1024 * 1024
MAX_BACKUP = 512 * 1024 * 1024
COOKIE = 'sentinel_session'
SESSION_SECONDS = 8 * 3600
IDLE_SECONDS = 30 * 60
CSV_FIELDS = ('review_id','actor_key','app_context_key','kind','transport',
              'destination_address','destination_port','status','first_seen','last_seen','sightings')


class DashboardError(ValueError):
    pass


def _private_path(path, *, existing=False):
    path = Path(os.path.abspath(path))
    for item in (*reversed(path.parents), path):
        try:
            meta = item.lstat()
        except FileNotFoundError:
            if item == path and not existing:
                continue
            raise DashboardError('E_AUTH_PATH') from None
        if stat.S_ISLNK(meta.st_mode) or getattr(meta,'st_file_attributes',0) & 0x400:
            raise DashboardError('E_AUTH_PATH')
        if item == path and (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1):
            raise DashboardError('E_AUTH_PATH')
    parent = path.parent.stat()
    if os.name == 'posix' and (parent.st_uid != os.geteuid() or parent.st_mode & 0o077):
        raise DashboardError('E_AUTH_PERMISSIONS')
    return path


def write_password_file(path, password, *, username='sentinel'):
    """Exclusive setup API. Caller supplies password in memory, never argv/logs."""
    path = _private_path(path)
    if not isinstance(username,str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',username) is None:
        raise DashboardError('E_AUTH_USERNAME')
    if not isinstance(password,str) or not 12 <= len(password) <= 256:
        raise DashboardError('E_AUTH_PASSWORD')
    salt = secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),salt,ITERATIONS)
    value = {'version':1,'algorithm':'pbkdf2-sha256','iterations':ITERATIONS,
             'username':username,'salt':base64.b64encode(salt).decode('ascii'),
             'password_hash':base64.b64encode(digest).decode('ascii')}
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write((json.dumps(value,sort_keys=True)+'\n').encode('utf-8'))
        stream.flush();os.fsync(stream.fileno())
    return {'configured':True,'username':username}


def initialize_password_file(path=DEFAULT_AUTH, *, username='sentinel', password_prompt=None):
    """Hidden native setup prompts; refuse an echoing getpass fallback."""
    _private_path(path)
    if os.path.lexists(path):
        raise DashboardError('E_AUTH_EXISTS')
    prompt = password_prompt or getpass.getpass
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error',getpass.GetPassWarning)
            first = prompt('New Sentinel dashboard password (hidden, at least 12 characters): ')
            second = prompt('Confirm dashboard password (hidden): ')
    except Exception:
        raise DashboardError('E_HIDDEN_INPUT') from None
    if not isinstance(first,str) or not isinstance(second,str) or not hmac.compare_digest(first.encode(),second.encode()):
        raise DashboardError('E_AUTH_CONFIRMATION')
    return write_password_file(path,first,username=username)


class PasswordAuth:
    def __init__(self,path):
        path = _private_path(path,existing=True)
        fd = os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
        try:
            meta = os.fstat(fd)
            if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_size > 4096 or
                (os.name == 'posix' and (meta.st_uid != os.geteuid() or meta.st_mode & 0o077))):
                raise DashboardError('E_AUTH_PERMISSIONS')
            with os.fdopen(fd,'rb') as stream:
                fd = None
                data = json.loads(stream.read(4097))
            if (set(data) != {'version','algorithm','iterations','username','salt','password_hash'} or
                data['version'] != 1 or data['algorithm'] != 'pbkdf2-sha256' or
                type(data['iterations']) is not int or data['iterations'] != ITERATIONS or
                re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',data['username']) is None):
                raise DashboardError('E_AUTH_FILE')
            self.salt = base64.b64decode(data['salt'],validate=True)
            self.digest = base64.b64decode(data['password_hash'],validate=True)
            self.username = data['username']
            if len(self.salt) != 32 or len(self.digest) != 32:
                raise DashboardError('E_AUTH_FILE')
        except DashboardError:
            raise
        except Exception:
            raise DashboardError('E_AUTH_FILE') from None
        finally:
            if fd is not None:os.close(fd)

    def verify(self,username,password):
        if not isinstance(username,str) or not isinstance(password,str) or len(username)>64 or len(password)>256:
            return False
        try:
            digest = hashlib.pbkdf2_hmac('sha256',password.encode('utf-8'),self.salt,ITERATIONS)
            return hmac.compare_digest(digest,self.digest) and hmac.compare_digest(username.encode(),self.username.encode())
        except (UnicodeError,ValueError):return False


@dataclass
class Response:
    status: int
    body: bytes
    headers: dict = field(default_factory=dict)
    stream: object | None = None
    content_length: int | None = None


def _json(value):
    return json.dumps(value,ensure_ascii=True,allow_nan=False,separators=(',',':')).encode('utf-8')


def _safe_hub(value):
    """Defense in depth; Hub must itself return reports without credentials."""
    if isinstance(value,dict):
        return {str(k):_safe_hub(v) for k,v in value.items()
                if not re.search(r'password|passphrase|secret|token|credential|password_hash|authorization|^topic$|^base_url$|^salt$',str(k),re.I)}
    if isinstance(value,(list,tuple)):return [_safe_hub(v) for v in value]
    if value is None or isinstance(value,(str,int,float,bool)):return value
    raise DashboardError('E_REPORT')


def csv_report(report):
    rows = report.get('relationships',[]) if isinstance(report,dict) else []
    if not isinstance(rows,list):raise DashboardError('E_REPORT')
    output=io.StringIO(newline='');writer=csv.writer(output);writer.writerow(CSV_FIELDS)
    for row in rows:
        if not isinstance(row,dict):raise DashboardError('E_REPORT')
        cells=[]
        for key in CSV_FIELDS:
            value=row.get(key,'');value='' if value is None else str(value)
            if value.lstrip().startswith(('=','+','-','@')) or value.startswith(('\t','\r','\n')):
                value="'"+value
            cells.append(value)
        writer.writerow(cells)
    return output.getvalue().encode('utf-8-sig')


def _open_backup(path):
    """Open only the Hub-selected, closed private file; never a request path."""
    path=_private_path(path,existing=True)
    before=path.lstat()
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    try:
        meta=os.fstat(fd)
        if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or
            getattr(meta,'st_file_attributes',0)&0x400 or
            not 0<meta.st_size<=MAX_BACKUP or
            (before.st_dev,before.st_ino,before.st_size)!=(meta.st_dev,meta.st_ino,meta.st_size) or
            (os.name=='posix' and (meta.st_uid!=os.geteuid() or meta.st_mode&0o777!=0o600))):
            raise DashboardError('E_BACKUP_FILE')
        stream=os.fdopen(fd,'rb');fd=None
        return stream,meta.st_size
    finally:
        if fd is not None:os.close(fd)


class DashboardApp:
    """Pure request router for offline tests and the fixed HTTP adapter."""
    def __init__(self,hub,auth,*,origin='http://127.0.0.1:8765',clock=time.monotonic):
        self.hub,self.auth,self.origin,self.clock=hub,auth,origin,clock
        self.host=urlsplit(origin).netloc
        self.sessions={};self.failures=[]

    def _response(self,status,value,headers=None):
        raw=value if isinstance(value,bytes) else _json(value)
        if len(raw)>MAX_RESPONSE:raise DashboardError('E_REPORT_TOO_LARGE')
        base={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',
              'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
              'X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"}
        base.update(headers or {})
        return Response(status,raw,base)

    def _operation(self,value):
        value=_safe_hub(value)
        if isinstance(value,dict) and value.get('ok') is False:
            return self._response(409,{'error':'E_OPERATION'})
        return self._response(200,value)

    def _backup(self,data):
        if set(data)!={'passphrase','confirmation'}:raise DashboardError('E_BACKUP_INPUT')
        phrase,confirmation=data['passphrase'],data['confirmation']
        if (not isinstance(phrase,str) or not isinstance(confirmation,str) or
            not 16<=len(phrase)<=256 or len(confirmation)>256 or
            any(ord(c)<32 or ord(c)==127 for c in phrase) or
            not hmac.compare_digest(phrase.encode('utf-8'),confirmation.encode('utf-8'))):
            raise DashboardError('E_BACKUP_INPUT')
        try:result=self.hub.create_backup(phrase)
        finally:data.clear();phrase=confirmation=None
        if not isinstance(result,dict) or result.get('ok') is not True:
            return self._response(409,{'error':'E_OPERATION'})
        ident=result.get('backup_id')
        if (not isinstance(ident,str) or re.fullmatch(r'[0-9a-f]{32}',ident) is None or
            result.get('filename')!=ident+'.tar.gpg' or
            not isinstance(result.get('sha256'),str) or re.fullmatch(r'[0-9a-fA-F]{64}',result['sha256']) is None or
            type(result.get('bytes')) is not int or not 0<result['bytes']<=MAX_BACKUP or
            result.get('integrity_verified') is not True):
            raise DashboardError('E_BACKUP_RESULT')
        allowed=('ok','backup_id','filename','sha256','bytes','integrity_verified','restore_verified',
                 'files_restored','local_only','offhost_copy_verified','system_backup_complete','missing_components')
        return self._response(200,_safe_hub({key:result[key] for key in allowed if key in result}))

    def _download(self,ident):
        if re.fullmatch(r'[0-9a-f]{32}',ident) is None:raise DashboardError('E_BACKUP_ID')
        path=self.hub.backup_download(ident)
        stream,size=_open_backup(path)
        response=self._response(200,b'',{'Content-Type':'application/octet-stream',
            'Content-Disposition':'attachment; filename="'+ident+'.tar.gpg"'})
        response.stream=stream;response.content_length=size
        return response

    def _session(self,headers):
        now=self.clock()
        self.sessions={key:value for key,value in self.sessions.items()
                       if now-value['created']<SESSION_SECONDS and now-value['seen']<IDLE_SECONDS}
        try:
            jar=SimpleCookie();jar.load(headers.get('cookie',''))
            value=jar[COOKIE].value
            session=self.sessions.get(value)
            if session:session['seen']=now
            return value,session
        except Exception:return None,None

    def dispatch(self,method,target,headers=(),body=b'',*,client_ip='127.0.0.1'):
        try:
            if not ipaddress.ip_address(client_ip).is_loopback:return self._response(403,{'error':'E_LOCAL_ONLY'})
            pairs=list(headers.items()) if hasattr(headers,'items') else list(headers)
            if sum(len(str(k))+len(str(v)) for k,v in pairs)>8192:return self._response(400,{'error':'E_HEADERS'})
            values={}
            for key,value in pairs:
                key=str(key).lower()
                if key in values and key in ('host','origin','content-length','content-type','cookie','transfer-encoding','x-csrf-token'):
                    return self._response(400,{'error':'E_HEADERS'})
                values[key]=str(value)
            if values.get('host')!=self.host:return self._response(403,{'error':'E_HOST'})
            if 'origin' in values and values['origin']!=self.origin:return self._response(403,{'error':'E_ORIGIN'})
            if values.get('sec-fetch-site')=='cross-site':return self._response(403,{'error':'E_ORIGIN'})
            if 'transfer-encoding' in values:return self._response(400,{'error':'E_BODY'})
            if len(body)>MAX_BODY:return self._response(413,{'error':'E_BODY'})
            url=urlsplit(target)
            if url.scheme or url.netloc or url.fragment:return self._response(400,{'error':'E_PATH'})
            path=url.path
            if method=='GET' and path=='/' and not url.query:
                nonce=secrets.token_urlsafe(24)
                content=HTML.replace('__NONCE__',nonce).encode('utf-8')
                return self._response(200,content,{'Content-Type':'text/html; charset=utf-8',
                    'Content-Security-Policy':"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
            if method not in ('GET','POST'):return self._response(405,{'error':'E_METHOD'})
            data={}
            if method=='POST':
                if url.query or values.get('origin')!=self.origin:return self._response(403,{'error':'E_ORIGIN'})
                if values.get('content-type','').split(';')[0].strip().lower()!='application/json':
                    return self._response(415,{'error':'E_CONTENT_TYPE'})
                try:data=json.loads(body)
                except Exception:return self._response(400,{'error':'E_JSON'})
                if not isinstance(data,dict):return self._response(400,{'error':'E_JSON'})
            if method=='POST' and path=='/api/login':
                now=self.clock();self.failures=[value for value in self.failures if now-value<60]
                if len(self.failures)>=5:return self._response(429,{'error':'E_LOGIN_RATE'},{'Retry-After':'60'})
                if set(data)!={'username','password'} or not self.auth.verify(data.get('username'),data.get('password')):
                    self.failures.append(now);return self._response(401,{'error':'E_LOGIN'})
                self.failures.clear()
                if len(self.sessions)>=32:self.sessions.pop(next(iter(self.sessions)))
                ident=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32)
                self.sessions[ident]={'created':now,'seen':now,'csrf':csrf}
                return self._response(200,{'ok':True,'csrf_token':csrf},
                    {'Set-Cookie':COOKIE+'='+ident+'; HttpOnly; SameSite=Strict; Path=/; Max-Age='+str(SESSION_SECONDS)})
            ident,session=self._session(values)
            if session is None:return self._response(401,{'error':'E_LOGIN_REQUIRED'})
            if method=='GET':
                query=parse_qs(url.query,keep_blank_values=True,strict_parsing=True)
                if path=='/api/session' and not query:return self._response(200,{'ok':True,'csrf_token':session['csrf']})
                if path=='/api/overview' and not query:return self._response(200,_safe_hub(self.hub.overview()))
                if path=='/api/relationships':
                    if set(query)-{'limit','offset'} or any(len(v)!=1 for v in query.values()):raise DashboardError('E_PAGE')
                    limit=int(query.get('limit',['50'])[0]);offset=int(query.get('offset',['0'])[0])
                    if not 1<=limit<=200 or not 0<=offset<=50000:raise DashboardError('E_PAGE')
                    return self._response(200,{'relationships':_safe_hub(self.hub.relationships(limit=limit,offset=offset))})
                if path.startswith('/api/backups/') and not query:
                    return self._download(path[len('/api/backups/'):])
                if path in ('/api/report.json','/api/report.csv') and not query:
                    report=_safe_hub(self.hub.report())
                    if path.endswith('.csv'):
                        return self._response(200,csv_report(report),{'Content-Type':'text/csv; charset=utf-8',
                            'Content-Disposition':'attachment; filename="sentinel-report.csv"'})
                    return self._response(200,report,{'Content-Disposition':'attachment; filename="sentinel-report.json"'})
                return self._response(404,{'error':'E_NOT_FOUND'})
            if not hmac.compare_digest(values.get('x-csrf-token',''),session['csrf']):
                return self._response(403,{'error':'E_CSRF'})
            if path=='/api/logout' and not data:
                self.sessions.pop(ident,None)
                return self._response(200,{'ok':True},{'Set-Cookie':COOKIE+'=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})
            if path=='/api/tick' and not data:return self._operation(self.hub.tick())
            if path=='/api/test-alert' and not data:return self._operation(self.hub.test_alert())
            if path=='/api/backups':return self._backup(data)
            if path=='/api/network/onboard':
                if (set(data)!={'label'} or not isinstance(data['label'],str) or
                    not 1<=len(data['label'].strip())<=80 or any(ord(c)<32 for c in data['label'])):
                    raise DashboardError('E_NETWORK_PROFILE')
                return self._operation(self.hub.onboard_network(data['label'].strip()))
            if path=='/api/network/activate':
                if (set(data)!={'network_id'} or not isinstance(data['network_id'],str) or
                    re.fullmatch(r'[A-Za-z0-9_-]{1,128}',data['network_id']) is None):
                    raise DashboardError('E_NETWORK_PROFILE')
                return self._operation(self.hub.activate_network(data['network_id']))
            if path=='/api/recognize':
                if set(data)!={'review_id','expected_app_context_key'}:raise DashboardError('E_DECISION')
                self._id(data['review_id']);self._key(data['expected_app_context_key'])
                return self._operation(self.hub.recognize(data['review_id'],
                    expected_app_context_key=data['expected_app_context_key']))
            if path=='/api/decide':
                if set(data)!={'review_id','decision','duration_seconds','until_revoked','expected_relationship_key'}:
                    raise DashboardError('E_DECISION')
                self._id(data['review_id']);self._key(data['expected_relationship_key'])
                if data['decision'] not in ('approve','reject','revoke') or type(data['until_revoked']) is not bool:
                    raise DashboardError('E_DECISION')
                duration=data['duration_seconds']
                if data['until_revoked']:
                    if duration is not None:raise DashboardError('E_DURATION')
                elif type(duration) is not int or not 1<=duration<=86400:raise DashboardError('E_DURATION')
                return self._operation(self.hub.decide(data['review_id'],data['decision'],duration,
                    until_revoked=data['until_revoked'],expected_relationship_key=data['expected_relationship_key']))
            return self._response(404,{'error':'E_NOT_FOUND'})
        except DashboardError:
            return self._response(400,{'error':'E_REQUEST'})
        except Exception:
            return self._response(400,{'error':'E_OPERATION'})

    @staticmethod
    def _id(value):
        if not isinstance(value,str) or re.fullmatch(r'C[0-9]{4,}',value) is None:raise DashboardError('E_ID')

    @staticmethod
    def _key(value):
        if (not isinstance(value,str) or not 1<=len(value)<=1024 or
            any(ord(c)<32 or ord(c)==127 for c in value)):raise DashboardError('E_KEY')


def create_server(hub,auth_path=DEFAULT_AUTH,*,host='127.0.0.1',port=8765):
    if host!='127.0.0.1' or type(port) is not int or not 0<=port<=65535:
        raise DashboardError('E_LOOPBACK_BIND')
    auth=PasswordAuth(auth_path)
    class Handler(BaseHTTPRequestHandler):
        server_version='Sentinel';sys_version=''
        def log_message(self,*_):pass
        def send_error(self,code,message=None,explain=None):
            self.send_response(code);self.send_header('Content-Type','application/json')
            self.send_header('Cache-Control','no-store');self.send_header('Connection','close')
            self.end_headers();self.close_connection=True
            try:self.wfile.write(b'{"error":"E_HTTP"}')
            except OSError:pass
        def setup(self):
            super().setup();self.connection.settimeout(5)
        def _handle(self):
            lengths=self.headers.get_all('Content-Length',[])
            try:
                if len(lengths)>1 or self.headers.get('Transfer-Encoding'):
                    raise ValueError
                length=int(lengths[0]) if lengths else 0
                if length<0 or length>MAX_BODY:raise ValueError
                body=self.rfile.read(length) if length else b''
                if len(body)!=length:raise ValueError
                response=self.server.app.dispatch(self.command,self.path,list(self.headers.raw_items()),
                                                  body,client_ip=self.client_address[0])
            except Exception:
                response=Response(400,b'{"error":"E_HTTP"}',{'Content-Type':'application/json','Cache-Control':'no-store'})
            try:
                self.send_response(response.status)
                for key,value in response.headers.items():self.send_header(key,value)
                self.send_header('Content-Length',str(response.content_length if response.stream is not None else len(response.body)))
                self.send_header('Connection','close');self.end_headers();self.close_connection=True
                if response.stream is None:self.wfile.write(response.body)
                else:
                    remaining=response.content_length
                    while remaining:
                        chunk=response.stream.read(min(65536,remaining))
                        if not chunk:break
                        self.wfile.write(chunk);remaining-=len(chunk)
            except OSError:pass
            finally:
                if response.stream is not None:response.stream.close()
        do_GET=do_POST=do_PUT=do_DELETE=do_HEAD=_handle
    server=HTTPServer((host,port),Handler)
    server.app=DashboardApp(hub,auth,origin='http://127.0.0.1:'+str(server.server_port))
    return server


def serve(hub,auth_path=DEFAULT_AUTH,*,host='127.0.0.1',port=8765):
    with create_server(hub,auth_path,host=host,port=port) as server:server.serve_forever()


HTML=r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel</title>
<style nonce="__NONCE__">
:root{font:15px system-ui;color:#14243a;background:#f3f6fa}body{margin:0}header{background:#12233c;color:white;padding:20px 5%;display:flex;align-items:center;gap:18px}header strong{font-size:24px}header span{color:#b8c9de}main{max-width:1200px;margin:26px auto;padding:0 24px}section,.card{background:white;border:1px solid #dce4ee;border-radius:12px;padding:22px;margin-bottom:20px}h1{font-size:24px;margin:0 0 14px}h2{font-size:18px;margin:0 0 14px}p{line-height:1.5}.muted{color:#5b6c82}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin-bottom:20px}.grid .card{margin:0}.metric{font-size:29px;font-weight:650;margin:6px 0}.card h2{font-size:13px;color:#5b6c82;font-weight:600;margin-bottom:10px}.card small{display:block;line-height:1.5}input,select,button{font:inherit;border:1px solid #bdcbdc;border-radius:7px;padding:9px 12px;max-width:100%;box-sizing:border-box}button{cursor:pointer;background:#2058a5;color:white;border-color:#2058a5}button.secondary{background:white;color:#2058a5}button:disabled{opacity:.45;cursor:default}label{display:block;margin:14px 0 6px}form{max-width:380px}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:16px 0}a{color:#2058a5}.status{padding:10px 0;min-height:22px}.error{color:#a51d2d}table{width:100%;border-collapse:collapse;text-align:left}th,td{padding:12px 8px;border-bottom:1px solid #e3e9f0;vertical-align:top}th{font-size:12px;color:#60728a;text-transform:uppercase}td{word-break:break-word}td small{display:block;margin-top:5px}.empty{padding:28px;color:#5b6c82;text-align:center}pre{white-space:pre-wrap;word-break:break-word;background:#f3f6fa;padding:14px;border-radius:8px;font-size:12px}.badge{display:inline-block;background:#edf3fc;color:#28558d;border-radius:20px;padding:4px 9px;font-size:12px}.good{color:#176443}.attention{color:#975315}.badge.good{background:#e8f5ed}.badge.attention{background:#fff2dc}dialog{max-width:780px;width:85%;border:1px solid #cad5e4;border-radius:12px;padding:24px}dialog::backdrop{background:#10213988}[hidden]{display:none!important}.tablewrap{overflow:auto}.right{margin-left:auto}.notice{border-left:4px solid #5688bd;padding:12px;background:#eef5fd}#login{max-width:460px;margin:60px auto}small{color:#61728b}dl{display:grid;grid-template-columns:minmax(110px,150px) 1fr;gap:10px;margin:18px 0}dt{color:#5b6c82}dd{margin:0;overflow-wrap:anywhere}summary{cursor:pointer;color:#2058a5;padding:8px 0}li{margin:9px 0;line-height:1.5}#networkcontext{font-weight:600}#reportnote{font-size:13px}#reviewmessage{margin-bottom:0}@media(max-width:600px){header{flex-wrap:wrap}header span{font-size:13px}main{padding:0 12px}section,.card{padding:16px}.metric{font-size:24px}dialog{width:90%;padding:16px}dl{grid-template-columns:1fr;gap:5px}dd{margin-bottom:9px}}
</style></head><body>
<header><strong>Sentinel</strong><span>Local monitoring &amp; connection review</span><button id="logout" class="secondary right" hidden>Log out</button></header>
<main>
<section id="login"><h1>Sign in</h1><p class="muted">Use your separate Sentinel dashboard account. This interface is available only on this computer.</p><form id="loginform"><label for="username">Username</label><input id="username" autocomplete="username" value="sentinel" required><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" required><div class="toolbar"><button>Sign in</button></div></form><div id="loginmessage" class="status error" role="status"></div></section>
<div id="dashboard" hidden>
<div class="toolbar"><h1>Overview</h1><button id="refresh" class="secondary right">Refresh</button><button id="tick" class="secondary">Collect now</button><button id="testalert" class="secondary">Test alert</button></div>
<div id="message" class="status" role="status"></div><div id="overview" class="grid"></div>
<section><h2>Coverage &amp; alerts</h2><p id="delivery"></p><p id="collection"></p><div id="services" hidden><h2>Existing local services</h2><p id="servicestatus"></p><ul id="servicechecks"></ul><p><a href="http://127.0.0.1:3000" target="_blank" rel="noopener noreferrer">Open existing AdGuard Home</a> <small>Separate login. The current DNS test is local to this computer; household DNS use is not implied.</small></p></div><ul id="gaps"></ul><details><summary>What this monitoring can see</summary><ul id="limits"></ul></details></section>
<section><h2>Network profile</h2><p id="networkcontext" class="notice"></p><p id="networkhint" class="muted"></p><div class="toolbar"><select id="networks" aria-label="Existing network profiles"></select><button id="activate" class="secondary">Activate selected profile</button></div><div class="toolbar"><input id="networklabel" maxlength="80" placeholder="Label for a new network" aria-label="New network label"><button id="onboard" class="secondary">Create fresh profile</button></div><small>Network context uses local hints, not proof of identity. Choose profiles deliberately. A fresh profile starts without inherited endpoint permissions. These actions do not change network settings or scan devices.</small></section>
<section><h2>Encrypted backup</h2><p>Create an encrypted copy of Sentinel's hub data and configuration with a separate backup passphrase. Keep that passphrase somewhere you can recover it.</p><form id="backupform" autocomplete="off"><label for="backupphrase">Backup passphrase</label><input id="backupphrase" type="password" autocomplete="new-password" minlength="16" maxlength="256" required><label for="backupconfirm">Confirm backup passphrase</label><input id="backupconfirm" type="password" autocomplete="new-password" minlength="16" maxlength="256" required><div class="toolbar"><button id="createbackup">Create encrypted backup</button></div></form><p id="backupstatus" role="status"></p><a id="backupdownload" hidden>Download encrypted backup</a><details id="backupdetails" hidden><summary>Backup verification &amp; limitations</summary><pre id="backupmetadata"></pre></details><small>This creates a local copy. A download is not proof of an off-host copy. Encrypted integrity inspection is not a restore test. This is not a complete system backup; the result lists excluded components. No restore operation runs here.</small></section>
<section><div class="toolbar"><h2>Connection review</h2><span class="badge">Individual decisions</span><a href="/api/report.json" class="right">Download JSON</a><a href="/api/report.csv">Download CSV</a></div><p id="reportnote" class="muted">CSV/JSON summaries include up to 200 relationships and may be shortened by the response size limit. Use the queue pages to review every relationship. Counts represent observations and review items, not sessions or traffic volume.</p><p class="notice">Recognizing an application does not approve its destinations. Unknown transport or incomplete identity needs more evidence. Decisions record permission; they do not block traffic or change firewall rules.</p><div class="tablewrap"><table><thead><tr><th>Record</th><th>Application / actor</th><th>Endpoint / kind</th><th>Status</th><th></th></tr></thead><tbody id="rows"></tbody></table></div><div class="toolbar"><button id="previous" class="secondary">Previous</button><span id="page"></span><button id="next" class="secondary">Next</button></div></section>
</div>
<dialog id="reviewdialog"><h2 id="reviewtitle">Review connection</h2><dl id="reviewsummary"></dl><p id="reviewmessage" class="notice"></p><details id="technical"><summary>Technical evidence &amp; exact identity keys</summary><pre id="details"></pre></details><p>A decision covers only this application context, actor, transport, address and port. It does not authorize future destinations.</p><label for="duration">Decision duration</label><select id="duration"><option value="">Choose explicitly…</option><option value="3600">1 hour</option><option value="86400">24 hours</option><option value="until">Until explicitly revoked</option></select><div class="toolbar"><button id="approve">Approve exact endpoint</button><button id="reject" class="secondary">Not approved</button><button id="revoke" class="secondary">Revoke approval</button></div><div class="toolbar"><button id="recognize" class="secondary">Recognize captured identity only</button><button id="close" class="secondary right">Close</button></div><small>Identity recognition is a separate historical fact. New endpoints still require review.</small></dialog>
</main>
<script nonce="__NONCE__">
'use strict';
let csrf='',offset=0,records=[],selected=null,currentOverview=null;
const $=id=>document.getElementById(id);
function text(node,value){node.textContent=String(value??'');}
function element(tag,value,className=''){const node=document.createElement(tag);text(node,value);if(className)node.className=className;return node;}
function message(value,bad=false){text($('message'),value);$('message').className='status'+(bad?' error':'');}
function age(value){if(!Number.isFinite(value))return 'not yet collected';if(value<60)return 'less than a minute ago';if(value<3600)return Math.floor(value/60)+' min ago';if(value<86400)return Math.floor(value/3600)+' hours ago';return Math.floor(value/86400)+' days ago';}
function timestamp(value){if(!Number.isFinite(value))return 'Not recorded';const date=new Date(value*1000);return Number.isNaN(date.getTime())?'Not recorded':date.toLocaleString();}
function appName(record){return record.evidence?.application_name||record.evidence?.executable_name||'Application not attributed';}
function endpoint(record){const address=record.destination_address;const shown=address===null||address===undefined?'Destination not reported':String(address).includes(':')?'['+address+']':address;return shown+(record.destination_port!==null&&record.destination_port!==undefined?':'+record.destination_port:'')+' / '+(record.transport==='unknown'?'transport not reported':record.transport);}
function kindName(kind){return {native_tcp:'Observed TCP peer',router_record:'Retained router record',listener:'Local listening socket'}[kind]||'Observed relationship';}
function statusName(status){return {pending:'Needs review',pending_more_evidence:'Needs more evidence',approved:'Approved exact endpoint',not_approved:'Not approved'}[status]||'Status unavailable';}
function approvalReady(record){return record.approval_available!==false&&Boolean(record.destination_address)&&record.transport!=='unknown'&&record.status!=='pending_more_evidence'&&record.evidence?.endpoint_complete!==false&&record.evidence?.app_identity_complete!==false;}
function recognitionReady(record){return Boolean(record.app_context_key)&&record.kind!=='router_record'&&record.evidence?.app_identity_complete!==false&&(record.evidence?.app_identity_complete===true||record.approval_available===true);}
function card(title,value,note,tone=''){const node=element('div','','card');node.append(element('h2',title),element('p',value,'metric '+tone),element('small',note));$('overview').append(node);}
const gapNames={E_HOST_BINDING:'This computer does not match the saved monitoring identity.',E_NETWORK_REVIEW_REQUIRED:'The current network context needs a deliberate profile review.',E_LINUX_PARTIAL:'Some local TCP or application evidence could not be collected.',E_LINUX_COLLECTION:'The local TCP collection did not complete.',E_ROUTER_STALE_OR_GAP:'Router evidence is missing, stale or incomplete.',E_INTAKE_OR_CAP:'Some observations could not enter the review queue. Stored records were preserved.',E_NOTICE_CAP_OR_STATE:'Some review notices have not reached the alert outbox.',E_ALERTS_NOT_CONFIGURED:'Notifications are not configured.',E_ALERT_DELIVERY:'Notification delivery needs attention.',E_ALERT_HANDOFF:'Some notifications could not enter or leave the outbox.'};
function renderOverview(overview){
 currentOverview=overview;
 const counts=overview.queue?.counts||{},last=overview.last_collection,network=overview.network||{},alerts=last?.alerts||{};
 $('overview').replaceChildren();
 card('Monitoring',overview.ok?'Running':'Needs attention',overview.collection_stale?'The last collection is missing or stale.':'Review coverage and delivery below.',overview.ok?'good':'attention');
 card('Needs review',counts.pending??0,'Exact endpoint decisions pending.');
 card('More evidence',counts.pending_more_evidence??0,'Approval unavailable until the evidence is complete.');
 card('Approved',counts.approved??0,(counts.not_approved??0)+' marked not approved. No automatic blocking.','good');
 const queued=(alerts.outbox?.pending??0)+(alerts.outbox?.posting??0)+(alerts.outbox?.accepted??0);
 const deliveryNames={verified:'Server readback verified',pending:'Waiting or retrying',blocked:'Delivery needs attention',not_yet_tested:'Not yet verified',not_configured:'Not configured',degraded:'Delivery needs attention'};
 text($('delivery'),'Notifications: '+(deliveryNames[alerts.delivery_state]||'No delivery result yet')+'. '+(alerts.outbox?.verified??0)+' verified, '+queued+' awaiting readback or retry. Server readback does not confirm that you saw the notification.');
 text($('collection'),'Last collection: '+timestamp(last?.checked_at)+' ('+age(overview.collection_age_seconds)+'). '+(overview.application_recognition_count??0)+' captured application identities recognized.');
 const services=overview.existing_services?.alerts_and_adguard;$('services').hidden=!services;
 if(services){
  const serviceDelivery=deliveryNames[services.delivery_state]||'Delivery status unavailable';
  text($('servicestatus'),services.available?(services.fresh?'Recent service status':'Service status is stale')+' — '+(services.health_state==='healthy'?'checks healthy':['down','unhealthy'].includes(services.health_state)?'checks need attention':'health not yet confirmed')+'. '+serviceDelivery+'.':'Existing service status is unavailable.');
  $('servicechecks').replaceChildren();
  const labels={docker_service:'Docker service',adguard_container:'AdGuard container',dns_udp:'Local DNS over UDP',dns_tcp:'Local DNS over TCP',adguard_ui:'AdGuard web interface',adguard_web:'AdGuard web interface',outbox_filesystem:'Alert outbox storage',router_collector_fresh:'Router collector freshness'};
  for(const [key,value]of Object.entries(services.checks||{}))if(typeof value==='boolean')$('servicechecks').append(element('li',(value?'✓ ':'! ')+(labels[key]||key.replaceAll('_',' '))+': '+(value?'passed':'needs attention')));
 }
 $('gaps').replaceChildren();
 for(const gap of (last?.gaps||[]))$('gaps').append(element('li',gapNames[gap.code]||'A monitoring source needs attention. Review its technical evidence.'));
 const linux=last?.sources?.linux;
 if(linux?.unattributed>0)$('gaps').append(element('li',linux.unattributed+' local observations have no complete application attribution.'));
 if(last?.sources?.router?.configured===false)$('gaps').append(element('li','Router evidence is not configured for this profile. Local TCP snapshots continue separately.'));
 if(!$('gaps').children.length)$('gaps').append(element('li',last?'No operational gap was reported in the last collection. Coverage limits still apply.':'The first collection has not completed.'));
 $('limits').replaceChildren();for(const limit of (overview.coverage_limits||[]))$('limits').append(element('li',limit));
 const matches=network.context_matches===true;
 text($('networkcontext'),(network.label||'No active profile')+' — '+(matches?'Context matches saved hints':'Profile review required'));
 $('networkcontext').className='notice '+(matches?'good':'attention');
 text($('networkhint'),network.current_gateway_hint?'Current gateway hint: '+network.current_gateway_hint+'. Hints do not authenticate a network.':'Current gateway hints are unavailable.');
 $('networks').replaceChildren();for(const profile of (overview.profiles||[])){const option=element('option',profile.label||'Unnamed profile');option.value=profile.network_id;$('networks').append(option);}
 if(network.network_id)$('networks').value=network.network_id;
 $('activate').disabled=!$('networks').options.length;
 text($('reportnote'),'CSV/JSON summaries include up to 200 of '+(overview.queue?.relationships??0)+' relationships and may be shortened by the response size limit; each JSON summary reports truncation. Use the queue pages to review every relationship. Counts are observations and review items, not sessions or traffic volume.');
}
function renderRows(){
 $('rows').replaceChildren();
 for(const record of records){
  const tr=document.createElement('tr');
  const id=element('td',record.review_id);id.append(element('small',record.recently_observed?'Recently observed':'Historical observation'));tr.append(id);
  const app=element('td',appName(record));app.append(element('small',record.application_recognized?'✓ Captured identity recognized':'○ Identity not recognized'),element('small',record.actor_key));tr.append(app);
  const peer=element('td',endpoint(record));peer.append(element('small',kindName(record.kind)));tr.append(peer);
  const state=document.createElement('td');state.append(element('span',statusName(record.status),'badge '+(record.status==='approved'?'good':record.status==='pending_more_evidence'?'attention':'')));if(record.status==='approved')state.append(element('small',record.decision?.until_revoked?'Until explicitly revoked':'Expires '+timestamp(record.decision?.expires_at)));tr.append(state);
  const cell=document.createElement('td'),button=element('button','Review','secondary');button.onclick=()=>openRecord(record);cell.append(button);tr.append(cell);$('rows').append(tr);
 }
 if(!records.length){const tr=document.createElement('tr'),cell=element('td',offset?'No records on this page. Use Previous to return.':'No relationships have been recorded for this profile.','empty');cell.colSpan=5;tr.append(cell);$('rows').append(tr);}
 text($('page'),'Records '+(records.length?offset+1:0)+'–'+(offset+records.length)+' of '+(currentOverview?.queue?.relationships??'…'));
 $('previous').disabled=offset===0;$('next').disabled=records.length<50;
}
async function api(path,data){
 const options={credentials:'same-origin',headers:{}};
 if(data!==undefined){options.method='POST';options.headers={'Content-Type':'application/json','X-CSRF-Token':csrf};options.body=JSON.stringify(data);}
 const response=await fetch(path,options);let value;try{value=await response.json();}catch{throw Error('The local service returned an invalid response.');}
 if(response.status===401){showLogin();throw Error('Sign in to continue.');}
 if(!response.ok){const errors={E_OPERATION:'The operation did not complete. Refresh the record and review its coverage gaps.',E_REQUEST:'Check the selected scope and duration.',E_LOGIN:'The username or password was not accepted.',E_LOGIN_RATE:'Too many attempts. Wait one minute and try again.'};throw Error(errors[value.error]||'The local operation did not complete. Refresh and try again.');}return value;
}
function showLogin(){$('login').hidden=false;$('dashboard').hidden=true;$('logout').hidden=true;$('reviewdialog').close();$('backupphrase').value='';$('backupconfirm').value='';csrf='';selected=null;}
function showDashboard(){$('login').hidden=true;$('dashboard').hidden=false;$('logout').hidden=false;text($('loginmessage'),'');}
async function refresh(){const overview=await api('/api/overview');renderOverview(overview);const result=await api('/api/relationships?limit=50&offset='+offset);records=result.relationships||[];renderRows();}
function openRecord(record){
 selected=record;text($('reviewtitle'),'Review '+record.review_id);$('reviewsummary').replaceChildren();
 const values=[['Application',appName(record)],['Identity',record.application_recognized?'Captured identity recognized':'Not recognized'],['Actor',record.actor_key],['Endpoint',endpoint(record)],['Observation',kindName(record.kind)],['Status',statusName(record.status)],['First / last seen',timestamp(record.first_seen)+' / '+timestamp(record.last_seen)],['Sightings',record.sightings??'Not recorded'],['Binary SHA-256',record.evidence?.executable_sha256||record.evidence?.binary_sha256||'Not available']];
 for(const [label,value]of values)$('reviewsummary').append(element('dt',label),element('dd',value));
 text($('details'),JSON.stringify(record,null,2));$('technical').open=false;$('duration').value='';
 const contextOK=currentOverview?.network?.context_matches===true,ready=approvalReady(record);
 $('approve').disabled=!contextOK||!ready;$('reject').disabled=!contextOK;$('revoke').disabled=!contextOK||record.status!=='approved';
 $('recognize').disabled=!contextOK||record.application_recognized===true||!recognitionReady(record);
 text($('reviewmessage'),!contextOK?'Review and select the current network profile before recording decisions.':!ready?'This relationship needs more evidence. Exact endpoint approval is unavailable. Marking it not approved does not block traffic.':'Review this exact relationship. Application recognition and endpoint permission are separate decisions.');
 $('reviewdialog').showModal();
}
async function decide(decision){
 if(!selected)return;const duration=$('duration').value;
 if(!duration){message('Choose an explicit decision duration.',true);return;}
 const action={approve:'Approve',reject:'Record as not approved',revoke:'Revoke approval for'}[decision];
 if(!confirm(action+' only '+selected.review_id+' ('+appName(selected)+') at '+endpoint(selected)+'?'))return;
 try{await api('/api/decide',{review_id:selected.review_id,decision,duration_seconds:duration==='until'?null:Number(duration),until_revoked:duration==='until',expected_relationship_key:selected.relationship_key});$('reviewdialog').close();await refresh();message('Decision recorded. No firewall settings changed.');}catch(error){message(error.message,true);}
}
$('loginform').onsubmit=async event=>{event.preventDefault();try{const result=await api('/api/login',{username:$('username').value,password:$('password').value});$('password').value='';csrf=result.csrf_token;showDashboard();await refresh();}catch(error){$('password').value='';text($('loginmessage'),error.message);}};
$('logout').onclick=async()=>{try{await api('/api/logout',{});}finally{showLogin();}};
$('refresh').onclick=()=>refresh().catch(error=>message(error.message,true));
$('tick').onclick=async()=>{try{$('tick').disabled=true;await api('/api/tick',{});await refresh();message('Collection completed. Review coverage and notification delivery above.');}catch(error){message(error.message,true);}finally{$('tick').disabled=false;}};
$('testalert').onclick=async()=>{if(!confirm('Send a generic test alert to the already configured notification destination?'))return;try{await api('/api/test-alert',{});await refresh();message('Test queued. Wait for server readback and personally confirm receipt in your notification client.');}catch(error){message(error.message,true);}};
$('backupform').onsubmit=async event=>{
 event.preventDefault();const data={passphrase:$('backupphrase').value,confirmation:$('backupconfirm').value};
 if(data.passphrase.length<16||data.passphrase!==data.confirmation){text($('backupstatus'),'Enter matching backup passphrases with at least 16 characters.');data.passphrase=data.confirmation='';return;}
 if(!confirm('Create a local encrypted Sentinel backup and inspect its integrity? This does not restore files or create a verified off-host copy.')){data.passphrase=data.confirmation='';return;}
 $('backupphrase').value='';$('backupconfirm').value='';$('createbackup').disabled=true;$('backupdownload').hidden=true;$('backupdetails').hidden=true;text($('backupstatus'),'Creating and inspecting the encrypted backup. This may take a moment…');
 try{const result=await api('/api/backups',data);if(!/^[0-9a-f]{32}$/.test(result.backup_id)||result.integrity_verified!==true)throw Error('The local backup did not return a verified result.');
  $('backupdownload').href='/api/backups/'+result.backup_id;$('backupdownload').hidden=false;$('backupdetails').hidden=false;text($('backupmetadata'),JSON.stringify(result,null,2));text($('backupstatus'),'Encrypted backup created and integrity inspected. Download it, then arrange a separate off-host copy and restore test.');
 }catch(error){text($('backupstatus'),error.message);}finally{data.passphrase=data.confirmation='';$('backupphrase').value='';$('backupconfirm').value='';$('createbackup').disabled=false;}
};
$('onboard').onclick=async()=>{const label=$('networklabel').value.trim();if(!label){message('Enter a label for the current network.',true);return;}if(!confirm('Create a fresh profile for the current network context, without inherited permissions?'))return;try{await api('/api/network/onboard',{label});$('networklabel').value='';offset=0;await refresh();message('Fresh profile created. Review its context and coverage gaps.');}catch(error){message(error.message,true);}};
$('activate').onclick=async()=>{const network_id=$('networks').value;if(!network_id||!confirm('Activate the selected profile only if its context matches the current network?'))return;try{await api('/api/network/activate',{network_id});offset=0;await refresh();message('Profile selection completed.');}catch(error){message(error.message,true);}};
$('previous').onclick=()=>{offset=Math.max(0,offset-50);refresh().catch(error=>message(error.message,true));};$('next').onclick=()=>{offset+=50;refresh().catch(error=>message(error.message,true));};
$('approve').onclick=()=>decide('approve');$('reject').onclick=()=>decide('reject');$('revoke').onclick=()=>decide('revoke');$('close').onclick=()=>$('reviewdialog').close();
$('recognize').onclick=async()=>{if(!selected||!confirm('Recognize only this captured application identity? New destinations will still need review.'))return;try{await api('/api/recognize',{review_id:selected.review_id,expected_app_context_key:selected.app_context_key});$('reviewdialog').close();await refresh();message('Identity recognized separately. No endpoint permission granted.');}catch(error){message(error.message,true);}};
setInterval(()=>{if(!$('dashboard').hidden&&!$('reviewdialog').open&&document.visibilityState==='visible'&&!['INPUT','SELECT'].includes(document.activeElement?.tagName))refresh().catch(error=>message(error.message,true));},30000);
(async()=>{try{const session=await api('/api/session');csrf=session.csrf_token;showDashboard();await refresh();}catch{showLogin();}})();
</script></body></html>'''

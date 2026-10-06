import base64, hmac, json, os, secrets, sqlite3, subprocess, time, uuid, urllib.parse, threading, re, io, html, socket, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB=os.environ.get('VPNSTAN_WEB','/opt/vpnstan/web')
DB=os.environ.get('VPNSTAN_DB','/data/vpnstan.db')
PANEL_PORT=int(os.environ.get('VPNSTAN_PANEL_PORT','3000'))
USERNAME=os.environ.get('VPNSTAN_USERNAME','admin')
PASSWORD=os.environ.get('VPNSTAN_PASSWORD','admin')
DEFAULT_HOST=os.environ.get('VPNSTAN_NODE_HOST','')
DEFAULT_PORT=int(os.environ.get('VPNSTAN_NODE_PORT','443'))
DEFAULT_PATH=os.environ.get('VPNSTAN_WS_PATH','/ws')
SUB_PATH=os.environ.get('VPNSTAN_SUB_PATH','sub')
XRAY_BIN=os.environ.get('XRAY_BIN','/usr/local/bin/xray')
XRAY_CONFIG=os.environ.get('XRAY_CONFIG','/data/xray.json')
XRAY_INBOUND_PORT=int(os.environ.get('XRAY_INBOUND_PORT','10000'))
XRAY_VMESS_PORT=int(os.environ.get('XRAY_VMESS_PORT','10001'))
DEFAULT_VMESS_PATH=os.environ.get('VPNSTAN_VMESS_PATH','/vmess')
DEFAULT_XHTTP_PATH=os.environ.get('VPNSTAN_XHTTP_PATH','/xhttp')
DEFAULT_GRPC_SERVICE=os.environ.get('VPNSTAN_GRPC_SERVICE','vpnstan')
DEFAULT_HTTPUPGRADE_PATH=os.environ.get('VPNSTAN_HTTPUPGRADE_PATH','/upgrade')
XRAY_API_ADDR=os.environ.get('XRAY_API_ADDR','127.0.0.1:10085')
PANEL_VERSION='v25.0'
DNS_LISTEN_HOST=os.environ.get('VPNSTAN_DNS_LISTEN_HOST','127.0.0.1')
DNS_LISTEN_PORT=int(os.environ.get('VPNSTAN_DNS_LISTEN_PORT','5353'))
SESSIONS={}
XRAY_PROC=None
SESSION_USERS={}

XRAY_LOCK=threading.RLock()

# The panel provides its own per-client DNS-over-HTTPS endpoint.
# Public DNS addresses are intentionally not exposed as a client DNS profile.

def dns_profile_for(value):
    return {"name":"Private VPNSTAN DNS","primary":"","secondary":"","dot":""}


def dns_usage_add(client_id, nbytes):
    if not client_id or nbytes <= 0: return
    c=db(); c.execute("INSERT INTO traffic(client_id,upload,download,last_seen,raw_upload,raw_download) VALUES(?,?,?,?,?,?) ON CONFLICT(client_id) DO UPDATE SET upload=upload+excluded.upload,last_seen=excluded.last_seen", (client_id,int(nbytes),0,int(time.time()),0,0)); c.commit(); c.close()

def resolve_dns_wire(query):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.settimeout(4)
    try:
        sock.sendto(query,(DNS_LISTEN_HOST,DNS_LISTEN_PORT))
        data,_=sock.recvfrom(65535)
        return data
    finally:
        sock.close()

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    os.makedirs(os.path.dirname(DB),exist_ok=True)
    c=db()
    c.execute('''CREATE TABLE IF NOT EXISTS clients(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, uuid TEXT NOT NULL UNIQUE,
      sub_id TEXT NOT NULL, gb REAL NOT NULL, days INTEGER NOT NULL,
      created_at INTEGER NOT NULL, expiry_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)''')
    # Older releases incorrectly made sub_id UNIQUE; migrate it so one subscription can contain multiple clients.
    try:
        unique_sub = False
        for idx in c.execute("PRAGMA index_list(clients)").fetchall():
            if int(idx[2] or 0):
                cols = [r[2] for r in c.execute("PRAGMA index_info(%s)" % idx[1]).fetchall()]
                if cols == ['sub_id']:
                    unique_sub = True
                    break
        if unique_sub:
            c.execute('''CREATE TABLE clients_migrate(
              id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, uuid TEXT NOT NULL UNIQUE,
              sub_id TEXT NOT NULL, gb REAL NOT NULL, days INTEGER NOT NULL,
              created_at INTEGER NOT NULL, expiry_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
              protocol TEXT NOT NULL DEFAULT 'vless', transport TEXT NOT NULL DEFAULT 'ws', dns_server TEXT NOT NULL DEFAULT '1.1.1.1',
              wg_private_key TEXT NOT NULL DEFAULT '', wg_address TEXT NOT NULL DEFAULT '',
              dns_token TEXT NOT NULL DEFAULT '')''')
            cols_now=[r[1] for r in c.execute("PRAGMA table_info(clients)").fetchall()]
            extra=[x for x in ('protocol','transport','dns_server','wg_private_key','wg_address','dns_token') if x in cols_now]
            if len(extra)==6:
                c.execute('''INSERT INTO clients_migrate(id,name,uuid,sub_id,gb,days,created_at,expiry_at,enabled,protocol,transport,dns_server,wg_private_key,wg_address,dns_token)
                             SELECT id,name,uuid,sub_id,gb,days,created_at,expiry_at,enabled,protocol,transport,dns_server,wg_private_key,wg_address,dns_token FROM clients''')
            elif len(extra)==5:
                c.execute('''INSERT INTO clients_migrate(id,name,uuid,sub_id,gb,days,created_at,expiry_at,enabled,protocol,dns_server,wg_private_key,wg_address,dns_token)
                             SELECT id,name,uuid,sub_id,gb,days,created_at,expiry_at,enabled,protocol,dns_server,wg_private_key,wg_address,dns_token FROM clients''')
            else:
                c.execute('''INSERT INTO clients_migrate(id,name,uuid,sub_id,gb,days,created_at,expiry_at,enabled)
                             SELECT id,name,uuid,sub_id,gb,days,created_at,expiry_at,enabled FROM clients''')
            c.execute('DROP TABLE clients')
            c.execute('ALTER TABLE clients_migrate RENAME TO clients')
    except sqlite3.Error as e:
        print('CLIENTS SCHEMA MIGRATION:', e, flush=True)

    c.execute('''CREATE TABLE IF NOT EXISTS panel_users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
      enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS traffic(
      client_id INTEGER PRIMARY KEY, upload INTEGER NOT NULL DEFAULT 0,
      download INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0,
      raw_upload INTEGER NOT NULL DEFAULT 0, raw_download INTEGER NOT NULL DEFAULT 0)''')
    for col in ('raw_upload','raw_download'):
        try: c.execute(f'ALTER TABLE traffic ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0')
        except sqlite3.OperationalError: pass
    for col,typ,default in [('protocol','TEXT',"'vless'"),('transport','TEXT',"'ws'"),('dns_server','TEXT',"'1.1.1.1'"),('wg_private_key','TEXT',"''"),('wg_address','TEXT',"''"),('dns_token','TEXT',"''")]:
        try: c.execute(f'ALTER TABLE clients ADD COLUMN {col} {typ} NOT NULL DEFAULT {default}')
        except sqlite3.OperationalError: pass
    # Seed the first administrator from environment variables, only on first startup.
    if c.execute('SELECT COUNT(*) FROM panel_users').fetchone()[0] == 0:
        import hashlib
        ph=hashlib.sha256(PASSWORD.encode()).hexdigest()
        c.execute('INSERT INTO panel_users(username,password_hash,role,enabled,created_at) VALUES(?,?,?,?,?)',(USERNAME,ph,'admin',1,int(time.time())))
    defaults={'node_host':DEFAULT_HOST,'node_port':str(DEFAULT_PORT),'ws_path':DEFAULT_PATH,'vmess_path':DEFAULT_VMESS_PATH,'xhttp_path':DEFAULT_XHTTP_PATH,'grpc_service':DEFAULT_GRPC_SERVICE,'httpupgrade_path':DEFAULT_HTTPUPGRADE_PATH,'sub_path':SUB_PATH,
              'panel_title':'vpnstan','support_url':'','dns_server':'1.1.1.1,1.0.0.1','dns_profile':'cloudflare','wg_endpoint':'','wg_server_public_key':'','announce':'اشتراک vpnstan — برای دریافت آخرین کانفیگ، لینک اشتراک را به‌روزرسانی کنید.','update_interval':'1','theme':'dark'}
    for k,v in defaults.items(): c.execute('INSERT OR IGNORE INTO settings(k,v) VALUES(?,?)',(k,v))
    c.commit(); c.close()

def hash_password(v):
    import hashlib
    return hashlib.sha256(str(v).encode()).hexdigest()

def current_user(h):
    for x in h.headers.get('Cookie','').split(';'):
        if x.strip().startswith('vpnstan_session='):
            t=x.strip().split('=',1)[1]
            if SESSIONS.get(t,0)>time.time():
                uid=SESSION_USERS.get(t)
                if uid:
                    c=db(); r=c.execute('SELECT id,username,role,enabled FROM panel_users WHERE id=?',(uid,)).fetchone(); c.close()
                    if r and r['enabled']: return r
    return None

def is_admin(h):
    u=current_user(h); return bool(u and u['role']=='admin')

def auth_error(h):
    return send(h,401,{'success':False,'msg':'نیاز به ورود دارید'})

def settings():
    c=db(); rows=c.execute('SELECT k,v FROM settings').fetchall(); c.close(); return {r['k']:r['v'] for r in rows}

def set_setting(k,v):
    c=db(); c.execute('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v',(k,str(v))); c.commit(); c.close()

def active_clients():
    c=db(); rows=c.execute('SELECT * FROM clients WHERE enabled=1 ORDER BY id').fetchall(); c.close(); now=int(time.time()); return [r for r in rows if r['expiry_at']==0 or r['expiry_at']>now]

def traffic_for(cid):
    c=db(); r=c.execute('SELECT upload,download,last_seen FROM traffic WHERE client_id=?',(cid,)).fetchone(); c.close()
    return {'upload':int(r['upload']) if r else 0,'download':int(r['download']) if r else 0,'last_seen':int(r['last_seen']) if r else 0}

def fmt_bytes(n):
    n=max(0,int(n)); units=['B','KB','MB','GB','TB']
    x=float(n); i=0
    while x>=1024 and i<len(units)-1: x/=1024; i+=1
    return f'{x:.2f} {units[i]}' if i else f'{int(x)} B'

def fmt_date(ts):
    if not ts:return 'نامحدود'
    return time.strftime('%Y/%m/%d %H:%M',time.localtime(ts))

def collect_xray_stats():
    # Poll Xray's cumulative per-user counters every second and persist deltas.
    if not os.path.exists(XRAY_BIN): return
    try:
        proc=subprocess.run([XRAY_BIN,'api','statsquery','--server='+XRAY_API_ADDR],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
        if proc.returncode != 0:
            try:
                with open('/data/xray-stats.log','ab') as f: f.write((proc.stderr or b'')[-4000:]+b"\n")
            except Exception: pass
            return
        data=json.loads((proc.stdout or b'{}').decode('utf-8','replace'))
    except Exception as e:
        try:
            with open('/data/xray-stats.log','a',encoding='utf-8') as f: f.write(str(e)+'\n')
        except Exception: pass
        return
    stats={}
    for item in data.get('stat',[]) or []:
        name=str(item.get('name','')); value=int(item.get('value',0) or 0)
        m=re.match(r'^user>>>(.+)>>>traffic>>>(uplink|downlink)$',name)
        if m:
            email,kind=m.group(1),m.group(2)
            stats.setdefault(email,{'upload':0,'download':0})['upload' if kind=='uplink' else 'download']=value
    if not stats:
        try:
            with open('/data/xray-stats.log','a',encoding='utf-8') as f:
                f.write(time.strftime('%Y-%m-%d %H:%M:%S ')+'statsquery returned no user counters\\n')
        except Exception: pass
        return
    c=db(); now=int(time.time())
    rows=c.execute('SELECT id,uuid FROM clients').fetchall()
    for r in rows:
        st=stats.get('vpnstan-'+r['uuid']) or stats.get(r['uuid'])
        if not st: continue
        old=c.execute('SELECT upload,download,last_seen,raw_upload,raw_download FROM traffic WHERE client_id=?',(r['id'],)).fetchone()
        if not old:
            total_u=0; total_d=0; delta_u=0; delta_d=0; last=0
        else:
            raw_u=int(old['raw_upload']); raw_d=int(old['raw_download'])
            delta_u=(st['upload']-raw_u) if st['upload']>=raw_u else st['upload']
            delta_d=(st['download']-raw_d) if st['download']>=raw_d else st['download']
            total_u=int(old['upload'])+max(0,delta_u); total_d=int(old['download'])+max(0,delta_d)
            last=now if delta_u+delta_d>0 else int(old['last_seen'])
        c.execute("INSERT INTO traffic(client_id,upload,download,last_seen,raw_upload,raw_download) VALUES(?,?,?,?,?,?) ON CONFLICT(client_id) DO UPDATE SET upload=excluded.upload,download=excluded.download,last_seen=excluded.last_seen,raw_upload=excluded.raw_upload,raw_download=excluded.raw_download",(r['id'],total_u,total_d,last,st['upload'],st['download']))
    c.commit()
    rows=c.execute('SELECT id,gb,expiry_at,enabled FROM clients').fetchall()
    for r in rows:
        if not r['enabled'] or (r['expiry_at'] and r['expiry_at']<=now): continue
        tr=c.execute('SELECT upload,download FROM traffic WHERE client_id=?',(r['id'],)).fetchone()
        if tr and int(tr['upload'])+int(tr['download']) >= float(r['gb'])*1024**3:
            c.execute('UPDATE clients SET enabled=0 WHERE id=?',(r['id'],))
    c.commit(); c.close()

def write_xray_config():
    os.makedirs(os.path.dirname(XRAY_CONFIG),exist_ok=True)
    s=settings()
    paths={
        'vless_ws':s.get('ws_path','/ws') or '/ws',
        'vmess_ws':s.get('vmess_path','/vmess') or '/vmess',
        'trojan_ws':s.get('trojan_ws_path','/trojan') or '/trojan',
        'vless_xhttp':s.get('xhttp_path','/xhttp') or '/xhttp',
        'vmess_xhttp':s.get('vmess_xhttp_path','/vmess-xhttp') or '/vmess-xhttp',
        'trojan_xhttp':s.get('trojan_xhttp_path','/trojan-xhttp') or '/trojan-xhttp',
        'vless_grpc':s.get('grpc_path','/grpc') or '/grpc',
        'vmess_grpc':s.get('vmess_grpc_path','/vmess-grpc') or '/vmess-grpc',
        'trojan_grpc':s.get('trojan_grpc_path','/trojan-grpc') or '/trojan-grpc',
        'vless_httpupgrade':s.get('httpupgrade_path','/upgrade') or '/upgrade',
        'vmess_httpupgrade':s.get('vmess_httpupgrade_path','/vmess-upgrade') or '/vmess-upgrade',
        'trojan_httpupgrade':s.get('trojan_httpupgrade_path','/trojan-upgrade') or '/trojan-upgrade',
    }
    svc=s.get('grpc_service','vpnstan') or 'vpnstan'
    rows=active_clients(); inbounds=[]
    base=XRAY_INBOUND_PORT
    transports=['ws','xhttp','grpc','httpupgrade']
    protocols=['vless','vmess','trojan']
    port_map={(proto,transport):base+(pi*4+ti) for pi,proto in enumerate(protocols) for ti,transport in enumerate(transports)}
    # One inbound per protocol/transport keeps Xray's protocol parser unambiguous.
    idx=0
    for proto in protocols:
        for transport in transports:
            selected=[r for r in rows if (r['protocol'] or 'vless')==proto and (r['transport'] or 'ws')==transport]
            if not selected: continue
            clients=[]
            if proto in ('vless','vmess'):
                for r in selected:
                    item={'id':r['uuid'],'email':'vpnstan-'+r['uuid'],'level':0}
                    if proto=='vmess': item['alterId']=0
                    clients.append(item)
                settings_obj={'clients':clients,'decryption':'none'} if proto=='vless' else {'clients':clients}
            else:
                clients=[{'password':r['uuid'],'email':'vpnstan-'+r['uuid'],'level':0} for r in selected]
                settings_obj={'clients':clients}
            path=paths[f'{proto}_{transport}']
            stream={'network':transport,'security':'none'}
            if transport=='ws': stream['wsSettings']={'path':path}
            elif transport=='xhttp': stream['xhttpSettings']={'path':path,'mode':'auto'}
            elif transport=='grpc': stream['grpcSettings']={'serviceName':svc,'multiMode':False}
            elif transport=='httpupgrade': stream['httpupgradeSettings']={'path':path}
            inbounds.append({'tag':f'{proto}-{transport}','listen':'127.0.0.1','port':port_map[(proto,transport)],'protocol':proto,'settings':settings_obj,'streamSettings':stream})
    api_port=int(XRAY_API_ADDR.rsplit(':',1)[-1])
    api_inbound={'tag':'api','listen':'127.0.0.1','port':api_port,'protocol':'dokodemo-door','settings':{'address':'127.0.0.1'}}
    cfg={'log':{'loglevel':'warning'},'api':{'tag':'api','services':['StatsService']},'stats':{},
      'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True,'statsUserOnline':True}},'system':{'statsInboundUplink':True,'statsInboundDownlink':True,'statsOutboundUplink':True,'statsOutboundDownlink':True}},
      'inbounds':[api_inbound]+inbounds,
      'routing':{'rules':[{'type':'field','inboundTag':['api'],'outboundTag':'api'}]},
      'outbounds':[{'protocol':'freedom','tag':'direct'},{'protocol':'blackhole','tag':'block'}]}
    tmp=XRAY_CONFIG+'.tmp'
    with open(tmp,'w',encoding='utf-8') as f: json.dump(cfg,f,ensure_ascii=False,indent=2)
    os.replace(tmp,XRAY_CONFIG); return cfg

def restart_xray():
    global XRAY_PROC
    with XRAY_LOCK:
        collect_xray_stats()
        write_xray_config()
        if XRAY_PROC and XRAY_PROC.poll() is None:
            XRAY_PROC.terminate()
            try: XRAY_PROC.wait(timeout=3)
            except subprocess.TimeoutExpired: XRAY_PROC.kill()
        try:
            test=subprocess.run([XRAY_BIN,'run','-test','-c',XRAY_CONFIG],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=8)
            if test.returncode != 0:
                print('XRAY CONFIG TEST FAILED:',test.stdout.decode('utf-8','replace')[-4000:],flush=True)
                return
            log=open('/data/xray.log','ab')
            XRAY_PROC=subprocess.Popen([XRAY_BIN,'run','-c',XRAY_CONFIG],stdout=log,stderr=log)
            time.sleep(0.5)
            if XRAY_PROC.poll() is not None: print('XRAY FAILED — see /data/xray.log',flush=True)
            else: print('Xray started with',len(active_clients()),'active client(s)',flush=True)
        except Exception as e: print('XRAY START ERROR:',e,flush=True)

def collector_loop():
    while True:
        try:
            with XRAY_LOCK:
                c1=db(); before=[(r['id'],int(r['enabled'])) for r in c1.execute('SELECT id,enabled FROM clients').fetchall()]; c1.close()
                collect_xray_stats()
                c2=db(); after=[(r['id'],int(r['enabled'])) for r in c2.execute('SELECT id,enabled FROM clients').fetchall()]; c2.close()
                if before != after:
                    write_xray_config()
                    if XRAY_PROC and XRAY_PROC.poll() is None:
                        XRAY_PROC.terminate()
                        try: XRAY_PROC.wait(timeout=3)
                        except subprocess.TimeoutExpired: XRAY_PROC.kill()
                        log=open('/data/xray.log','ab')
                        globals()['XRAY_PROC']=subprocess.Popen([XRAY_BIN,'run','-c',XRAY_CONFIG],stdout=log,stderr=log)
        except Exception as e: print('STATS ERROR:',e,flush=True)
        time.sleep(1)

def authed(h):
    return current_user(h) is not None

def body(h):
    n=int(h.headers.get('Content-Length','0')); return json.loads(h.rfile.read(n) or b'{}')

def send(h,status,obj,extra=None):
    raw=json.dumps(obj,ensure_ascii=False).encode(); h.send_response(status); h.send_header('Content-Type','application/json; charset=utf-8'); h.send_header('Content-Length',str(len(raw))); h.send_header('Cache-Control','no-store')
    for k,v in (extra or {}).items(): h.send_header(k,v)
    h.end_headers(); h.wfile.write(raw)

def clean_host(v): return (v or '').split(':',1)[0].strip()
def host_for(h,s):
    return (clean_host(s.get('node_host')) or clean_host(os.environ.get('RAILWAY_PUBLIC_DOMAIN')) or clean_host(h.headers.get('X-Forwarded-Host') or h.headers.get('Host','')))


def wg_config_for(h,r,s):
    """Return a WireGuard client profile when a real server endpoint/key is configured.
    The panel can generate a client keypair, but the endpoint must expose a real UDP
    WireGuard server; Railway HTTP ingress alone is not sufficient.
    """
    if (r['protocol'] or '').lower()!='wireguard':
        return ''
    endpoint=(s.get('wg_endpoint') or '').strip()
    server_pub=(s.get('wg_server_public_key') or '').strip()
    if not endpoint or not server_pub:
        return '# WireGuard endpoint/server public key is not configured in Settings'
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        private=X25519PrivateKey.generate()
        priv=private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        pub=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        import base64 as _b64
        priv_b64=_b64.b64encode(priv).decode(); pub_b64=_b64.b64encode(pub).decode()
    except Exception:
        priv_b64=base64.b64encode(secrets.token_bytes(32)).decode(); pub_b64=''
    addr=(r['wg_address'] or '10.66.0.2/32').strip()
    dns=(s.get('dns_server') or '1.1.1.1').split(',')[0].strip()
    return ('[Interface]\n'
            f'PrivateKey = {priv_b64}\nAddress = {addr}\nDNS = {dns}\n\n'
            '[Peer]\n'
            f'PublicKey = {server_pub}\nEndpoint = {endpoint}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n')

def link_for(h,r,s):
    proto=(r['protocol'] if 'protocol' in r.keys() else 'vless') or 'vless'
    host=host_for(h,s); name=urllib.parse.quote(r['name']); port=int(s.get('node_port','443'))
    if proto=='wireguard': return wg_config_for(h,r,s)
    if proto=='dns':
        token=r['dns_token'] or ''
        return f'https://{host}/doh/{token}' if token else ''
    transport=(r['transport'] or 'ws').lower() if 'transport' in r.keys() else 'ws'
    paths={'ws':s.get('ws_path','/ws'),'xhttp':s.get('xhttp_path','/xhttp'),'grpc':s.get('grpc_path','/grpc'),'httpupgrade':s.get('httpupgrade_path','/upgrade')}
    path=paths.get(transport,'/ws') or '/ws'; svc=s.get('grpc_service','vpnstan') or 'vpnstan'
    if proto=='vmess':
        obj={'v':'2','ps':r['name'],'add':host,'port':str(port),'id':r['uuid'],'aid':'0','scy':'auto','net':transport,'type':'none','host':host,'path':path,'tls':'tls','sni':host}
        if transport=='grpc': obj['path']=svc; obj['type']='none'
        return 'vmess://'+base64.b64encode(json.dumps(obj,separators=(',',':'),ensure_ascii=False).encode()).decode()
    if proto=='trojan':
        q={'security':'tls','type':transport,'sni':host}
        if transport in ('ws','xhttp','httpupgrade'): q.update({'host':host,'path':path})
        if transport=='grpc': q['serviceName']=svc
        return f'trojan://{urllib.parse.quote(r["uuid"])}@{host}:{port}?{urllib.parse.urlencode(q,safe="/",quote_via=urllib.parse.quote)}#{name}'
    q={'encryption':'none','security':'tls','type':transport,'sni':host}
    if transport in ('ws','xhttp','httpupgrade'): q.update({'host':host,'path':path})
    if transport=='grpc': q['serviceName']=svc
    return f'vless://{r["uuid"]}@{host}:{port}?{urllib.parse.urlencode(q,safe="/",quote_via=urllib.parse.quote)}#{name}'

def client_data(h,r,s):
    now=int(time.time()); tr=traffic_for(r['id']); used=tr['upload']+tr['download']; total=int(float(r['gb'])*1024**3); remain=max(0,total-used)
    sub_host=host_for(h,s); proto=(r['protocol'] or 'vless').lower(); sub=(f'https://{sub_host}/dns-sub/{r["sub_id"]}' if proto=='dns' else f'https://{sub_host}/{s.get("sub_path","sub").strip("/")}/{r["sub_id"]}')
    online=(tr['last_seen'] and now-tr['last_seen']<=90)
    return {'id':r['id'],'name':r['name'],'protocol':r['protocol'] or 'vless','transport':r['transport'] if 'transport' in r.keys() else 'ws','uuid':r['uuid'],'subId':r['sub_id'],'gb':r['gb'],'days':r['days'],'createdAt':r['created_at'],'expiryAt':r['expiry_at'],'enabled':bool(r['enabled']),
            'upload':tr['upload'],'download':tr['download'],'used':used,'remaining':remain,'totalBytes':total,'lastSeen':tr['last_seen'],'online':bool(online),
            'remainingText':fmt_bytes(remain),'usedText':fmt_bytes(used),'totalText':fmt_bytes(total),'uploadText':fmt_bytes(tr['upload']),'downloadText':fmt_bytes(tr['download']),
            'expiryText':fmt_date(r['expiry_at']),'vless':link_for(h,r,s),'config':link_for(h,r,s),'subscription':sub,'dnsServer':f'https://{sub_host}/doh/{r["dns_token"]}' if (r['protocol'] or '')=='dns' and r['dns_token'] else '','dnsProfile':dns_profile_for('internal'),'dnsSubscription':f'https://{sub_host}/dns-sub/{r["sub_id"]}','dnsUrl':f'https://{sub_host}/doh/{r["dns_token"]}' if (r['protocol'] or '')=='dns' and r['dns_token'] else '','wireguardConfig':wg_config_for(h,r,s),'version':PANEL_VERSION}

def load_sub(h,sid):
    s=settings(); c=db(); rows=c.execute('SELECT * FROM clients WHERE sub_id=? AND enabled=1',(sid,)).fetchall(); c.close(); now=int(time.time())
    rows=[r for r in rows if r['expiry_at']==0 or r['expiry_at']>now]
    return s,rows

def sub_page(h,sid):
    with XRAY_LOCK:
        collect_xray_stats()
    s,rows=load_sub(h,sid)
    if not rows:
        h.send_response(404); h.send_header('Content-Type','text/html; charset=utf-8'); h.end_headers(); h.wfile.write('<h2>اشتراک پیدا نشد یا منقضی شده است.</h2>'.encode()); return
    title=html.escape(s.get('panel_title','VPNSTAN')); sid_safe=html.escape(sid)
    total=sum(int(float(r['gb'])*1024**3) for r in rows); trs=[traffic_for(r['id']) for r in rows]
    up=sum(x['upload'] for x in trs); down=sum(x['download'] for x in trs); used=up+down; remain=max(0,total-used); pct=min(100,(used/total*100) if total else 0)
    now=int(time.time()); exp=max((r['expiry_at'] for r in rows),default=0); last=max((x['last_seen'] for x in trs),default=0); online=any(x['last_seen'] and now-x['last_seen']<=90 for x in trs)
    status='آنلاین' if online else 'آفلاین'; status_cls='online' if online else ''
    sub_url=f'https://{host_for(h,s)}/{s.get("sub_path","sub").strip("/")}/{sid}'; sub_safe=html.escape(sub_url,quote=True); announce=html.escape(s.get('announce','')); support=html.escape(s.get('support_url',''),quote=True)
    cards=[]
    for i,(r,tr) in enumerate(zip(rows,trs),1):
        proto=(r['protocol'] or 'vless').upper(); transport=(r['transport'] or 'ws').upper(); link=html.escape(link_for(h,r,s),quote=True)
        ctotal=int(float(r['gb'])*1024**3); cused=tr['upload']+tr['download']; cpct=min(100,(cused/ctotal*100) if ctotal else 0); active=bool(tr['last_seen'] and now-tr['last_seen']<=90); cls='online' if active else ''; lab='آنلاین' if active else 'آفلاین'
        cards.append(f'''<article class="config-card"><div class="config-head"><div><span class="number">#{i}</span><strong>{html.escape(r['name'])}</strong><span class="tag">{proto}</span><span class="tag">{transport}</span></div><span class="mini-status {cls}">● {lab}</span></div><div class="config-meta"><span>مصرف <b>{fmt_bytes(cused)}</b> از {fmt_bytes(ctotal)}</span><span>انقضا <b>{html.escape(fmt_date(r['expiry_at']))}</b></span></div><div class="bar small"><i style="width:{cpct:.1f}%"></i></div><div class="config-stats"><span>↓ {fmt_bytes(tr['download'])}</span><span>↑ {fmt_bytes(tr['upload'])}</span><span>آخرین فعالیت: {fmt_date(tr['last_seen']) if tr['last_seen'] else 'ثبت نشده'}</span></div><div class="code" id="cfg{i}">{link}</div><button class="copy" onclick="copyText('cfg{i}',this)">کپی کانفیگ</button></article>''')
    cards_html=''.join(cards); qr=f'/qr/{html.escape(rows[0]["sub_id"],quote=True)}'
    page=f'''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#070b14"><title>{title} — اشتراک • V25</title><style>
:root{{--bg:#060912;--line:#22304a;--text:#eef4ff;--muted:#8fa0bb;--accent:#6685ff;--accent2:#8b6cff;--good:#36d99b}}*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 15% 0%,#18244a 0,transparent 34%),radial-gradient(circle at 90% 10%,#24174a 0,transparent 30%),var(--bg);color:var(--text);font-family:Tahoma,"Segoe UI",Arial,sans-serif;min-height:100vh}}.wrap{{max-width:980px;margin:auto;padding:28px 16px 60px}}.hero,.card{{background:linear-gradient(145deg,#101929ee,#0a111eee);border:1px solid var(--line);border-radius:24px;padding:20px;margin-bottom:16px;box-shadow:0 15px 45px #0005}}.hero{{background:linear-gradient(145deg,#121c30ee,#09101eee);padding:25px;border-color:#2a3855}}.top,.section-title,.config-head,.config-meta,.usage-line{{display:flex;justify-content:space-between;gap:12px;align-items:center}}.brand{{font-size:13px;color:#a9b9d3}}.brand b{{color:#fff;font-size:19px}}h1{{font-size:28px;margin:10px 0 5px}}h2{{font-size:17px;margin:0 0 15px}}.muted,.subid{{color:var(--muted);font-size:12px}}.subid{{direction:ltr;word-break:break-all}}.badge{{padding:8px 12px;border:1px solid #33425f;border-radius:999px;background:#111b2e;color:#a8b6ce;font-size:12px}}.badge.online,.mini-status.online{{color:var(--good)}}.overview{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.stat,.pill{{padding:15px;border-radius:17px;background:#080f1c;border:1px solid #1d2a40}}.stat span{{display:block;color:var(--muted);font-size:11px}}.stat b{{display:block;font-size:18px;margin-top:7px}}.bar{{height:10px;background:#1a263a;border-radius:99px;overflow:hidden;margin:15px 0 10px}}.bar i{{display:block;height:100%;border-radius:inherit;background:linear-gradient(90deg,var(--accent),var(--accent2));transition:width .5s}}.bar.small{{height:7px;margin:10px 0}}.usage-line{{color:var(--muted);font-size:11px}}.usage-line b,.config-meta b{{color:#e8efff}}.qr-layout{{display:grid;grid-template-columns:190px 1fr;gap:22px;align-items:center}}.qr-box{{background:#fff;border-radius:20px;padding:10px;width:190px;height:190px;box-shadow:0 15px 40px #0007}}.qr-box img{{width:100%;height:100%}}.sub-code,.code{{direction:ltr;text-align:left;word-break:break-all;font:12px/1.6 Consolas,monospace;background:#050811;border:1px solid #22304a;border-radius:14px;padding:12px;color:#bdd0ff}}.actions{{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}}button,.btn{{border:1px solid #7185ff;background:linear-gradient(135deg,#617aff,#7a62ff);color:#fff;border-radius:12px;padding:10px 15px;font-weight:800;cursor:pointer;text-decoration:none;font-family:inherit;font-size:12px}}.btn.secondary{{background:#121d31;border-color:#2b3a57}}.config-card{{background:#080f1b;border:1px solid #1d2a40;border-radius:18px;padding:16px;margin-top:10px}}.number{{color:#667895;font-size:11px}}.tag{{font-size:10px;padding:4px 7px;border-radius:7px;background:#18243a;color:#aebfe0;margin-right:5px}}.mini-status{{font-size:10px;color:#8b99b0}}.config-meta,.config-stats{{color:var(--muted);font-size:10px;margin-top:12px}}.config-stats{{display:flex;gap:8px;flex-wrap:wrap}}.config-stats span{{background:#0d1728;padding:6px 8px;border-radius:8px}}.code{{margin-top:12px;max-height:86px;overflow:auto;font-size:11px}}.copy{{margin-top:8px;padding:8px 12px}}.notice{{padding:13px 15px;border:1px dashed #30415e;border-radius:15px;background:#0b1526;color:#aebbd0;font-size:12px;line-height:1.8}}.footer{{text-align:center;color:#65758f;font-size:10px;padding-top:8px}}@media(max-width:720px){{.overview{{grid-template-columns:1fr 1fr}}.qr-layout{{grid-template-columns:1fr;text-align:center}}.qr-box{{margin:auto}}.top{{align-items:flex-start}}.config-head{{align-items:flex-start;flex-direction:column}}h1{{font-size:23px}}}}
</style></head><body><main class="wrap"><section class="hero"><div class="top"><div><div class="brand"><b>{title}</b> <span>• پنل اشتراک</span></div><h1>اشتراک شما</h1><div class="subid">{sid_safe}</div></div><span class="badge {status_cls}" id="status">● {status}</span></div></section><section class="card"><div class="section-title"><h2>وضعیت مصرف</h2><span class="muted" id="percent">{pct:.1f}% مصرف شده</span></div><div class="overview"><div class="stat"><span>حجم کل</span><b id="total">{fmt_bytes(total)}</b></div><div class="stat"><span>مصرف‌شده</span><b id="used">{fmt_bytes(used)}</b></div><div class="stat"><span>باقی‌مانده</span><b id="remaining">{fmt_bytes(remain)}</b></div><div class="stat"><span>انقضا</span><b id="expiry">{html.escape(fmt_date(exp))}</b></div></div><div class="bar"><i id="fill" style="width:{pct:.1f}%"></i></div><div class="usage-line"><span>آپلود <b id="upload">{fmt_bytes(up)}</b></span><span>دانلود <b id="download">{fmt_bytes(down)}</b></span></div></section><section class="card"><div class="section-title"><h2>لینک اشتراک</h2><span class="muted">یک لینک برای همه کانفیگ‌ها</span></div><div class="sub-code" id="sub">{sub_safe}</div><div class="actions"><button onclick="copyText('sub',this)">کپی لینک اشتراک</button><a class="btn secondary" href="{html.escape(sub_url,quote=True)}">باز کردن ساب</a></div></section><section class="card"><div class="qr-layout"><div class="qr-box"><img src="{qr}" alt="QR اشتراک"></div><div><h2>اتصال سریع</h2><p class="muted" style="line-height:2">QR را با کلاینت سازگار اسکن کنید. اگر چند کانفیگ دارید، بهتر است لینک اشتراک را وارد کنید.</p><div class="pill"><span>تعداد کانفیگ‌ها</span><b>{len(rows)}</b></div><div class="pill" style="margin-top:8px"><span>آخرین فعالیت</span><b id="last">{fmt_date(last) if last else 'ثبت نشده'}</b></div></div></div></section><section class="card"><div class="section-title"><h2>کانفیگ‌های این اشتراک</h2><span class="muted">{len(rows)} مورد</span></div>{cards_html}</section>{('<section class="notice">'+announce+'</section>') if announce else ''}{('<p><a class="btn secondary" href="'+support+'">پشتیبانی</a></p>') if support else ''}<div class="footer">VPNSTAN V25 • وضعیت مصرف به‌صورت خودکار به‌روزرسانی می‌شود</div></main><script>
function copyText(id,btn){{const t=document.getElementById(id).textContent.trim();navigator.clipboard.writeText(t).then(()=>{{const old=btn.textContent;btn.textContent='کپی شد ✓';setTimeout(()=>btn.textContent=old,1400)}})}}
async function live(){{try{{const r=await fetch('/sub-status/{html.escape(sid,quote=True)}',{{cache:'no-store'}});if(!r.ok)return;const d=await r.json();document.getElementById('used').textContent=d.usedText;document.getElementById('remaining').textContent=d.remainingText;document.getElementById('upload').textContent=d.uploadText;document.getElementById('download').textContent=d.downloadText;document.getElementById('percent').textContent=(Number(d.percent)||0).toFixed(1)+'% مصرف شده';document.getElementById('fill').style.width=Math.min(100,Number(d.percent)||0)+'%';const st=document.getElementById('status');st.textContent=d.online?'● آنلاین':'● آفلاین';st.classList.toggle('online',!!d.online);if(d.lastSeen)document.getElementById('last').textContent=new Date(d.lastSeen*1000).toLocaleString('fa-IR')}}catch(e){{}}}}live();setInterval(live,5000);
</script></body></html>'''
    raw=page.encode(); h.send_response(200); h.send_header('Content-Type','text/html; charset=utf-8'); h.send_header('Cache-Control','no-store'); h.send_header('Content-Length',str(len(raw))); h.end_headers(); h.wfile.write(raw)

def qr_svg(h,sid):
    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
        s,rows=load_sub(h,sid)
        if not rows:return send(h,404,{'error':'not found'})
        link=f'https://{host_for(h,s)}/{s.get("sub_path","sub").strip("/")}/{sid}'
        qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,box_size=8,border=2); qr.add_data(link); qr.make(fit=True)
        img=qr.make_image(image_factory=SvgPathImage); out=io.BytesIO(); img.save(out); raw=out.getvalue()
        h.send_response(200); h.send_header('Content-Type','image/svg+xml'); h.send_header('Cache-Control','no-store'); h.send_header('Content-Length',str(len(raw))); h.end_headers(); h.wfile.write(raw)
    except Exception as e: send(h,500,{'error':str(e)})

class H(BaseHTTPRequestHandler):
    def log_message(self,fmt,*a): print(fmt%a,flush=True)
    def do_HEAD(self):
        u=urllib.parse.urlparse(self.path); p=u.path
        if p.startswith('/sub/'):
            # Refresh Xray counters immediately before serving the subscription.
            with XRAY_LOCK:
                collect_xray_stats()
            sid=p.split('/')[-1]; s,rows=load_sub(self,sid)
            if not rows:self.send_response(404); self.end_headers(); return
            total=sum(int(float(r['gb'])*1024**3) for r in rows); up=sum(traffic_for(r['id'])['upload'] for r in rows); down=sum(traffic_for(r['id'])['download'] for r in rows); exp=max((r['expiry_at'] for r in rows),default=0); self.send_response(200); self.send_header('Subscription-Userinfo',f'upload={up}; download={down}; total={total}; expire={exp}'); self.send_header('Profile-Title',base64.b64encode(s.get('panel_title','vpnstan').encode()).decode()); self.send_header('Profile-Update-Interval','1'); self.send_header('Cache-Control','no-store, no-cache, must-revalidate'); self.end_headers(); return
        self.send_response(404); self.end_headers()
    def do_OPTIONS(self):
        p=urllib.parse.urlparse(self.path).path
        if p.startswith('/dns-query') or p.startswith('/doh/'):
            self.send_response(204); self.send_header('Access-Control-Allow-Origin','*'); self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS'); self.send_header('Access-Control-Allow-Headers','Content-Type,Accept'); self.end_headers(); return
        self.send_response(204); self.end_headers()
    def do_GET(self):
        u=urllib.parse.urlparse(self.path); p=u.path; q=urllib.parse.parse_qs(u.query)
        if p in ('/health','/api/health'): return send(self,200,{'ok':True,'name':'vpnstan','independent':True,'xray': bool(XRAY_PROC and XRAY_PROC.poll() is None)})
        if p.startswith('/sub/'):
            # Always take a fresh Xray stats snapshot before returning a subscription.
            with XRAY_LOCK:
                collect_xray_stats()
            sid=p.split('/')[-1]
            if q.get('html')==['1'] or 'text/html' in self.headers.get('Accept',''):
                return sub_page(self,sid)
            s,rows=load_sub(self,sid); links=[link_for(self,r,s) for r in rows]; enc=base64.b64encode('\n'.join(links).encode()).decode(); total=sum(int(float(r['gb'])*1024**3) for r in rows); up=sum(traffic_for(r['id'])['upload'] for r in rows); down=sum(traffic_for(r['id'])['download'] for r in rows); exp=max([r['expiry_at'] for r in rows],default=0)
            raw=enc.encode(); self.send_response(200); self.send_header('Content-Type','text/plain; charset=utf-8'); self.send_header('Subscription-Userinfo',f'upload={up}; download={down}; total={total}; expire={exp}'); self.send_header('Profile-Title',base64.b64encode(s.get('panel_title','vpnstan').encode()).decode()); self.send_header('Profile-Update-Interval','1'); self.send_header('Cache-Control','no-store, no-cache, must-revalidate'); self.send_header('Support-Url',s.get('support_url','')); self.send_header('Profile-Web-Page-Url',f'https://{host_for(self,s)}/{s.get("sub_path","sub").strip("/")}/{sid}?html=1&v=25'); self.send_header('Announce',base64.b64encode(s.get('announce','').encode()).decode()); self.send_header('Content-Disposition',f'inline; filename="{sid}.txt"'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw); return
        if p.startswith('/dns-query/') or p == '/dns-query' or p.startswith('/doh/'):
            if p.startswith('/doh/'):
                token=p.split('/')[-1]
            elif p.startswith('/dns-query/'):
                token=p.split('/')[-1]
            else:
                token=q.get('token',[''])[0]
            c=db(); r=c.execute('SELECT * FROM clients WHERE dns_token=? AND protocol="dns" AND enabled=1',(token,)).fetchone(); c.close()
            if not r or (r['expiry_at'] and r['expiry_at']<=int(time.time())):
                return send(self,404,{'error':'DNS اختصاصی پیدا نشد یا منقضی شده است'})
            tr=traffic_for(r['id']); total=int(float(r['gb'])*1024**3); used=tr['upload']+tr['download']
            if used >= total:
                return send(self,429,{'error':'حجم DNS این کاربر تمام شده است'})
            qbytes=b''
            if self.command=='POST':
                n=min(int(self.headers.get('Content-Length','0')),65535); qbytes=self.rfile.read(n)
            else:
                val=urllib.parse.parse_qs(u.query).get('dns',[''])[0]
                try: qbytes=base64.urlsafe_b64decode(val+'='*((4-len(val)%4)%4))
                except Exception: qbytes=b''
            if not qbytes or len(qbytes)>65535:
                return send(self,400,{'error':'invalid DNS query'})
            try: answer=resolve_dns_wire(qbytes)
            except Exception as e: return send(self,502,{'error':'DNS resolver unavailable','detail':str(e)})
            dns_usage_add(r['id'],len(qbytes)+len(answer))
            self.send_response(200); self.send_header('Content-Type','application/dns-message'); self.send_header('Cache-Control','no-store'); self.send_header('Access-Control-Allow-Origin','*'); self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS'); self.send_header('Content-Length',str(len(answer))); self.end_headers(); self.wfile.write(answer); return
        if p.startswith('/dns-sub/'):
            with XRAY_LOCK:
                collect_xray_stats()
            sid=p.split('/')[-1]; s,rows=load_sub(self,sid)
            if not rows or (rows[0]['protocol'] or '').lower()!='dns':return send(self,404,{'error':'DNS subscription not found or expired'})
            r=rows[0]; total=int(float(r['gb'])*1024**3); tr=traffic_for(r['id']); exp=r['expiry_at']; doh=f'https://{host_for(self,s)}/doh/{r["dns_token"]}'
            if 'text/html' in self.headers.get('Accept',''):
                self.send_response(302); self.send_header('Location',f'/dns/{r["sub_id"]}'); self.send_header('Cache-Control','no-store'); self.end_headers(); return
            raw=(doh+'\n').encode()
            self.send_response(200); self.send_header('Content-Type','text/plain; charset=utf-8'); self.send_header('Cache-Control','no-store, no-cache, must-revalidate'); self.send_header('Subscription-Userinfo',f'upload={tr["upload"]}; download={tr["download"]}; total={total}; expire={exp}'); self.send_header('Profile-Title',base64.b64encode((s.get('panel_title','vpnstan')+' DNS').encode()).decode()); self.send_header('Profile-Update-Interval','1'); self.send_header('Profile-Web-Page-Url',f'https://{host_for(self,s)}/dns/{r["sub_id"]}'); self.send_header('Content-Disposition',f'inline; filename="dns-{r["sub_id"]}.txt"'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw); return
        if p.startswith('/dns/'):
            sid=p.split('/')[-1]; s,rows=load_sub(self,sid)
            if not rows:return send(self,404,{'error':'not found'})
            r=rows[0]; d=client_data(self,r,s); title=html.escape(s.get('panel_title','vpnstan')); name=html.escape(r['name']);
            page=f'''<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Cache-Control" content="no-store"><title>{title} DNS</title><style>body{{margin:0;background:#0a1020;color:#eef3ff;font-family:Tahoma,Arial}}.wrap{{max-width:760px;margin:auto;padding:24px}}.card{{background:#111a2d;border:1px solid #263654;border-radius:20px;padding:24px;margin:14px 0}}.code{{direction:ltr;text-align:left;font:600 15px Consolas;word-break:break-all;background:#070d18;border:1px solid #263654;border-radius:14px;padding:16px}}.muted{{color:#9aabc7}}button{{border:0;border-radius:12px;padding:12px 18px;background:#6178ff;color:white;font-weight:700;cursor:pointer}}</style><div class=wrap><div class=card><div class=muted>VPNSTAN • DNS اختصاصی</div><h1>{name}</h1><p class=muted>این اشتراک فقط برای DNS-over-HTTPS اختصاصی همین کاربر است.</p><h3>لینک DNS اختصاصی</h3><div class=code id=doh>{d['dnsUrl']}</div><button onclick=copyDoh()>کپی لینک DNS</button></div><div class=card><b>حجم اختصاص‌داده‌شده: {d['totalText']}</b><p>مصرف‌شده: {d['usedText']}</p><p>باقی‌مانده: {d['remainingText']}</p><p>دانلود: {d['downloadText']}</p><p>آپلود/درخواست DNS: {d['uploadText']}</p><p>انقضا: {html.escape(d['expiryText'])}</p><p class=muted>DNSهای عمومی مثل 1.1.1.1 و 8.8.8.8 در این اشتراک استفاده نمی‌شوند. حجم فقط برای درخواست‌هایی که از این لینک اختصاصی عبور کنند محاسبه می‌شود.</p></div></div><script>function copyDoh(){{navigator.clipboard.writeText(document.getElementById('doh').textContent.trim()).then(()=>alert('کپی شد'))}}</script></html>'''.encode(); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(page))); self.end_headers(); self.wfile.write(page); return
        if p.startswith('/qr/'): return qr_svg(self,p.split('/')[-1])
        if p.startswith('/sub-status/'):
            sid=p.split('/')[-1]
            with XRAY_LOCK:
                collect_xray_stats()
            s,rows=load_sub(self,sid)
            if not rows:return send(self,404,{'error':'subscription not found'})
            total=sum(int(float(r['gb'])*1024**3) for r in rows)
            trs=[traffic_for(r['id']) for r in rows]; up=sum(x['upload'] for x in trs); down=sum(x['download'] for x in trs)
            used=up+down; remain=max(0,total-used); last=max((x['last_seen'] for x in trs),default=0)
            return send(self,200,{'upload':up,'download':down,'used':used,'remaining':remain,'total':total,'usedText':fmt_bytes(used),'remainingText':fmt_bytes(remain),'uploadText':fmt_bytes(up),'downloadText':fmt_bytes(down),'percent':round((used/total*100) if total else 0,2),'online':bool(last and int(time.time())-last<=90),'lastSeen':last})
        if p.startswith('/subjson/'):
            sid=p.split('/')[-1]; s,rows=load_sub(self,sid); out=[]; host=host_for(self,s); port=int(s.get('node_port','443')); svc=s.get('grpc_service','vpnstan') or 'vpnstan'
            for r in rows:
                proto=(r['protocol'] or 'vless'); transport=(r['transport'] or 'ws'); path={'ws':s.get('ws_path','/ws'),'xhttp':s.get('xhttp_path','/xhttp'),'grpc':s.get('grpc_path','/grpc'),'httpupgrade':s.get('httpupgrade_path','/upgrade')}.get(transport,'/ws')
                if proto=='vless':
                    ss={'network':transport,'security':'tls','tlsSettings':{'serverName':host}}
                    if transport=='ws': ss['wsSettings']={'path':path}
                    elif transport=='xhttp': ss['xhttpSettings']={'path':path,'mode':'auto'}
                    elif transport=='grpc': ss['grpcSettings']={'serviceName':svc,'multiMode':False}
                    else: ss['httpupgradeSettings']={'path':path}
                    out.append({'protocol':'vless','tag':r['name'],'settings':{'vnext':[{'address':host,'port':port,'users':[{'id':r['uuid'],'encryption':'none'}]}]},'streamSettings':ss})
                elif proto=='vmess':
                    ss={'network':transport,'security':'tls','tlsSettings':{'serverName':host}}
                    if transport=='ws': ss['wsSettings']={'path':path}
                    elif transport=='xhttp': ss['xhttpSettings']={'path':path,'mode':'auto'}
                    elif transport=='grpc': ss['grpcSettings']={'serviceName':svc,'multiMode':False}
                    else: ss['httpupgradeSettings']={'path':path}
                    out.append({'protocol':'vmess','tag':r['name'],'settings':{'vnext':[{'address':host,'port':port,'users':[{'id':r['uuid'],'alterId':0,'security':'auto'}]}]},'streamSettings':ss})
                elif proto=='trojan':
                    ss={'network':transport,'security':'tls','tlsSettings':{'serverName':host}}
                    if transport=='ws': ss['wsSettings']={'path':path}
                    elif transport=='xhttp': ss['xhttpSettings']={'path':path,'mode':'auto'}
                    elif transport=='grpc': ss['grpcSettings']={'serviceName':svc,'multiMode':False}
                    else: ss['httpupgradeSettings']={'path':path}
                    out.append({'protocol':'trojan','tag':r['name'],'settings':{'servers':[{'address':host,'port':port,'password':r['uuid']} ]},'streamSettings':ss})
            return send(self,200,out)
        if p=='/api/me':
            u=current_user(self); return send(self,200,{'authenticated':bool(u),'user':({'id':u['id'],'username':u['username'],'role':u['role']} if u else None)})
        if p=='/api/admin/users':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            c=db(); rows=c.execute('SELECT id,username,role,enabled,created_at FROM panel_users ORDER BY id').fetchall(); c.close()
            return send(self,200,{'success':True,'users':[dict(r) for r in rows]})
        if p=='/api/settings':
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            return send(self,200,{'success':True,'settings':settings()})
        if p=='/api/clients':
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            s=settings(); c=db(); rows=c.execute('SELECT * FROM clients ORDER BY id DESC').fetchall(); c.close(); return send(self,200,{'success':True,'clients':[client_data(self,r,s) for r in rows]})
        if p.startswith('/api/client/'):
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            try: cid=int(p.rsplit('/',1)[1])
            except: return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            c=db(); r=c.execute('SELECT * FROM clients WHERE id=?',(cid,)).fetchone(); c.close()
            if not r:return send(self,404,{'success':False,'msg':'کاربر پیدا نشد'})
            return send(self,200,{'success':True,'client':client_data(self,r,settings())})
        if p=='/api/system':
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            alive=bool(XRAY_PROC and XRAY_PROC.poll() is None)
            try: log=open('/data/xray.log','rb').read()[-6000:].decode('utf-8','replace')
            except: log=''
            return send(self,200,{'success':True,'xray':alive,'port':int(os.environ.get('PORT','8080')),'inboundPort':XRAY_INBOUND_PORT,'log':log})
        return self.static()
    def do_POST(self):
        p=urllib.parse.urlparse(self.path).path
        # DNS-over-HTTPS uses POST with Content-Type application/dns-message.
        # Handle it before panel authentication because the DNS token is the credential.
        if p.startswith('/dns-query/') or p == '/dns-query' or p.startswith('/doh/'):
            if p.startswith('/doh/'):
                token=p.split('/')[-1]
            elif p.startswith('/dns-query/'):
                token=p.split('/')[-1]
            else:
                token=q.get('token',[''])[0]
            c=db(); r=c.execute('SELECT * FROM clients WHERE dns_token=? AND protocol=\"dns\" AND enabled=1',(token,)).fetchone(); c.close()
            if not r or (r['expiry_at'] and r['expiry_at']<=int(time.time())):
                return send(self,404,{'error':'DNS profile not found or expired'})
            try:
                n=min(int(self.headers.get('Content-Length','0')),65535)
                qbytes=self.rfile.read(n)
            except Exception:
                return send(self,400,{'error':'invalid DNS query'})
            if not qbytes or len(qbytes)>65535:
                return send(self,400,{'error':'invalid DNS query'})
            try:
                answer=resolve_dns_wire(qbytes)
            except Exception as e:
                return send(self,502,{'error':'DNS resolver unavailable','detail':str(e)})
            dns_usage_add(r['id'],len(qbytes)+len(answer))
            self.send_response(200); self.send_header('Content-Type','application/dns-message'); self.send_header('Cache-Control','no-store'); self.send_header('Access-Control-Allow-Origin','*'); self.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS'); self.send_header('Content-Length',str(len(answer))); self.end_headers(); self.wfile.write(answer); return
        if p=='/api/login':
            try:d=body(self)
            except:return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            c=db(); r=c.execute('SELECT * FROM panel_users WHERE username=? AND enabled=1',(str(d.get('username','')).strip(),)).fetchone(); c.close()
            if r and hmac.compare_digest(r['password_hash'],hash_password(d.get('password',''))):
                t=secrets.token_urlsafe(32); SESSIONS[t]=time.time()+86400; SESSION_USERS[t]=r['id']; return send(self,200,{'success':True,'user':{'username':r['username'],'role':r['role']}},{'Set-Cookie':f'vpnstan_session={t}; Path=/; HttpOnly; SameSite=Lax'})
            return send(self,401,{'success':False,'msg':'نام کاربری یا رمز عبور اشتباه است'})
        if p=='/api/logout':
            for x in self.headers.get('Cookie','').split(';'):
                if x.strip().startswith('vpnstan_session='): SESSIONS.pop(x.strip().split('=',1)[1],None); SESSION_USERS.pop(x.strip().split('=',1)[1],None)
            return send(self,200,{'success':True},{'Set-Cookie':'vpnstan_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax'})
        if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
        if p=='/api/account/change':
            try:d=body(self); u=current_user(self); old=str(d.get('oldPassword','')); nu=str(d.get('username','')).strip(); np=str(d.get('newPassword',''))
            except:return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            c=db(); row=c.execute('SELECT * FROM panel_users WHERE id=?',(u['id'],)).fetchone()
            if not row or not hmac.compare_digest(row['password_hash'],hash_password(old)): c.close(); return send(self,400,{'success':False,'msg':'رمز فعلی اشتباه است'})
            if len(nu)<3 or len(np)<4: c.close(); return send(self,400,{'success':False,'msg':'نام کاربری حداقل ۳ و رمز حداقل ۴ کاراکتر باشد'})
            try:
                c.execute('UPDATE panel_users SET username=?,password_hash=? WHERE id=?',(nu,hash_password(np),u['id'])); c.commit(); c.close(); return send(self,200,{'success':True,'msg':'اطلاعات ورود تغییر کرد؛ دوباره وارد شوید'})
            except sqlite3.IntegrityError: c.close(); return send(self,409,{'success':False,'msg':'این نام کاربری قبلاً وجود دارد'})
        if p=='/api/admin/users/create':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:d=body(self); nu=str(d.get('username','')).strip(); np=str(d.get('password','')); role=str(d.get('role','user'))
            except:return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            if len(nu)<3 or len(np)<4 or role not in ('admin','user'): return send(self,400,{'success':False,'msg':'نام کاربری/رمز/نقش نامعتبر است'})
            c=db()
            try:c.execute('INSERT INTO panel_users(username,password_hash,role,enabled,created_at) VALUES(?,?,?,?,?)',(nu,hash_password(np),role,1,int(time.time()))); c.commit(); c.close(); return send(self,201,{'success':True})
            except sqlite3.IntegrityError:c.close(); return send(self,409,{'success':False,'msg':'این نام کاربری قبلاً وجود دارد'})
        if p.startswith('/api/admin/users/') and p.endswith('/toggle'):
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:uid=int(p.split('/')[4])
            except:return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            if current_user(self)['id']==uid:return send(self,400,{'success':False,'msg':'نمی‌توان اکانت فعلی را غیرفعال کرد'})
            c=db(); c.execute('UPDATE panel_users SET enabled=1-enabled WHERE id=?',(uid,)); c.commit(); c.close(); return send(self,200,{'success':True})
        if p.startswith('/api/admin/users/') and p.endswith('/delete'):
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:uid=int(p.split('/')[4])
            except:return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            if current_user(self)['id']==uid:return send(self,400,{'success':False,'msg':'اکانت فعلی را نمی‌توان حذف کرد'})
            c=db(); c.execute('DELETE FROM panel_users WHERE id=?',(uid,)); c.commit(); c.close(); return send(self,200,{'success':True})
        if p=='/api/settings':
            try:d=body(self); allowed={'node_host','node_port','ws_path','vmess_path','xhttp_path','grpc_service','grpc_path','httpupgrade_path','trojan_ws_path','trojan_xhttp_path','trojan_grpc_path','trojan_httpupgrade_path','vmess_xhttp_path','vmess_grpc_path','vmess_httpupgrade_path','sub_path','panel_title','support_url','announce','update_interval','wg_endpoint','wg_server_public_key','dns_server','dns_profile','theme'}
            except:return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            if 'node_port' in d:
                try: port=int(d['node_port']); assert 1<=port<=65535
                except:return send(self,400,{'success':False,'msg':'پورت نامعتبر است'})
            for k,v in d.items():
                if k in allowed:set_setting(k,str(v).strip())
            restart_xray(); return send(self,200,{'success':True,'settings':settings()})
        if p=='/api/clients/create':
            try:
                d=body(self); name=str(d.get('name','')).strip(); gb=float(d.get('gb',0)); days=int(d.get('days',0)); protocol=str(d.get('protocol','vless')).lower(); transport=str(d.get('transport','ws')).lower(); sub_count=int(d.get('subCount',1) or 1); st=settings(); dns_server=('internal' if protocol=='dns' else st.get('dns_server',''))
                if protocol not in ('vless','vmess','trojan','wireguard','dns') or transport not in ('ws','xhttp','grpc','httpupgrade') or (protocol in ('wireguard','dns') and transport!='ws') or not name or gb<=0 or days<=0 or len(name)>80 or sub_count<1 or sub_count>20: raise ValueError
                if protocol=='dns' and sub_count!=1: raise ValueError
            except:return send(self,400,{'success':False,'msg':'نام، حجم، مدت یا تعداد کانفیگ نامعتبر است'})
            now=int(time.time()); sub_id=secrets.token_urlsafe(18); rows=[]
            c=db()
            for i in range(sub_count):
                cname=name if sub_count==1 else f'{name}-{i+1:02d}'
                cuuid=str(uuid.uuid4()); dns_token=secrets.token_urlsafe(24) if protocol=='dns' else ''
                r=(cname,cuuid,sub_id,gb,days,now,now+days*86400,protocol,transport,dns_server,'','10.66.0.2/32',dns_token)
                c.execute('INSERT INTO clients(name,uuid,sub_id,gb,days,created_at,expiry_at,protocol,transport,dns_server,wg_private_key,wg_address,dns_token) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',r)
                rows.append(c.execute('SELECT * FROM clients WHERE uuid=?',(cuuid,)).fetchone())
            c.commit(); c.close(); restart_xray(); first=rows[0]
            return send(self,201,{'success':True,'count':sub_count,'subId':sub_id,'client':client_data(self,first,settings()),'clients':[client_data(self,r,settings()) for r in rows]})
        if p.startswith('/api/clients/') and p.endswith('/edit'):
            try:
                cid=int(p.split('/')[3]); d=body(self)
                name=str(d.get('name','')).strip(); gb=float(d.get('gb',0)); days=int(d.get('days',0)); protocol=str(d.get('protocol','vless')).lower(); transport=str(d.get('transport','ws')).lower()
                if not name or gb<=0 or days<=0 or len(name)>80 or protocol not in ('vless','vmess','trojan','wireguard','dns') or transport not in ('ws','xhttp','grpc','httpupgrade') or (protocol in ('wireguard','dns') and transport!='ws'): raise ValueError
            except Exception:
                return send(self,400,{'success':False,'msg':'نام، حجم، مدت یا پروتکل نامعتبر است'})
            c=db(); old=c.execute('SELECT * FROM clients WHERE id=?',(cid,)).fetchone()
            if not old: c.close(); return send(self,404,{'success':False,'msg':'کلاینت پیدا نشد'})
            expiry=int(time.time())+days*86400
            dns_token=old['dns_token'] or (secrets.token_urlsafe(24) if protocol=='dns' else '')
            if protocol!='dns': dns_token=''
            dns_server=(old['dns_server'] or 'internal') if protocol=='dns' else (settings().get('dns_server',''))
            c.execute('UPDATE clients SET name=?,gb=?,days=?,expiry_at=?,protocol=?,transport=?,dns_server=?,dns_token=?,enabled=1 WHERE id=?',(name,gb,days,expiry,protocol,transport,dns_server,dns_token,cid)); c.commit(); row=c.execute('SELECT * FROM clients WHERE id=?',(cid,)).fetchone(); c.close(); restart_xray(); return send(self,200,{'success':True,'client':client_data(self,row,settings())})
        if p.startswith('/api/clients/') and p.endswith('/toggle'):
            try:cid=int(p.split('/')[3])
            except:return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            c=db(); c.execute('UPDATE clients SET enabled=1-enabled WHERE id=?',(cid,)); c.commit(); c.close(); restart_xray(); return send(self,200,{'success':True})
        if p.startswith('/api/clients/') and p.endswith('/delete'):
            try:cid=int(p.split('/')[3])
            except:return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            c=db(); c.execute('DELETE FROM clients WHERE id=?',(cid,)); c.execute('DELETE FROM traffic WHERE client_id=?',(cid,)); c.commit(); c.close(); restart_xray(); return send(self,200,{'success':True})
        return send(self,404,{'success':False,'msg':'Not found'})
    def static(self):
        p=urllib.parse.urlparse(self.path).path
        if p in ('','/'):p='/index.html'
        if '..' in p:return send(self,400,{'error':'bad path'})
        f=os.path.join(WEB,p.lstrip('/'))
        if not os.path.isfile(f):return send(self,404,{'error':'not found'})
        mime='text/plain; charset=utf-8'
        if f.endswith('.html'):mime='text/html; charset=utf-8'
        elif f.endswith('.js'):mime='application/javascript; charset=utf-8'
        elif f.endswith('.css'):mime='text/css; charset=utf-8'
        raw=open(f,'rb').read(); self.send_response(200); self.send_header('Content-Type',mime); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)

if __name__=='__main__':
    init_db(); restart_xray(); threading.Thread(target=collector_loop,daemon=True).start(); print(f'vpnstan panel listening on 127.0.0.1:{PANEL_PORT}',flush=True); ThreadingHTTPServer(('127.0.0.1',PANEL_PORT),H).serve_forever()

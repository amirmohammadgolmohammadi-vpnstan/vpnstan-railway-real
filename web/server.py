import base64, hmac, json, os, secrets, sqlite3, subprocess, time, uuid, urllib.parse, threading, re, io, html, socket, urllib.request, tempfile, shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WEB=os.environ.get('VPNSTAN_WEB','/opt/vpnstan/web')
DB=os.environ.get('VPNSTAN_DB','/opt/vpnstan/data/vpnstan.db')
PANEL_PORT=int(os.environ.get('VPNSTAN_PANEL_PORT','3000'))
USERNAME=os.environ.get('VPNSTAN_USERNAME','admin')
PASSWORD=os.environ.get('VPNSTAN_PASSWORD','admin')
DEFAULT_HOST=os.environ.get('VPNSTAN_NODE_HOST','')
DEFAULT_PORT=int(os.environ.get('VPNSTAN_NODE_PORT','443'))
DEFAULT_PATH=os.environ.get('VPNSTAN_WS_PATH','/ws')
SUB_PATH=os.environ.get('VPNSTAN_SUB_PATH','sub')
XRAY_BIN=os.environ.get('XRAY_BIN','/usr/local/bin/xray')
XRAY_CONFIG=os.environ.get('XRAY_CONFIG','/opt/vpnstan/data/xray.json')
XRAY_INBOUND_PORT=int(os.environ.get('XRAY_INBOUND_PORT','10000'))
XRAY_VMESS_PORT=int(os.environ.get('XRAY_VMESS_PORT','10001'))
DEFAULT_VMESS_PATH=os.environ.get('VPNSTAN_VMESS_PATH','/vmess')
XRAY_API_ADDR=os.environ.get('XRAY_API_ADDR','127.0.0.1:10085')
PANEL_VERSION='v28'
DNS_LISTEN_HOST=os.environ.get('VPNSTAN_DNS_LISTEN_HOST','127.0.0.1')
DNS_LISTEN_PORT=int(os.environ.get('VPNSTAN_DNS_LISTEN_PORT','5353'))
DNS_TCP_PORT=int(os.environ.get('VPNSTAN_DNS_TCP_PORT','5354'))
DNS_TCP_ENABLED=os.environ.get('VPNSTAN_DNS_TCP_ENABLED','1').lower() in ('1','true','yes','on')
SESSIONS={}
XRAY_PROC=None
SESSION_USERS={}

def client_ip(h):
    # Prefer proxy-aware headers used by Railway/Cloudflare, then the direct socket.
    for key in ("CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"):
        value=h.headers.get(key,'').strip()
        if value:
            return value.split(',')[0].strip()
    try: return h.client_address[0]
    except Exception: return 'unknown'

def permission_map(row):
    try: return json.loads(row['permissions_json'] or '{}')
    except Exception: return {}

def has_permission(h, name):
    u=current_user(h)
    if not u: return False
    if u['role']=='admin' or int(u['panel_id'] or 0)==0: return True
    c=db(); r=c.execute('SELECT permissions_json FROM child_panels WHERE id=?',(u['panel_id'],)).fetchone(); c.close()
    perms=permission_map(r) if r else {}
    return bool(perms.get(name, False))

def panel_scope(h):
    u=current_user(h)
    return None if u and (u['role']=='admin' or int(u['panel_id'] or 0)==0) else (int(u['panel_id']) if u else None)

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

def dns_tcp_client(conn, addr):
    conn.settimeout(8)
    try:
        while True:
            hdr=conn.recv(2)
            if not hdr:
                return
            if len(hdr)!=2:
                return
            n=int.from_bytes(hdr,'big')
            if n<12 or n>65535:
                return
            q=b''
            while len(q)<n:
                chunk=conn.recv(min(4096,n-len(q)))
                if not chunk:
                    return
                q+=chunk
            answer=resolve_dns_wire(q)
            conn.sendall(len(answer).to_bytes(2,'big')+answer)
    except Exception:
        return
    finally:
        try: conn.close()
        except Exception: pass

def dns_tcp_server():
    if not DNS_TCP_ENABLED:
        return
    srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    srv.bind(('0.0.0.0',DNS_TCP_PORT))
    srv.listen(64)
    print(f'VPNSTAN DNS TCP listening on 0.0.0.0:{DNS_TCP_PORT}',flush=True)
    while True:
        try:
            conn,addr=srv.accept()
            threading.Thread(target=dns_tcp_client,args=(conn,addr),daemon=True).start()
        except Exception as e:
            print('DNS TCP:',e,flush=True)

def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def init_db():
    os.makedirs(os.path.dirname(DB),exist_ok=True)
    c=db()
    c.execute('''CREATE TABLE IF NOT EXISTS clients(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, uuid TEXT NOT NULL UNIQUE,
      sub_id TEXT NOT NULL UNIQUE, gb REAL NOT NULL, days INTEGER NOT NULL,
      created_at INTEGER NOT NULL, expiry_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)''')
    # Migrate legacy clients table: older builds incorrectly made sub_id UNIQUE,
    # which prevents multiple configs from sharing one Subscription.
    # Rebuild only when that legacy unique constraint is present.
    try:
        idx_rows=c.execute("PRAGMA index_list(clients)").fetchall()
        legacy_unique=False
        for idx in idx_rows:
            if int(idx[2]) == 1:
                cols=c.execute(f'PRAGMA index_info("{idx[1]}")').fetchall()
                if [x[2] for x in cols] == ['sub_id']:
                    legacy_unique=True
                    break
        if legacy_unique:
            c.execute('ALTER TABLE clients RENAME TO clients_legacy')
            c.execute('''CREATE TABLE clients(
              id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, uuid TEXT NOT NULL UNIQUE,
              sub_id TEXT NOT NULL, gb REAL NOT NULL, days INTEGER NOT NULL,
              created_at INTEGER NOT NULL, expiry_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)''')
            cols=[r[1] for r in c.execute('PRAGMA table_info(clients_legacy)').fetchall()]
            base=['id','name','uuid','sub_id','gb','days','created_at','expiry_at','enabled']
            available=[x for x in base if x in cols]
            c.execute(f"INSERT INTO clients ({','.join(available)}) SELECT {','.join(available)} FROM clients_legacy")
            c.execute('DROP TABLE clients_legacy')
    except Exception as e:
        print('CLIENTS SCHEMA MIGRATION:',e,flush=True)

    c.execute('''CREATE TABLE IF NOT EXISTS child_panels(
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
      panel_key TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1,
      detected_ip TEXT NOT NULL DEFAULT '', allowed_ip TEXT NOT NULL DEFAULT '',
      permissions_json TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS panel_users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
      enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL,
      panel_id INTEGER NOT NULL DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS traffic(
      client_id INTEGER PRIMARY KEY, upload INTEGER NOT NULL DEFAULT 0,
      download INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0,
      raw_upload INTEGER NOT NULL DEFAULT 0, raw_download INTEGER NOT NULL DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS telegram_orders(
      id INTEGER PRIMARY KEY AUTOINCREMENT, telegram_user_id INTEGER NOT NULL, username TEXT NOT NULL DEFAULT '',
      plan_name TEXT NOT NULL, gb REAL NOT NULL, days INTEGER NOT NULL, price TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'created', client_id INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS telegram_wallet_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_user_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'awaiting_payment',
    created_at INTEGER NOT NULL
)''')
    c.execute('''CREATE TABLE IF NOT EXISTS telegram_wallet_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_user_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    kind TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
)''')
    c.execute('''CREATE TABLE IF NOT EXISTS telegram_users(
      telegram_user_id INTEGER PRIMARY KEY, username TEXT NOT NULL DEFAULT '', first_name TEXT NOT NULL DEFAULT '',
      wallet REAL NOT NULL DEFAULT 0, referral_code TEXT NOT NULL DEFAULT '', referred_by INTEGER NOT NULL DEFAULT 0,
      trial_used INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS telegram_tickets(
      id INTEGER PRIMARY KEY AUTOINCREMENT, telegram_user_id INTEGER NOT NULL, text TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open', admin_reply TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL)''')
    for col in ('raw_upload','raw_download'):
        try: c.execute(f'ALTER TABLE traffic ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0')
        except sqlite3.OperationalError: pass
    try: c.execute("ALTER TABLE panel_users ADD COLUMN panel_id INTEGER NOT NULL DEFAULT 0")
    except sqlite3.OperationalError: pass
    for col,typ,default in [('carrier_profile','TEXT',"'auto'"),('protocol','TEXT',"'vless'"),('transport','TEXT',"'ws'"),('dns_server','TEXT',"'1.1.1.1'"),('wg_private_key','TEXT',"''"),('wg_address','TEXT',"''"),('dns_token','TEXT',"''"),('panel_id','INTEGER','0')]:
        try: c.execute(f'ALTER TABLE clients ADD COLUMN {col} {typ} NOT NULL DEFAULT {default}')
        except sqlite3.OperationalError: pass
    # Seed the first administrator from environment variables, only on first startup.
    if c.execute('SELECT COUNT(*) FROM panel_users').fetchone()[0] == 0:
        import hashlib
        ph=hashlib.sha256(PASSWORD.encode()).hexdigest()
        c.execute('INSERT INTO panel_users(username,password_hash,role,enabled,created_at) VALUES(?,?,?,?,?)',(USERNAME,ph,'admin',1,int(time.time())))
    defaults={'node_host':DEFAULT_HOST,'node_port':str(DEFAULT_PORT),'carrier_profile':'auto','ws_path':DEFAULT_PATH,'vmess_path':DEFAULT_VMESS_PATH,'xhttp_path':'/xhttp','grpc_service':'vpnstan','grpc_path':'/grpc','httpupgrade_path':'/upgrade','vmess_xhttp_path':'/vmess-xhttp','vmess_grpc_path':'/vmess-grpc','vmess_httpupgrade_path':'/vmess-upgrade','trojan_ws_path':'/trojan','trojan_xhttp_path':'/trojan-xhttp','trojan_grpc_path':'/trojan-grpc','trojan_httpupgrade_path':'/trojan-upgrade','sub_path':SUB_PATH,
              'panel_title':'vpnstan','support_url':'','dns_server':'1.1.1.1,1.0.0.1','dns_profile':'cloudflare','wg_endpoint':'','wg_server_public_key':'','announce':'اشتراک vpnstan — برای دریافت آخرین کانفیگ، لینک اشتراک را به‌روزرسانی کنید.','update_interval':'1','theme':'dark','telegram_token':'','telegram_admin_id':'','telegram_enabled':'0','telegram_plans':json.dumps([{'name':'50GB / 30 روز','gb':50,'days':30,'price':''}],ensure_ascii=False),'telegram_payment_text':'پس از پرداخت، روی «پرداخت کردم» بزنید تا سفارش برای ادمین ارسال شود. پرداخت به‌صورت دستی بررسی می‌شود.',
              'telegram_trial_enabled':'1','telegram_trial_gb':'1','telegram_trial_days':'1','telegram_referral_reward':'1','telegram_support_text':'برای پشتیبانی پیام خود را ارسال کنید.','telegram_mandatory_channel':'','telegram_welcome_text':'به فروشگاه VPNSTAN خوش آمدید.','telegram_card_number':'','telegram_card_name':'',
              'telegram_renew_7_price':'30000','telegram_renew_30_price':'100000','telegram_renew_90_price':'250000',
              'telegram_add_5_price':'30000','telegram_add_10_price':'50000','telegram_add_25_price':'100000'}
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
                    c=db(); r=c.execute('SELECT id,username,role,enabled,panel_id FROM panel_users WHERE id=?',(uid,)).fetchone(); c.close()
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
                with open('/opt/vpnstan/data/xray-stats.log','ab') as f: f.write((proc.stderr or b'')[-4000:]+b"\n")
            except Exception: pass
            return
        data=json.loads((proc.stdout or b'{}').decode('utf-8','replace'))
    except Exception as e:
        try:
            with open('/opt/vpnstan/data/xray-stats.log','a',encoding='utf-8') as f: f.write(str(e)+'\n')
        except Exception: pass
        return
    stats={}
    for item in data.get('stat',[]) or []:
        name=str(item.get('name','')); value=int(item.get('value',0) or 0)
        m=re.match(r'^user>>>(.+)>>>traffic>>>(uplink|downlink)$',name)
        if m:
            email,kind=m.group(1),m.group(2)
            stats.setdefault(email,{'upload':0,'download':0})[kind]=value
    if not stats: return
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
        'vless_ws':s.get('ws_path','/ws') or '/ws','vmess_ws':s.get('vmess_path','/vmess') or '/vmess','trojan_ws':s.get('trojan_ws_path','/trojan') or '/trojan',
        'vless_xhttp':s.get('xhttp_path','/xhttp') or '/xhttp','vmess_xhttp':s.get('vmess_xhttp_path','/vmess-xhttp') or '/vmess-xhttp','trojan_xhttp':s.get('trojan_xhttp_path','/trojan-xhttp') or '/trojan-xhttp',
        'vless_grpc':s.get('grpc_path','/grpc') or '/grpc','vmess_grpc':s.get('vmess_grpc_path','/vmess-grpc') or '/vmess-grpc','trojan_grpc':s.get('trojan_grpc_path','/trojan-grpc') or '/trojan-grpc',
        'vless_httpupgrade':s.get('httpupgrade_path','/upgrade') or '/upgrade','vmess_httpupgrade':s.get('vmess_httpupgrade_path','/vmess-upgrade') or '/vmess-upgrade','trojan_httpupgrade':s.get('trojan_httpupgrade_path','/trojan-upgrade') or '/trojan-upgrade'}
    svc=s.get('grpc_service','vpnstan') or 'vpnstan'; rows=active_clients(); inbounds=[]; base=XRAY_INBOUND_PORT
    transports=['ws','xhttp','grpc','httpupgrade']; protocols=['vless','vmess','trojan']
    port_map={(proto,transport):base+(pi*4+ti) for pi,proto in enumerate(protocols) for ti,transport in enumerate(transports)}
    for proto in protocols:
        for transport in transports:
            selected=[r for r in rows if (r['protocol'] or 'vless')==proto and (r['transport'] or 'ws')==transport]
            if not selected: continue
            if proto in ('vless','vmess'):
                clients=[]
                for r in selected:
                    item={'id':r['uuid'],'email':'vpnstan-'+r['uuid'],'level':0}
                    if proto=='vmess': item['alterId']=0
                    clients.append(item)
                settings_obj={'clients':clients,'decryption':'none'} if proto=='vless' else {'clients':clients}
            else:
                settings_obj={'clients':[{'password':r['uuid'],'email':'vpnstan-'+r['uuid'],'level':0} for r in selected]}
            path=paths[f'{proto}_{transport}']; stream={'network':transport,'security':'none'}
            if transport=='ws': stream['wsSettings']={'path':path}
            elif transport=='xhttp': stream['xhttpSettings']={'path':path,'mode':'auto'}
            elif transport=='grpc': stream['grpcSettings']={'serviceName':svc,'multiMode':False}
            elif transport=='httpupgrade': stream['httpupgradeSettings']={'path':path}
            inbounds.append({'tag':f'{proto}-{transport}','listen':'127.0.0.1','port':port_map[(proto,transport)],'protocol':proto,'settings':settings_obj,'streamSettings':stream})
    api_port=int(XRAY_API_ADDR.rsplit(':',1)[-1])
    api_inbound={'tag':'api','listen':'127.0.0.1','port':api_port,'protocol':'dokodemo-door','settings':{'address':'127.0.0.1'}}
    cfg={'log':{'loglevel':'warning'},'api':{'tag':'api','services':['StatsService']},'stats':{},'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True,'statsUserOnline':True}},'system':{'statsInboundUplink':True,'statsInboundDownlink':True,'statsOutboundUplink':True,'statsOutboundDownlink':True}},'inbounds':[api_inbound]+inbounds,'routing':{'rules':[{'type':'field','inboundTag':['api'],'outboundTag':'api'}]},'outbounds':[{'protocol':'freedom','tag':'direct'},{'protocol':'blackhole','tag':'block'}]}
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
            log=open('/opt/vpnstan/data/xray.log','ab')
            XRAY_PROC=subprocess.Popen([XRAY_BIN,'run','-c',XRAY_CONFIG],stdout=log,stderr=log)
            time.sleep(0.5)
            if XRAY_PROC.poll() is not None: print('XRAY FAILED — see /opt/vpnstan/data/xray.log',flush=True)
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
                        log=open('/opt/vpnstan/data/xray.log','ab')
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

def export_backup_bytes():
    """Create one portable backup file containing the complete panel database.
    The SQLite database holds clients, traffic, settings, Telegram data, wallets,
    child panels and login accounts. Xray is regenerated from the restored DB/settings.
    """
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='vpnstan-backup-', suffix='.db')
    os.close(fd)
    try:
        src=sqlite3.connect(DB)
        try:
            try: src.execute('PRAGMA wal_checkpoint(FULL)')
            except Exception: pass
            dst=sqlite3.connect(tmp)
            src.backup(dst)
            dst.commit(); dst.close()
        finally:
            src.close()
        raw=open(tmp,'rb').read()
        payload={
            'format':'VPNSTAN_BACKUP',
            'backup_version':1,
            'panel_version':PANEL_VERSION,
            'created_at':int(time.time()),
            'database_base64':base64.b64encode(raw).decode('ascii')
        }
        return json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode('utf-8')
    finally:
        try: os.remove(tmp)
        except OSError: pass

def import_backup_bytes(raw):
    payload=json.loads(raw.decode('utf-8'))
    if payload.get('format')!='VPNSTAN_BACKUP': raise ValueError('این فایل بکاپ VPNSTAN نیست.')
    if int(payload.get('backup_version',0))!=1: raise ValueError('نسخه بکاپ پشتیبانی نمی‌شود.')
    b64=payload.get('database_base64','')
    if not b64: raise ValueError('دیتابیس داخل بکاپ وجود ندارد.')
    dbraw=base64.b64decode(b64,validate=True)
    if len(dbraw)>100*1024*1024: raise ValueError('حجم بکاپ بیش از حد مجاز است.')
    fd,tmp=tempfile.mkstemp(prefix='vpnstan-restore-', suffix='.db')
    os.close(fd)
    try:
        open(tmp,'wb').write(dbraw)
        c=sqlite3.connect(tmp)
        try:
            ok=c.execute('PRAGMA integrity_check').fetchone()[0]
            if str(ok).lower()!='ok': raise ValueError('دیتابیس بکاپ سالم نیست.')
            tables={r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            required={'clients','settings','panel_users'}
            missing=required-tables
            if missing: raise ValueError('ساختار بکاپ ناقص است: '+', '.join(sorted(missing)))
        finally: c.close()
        # Keep a safety copy of the current DB until the new DB is verified.
        live_tmp=DB+'.before-restore'
        try: shutil.copy2(DB,live_tmp)
        except Exception: pass
        try:
            os.replace(tmp,DB)
        except Exception:
            # Fallback for filesystems where replace is unavailable.
            shutil.copy2(tmp,DB)
        for suffix in ('-wal','-shm'):
            try: os.remove(DB+suffix)
            except OSError: pass
        try: os.remove(live_tmp)
        except OSError: pass
        return payload
    finally:
        try: os.remove(tmp)
        except OSError: pass

def clean_host(v): return (v or '').split(':',1)[0].strip()
def host_for(h,s):
    return (clean_host(s.get('node_host')) or clean_host(os.environ.get('RAILWAY_PUBLIC_DOMAIN')) or clean_host(h.headers.get('X-Forwarded-Host') or h.headers.get('Host','')))


def link_for(h,r,s):
    proto=(r['protocol'] if 'protocol' in r.keys() else 'vless') or 'vless'; host=host_for(h,s); name=urllib.parse.quote(r['name']); port=int(s.get('node_port','443'))
    if proto=='wireguard': return wg_config_for(h,r,s)
    if proto=='dns':
        token=r['dns_token'] or ''; return f'https://{host}/doh/{token}' if token else ''
    transport=(r['transport'] or 'ws').lower() if 'transport' in r.keys() else 'ws'
    paths={'ws':s.get('ws_path','/ws'),'xhttp':s.get('xhttp_path','/xhttp'),'grpc':s.get('grpc_path','/grpc'),'httpupgrade':s.get('httpupgrade_path','/upgrade')}
    path=paths.get(transport,'/ws') or '/ws'; svc=s.get('grpc_service','vpnstan') or 'vpnstan'
    if proto=='vmess':
        obj={'v':'2','ps':r['name'],'add':host,'port':str(port),'id':r['uuid'],'aid':'0','scy':'auto','net':transport,'type':'none','host':host,'path':path,'tls':'tls','sni':host}
        if transport=='grpc': obj['path']=svc
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

def wg_config_for(h,r,s):
    endpoint=s.get('wg_endpoint','') or 'SET-WIREGUARD-ENDPOINT:51820'
    server_key=s.get('wg_server_public_key','') or 'SET-SERVER-PUBLIC-KEY'
    private=r['wg_private_key'] or 'GENERATE-CLIENT-PRIVATE-KEY'
    addr=r['wg_address'] or '10.66.0.2/32'
    dns=r['dns_server'] or s.get('dns_server','1.1.1.1')
    return f'[Interface]\nPrivateKey = {private}\nAddress = {addr}\nDNS = {dns}\n\n[Peer]\nPublicKey = {server_key}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = {endpoint}\nPersistentKeepalive = 25'

def client_data(h,r,s):
    now=int(time.time()); tr=traffic_for(r['id']); used=tr['upload']+tr['download']; total=int(float(r['gb'])*1024**3); remain=max(0,total-used)
    sub_host=host_for(h,s); proto=(r['protocol'] or 'vless').lower(); sub=(f'https://{sub_host}/dns-sub/{r["sub_id"]}' if proto=='dns' else f'https://{sub_host}/{s.get("sub_path","sub").strip("/")}/{r["sub_id"]}')
    online=(tr['last_seen'] and now-tr['last_seen']<=90)
    return {'id':r['id'],'name':r['name'],'protocol':r['protocol'] or 'vless','uuid':r['uuid'],'subId':r['sub_id'],'gb':r['gb'],'days':r['days'],'createdAt':r['created_at'],'expiryAt':r['expiry_at'],'enabled':bool(r['enabled']),
            'upload':tr['upload'],'download':tr['download'],'used':used,'remaining':remain,'totalBytes':total,'lastSeen':tr['last_seen'],'online':bool(online),
            'remainingText':fmt_bytes(remain),'usedText':fmt_bytes(used),'totalText':fmt_bytes(total),'uploadText':fmt_bytes(tr['upload']),'downloadText':fmt_bytes(tr['download']),
            'expiryText':fmt_date(r['expiry_at']),'vless':link_for(h,r,s),'config':link_for(h,r,s),'subscription':sub,'dnsServer':f'https://{sub_host}/doh/{r["dns_token"]}' if (r['protocol'] or '')=='dns' and r['dns_token'] else '','dnsProfile':dns_profile_for('internal'),'dnsSubscription':f'https://{sub_host}/dns-sub/{r["sub_id"]}','dnsUrl':f'https://{sub_host}/doh/{r["dns_token"]}' if (r['protocol'] or '')=='dns' and r['dns_token'] else '','wireguardConfig':wg_config_for(h,r,s),'version':PANEL_VERSION}

def load_sub(h,sid):
    s=settings(); c=db(); rows=c.execute('SELECT * FROM clients WHERE sub_id=? AND enabled=1',(sid,)).fetchall(); c.close(); now=int(time.time())
    rows=[r for r in rows if r['expiry_at']==0 or r['expiry_at']>now]
    return s,rows

def sub_page(h,sid):
    # Public subscription/config page. This is a UI-only redesign of the existing
    # subscription page; all existing subscription generation, traffic and config
    # endpoints remain unchanged.
    s,rows=load_sub(h,sid)
    if not rows:
        h.send_response(404); h.send_header('Content-Type','text/html; charset=utf-8'); h.end_headers(); h.wfile.write('<h2>اشتراک پیدا نشد یا منقضی شده است.</h2>'.encode()); return
    r=rows[0]; d=client_data(h,r,s)
    title=html.escape(s.get('panel_title','vpnstan')); name=html.escape(r['name'])
    sub=html.escape(d['subscription'],quote=True); pct=min(100,(d['used']/d['totalBytes']*100) if d['totalBytes'] else 0)
    support=html.escape(s.get('support_url',''),quote=True); announce=html.escape(s.get('announce',''))
    qr=f'/qr/{r["sub_id"]}'
    host=html.escape(str(s.get('node_host') or h.headers.get('Host','')),quote=True); port=html.escape(str(s.get('node_port','443')),quote=True)
    expiry=html.escape(d['expiryText']); used=html.escape(d['usedText']); remain=html.escape(d['remainingText']); total=html.escape(d['totalText'])
    protocols=[]
    for rr in rows:
        pr=(rr['protocol'] or 'vless').upper()
        if pr not in protocols: protocols.append(pr)
    active_proto=(r['protocol'] or 'vless').upper()
    proto_tabs=''.join(f'<button class="proto-tab {"active" if pr==active_proto else ""}" data-proto="{html.escape(pr)}">{html.escape(pr)}</button>' for pr in protocols)
    config_rows=[]
    for idx,rr in enumerate(rows,1):
        dd=client_data(h,rr,s); pr=(rr['protocol'] or 'vless').upper(); cfg=html.escape(dd['config'],quote=True)
        state='فعال' if dd['enabled'] else 'غیرفعال'
        state_cls='on' if dd['enabled'] else 'off'
        config_rows.append(f'''<div class="cfg-row" data-proto="{html.escape(pr)}">
          <div class="cfg-name"><span class="cfg-num">{idx}</span><div><b>{html.escape(rr['name'])}</b><small>{pr} · {html.escape(str(rr['transport'] or 'WS').upper())}</small></div></div>
          <div class="cfg-value"><span>حجم</span><b>{html.escape(dd['totalText'])}</b></div>
          <div class="cfg-value"><span>انقضا</span><b>{html.escape(dd['expiryText'])}</b></div>
          <div class="cfg-status {state_cls}"><i></i>{state}</div>
          <div class="cfg-actions"><button class="small-btn" onclick="copyConfig({idx})">کپی</button><button class="small-btn secondary" onclick="showQr()">QR</button></div>
          <textarea id="cfg-{idx}" class="hidden-data">{cfg}</textarea>
        </div>''')
    cfg_html=''.join(config_rows)
    page = r'''<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#06152b"><title>VPNSTAN · ساب لینک</title>
<style>
*{box-sizing:border-box}html,body{margin:0;min-height:100%;font-family:Tahoma,Arial,sans-serif;background:#06111f;color:#eaf3ff}body{background:radial-gradient(circle at 70% -20%,#102d54 0,#06111f 42%,#040b14 100%)}button,input{font-family:inherit}.app{min-height:100vh}.topbar{height:66px;background:rgba(5,16,31,.96);border-bottom:1px solid #173354;display:flex;align-items:center;padding:0 22px;gap:22px;position:sticky;top:0;z-index:10}.brand{display:flex;align-items:center;gap:11px;min-width:230px}.brand-logo{width:38px;height:38px;border-radius:11px;background:linear-gradient(145deg,#1d69f4,#5d3cf5);display:grid;place-items:center;font-size:23px;font-weight:900}.brand b{font-size:19px}.brand small{color:#2e83ff;margin-right:8px;font-weight:800}.menu{font-size:25px;color:#8bb7ee}.channel{margin:auto 0;background:#0b1c33;border:1px solid #214064;border-radius:9px;padding:9px 14px;color:#d8e8ff}.channel a{color:#fff;text-decoration:none;font-weight:800;direction:ltr;display:inline-block}.channel .tg{color:#43a7ff;font-size:20px;margin-right:7px}.top-spacer{flex:1}.top-dot{width:42px;height:28px;border:1px solid #294664;border-radius:20px;background:#0d2139;display:grid;place-items:center;color:#9bc4ff}.top-user{display:flex;align-items:center;gap:9px}.top-user b{display:block;font-size:12px}.top-user small{display:block;color:#7890ac;font-size:9px}.avatar{width:34px;height:34px;border-radius:50%;background:#2b5284;display:grid;place-items:center}.body{display:grid;grid-template-columns:235px minmax(0,1fr);min-height:calc(100vh - 66px)}.sidebar{border-left:1px solid #173354;background:linear-gradient(180deg,#061322,#06101d);padding:15px 10px;display:flex;flex-direction:column;gap:5px}.side-item{display:flex;align-items:center;gap:13px;color:#b8cbe1;text-decoration:none;padding:13px 14px;border-radius:8px;font-size:12px}.side-item.active{background:#176df2;color:#fff;box-shadow:0 8px 22px #176df23a}.side-item .ico{width:23px;text-align:center;font-size:18px}.side-footer{margin-top:auto;border:1px solid #173d65;border-radius:9px;padding:15px;text-align:center;background:#071a30}.side-footer b{display:block;font-size:14px}.side-footer small{color:#77a6dd;display:block;margin-top:6px}.main{padding:20px 24px 35px;max-width:1320px;width:100%;margin:auto}.crumb{display:flex;align-items:center;gap:8px;color:#6685aa;font-size:10px;margin-bottom:16px}.crumb .back{background:#0c2039;border:1px solid #214365;color:#d9e9ff;border-radius:8px;padding:10px 13px;font-size:16px}.crumb strong{background:#0b1d34;border:1px solid #193a5d;color:#e5effd;border-radius:8px;padding:10px 14px;font-size:11px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:13px;margin-bottom:14px}.metric{background:linear-gradient(145deg,#0b1d34,#071527);border:1px solid #193b61;border-radius:10px;padding:14px 16px;min-height:96px;display:flex;align-items:center;gap:12px}.metric-icon{width:42px;height:42px;border-radius:9px;display:grid;place-items:center;font-size:20px}.blue{background:#0c55bd;color:#a9d0ff}.green{background:#0aaf78;color:#d7fff2}.purple{background:#6636c9;color:#f0e7ff}.orange{background:#d87910;color:#fff1d5}.metric small{display:block;color:#9bb0c9;font-size:9px}.metric b{display:block;color:#f0f5ff;font-size:19px;margin-top:7px}.metric .up{color:#16d9a7;font-size:9px;margin-top:7px}.layout{display:grid;grid-template-columns:minmax(0,1fr) 315px;gap:16px}.card{background:linear-gradient(145deg,#091a30,#061325);border:1px solid #183b60;border-radius:10px;box-shadow:0 12px 30px #0003}.section{padding:16px;margin-bottom:14px}.section-title{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}.section-title h2{margin:0;font-size:15px}.muted{color:#7089a6;font-size:9px}.sub-info-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:9px}.info{background:#081a30;border:1px solid #183a5d;border-radius:8px;padding:12px}.info .label{color:#8199b5;font-size:9px}.info .value{font-size:12px;font-weight:800;margin-top:8px}.badge{display:inline-flex;padding:5px 8px;border-radius:10px;background:#063b35;color:#26d9aa;font-size:8px}.proto-row{display:flex;align-items:center;gap:0;border:1px solid #204466;border-radius:8px;overflow:hidden;margin-bottom:12px}.proto-tab{flex:1;border:0;border-left:1px solid #204466;background:#091b31;color:#8ca5c2;padding:11px 15px;cursor:pointer;font-size:10px}.proto-tab:last-child{border-left:0}.proto-tab.active{background:#176df2;color:#fff}.link-panel{display:grid;grid-template-columns:165px minmax(0,1fr);gap:18px;align-items:center;background:#07172a;border:1px solid #1a4169;border-radius:9px;padding:14px}.qrbox{display:flex;align-items:center;justify-content:center}.qrbox img{width:145px;height:145px;background:#fff;border-radius:5px;padding:5px}.link-content h3{margin:0 0 9px;font-size:13px}.linkbox{display:flex;background:#071c32;border:1px solid #28557e;border-radius:8px;overflow:hidden}.linkbox code{flex:1;min-width:0;padding:12px;color:#a2c1e4;font:10px Consolas,monospace;direction:ltr;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.btn{border:1px solid #2a7cf1;background:#146df1;color:#fff;border-radius:8px;padding:10px 15px;cursor:pointer;font-size:9px;font-weight:800}.btn.alt{background:#0b213a;border-color:#285078;color:#a9c7e7}.actions{display:flex;gap:8px;margin-top:9px;flex-wrap:wrap}.advanced{display:grid;grid-template-columns:1fr 1fr;gap:9px}.field{display:flex;justify-content:space-between;gap:10px;background:#091b31;border:1px solid #193b5d;border-radius:7px;padding:10px 12px}.field span{color:#7f96b2;font-size:9px}.field b{font-size:9px;font-weight:500;direction:ltr}.quick{display:grid;grid-template-columns:1fr 1fr;gap:8px}.quick button{border:1px solid #21486d;background:#091d34;color:#aac4e0;border-radius:8px;padding:10px;cursor:pointer;font-size:9px}.quick .primary{background:#176df2;border-color:#2c83ff;color:#fff}.bottom-stats{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid #1a3c5f;border-radius:9px;overflow:hidden}.bottom-stat{background:#081a30;padding:14px;border-left:1px solid #183a5d}.bottom-stat:last-child{border-left:0}.bottom-stat small{display:block;color:#8197b1;font-size:8px}.bottom-stat b{display:block;font-size:13px;margin-top:7px}.bottom-stat .good{color:#1bd9aa}.side-card{padding:16px;height:max-content}.side-card h3{font-size:13px;margin:0 0 12px}.side-line{display:flex;justify-content:space-between;padding:11px 0;border-bottom:1px solid #17344f;font-size:10px}.side-line span{color:#8098b4}.side-line b{font-weight:500;color:#d9e8f9}.side-status{display:flex;align-items:center;justify-content:space-between;background:#071b2e;border:1px solid #193e60;border-radius:8px;padding:11px;margin-top:10px}.online{color:#20dcae}.online i{display:inline-block;width:7px;height:7px;border-radius:50%;background:#20dcae;box-shadow:0 0 9px #20dcae;margin-left:5px}.connected{margin-top:14px}.device{display:flex;align-items:center;gap:9px;background:#081b30;border:1px solid #183a5d;border-radius:8px;padding:10px;margin-top:7px}.device .devico{width:31px;height:31px;border-radius:8px;background:#112c4c;display:grid;place-items:center;color:#76adf4}.device b{font-size:9px}.device span{margin-right:auto;color:#7890aa;font-size:8px}.configs{overflow:hidden}.cfg-head,.cfg-row{display:grid;grid-template-columns:minmax(180px,2fr) 1fr 1fr .8fr 1fr;gap:10px;align-items:center;padding:11px 12px}.cfg-head{background:#0b2039;color:#7690ad;font-size:8px}.cfg-row{border-top:1px solid #14304c}.cfg-name{display:flex;align-items:center;gap:9px;min-width:0}.cfg-num{width:24px;height:24px;border-radius:6px;background:#102b49;color:#67a8ff;display:grid;place-items:center;font-size:8px;flex:0 0 24px}.cfg-name b{display:block;font-size:9px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.cfg-name small{display:block;color:#6f88a4;font-size:7px;margin-top:3px;direction:ltr;text-align:right}.cfg-value span{display:block;color:#7189a5;font-size:7px}.cfg-value b{display:block;font-size:9px;margin-top:4px}.cfg-status{font-size:8px}.cfg-status i{display:inline-block;width:6px;height:6px;border-radius:50%;background:currentColor;margin-left:5px}.cfg-status.on{color:#20d8aa}.cfg-status.off{color:#e26076}.cfg-actions{display:flex;justify-content:flex-end;gap:5px}.small-btn{border:1px solid #28537b;background:#0a2039;color:#8fb9ed;border-radius:6px;padding:6px 9px;cursor:pointer;font-size:8px}.small-btn.secondary{color:#b6c9df}.hidden-data{display:none}.announce{padding:11px 13px;background:#081a30;border:1px dashed #244b71;border-radius:8px;color:#8098b4;font-size:8px}.footer{text-align:center;color:#5f7896;font-size:8px;padding:16px}.creator{position:fixed;bottom:10px;left:15px;background:#071a30;border:1px solid #173d64;border-radius:8px;padding:7px 10px;color:#6f91b5;font-size:8px;z-index:9}.creator b{color:#55a2ff}.toast{position:fixed;bottom:25px;left:50%;transform:translateX(-50%);background:#176df2;color:#fff;padding:10px 18px;border-radius:8px;font:10px Tahoma;z-index:99;box-shadow:0 10px 30px #0008}@media(max-width:1050px){.body{grid-template-columns:75px minmax(0,1fr)}.sidebar .label{display:none}.side-item{justify-content:center;padding:13px 8px}.side-footer{display:none}.brand{min-width:auto}.brand b{display:none}.metrics{grid-template-columns:repeat(2,1fr)}.layout{grid-template-columns:1fr}.side-card{order:-1}.sub-info-grid{grid-template-columns:repeat(2,1fr)}}@media(max-width:700px){.topbar{padding:0 10px;gap:10px}.channel{display:none}.main{padding:12px 9px}.metrics{grid-template-columns:1fr 1fr;gap:8px}.metric{padding:10px}.link-panel{grid-template-columns:1fr}.qrbox{order:-1}.advanced{grid-template-columns:1fr}.bottom-stats{grid-template-columns:1fr 1fr}.cfg-head{display:none}.cfg-row{grid-template-columns:1fr 1fr}.cfg-actions{justify-content:flex-start}.creator{display:none}}
</style></head><body>
<div class="app">
<header class="topbar"><div class="brand"><div class="brand-logo">V</div><div><b>VPNSTAN</b><small>v28</small></div></div><div class="menu">☰</div><div class="channel"><a href="https://t.me/vpnstan1" target="_blank" rel="noopener">@vpnstan1</a> <span class="tg">✈</span> کانال رسمی</div><div class="top-spacer"></div><div class="top-dot">☼</div><div class="top-dot">♧</div><div class="top-user"><div><b>admin</b><small>مدیر کل</small></div><div class="avatar">●</div></div></header>
<div class="body"><aside class="sidebar">
<a class="side-item" href="javascript:void(0)"><span class="ico">⌂</span><span class="label">داشبورد</span></a>
<a class="side-item" href="javascript:void(0)"><span class="ico">♙</span><span class="label">کاربران</span></a>
<a class="side-item" href="javascript:void(0)"><span class="ico">⌘</span><span class="label">ساخت کانفیگ</span></a>
<a class="side-item" href="javascript:void(0)"><span class="ico">▣</span><span class="label">مدیریت کانفیگ‌ها</span></a>
<a class="side-item active" href="javascript:void(0)"><span class="ico">↗</span><span class="label">لینک ساب (اشتراک)</span></a>
<a class="side-item" href="javascript:void(0)"><span class="ico">◉</span><span class="label">ترافیک مصرفی</span></a>
<a class="side-item" href="javascript:void(0)"><span class="ico">⚙</span><span class="label">تنظیمات</span></a>
<a class="side-item" href="javascript:void(0)"><span class="ico">◫</span><span class="label">مدیریت پنل</span></a>
<a class="side-item" href="javascript:void(0)"><span class="ico">◷</span><span class="label">پیکربندی / بازیابی</span></a>
<a class="side-item" href="javascript:void(0)"><span class="ico">▤</span><span class="label">لاگ‌ها</span></a>
<a class="side-item" href="javascript:void(0)"><span class="ico">↪</span><span class="label">خروج</span></a>
<div class="side-footer"><b>VPNSTAN</b><small>v28</small><div style="margin-top:8px;color:#5ca4ff">Power By VPNSTAN</div><div style="margin-top:8px">✈ @vpnstan1</div></div>
</aside>
<main class="main">
<div class="crumb"><span class="back">‹</span><strong>لینک ساب (اشتراک)</strong><span>داشبورد</span><span>›</span><span>لینک ساب</span></div>
<div class="metrics">
<div class="metric"><div class="metric-icon orange">◷</div><div><small>روزهای باقی مانده</small><b id="metricDays">__DAYS__</b><div class="up">↑ امروز</div></div></div>
<div class="metric"><div class="metric-icon purple">▤</div><div><small>کل ترافیک مصرفی</small><b id="metricUsed">__USED__</b><div class="up">↑ مصرف شده</div></div></div>
<div class="metric"><div class="metric-icon green">▤</div><div><small>کانفیگ‌های فعال</small><b>__ACTIVE__</b><div class="up">↑ فعال</div></div></div>
<div class="metric"><div class="metric-icon blue">♙</div><div><small>تعداد کل ساب‌ها</small><b>1</b><div class="up">↑ این اشتراک</div></div></div>
</div>
<div class="layout"><section>
<div class="card section"><div class="section-title"><div><h2>اطلاعات ساب</h2><span class="muted">Subscription · VPNSTAN v28</span></div><span class="badge">● فعال</span></div>
<div class="sub-info-grid"><div class="info"><div class="label">نام کاربری</div><div class="value">__NAME__</div></div><div class="info"><div class="label">زمان انقضا</div><div class="value">__EXPIRY__</div><span class="badge" style="margin-top:7px">باقی مانده</span></div><div class="info"><div class="label">حجم کل</div><div class="value">__TOTAL__</div><span class="badge" style="margin-top:7px">مصرف شده</span></div><div class="info"><div class="label">ترافیک مصرفی</div><div class="value">__USED__</div><div style="color:#20d9ab;font-size:9px;margin-top:7px">__PCT__% مصرف</div></div></div></div>
<div class="card section"><div class="section-title"><h2>لینک ساب</h2><span class="muted">لینک اشتراک کانفیگ‌های شما</span></div>
<div class="proto-row">__PROTO_TABS__</div>
<div class="link-panel"><div class="qrbox"><img src="__QR__" alt="QR Code"></div><div class="link-content"><h3>لینک Subscription</h3><div class="linkbox"><code id="subLink">__SUB__</code><button class="btn" onclick="copyText('subLink')">کپی</button></div><div class="actions"><button class="btn" onclick="copyText('subLink')">⧉ کپی لینک</button><button class="btn alt" onclick="showQr()">▦ QR Code</button><button class="btn alt" onclick="downloadSub()">⇩ Download</button></div><p class="muted">با اسکن QR یا کپی لینک، می‌توانید این اشتراک را در برنامه موردنظر خود اضافه کنید.</p></div></div></div>
<div class="card section"><div class="section-title"><h2>تنظیمات پیشرفته</h2><span class="muted">اطلاعات اتصال</span></div><div class="advanced"><div class="field"><span>پورت</span><b>__PORT__</b></div><div class="field"><span>Host</span><b>__HOST__</b></div><div class="field"><span>مسیر</span><b>/ws</b></div><div class="field"><span>Encryption</span><b>auto</b></div><div class="field"><span>SNI (اختیاری)</span><b>__HOST__</b></div><div class="field"><span>Subscription Path</span><b>/__SUBPATH__</b></div></div><div class="quick" style="margin-top:10px"><button class="primary" onclick="copyText('subLink')">⚡ اتصال سریع</button><button onclick="copyAllConfigs()">♧ کپی همه موارد</button></div></div>
<div class="card section"><div class="section-title"><h2>لیست کانفیگ‌های اشتراک</h2><span class="muted">__COUNT__ کانفیگ</span></div><div class="configs"><div class="cfg-head"><div>نام کانفیگ</div><div>حجم</div><div>انقضا</div><div>وضعیت</div><div>عملیات</div></div>__CFG_HTML__</div></div>
<div class="card section"><div class="section-title"><h2>وضعیت و آمار</h2><span class="muted">مصرف لحظه‌ای</span></div><div class="bottom-stats"><div class="bottom-stat"><small>وضعیت اتصال</small><b class="good">● متصل / فعال</b></div><div class="bottom-stat"><small>زمان باقی مانده</small><b id="detailRemain">__REMAIN__</b></div><div class="bottom-stat"><small>ترافیک مصرفی</small><b id="detailUsed">__USED__</b></div><div class="bottom-stat"><small>درصد مصرف</small><b id="detailPct">__PCT__%</b></div></div></div>
<div class="announce">__ANNOUNCE__</div></section>
<aside>
<div class="card side-card"><h3>مشخصات اشتراک</h3><div class="side-line"><span>نام</span><b>__NAME__</b></div><div class="side-line"><span>نوع</span><b>__PROTO__</b></div><div class="side-line"><span>محدودیت حجم</span><b>__TOTAL__</b></div><div class="side-line"><span>محدودیت زمان</span><b>__EXPIRY__</b></div><div class="side-line"><span>ترافیک مصرفی</span><b id="sideUsed">__USED__</b></div><div class="side-status"><span>وضعیت</span><b class="online"><i></i> فعال</b></div></div>
<div class="card side-card" style="margin-top:14px"><h3>ورود سریع</h3><button class="btn" style="width:100%" onclick="copyText('subLink')">⚡ اتصال سریع</button><button class="small-btn" style="width:100%;margin-top:8px;padding:11px" onclick="copyAllConfigs()">♧ کپی همه موارد</button></div>
<div class="card side-card connected"><h3>کانفیگ‌های متصل</h3><div class="device"><div class="devico">▣</div><b>Android</b><span>فعال</span></div><div class="device"><div class="devico">▦</div><b>Windows</b><span>فعال</span></div></div>
</aside></div>
<div class="footer">VPNSTAN v28 · © 2025 VPNSTAN Panel · Powered by VPNSTAN · کانال رسمی @vpnstan1</div></main></div></div>
<div class="creator">سازنده این پنل: <b>VPNSTAN</b> · کانال رسمی <b>@vpnstan1</b></div>
<script>
function toast(t){const x=document.createElement('div');x.className='toast';x.textContent=t;document.body.appendChild(x);setTimeout(()=>x.remove(),1400)}
function copyText(id){const t=document.getElementById(id).textContent.trim();if(navigator.clipboard)navigator.clipboard.writeText(t).then(()=>toast('کپی شد'))}
function copyConfig(i){const e=document.getElementById('cfg-'+i);if(navigator.clipboard)navigator.clipboard.writeText(e.value).then(()=>toast('کانفیگ کپی شد'))}
function copyAllConfigs(){const a=[...document.querySelectorAll('.hidden-data')].map(x=>x.value.trim()).filter(Boolean).join('\n\n');if(navigator.clipboard)navigator.clipboard.writeText(a).then(()=>toast('همه کانفیگ‌ها کپی شد'))}
function showQr(){document.querySelector('.qrbox').scrollIntoView({behavior:'smooth',block:'center'});toast('QR Code آماده است')}
function downloadSub(){window.location.href='__SUB__'}
document.querySelectorAll('.proto-tab').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('.proto-tab').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.querySelectorAll('.cfg-row').forEach(r=>r.style.display=(b.dataset.proto===r.dataset.proto?'grid':'none'));document.getElementById('detailUsed').textContent=document.getElementById('metricUsed').textContent}))
async function live(){try{let r=await fetch('/sub-status/__SID__',{cache:'no-store'});if(!r.ok)return;let d=await r.json();document.getElementById('metricUsed').textContent=d.usedText;document.getElementById('detailUsed').textContent=d.usedText;document.getElementById('sideUsed').textContent=d.usedText;document.getElementById('detailRemain').textContent=d.remainingText;document.getElementById('detailPct').textContent=Math.round(d.percent)+'%'}catch(e){}}
setInterval(live,1000);live();
</script></body></html>'''
    active=sum(1 for rr in rows if rr['enabled'] and (rr['expiry_at']==0 or rr['expiry_at']>int(time.time())))
    days_left='∞'
    if r['expiry_at']:
        days_left=max(0, int((r['expiry_at']-int(time.time()))/86400))
        days_left=str(days_left)+' روز'
    replacements={
        '__DAYS__':html.escape(days_left),'__USED__':used,'__ACTIVE__':str(active),'__NAME__':name,'__EXPIRY__':expiry,
        '__TOTAL__':total,'__PCT__':f'{pct:.0f}','__PROTO_TABS__':proto_tabs,'__QR__':qr,'__SUB__':sub,'__PORT__':port,'__HOST__':host,
        '__SUBPATH__':html.escape(str(s.get('sub_path','sub')).strip('/')),'__COUNT__':str(len(rows)),'__CFG_HTML__':cfg_html,
        '__REMAIN__':remain,'__ANNOUNCE__':announce or 'برای اتصال سریع، لینک Subscription را کپی کنید و داخل کلاینت خود وارد نمایید.',
        '__PROTO__':html.escape(active_proto),'__SID__':html.escape(str(r['sub_id']))
    }
    for k,v in replacements.items(): page=page.replace(k,v)
    raw=page.encode(); h.send_response(200); h.send_header('Content-Type','text/html; charset=utf-8'); h.send_header('Cache-Control','no-store'); h.send_header('Content-Length',str(len(raw))); h.end_headers(); h.wfile.write(raw)

def qr_svg(h,sid):
    try:
        import qrcode
        from qrcode.image.svg import SvgPathImage
        s,rows=load_sub(h,sid)
        if not rows:return send(h,404,{'error':'not found'})
        link=link_for(h,rows[0],s)
        qr=qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M,box_size=8,border=2); qr.add_data(link); qr.make(fit=True)
        img=qr.make_image(image_factory=SvgPathImage); out=io.BytesIO(); img.save(out); raw=out.getvalue()
        h.send_response(200); h.send_header('Content-Type','image/svg+xml'); h.send_header('Cache-Control','no-store'); h.send_header('Content-Length',str(len(raw))); h.end_headers(); h.wfile.write(raw)
    except Exception as e: send(h,500,{'error':str(e)})


# ---------------- Telegram sales bot ----------------
TG_LOCK=threading.RLock()
TG_STOP=threading.Event()

def tg_api(method, payload=None, timeout=35):
    st=settings(); token=(st.get('telegram_token') or '').strip()
    if not token: raise RuntimeError('توکن ربات تلگرام تنظیم نشده است')
    url=f'https://api.telegram.org/bot{token}/{method}'
    data=json.dumps(payload or {}, ensure_ascii=False).encode('utf-8')
    req=urllib.request.Request(url,data=data,headers={'Content-Type':'application/json','User-Agent':'VPNSTAN/26'})
    with urllib.request.urlopen(req,timeout=timeout) as r:
        out=json.loads(r.read().decode('utf-8'))
    if not out.get('ok'): raise RuntimeError(str(out.get('description') or 'Telegram API error'))
    return out.get('result')

def tg_send(chat_id,text,keyboard=None):
    payload={'chat_id':chat_id,'text':text,'parse_mode':'HTML','disable_web_page_preview':True}
    if keyboard: payload['reply_markup']={'inline_keyboard':keyboard}
    return tg_api('sendMessage',payload,25)

def tg_send_photo(chat_id,photo,caption='',keyboard=None):
    payload={'chat_id':chat_id,'photo':photo,'caption':caption,'parse_mode':'HTML'}
    if keyboard: payload['reply_markup']={'inline_keyboard':keyboard}
    return tg_api('sendPhoto',payload,25)

def tg_edit(chat_id,message_id,text,keyboard=None):
    payload={'chat_id':chat_id,'message_id':message_id,'text':text,'parse_mode':'HTML','disable_web_page_preview':True}
    if keyboard: payload['reply_markup']={'inline_keyboard':keyboard}
    return tg_api('editMessageText',payload,25)

def tg_answer(cb_id,text=''):
    try: return tg_api('answerCallbackQuery',{'callback_query_id':cb_id,'text':text,'show_alert':False},15)
    except Exception: return None

def tg_user(uid, msg=None):
    chat=(msg or {}).get('chat',{})
    username=str(chat.get('username') or '').strip(); first=str(chat.get('first_name') or '').strip()
    c=db(); row=c.execute('SELECT * FROM telegram_users WHERE telegram_user_id=?',(uid,)).fetchone()
    if not row:
        code=secrets.token_hex(4).upper()
        c.execute('INSERT INTO telegram_users(telegram_user_id,username,first_name,referral_code,created_at,last_seen) VALUES(?,?,?,?,?,?)',(uid,username,first,code,int(time.time()),int(time.time())))
    else:
        c.execute('UPDATE telegram_users SET username=?,first_name=?,last_seen=? WHERE telegram_user_id=?',(username or row['username'],first or row['first_name'],int(time.time()),uid))
    c.commit(); row=c.execute('SELECT * FROM telegram_users WHERE telegram_user_id=?',(uid,)).fetchone(); c.close(); return row

def tg_main_keyboard(uid):
    return [[{'text':'🛒 خرید کانفیگ','callback_data':'plans'},{'text':'👤 حساب من','callback_data':'account'}],
            [{'text':'📦 اشتراک‌های من','callback_data':'subs'},{'text':'💳 کیف پول','callback_data':'wallet'}],
            [{'text':'🎁 تست رایگان','callback_data':'trial'},{'text':'🔄 تمدید','callback_data':'renew'}],
            [{'text':'➕ حجم اضافه','callback_data':'addvol'},{'text':'🤝 دعوت دوستان','callback_data':'ref'}],
            [{'text':'📜 سفارش‌ها','callback_data':'myorders'},{'text':'🎫 پشتیبانی','callback_data':'support'}]]

def tg_admin_keyboard():
    return [
        [{'text':'📊 داشبورد','callback_data':'admin_stats'},{'text':'👥 کاربران','callback_data':'admin_users'}],
        [{'text':'📦 سرویس‌ها','callback_data':'admin_services'},{'text':'🧾 سفارش‌ها','callback_data':'admin_orders'}],
        [{'text':'💰 پرداخت‌ها','callback_data':'admin_payments'},{'text':'💳 شماره کارت','callback_data':'admin_card'}],
        [{'text':'🛒 پلن‌ها','callback_data':'admin_plans'},{'text':'🎫 تیکت‌ها','callback_data':'admin_tickets'}],
        [{'text':'💰 قیمت تمدید/حجم','callback_data':'admin_prices'},{'text':'⚙️ تنظیمات','callback_data':'admin_settings'}],
        [{'text':'📢 پیام همگانی','callback_data':'admin_broadcast'}],
        [{'text':'🏠 منوی اصلی','callback_data':'home'}]
    ]

def tg_money(v):
    try:return f'{float(v):,.0f}'
    except:return '0'

def tg_user_clients(uid):
    c=db(); rows=c.execute("SELECT c.* FROM clients c JOIN telegram_orders o ON o.client_id=c.id WHERE o.telegram_user_id=? AND o.status='approved' ORDER BY c.id DESC",(uid,)).fetchall(); c.close(); return rows

def tg_create_trial(uid):
    st=settings(); gb=float(st.get('telegram_trial_gb','1') or 1); days=int(st.get('telegram_trial_days','1') or 1)
    c=db(); u=c.execute('SELECT * FROM telegram_users WHERE telegram_user_id=?',(uid,)).fetchone()
    if not u or int(u['trial_used']): c.close(); raise ValueError('تست رایگان قبلاً استفاده شده است')
    c.execute('UPDATE telegram_users SET trial_used=1 WHERE telegram_user_id=?',(uid,)); c.commit(); c.close()
    order={'id':0,'telegram_user_id':uid,'gb':gb,'days':days}
    return tg_create_client(order)

def tg_wallet_charge(uid, amount):
    c=db(); u=c.execute('SELECT wallet FROM telegram_users WHERE telegram_user_id=?',(uid,)).fetchone()
    if not u or float(u['wallet']) < float(amount): c.close(); return False
    c.execute('UPDATE telegram_users SET wallet=wallet-? WHERE telegram_user_id=?',(float(amount),uid)); c.commit(); c.close(); return True

def tg_wallet(uid):
    c=db(); r=c.execute('SELECT wallet FROM telegram_users WHERE telegram_user_id=?',(uid,)).fetchone(); c.close(); return float(r['wallet']) if r else 0.0

def tg_price(key, fallback=0):
    try: return max(0, int(float(settings().get(key, fallback) or fallback)))
    except Exception: return int(fallback)

def tg_apply_paid_change(uid, cid, kind, amount):
    """Atomically charge wallet and apply a renewal/volume change to the owned service."""
    amount=float(amount)
    if amount <= 0: return False, 'قیمت این عملیات تنظیم نشده است.', 0
    c=db()
    try:
        c.execute('BEGIN IMMEDIATE')
        u=c.execute('SELECT wallet FROM telegram_users WHERE telegram_user_id=?',(uid,)).fetchone()
        r=c.execute("SELECT c.* FROM clients c JOIN telegram_orders o ON o.client_id=c.id WHERE c.id=? AND o.telegram_user_id=? AND o.status='approved' ORDER BY o.id DESC LIMIT 1",(cid,uid)).fetchone()
        if not u or not r:
            c.rollback(); return False,'سرویس پیدا نشد.',0
        wallet=float(u['wallet'])
        if wallet < amount:
            c.rollback(); return False,f'موجودی کافی نیست. موجودی فعلی: {tg_money(wallet)} تومان',wallet
        now=int(time.time())
        if kind=='renew':
            days=int(amount and 0)  # replaced by caller through the temporary field below
        c.execute('UPDATE telegram_users SET wallet=wallet-? WHERE telegram_user_id=?',(amount,uid))
        c.execute('INSERT INTO telegram_wallet_transactions(telegram_user_id,amount,kind,description,created_at) VALUES(?,?,?,?,?)',(uid,-amount,kind,kind,int(time.time())))
        c.commit()
        return True,'',wallet-amount
    except Exception as e:
        try:c.rollback()
        except Exception:pass
        return False,str(e),0
    finally:
        c.close()

def tg_charge_and_renew(uid, cid, days, price):
    c=db()
    try:
        c.execute('BEGIN IMMEDIATE')
        u=c.execute('SELECT wallet FROM telegram_users WHERE telegram_user_id=?',(uid,)).fetchone()
        r=c.execute("SELECT c.* FROM clients c JOIN telegram_orders o ON o.client_id=c.id WHERE c.id=? AND o.telegram_user_id=? AND o.status='approved' ORDER BY o.id DESC LIMIT 1",(cid,uid)).fetchone()
        if not u or not r: c.rollback(); return False,'سرویس پیدا نشد.',0,0
        wallet=float(u['wallet']); price=float(price)
        if wallet < price: c.rollback(); return False,f'موجودی کافی نیست. موجودی: {tg_money(wallet)} تومان',wallet,price
        base=max(int(r['expiry_at']),int(time.time())); newexp=base+int(days)*86400
        c.execute('UPDATE clients SET expiry_at=?,enabled=1 WHERE id=?',(newexp,cid))
        c.execute('UPDATE telegram_users SET wallet=wallet-? WHERE telegram_user_id=?',(price,uid))
        c.execute('INSERT INTO telegram_wallet_transactions(telegram_user_id,amount,kind,description,created_at) VALUES(?,?,?,?,?)',(uid,-price,'renew',f'{days} روز تمدید سرویس #{cid}',int(time.time())))
        c.commit(); return True,'',wallet-price,price
    except Exception as e:
        try:c.rollback()
        except Exception:pass
        return False,str(e),0,price
    finally:c.close()

def tg_charge_and_add_volume(uid, cid, gb, price):
    c=db()
    try:
        c.execute('BEGIN IMMEDIATE')
        u=c.execute('SELECT wallet FROM telegram_users WHERE telegram_user_id=?',(uid,)).fetchone()
        r=c.execute("SELECT c.* FROM clients c JOIN telegram_orders o ON o.client_id=c.id WHERE c.id=? AND o.telegram_user_id=? AND o.status='approved' ORDER BY o.id DESC LIMIT 1",(cid,uid)).fetchone()
        if not u or not r: c.rollback(); return False,'سرویس پیدا نشد.',0,0
        wallet=float(u['wallet']); price=float(price)
        if wallet < price: c.rollback(); return False,f'موجودی کافی نیست. موجودی: {tg_money(wallet)} تومان',wallet,price
        c.execute('UPDATE clients SET gb=gb+? WHERE id=?',(float(gb),cid))
        c.execute('UPDATE telegram_users SET wallet=wallet-? WHERE telegram_user_id=?',(price,uid))
        c.execute('INSERT INTO telegram_wallet_transactions(telegram_user_id,amount,kind,description,created_at) VALUES(?,?,?,?,?)',(uid,-price,'add_volume',f'+{gb:g} GB برای سرویس #{cid}',int(time.time())))
        c.commit(); return True,'',wallet-price,price
    except Exception as e:
        try:c.rollback()
        except Exception:pass
        return False,str(e),0,price
    finally:c.close()

def tg_plans():
    try:
        arr=json.loads(settings().get('telegram_plans','[]') or '[]')
        return [x for x in arr if isinstance(x,dict) and float(x.get('gb',0))>0 and int(x.get('days',0))>0][:20]
    except Exception: return []

def tg_payment_text():
    st=settings(); card=str(st.get('telegram_card_number','')).strip(); name=str(st.get('telegram_card_name','')).strip()
    custom=str(st.get('telegram_payment_text','')).strip()
    lines=[]
    if card:
        lines.append(f'<b>💳 شماره کارت:</b> <code>{html.escape(card)}</code>')
        if name: lines.append(f'<b>👤 به نام:</b> {html.escape(name)}')
        lines.append('بعد از واریز، روی «✅ پرداخت کردم» بزنید تا سفارش برای ادمین ارسال شود.')
    if custom: lines.append(html.escape(custom))
    return '\n'.join(lines) if lines else 'روش پرداخت توسط ادمین تنظیم نشده است.'

def tg_plan_keyboard():
    rows=[]
    for i,p in enumerate(tg_plans()):
        price=f" · {p.get('price')}" if str(p.get('price','')).strip() else ''
        rows.append([{'text':f"{p.get('name','پلن')} — {p.get('gb')}GB / {p.get('days')} روز{price}",'callback_data':f'plan:{i}'}])
    return rows

def tg_admin_id():
    try: return int(str(settings().get('telegram_admin_id','')).strip())
    except Exception: return 0


def tg_admin_wizard():
    try: return json.loads(settings().get('telegram_admin_wizard','{}') or '{}')
    except Exception: return {}

def tg_set_admin_wizard(state):
    set_setting('telegram_admin_wizard', json.dumps(state or {}, ensure_ascii=False))

def tg_clear_admin_wizard():
    set_setting('telegram_admin_wizard', '{}')

def tg_create_client(order):
    now=int(time.time()); sub_id=secrets.token_urlsafe(18); cuuid=str(uuid.uuid4()); name=f"TG-{order['id']}-{order['telegram_user_id']}"
    st=settings(); host=clean_host(st.get('node_host')) or clean_host(os.environ.get('RAILWAY_PUBLIC_DOMAIN'))
    dns_server=st.get('dns_server','')
    c=db(); c.execute('''INSERT INTO clients(name,uuid,sub_id,gb,days,created_at,expiry_at,protocol,transport,dns_server,wg_private_key,wg_address,dns_token,panel_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)''',(name,cuuid,sub_id,float(order['gb']),int(order['days']),now,now+int(order['days'])*86400,'vless','ws',dns_server,'','10.66.0.2/32',''))
    cid=c.execute('SELECT last_insert_rowid()').fetchone()[0]; c.commit(); row=c.execute('SELECT * FROM clients WHERE id=?',(cid,)).fetchone(); c.close(); restart_xray()
    sub=f'https://{host}/{st.get("sub_path","sub").strip("/")}/{sub_id}' if host else f'/{st.get("sub_path","sub").strip("/")}/{sub_id}'
    return cid,sub,row

def tg_handle_callback(cb):
    data=str(cb.get('data','')); uid=int(cb.get('from',{}).get('id',0)); tg_user(uid, {'chat': cb.get('from',{})}); chat_id=cb.get('message',{}).get('chat',{}).get('id',uid); mid=cb.get('message',{}).get('message_id')
    admin=tg_admin_id()
    if data=='home':
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,html.escape(settings().get('telegram_welcome_text','به فروشگاه VPNSTAN خوش آمدید.')),tg_main_keyboard(uid)); return
    if data=='account':
        u=tg_user(uid); trial='استفاده شده' if u['trial_used'] else 'قابل استفاده'; tg_answer(cb.get('id','')); tg_edit(chat_id,mid,f"<b>👤 حساب من</b>\n\nآیدی: <code>{uid}</code>\nموجودی کیف پول: <b>{tg_money(u['wallet'])}</b>\nکد دعوت: <code>{html.escape(u['referral_code'])}</code>\nتست رایگان: {trial}",[[{'text':'🏠 منوی اصلی','callback_data':'home'}]]); return
    if data=='wallet':
        card=str(settings().get('telegram_card_number','')).strip(); name=str(settings().get('telegram_card_name','')).strip()
        extra='\n\nبرای شارژ کیف پول، مبلغ را انتخاب کن تا شماره کارت و مبلغ دقیق واریزی نمایش داده شود.'
        if not card:
            extra='\n\n⚠️ هنوز شماره کارت توسط ادمین ثبت نشده است.'
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,f"<b>💳 کیف پول</b>\n\nموجودی فعلی: <b>{tg_money(tg_wallet(uid))} تومان</b>{extra}",[[{'text':'➕ شارژ کیف پول','callback_data':'wallet_topup'}],[{'text':'🏠 منوی اصلی','callback_data':'home'}]]); return
    if data=='wallet_topup':
        if not str(settings().get('telegram_card_number','')).strip():
            tg_answer(cb.get('id',''),'شماره کارت هنوز ثبت نشده است'); return
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>➕ شارژ کیف پول</b>\n\nمبلغ واریزی را انتخاب کن:',[[{'text':'💵 ۱۰۰ هزار تومان','callback_data':'wallet_amt:100000'},{'text':'💵 ۲۰۰ هزار تومان','callback_data':'wallet_amt:200000'}],[{'text':'💵 ۵۰۰ هزار تومان','callback_data':'wallet_amt:500000'},{'text':'💵 ۱ میلیون تومان','callback_data':'wallet_amt:1000000'}],[{'text':'↩️ بازگشت','callback_data':'wallet'}]]); return
    if data.startswith('wallet_amt:'):
        try: amount=float(data.split(':',1)[1])
        except: tg_answer(cb.get('id',''),'مبلغ نامعتبر است'); return
        card=str(settings().get('telegram_card_number','')).strip(); name=str(settings().get('telegram_card_name','')).strip()
        if not card: tg_answer(cb.get('id',''),'شماره کارت ثبت نشده است'); return
        c=db(); c.execute("INSERT INTO telegram_wallet_orders(telegram_user_id,amount,status,created_at) VALUES(?,?,?,?)",(uid,amount,'awaiting_payment',int(time.time()))); oid=c.execute('SELECT last_insert_rowid()').fetchone()[0]; c.commit(); c.close()
        pay=f"<b>💳 شارژ کیف پول</b>\n\nمبلغ قابل واریز: <b>{tg_money(amount)} تومان</b>\nشماره کارت: <code>{html.escape(card)}</code>"
        if name: pay += f"\nنام صاحب کارت: <b>{html.escape(name)}</b>"
        pay += f"\n\nپس از واریز دقیقاً <b>{tg_money(amount)} تومان</b>، روی دکمه «✅ پرداخت کردم» بزن.\nکد درخواست: <code>#{oid}</code>"
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,pay,[[{'text':'✅ پرداخت کردم','callback_data':f'wallet_paid:{oid}'}],[{'text':'❌ لغو','callback_data':'wallet'}]]); return
    if data.startswith('wallet_paid:'):
        try: oid=int(data.split(':',1)[1])
        except: tg_answer(cb.get('id',''),'درخواست نامعتبر است'); return
        c=db(); order=c.execute('SELECT * FROM telegram_wallet_orders WHERE id=? AND telegram_user_id=?',(oid,uid)).fetchone(); c.close()
        if not order: tg_answer(cb.get('id',''),'درخواست پیدا نشد'); return
        if order['status'] not in ('awaiting_payment','awaiting_receipt'): tg_answer(cb.get('id',''),'این درخواست قبلاً ثبت شده است'); return
        c=db(); c.execute("UPDATE telegram_wallet_orders SET status='awaiting_receipt' WHERE id=?",(oid,)); c.commit(); c.close()
        tg_answer(cb.get('id',''),'رسید را ارسال کن')
        tg_send(chat_id,f"<b>🧾 ارسال رسید شارژ #{oid}</b>\n\nمبلغ: <b>{tg_money(order['amount'])} تومان</b>\n\nحالا <b>عکس رسید پرداخت</b> را همینجا به‌صورت Photo ارسال کن.\nبعد از دریافت عکس، رسید به‌همراه مشخصات سفارش برای ادمین فرستاده می‌شود.",[[{'text':'❌ لغو','callback_data':'wallet'}]])
        return
    if data.startswith('wallet_approve:') or data.startswith('wallet_reject:'):
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین مجاز است'); return
        action,raw=data.split(':',1)
        try: oid=int(raw)
        except: tg_answer(cb.get('id',''),'درخواست نامعتبر است'); return
        c=db(); order=c.execute('SELECT * FROM telegram_wallet_orders WHERE id=?',(oid,)).fetchone(); c.close()
        if not order: tg_answer(cb.get('id',''),'درخواست پیدا نشد'); return
        if order['status']!='pending_admin': tg_answer(cb.get('id',''),'این درخواست قبلاً پردازش شده است'); return
        if action=='wallet_approve':
            c=db(); c.execute("UPDATE telegram_wallet_orders SET status='approved' WHERE id=?",(oid,)); c.execute("UPDATE telegram_users SET wallet=wallet+? WHERE telegram_user_id=?",(order['amount'],order['telegram_user_id'])); c.commit(); c.close(); tg_send(order['telegram_user_id'],f"✅ شارژ کیف پول تأیید شد.\n\nمبلغ اضافه‌شده: <b>{tg_money(order['amount'])} تومان</b>\nموجودی جدید: <b>{tg_money(tg_wallet(order['telegram_user_id']))} تومان</b>",[[{'text':'💳 کیف پول','callback_data':'wallet'}]]); tg_answer(cb.get('id',''),'شارژ تأیید شد'); tg_edit(chat_id,mid,f"✅ درخواست <b>#{oid}</b> تأیید شد.",[[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
        c=db(); c.execute("UPDATE telegram_wallet_orders SET status='rejected' WHERE id=?",(oid,)); c.commit(); c.close(); tg_send(order['telegram_user_id'],f"❌ درخواست شارژ <b>#{oid}</b> رد شد.",[[{'text':'💳 کیف پول','callback_data':'wallet'}]]); tg_answer(cb.get('id',''),'رد شد'); tg_edit(chat_id,mid,f"❌ درخواست <b>#{oid}</b> رد شد.",[[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='subs':
        rows=tg_user_clients(uid)
        if not rows:
            text='<b>📦 اشتراک‌های من</b>\n\nهنوز سرویس فعالی نداری.'
            kb=[[{'text':'🛒 خرید سرویس','callback_data':'plans'}],[{'text':'🏠 منوی اصلی','callback_data':'home'}]]
        else:
            text='<b>📦 اشتراک‌های من</b>\n\nروی هر سرویس بزن تا جزئیات کاملش را ببینی:'
            kb=[]
            for r in rows:
                tr=traffic_for(int(r['id'])); used=int(tr['upload'])+int(tr['download']); total=max(1,int(float(r['gb'])*1024**3)); rem=max(0,total-used)
                status='🟢 فعال' if int(r['enabled']) and (not r['expiry_at'] or int(r['expiry_at'])>int(time.time())) else '🔴 منقضی/غیرفعال'
                kb.append([{'text':f'{status} · {str(r["name"])[:28]} · {rem/1024**3:.1f}GB باقی','callback_data':f'service:{r["id"]}'}])
            kb += [[{'text':'🛒 خرید سرویس','callback_data':'plans'}],[{'text':'🏠 منوی اصلی','callback_data':'home'}]]
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,text,kb); return
    if data.startswith('service:'):
        try: cid=int(data.split(':',1)[1])
        except: tg_answer(cb.get('id',''),'سرویس نامعتبر'); return
        c=db(); r=c.execute("SELECT c.* FROM clients c JOIN telegram_orders o ON o.client_id=c.id WHERE c.id=? AND o.telegram_user_id=? AND o.status='approved' ORDER BY o.id DESC LIMIT 1",(cid,uid)).fetchone(); c.close()
        if not r: tg_answer(cb.get('id',''),'سرویس پیدا نشد'); return
        tr=traffic_for(cid); used=int(tr['upload'])+int(tr['download']); total=max(1,int(float(r['gb'])*1024**3)); rem=max(0,total-used); pct=min(100,used/total*100)
        now=int(time.time()); days_left=max(0,((int(r['expiry_at'])-now)+86399)//86400) if r['expiry_at'] else 0
        st=settings(); host=clean_host(st.get('node_host')) or clean_host(os.environ.get('RAILWAY_PUBLIC_DOMAIN')); sub=f'https://{host}/{st.get("sub_path","sub").strip("/")}/{r["sub_id"]}' if host else f'/{st.get("sub_path","sub").strip("/")}/{r["sub_id"]}'
        status='🟢 فعال' if int(r['enabled']) and (not r['expiry_at'] or int(r['expiry_at'])>now) and rem>0 else '🔴 منقضی/غیرفعال'
        text=(f'<b>📦 جزئیات سرویس</b>\n\n<b>نام:</b> {html.escape(r["name"])}\n<b>وضعیت:</b> {status}\n<b>حجم کل:</b> {float(r["gb"]):g} GB\n<b>مصرف:</b> {used/1024**3:.2f} GB ({pct:.1f}%)\n<b>باقی‌مانده:</b> {rem/1024**3:.2f} GB\n<b>اعتبار باقی‌مانده:</b> {days_left} روز\n<b>تاریخ انقضا:</b> {fmt_date(r["expiry_at"])}\n<b>پروتکل:</b> {str(r["protocol"] or "VLESS").upper()}\n<b>انتقال:</b> {str(r["transport"] or "WS").upper()}\n<b>ساخته‌شده:</b> {fmt_date(r["created_at"])}\n\n<b>🔗 لینک اشتراک:</b>\n<code>{html.escape(sub)}</code>')
        kb=[]
        if sub.startswith('http'): kb.append([{'text':'📋 دریافت لینک اشتراک','url':sub}])
        kb += [[{'text':'🔄 تمدید','callback_data':f'renew:{cid}'},{'text':'➕ حجم اضافه','callback_data':f'addvol:{cid}'}],[{'text':'🔙 اشتراک‌های من','callback_data':'subs'}],[{'text':'🏠 منوی اصلی','callback_data':'home'}]]
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,text,kb); return
    if data.startswith('renew:') or data.startswith('addvol:'):
        try: cid=int(data.split(':',1)[1])
        except: cid=0
        rows=tg_user_clients(uid); r=next((x for x in rows if int(x['id'])==cid),None)
        if not r: tg_answer(cb.get('id',''),'سرویس پیدا نشد'); return
        tg_answer(cb.get('id',''))
        if data.startswith('renew:'):
            p7=tg_price('telegram_renew_7_price',30000); p30=tg_price('telegram_renew_30_price',100000); p90=tg_price('telegram_renew_90_price',250000)
            tg_edit(chat_id,mid,'<b>🔄 تمدید سرویس</b>\n\nمدت و قیمت را انتخاب کن:',[[{'text':f'➕ 7 روز · {tg_money(p7)} تومان','callback_data':f'renewdays:{cid}:7'},{'text':f'➕ 30 روز · {tg_money(p30)} تومان','callback_data':f'renewdays:{cid}:30'}],[{'text':f'➕ 90 روز · {tg_money(p90)} تومان','callback_data':f'renewdays:{cid}:90'}],[{'text':'🔙 بازگشت','callback_data':f'service:{cid}'}]])
        else:
            p5=tg_price('telegram_add_5_price',30000); p10=tg_price('telegram_add_10_price',50000); p25=tg_price('telegram_add_25_price',100000)
            tg_edit(chat_id,mid,'<b>➕ حجم اضافه</b>\n\nحجم و قیمت را انتخاب کن:',[[{'text':f'+5 GB · {tg_money(p5)} تومان','callback_data':f'addgb:{cid}:5'},{'text':f'+10 GB · {tg_money(p10)} تومان','callback_data':f'addgb:{cid}:10'}],[{'text':f'+25 GB · {tg_money(p25)} تومان','callback_data':f'addgb:{cid}:25'}],[{'text':'🔙 بازگشت','callback_data':f'service:{cid}'}]])
        return
    if data.startswith('renewdays:') or data.startswith('addgb:'):
        parts=data.split(':'); cid=int(parts[1]); value=float(parts[2]); rows=tg_user_clients(uid); r=next((x for x in rows if int(x['id'])==cid),None)
        if not r: tg_answer(cb.get('id',''),'سرویس پیدا نشد'); return
        if data.startswith('renewdays:'):
            price={7:tg_price('telegram_renew_7_price',30000),30:tg_price('telegram_renew_30_price',100000),90:tg_price('telegram_renew_90_price',250000)}.get(int(value),0)
            label=f'{int(value)} روز تمدید'
            confirm=f'renewconfirm:{cid}:{int(value)}'
        else:
            price={5:tg_price('telegram_add_5_price',30000),10:tg_price('telegram_add_10_price',50000),25:tg_price('telegram_add_25_price',100000)}.get(int(value),0)
            label=f'{value:g} GB حجم اضافه'
            confirm=f'addvolconfirm:{cid}:{value:g}'
        wallet=tg_wallet(uid)
        enough=wallet>=price
        text=f'<b>تأیید عملیات</b>\n\n{label}\nهزینه: <b>{tg_money(price)} تومان</b>\nموجودی فعلی: <b>{tg_money(wallet)} تومان</b>\nموجودی پس از پرداخت: <b>{tg_money(wallet-price)} تومان</b>' if enough else f'<b>❌ موجودی کافی نیست</b>\n\n{label}\nهزینه: <b>{tg_money(price)} تومان</b>\nموجودی فعلی: <b>{tg_money(wallet)} تومان</b>\n\nابتدا کیف پول را شارژ کن.'
        kb=[[{'text':'✅ تأیید و پرداخت','callback_data':confirm}]] if enough else [[{'text':'💳 شارژ کیف پول','callback_data':'wallet_topup'}]]
        kb.append([{'text':'🔙 بازگشت به سرویس','callback_data':f'service:{cid}'}])
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,text,kb); return
    if data.startswith('renewconfirm:'):
        try: _,cid_s,days_s=data.split(':',2); cid=int(cid_s); days=int(days_s)
        except: tg_answer(cb.get('id',''),'درخواست نامعتبر'); return
        prices={7:tg_price('telegram_renew_7_price',30000),30:tg_price('telegram_renew_30_price',100000),90:tg_price('telegram_renew_90_price',250000)}
        price=prices.get(days,0)
        ok,msg,newwallet,charged=tg_charge_and_renew(uid,cid,days,price)
        if not ok: tg_answer(cb.get('id',''),msg); tg_edit(chat_id,mid,f'❌ {html.escape(msg)}',[[{'text':'💳 شارژ کیف پول','callback_data':'wallet_topup'},{'text':'🔙 سرویس','callback_data':f'service:{cid}'}]]); return
        restart_xray(); tg_answer(cb.get('id',''),'پرداخت و تمدید با موفقیت انجام شد'); tg_edit(chat_id,mid,f'✅ <b>سرویس تمدید شد</b>\n\nمدت: {days} روز\nهزینه: {tg_money(charged)} تومان\nموجودی جدید: {tg_money(newwallet)} تومان',[[{'text':'📦 مشاهده سرویس','callback_data':f'service:{cid}'}],[{'text':'🏠 منوی اصلی','callback_data':'home'}]]); return
    if data.startswith('addvolconfirm:'):
        try: _,cid_s,gb_s=data.split(':',2); cid=int(cid_s); gb=float(gb_s)
        except: tg_answer(cb.get('id',''),'درخواست نامعتبر'); return
        prices={5:tg_price('telegram_add_5_price',30000),10:tg_price('telegram_add_10_price',50000),25:tg_price('telegram_add_25_price',100000)}
        price=prices.get(int(gb),0)
        ok,msg,newwallet,charged=tg_charge_and_add_volume(uid,cid,gb,price)
        if not ok: tg_answer(cb.get('id',''),msg); tg_edit(chat_id,mid,f'❌ {html.escape(msg)}',[[{'text':'💳 شارژ کیف پول','callback_data':'wallet_topup'},{'text':'🔙 سرویس','callback_data':f'service:{cid}'}]]); return
        restart_xray(); tg_answer(cb.get('id',''),'پرداخت و حجم اضافه شد'); tg_edit(chat_id,mid,f'✅ <b>حجم سرویس افزایش یافت</b>\n\nحجم اضافه: {gb:g} GB\nهزینه: {tg_money(charged)} تومان\nموجودی جدید: {tg_money(newwallet)} تومان',[[{'text':'📦 مشاهده سرویس','callback_data':f'service:{cid}'}],[{'text':'🏠 منوی اصلی','callback_data':'home'}]]); return
    if data=='trial':
        if settings().get('telegram_trial_enabled','1')!='1': tg_answer(cb.get('id',''),'تست رایگان غیرفعال است'); return
        try:
            cid,sub,row=tg_create_trial(uid); tg_answer(cb.get('id',''),'تست ساخته شد'); tg_edit(chat_id,mid,f"<b>🎁 تست رایگان فعال شد</b>\n\nحجم: {row['gb']} GB\nاعتبار: {int(settings().get('telegram_trial_days','1'))} روز\n\n<code>{html.escape(sub)}</code>",[[{'text':'🏠 منوی اصلی','callback_data':'home'}]])
        except Exception as e: tg_answer(cb.get('id',''),str(e))
        return
    if data in ('renew','addvol'):
        rows=tg_user_clients(uid)
        if not rows: tg_answer(cb.get('id',''),'اشتراک فعالی ندارید'); return
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'برای تمدید یا خرید حجم اضافه، ابتدا پلن جدید را انتخاب کنید.',[[{'text':'🛒 خرید پلن','callback_data':'plans'}],[{'text':'🏠 منوی اصلی','callback_data':'home'}]]); return
    if data=='ref':
        u=tg_user(uid); bot=''
        try: bot=tg_api('getMe',{},10).get('username','')
        except: pass
        link=f'https://t.me/{bot}?start=ref_{u["referral_code"]}' if bot else f'ref_{u["referral_code"]}'
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,f"<b>🤝 دعوت دوستان</b>\n\nکد شما: <code>{u['referral_code']}</code>\nلینک دعوت:\n<code>{html.escape(link)}</code>\n\nپاداش فعلی: {settings().get('telegram_referral_reward','1')} GB",[[{'text':'🏠 منوی اصلی','callback_data':'home'}]]); return
    if data=='support':
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>🎫 پشتیبانی</b>\n\n'+html.escape(settings().get('telegram_support_text','پیام خود را ارسال کنید.')),[[{'text':'🏠 منوی اصلی','callback_data':'home'}]]); return
    if data=='admin':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>🛠 مدیریت ربات VPNSTAN</b>\n\nهمه تنظیمات فروشگاه از همین ربات انجام می‌شود.\n\nبرای شماره کارت، پلن‌ها، آمار، پیام همگانی و تنظیمات از منوی زیر استفاده کنید.',tg_admin_keyboard()); return
    if data=='admin_users':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        c=db(); rows=c.execute('SELECT * FROM telegram_users ORDER BY last_seen DESC LIMIT 20').fetchall(); c.close()
        kb=[[{'text':f'👤 {str(r["first_name"] or r["username"] or r["telegram_user_id"])[:24]} · {tg_money(r["wallet"])} تومان','callback_data':f'admin_user:{r["telegram_user_id"]}'}] for r in rows]
        kb.append([{'text':'🛠 مدیریت ربات','callback_data':'admin'}]); tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>👥 کاربران</b>\n\nیک کاربر را انتخاب کن:',kb); return
    if data.startswith('admin_user:'):
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        target=int(data.split(':',1)[1]); c=db(); u=c.execute('SELECT * FROM telegram_users WHERE telegram_user_id=?',(target,)).fetchone(); orders=c.execute('SELECT COUNT(*) n FROM telegram_orders WHERE telegram_user_id=?',(target,)).fetchone()['n']; sv=c.execute("SELECT COUNT(*) n FROM telegram_orders WHERE telegram_user_id=? AND status='approved'",(target,)).fetchone()['n']; c.close()
        if not u: tg_answer(cb.get('id',''),'کاربر پیدا نشد'); return
        text=f'<b>👤 پروفایل کاربر</b>\n\nID: <code>{target}</code>\nنام: {html.escape(u["first_name"] or "-")}\nUsername: @{html.escape(u["username"] or "-")}\nکیف پول: <b>{tg_money(u["wallet"])} تومان</b>\nسفارش‌ها: {orders}\nسرویس‌های تأییدشده: {sv}\nثبت‌نام: {fmt_date(u["created_at"])}'
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,text,[[{'text':'💰 افزایش موجودی','callback_data':f'admin_walletadd:{target}'},{'text':'📦 سرویس‌ها','callback_data':f'admin_userservices:{target}'}],[{'text':'👥 کاربران','callback_data':'admin_users'},{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data.startswith('admin_walletadd:'):
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        target=int(data.split(':',1)[1]); tg_set_admin_wizard({'type':'wallet','step':'amount','data':{'uid':target}}); tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>💰 افزایش موجودی</b>\n\nمبلغ به تومان را ارسال کن؛ مثلاً <code>200000</code>.\nبرای لغو: /cancel',[[{'text':'❌ لغو','callback_data':'admin_cancel_wizard'}]]); return
    if data.startswith('admin_userservices:'):
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        target=int(data.split(':',1)[1]); rows=tg_user_clients(target); kb=[[{'text':f'📦 {str(r["name"])[:26]}','callback_data':f'admin_service:{r["id"]}'}] for r in rows]
        kb.append([{'text':'👤 بازگشت','callback_data':f'admin_user:{target}'}]); tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>📦 سرویس‌های کاربر</b>',kb or [[{'text':'بدون سرویس','callback_data':f'admin_user:{target}'}]]); return
    if data.startswith('admin_service:'):
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        cid=int(data.split(':',1)[1]); c=db(); r=c.execute('SELECT * FROM clients WHERE id=?',(cid,)).fetchone(); c.close()
        if not r: tg_answer(cb.get('id',''),'سرویس پیدا نشد'); return
        tr=traffic_for(cid); used=int(tr['upload'])+int(tr['download']); rem=max(0,int(float(r['gb'])*1024**3)-used); text=f'<b>📦 مدیریت سرویس</b>\n\nنام: <b>{html.escape(r["name"])}</b>\nوضعیت: {"فعال" if r["enabled"] else "غیرفعال"}\nحجم: {r["gb"]} GB\nمصرف: {used/1024**3:.2f} GB\nباقی: {rem/1024**3:.2f} GB\nانقضا: {fmt_date(r["expiry_at"])}'
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,text,[[{'text':'⏸ غیرفعال کردن' if r['enabled'] else '▶️ فعال کردن','callback_data':f'admin_toggle_service:{cid}'}],[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data.startswith('admin_toggle_service:'):
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        cid=int(data.split(':',1)[1]); c=db(); r=c.execute('SELECT enabled FROM clients WHERE id=?',(cid,)).fetchone()
        if not r: c.close(); tg_answer(cb.get('id',''),'سرویس پیدا نشد'); return
        new=0 if int(r['enabled']) else 1; c.execute('UPDATE clients SET enabled=? WHERE id=?',(new,cid)); c.commit(); c.close(); restart_xray(); tg_answer(cb.get('id',''),'وضعیت تغییر کرد'); tg_edit(chat_id,mid,'✅ وضعیت سرویس تغییر کرد.',[[{'text':'📦 سرویس','callback_data':f'admin_service:{cid}'}],[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='admin_services':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        c=db(); rows=c.execute('SELECT * FROM clients ORDER BY id DESC LIMIT 20').fetchall(); c.close(); kb=[[{'text':f'📦 {str(r["name"])[:25]} · {r["gb"]}GB','callback_data':f'admin_service:{r["id"]}'}] for r in rows]; kb.append([{'text':'🛠 مدیریت ربات','callback_data':'admin'}]); tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>📦 سرویس‌های سیستم</b>\n\nسرویس را انتخاب کن:',kb); return
    if data=='admin_orders':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        c=db(); rows=c.execute('SELECT * FROM telegram_orders ORDER BY id DESC LIMIT 15').fetchall(); c.close(); labels={'awaiting_payment':'💳 منتظر پرداخت','pending_admin':'⏳ در انتظار تأیید','approved':'✅ تأیید','rejected':'❌ رد'}
        lines=['<b>🧾 آخرین سفارش‌ها</b>']+[f'#{r["id"]} · {html.escape(r["plan_name"])} · {labels.get(r["status"],r["status"])} · {r["gb"]}GB' for r in rows]
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'\n'.join(lines),tg_admin_keyboard()); return
    if data=='admin_payments':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        c=db(); rows=c.execute("SELECT * FROM telegram_wallet_orders ORDER BY id DESC LIMIT 15").fetchall(); c.close(); labels={'awaiting_payment':'💳 منتظر پرداخت','pending_admin':'⏳ در انتظار تأیید','approved':'✅ تأیید','rejected':'❌ رد'}
        kb=[[{'text':f'#{r["id"]} · {tg_money(r["amount"])} تومان · {labels.get(r["status"],r["status"])}','callback_data':f'walletorder:{r["id"]}'}] for r in rows]; kb.append([{'text':'🛠 مدیریت ربات','callback_data':'admin'}]); tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>💰 درخواست‌های شارژ کیف پول</b>\n\nیک درخواست را انتخاب کن:',kb); return
    if data.startswith('walletorder:'):
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        oid=int(data.split(':',1)[1]); c=db(); r=c.execute('SELECT * FROM telegram_wallet_orders WHERE id=?',(oid,)).fetchone(); c.close()
        if not r: tg_answer(cb.get('id',''),'درخواست پیدا نشد'); return
        receipt_note='\nرسید: ✅ دریافت شده' if r['receipt_file_id'] else ''
        text=f'<b>💰 درخواست شارژ #{oid}</b>\n\nکاربر: <code>{r["telegram_user_id"]}</code>\nمبلغ: <b>{tg_money(r["amount"])} تومان</b>\nوضعیت: {html.escape(r["status"])}{receipt_note}\nتاریخ: {fmt_date(r["created_at"])}'
        kb=[]
        if r['status']=='pending_admin': kb.append([{'text':'✅ تأیید','callback_data':f'approvewallet:{oid}'},{'text':'❌ رد','callback_data':f'rejectwallet:{oid}'}])
        kb.append([{'text':'💰 پرداخت‌ها','callback_data':'admin_payments'},{'text':'🛠 مدیریت ربات','callback_data':'admin'}]); tg_answer(cb.get('id','')); tg_edit(chat_id,mid,text,kb); return
    if data.startswith('approvewallet:') or data.startswith('rejectwallet:'):
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        oid=int(data.split(':',1)[1]); c=db(); r=c.execute('SELECT * FROM telegram_wallet_orders WHERE id=?',(oid,)).fetchone()
        if not r: c.close(); tg_answer(cb.get('id',''),'درخواست پیدا نشد'); return
        if r['status']!='pending_admin': c.close(); tg_answer(cb.get('id',''),'قبلاً پردازش شده'); return
        if data.startswith('approvewallet:'):
            c.execute("UPDATE telegram_wallet_orders SET status='approved' WHERE id=?",(oid,)); c.execute('UPDATE telegram_users SET wallet=wallet+? WHERE telegram_user_id=?',(r['amount'],r['telegram_user_id'])); c.commit(); c.close(); tg_send(r['telegram_user_id'],f'✅ شارژ کیف پول شما تأیید شد.\nمبلغ: <b>{tg_money(r["amount"])} تومان</b>\nموجودی جدید: <b>{tg_money(tg_wallet(r["telegram_user_id"]))} تومان</b>'); msg='✅ درخواست شارژ تأیید شد.'
        else:
            c.execute("UPDATE telegram_wallet_orders SET status='rejected' WHERE id=?",(oid,)); c.commit(); c.close(); tg_send(r['telegram_user_id'],f'❌ درخواست شارژ #{oid} رد شد.'); msg='❌ درخواست شارژ رد شد.'
        tg_answer(cb.get('id',''),msg); tg_edit(chat_id,mid,msg,[[{'text':'💰 پرداخت‌ها','callback_data':'admin_payments'}],[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='admin_card':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        st=settings(); card=st.get('telegram_card_number','') or 'ثبت نشده'; name=st.get('telegram_card_name','') or 'ثبت نشده'
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,f'<b>💳 اطلاعات پرداخت</b>\n\nشماره کارت: <code>{html.escape(card)}</code>\nنام صاحب کارت: <b>{html.escape(name)}</b>\n\nبرای تغییر، فقط دکمه ثبت کارت را بزن؛ ربات مرحله‌به‌مرحله شماره کارت و نام صاحب کارت را می‌پرسد.',[[{'text':'➕ ثبت / تغییر کارت','callback_data':'admin_card_add'}],[{'text':'🗑 حذف شماره کارت','callback_data':'admin_card_delete'}],[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='admin_card_add':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        tg_set_admin_wizard({'type':'card','step':'number'}); tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>💳 ثبت شماره کارت</b>\n\nمرحله ۱ از ۲\nشماره کارت ۱۶ رقمی را همینجا ارسال کن.\n\nبرای لغو: /cancel',[[{'text':'❌ لغو','callback_data':'admin_cancel_wizard'}]]); return
    if data=='admin_card_delete':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        set_setting('telegram_card_number',''); set_setting('telegram_card_name',''); tg_answer(cb.get('id',''),'حذف شد'); tg_edit(chat_id,mid,'✅ اطلاعات کارت حذف شد.',[[{'text':'💳 اطلاعات پرداخت','callback_data':'admin_card'},{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='admin_stats':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        c=db(); users=c.execute('SELECT COUNT(*) n FROM telegram_users').fetchone()['n']; orders=c.execute('SELECT COUNT(*) n FROM telegram_orders').fetchone()['n']; approved=c.execute("SELECT COUNT(*) n FROM telegram_orders WHERE status='approved'").fetchone()['n']; pending=c.execute("SELECT COUNT(*) n FROM telegram_orders WHERE status='pending_admin'").fetchone()['n']; tickets=c.execute("SELECT COUNT(*) n FROM telegram_tickets WHERE status='open'").fetchone()['n']; c.close()
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,f'<b>📊 آمار ربات</b>\n\nکاربران: {users}\nسفارش‌ها: {orders}\nتأییدشده: {approved}\nدر انتظار تأیید: {pending}\nتیکت باز: {tickets}',[[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='admin_prices':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        st=settings(); text=(f'<b>💰 قیمت‌های تمدید و حجم اضافه</b>\n\n'
            f'تمدید 7 روز: <b>{tg_money(st.get("telegram_renew_7_price",30000))}</b> تومان\n'
            f'تمدید 30 روز: <b>{tg_money(st.get("telegram_renew_30_price",100000))}</b> تومان\n'
            f'تمدید 90 روز: <b>{tg_money(st.get("telegram_renew_90_price",250000))}</b> تومان\n\n'
            f'+5 GB: <b>{tg_money(st.get("telegram_add_5_price",30000))}</b> تومان\n'
            f'+10 GB: <b>{tg_money(st.get("telegram_add_10_price",50000))}</b> تومان\n'
            f'+25 GB: <b>{tg_money(st.get("telegram_add_25_price",100000))}</b> تومان\n\n'
            'برای تغییر: /setrenewprices 30000 100000 250000\n<code>/setvolprices 30000 50000 100000</code>')
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,text,[[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='admin_settings':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        st=settings(); tg_answer(cb.get('id','')); tg_edit(chat_id,mid,f'<b>⚙️ تنظیمات فروشگاه</b>\n\nخوش‌آمدگویی: {html.escape(st.get("telegram_welcome_text", ""))}\nتست رایگان: {"فعال" if st.get("telegram_trial_enabled","1")=="1" else "غیرفعال"}\nحجم تست: {st.get("telegram_trial_gb","1")} GB\nمدت تست: {st.get("telegram_trial_days","1")} روز\nپاداش دعوت: {st.get("telegram_referral_reward","1")} GB\nکانال اجباری: {html.escape(st.get("telegram_mandatory_channel","") or "ندارد")}\n\nبرای تغییر از دستورهای ربات استفاده کن: /setwelcome /settrial /setref /setchannel',[[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='admin_plans':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        arr=tg_plans(); lines=['<b>🛒 مدیریت پلن‌ها</b>']
        if arr:
            lines += ['\n<b>پلن‌های فعلی:</b>'] + [f'{i+1}. {html.escape(str(x.get("name","پلن")))} — {x.get("gb")}GB / {x.get("days")} روز — {html.escape(str(x.get("price","") or "بدون قیمت"))}' for i,x in enumerate(arr)]
        else: lines.append('\nهنوز هیچ پلنی ثبت نشده است.')
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'\n'.join(lines),[[{'text':'➕ افزودن پلن جدید','callback_data':'admin_addplan'}],[{'text':'🗑 حذف یک پلن','callback_data':'admin_deleteplan'}],[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='admin_addplan':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        tg_set_admin_wizard({'type':'plan','step':'name','data':{}}); tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>➕ افزودن پلن جدید</b>\n\nمرحله ۱ از ۴\nنام پلن را بفرست؛ مثلاً: <code>اقتصادی 30 روزه</code>\n\nبرای لغو: /cancel',[[{'text':'❌ لغو','callback_data':'admin_cancel_wizard'}]]); return
    if data=='admin_deleteplan':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        arr=tg_plans()
        if not arr: tg_answer(cb.get('id',''),'پلنی وجود ندارد'); return
        rows=[[{'text':f'🗑 {i+1}. {str(x.get("name","پلن"))} — {x.get("gb")}GB / {x.get("days")} روز','callback_data':f'admin_delplan:{i}'}] for i,x in enumerate(arr)]
        rows.append([{'text':'🔙 بازگشت','callback_data':'admin_plans'}]); tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>🗑 حذف پلن</b>\n\nروی پلنی که می‌خواهی حذف شود بزن:',rows); return
    if data.startswith('admin_delplan:'):
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        try:
            idx=int(data.split(':',1)[1]); arr=tg_plans(); removed=arr.pop(idx); set_setting('telegram_plans',json.dumps(arr,ensure_ascii=False)); tg_answer(cb.get('id',''),'پلن حذف شد'); tg_edit(chat_id,mid,f'✅ پلن «{html.escape(str(removed.get("name","پلن")))}» حذف شد.',[[{'text':'🛒 مدیریت پلن‌ها','callback_data':'admin_plans'},{'text':'🛠 مدیریت ربات','callback_data':'admin'}]])
        except Exception: tg_answer(cb.get('id',''),'پلن نامعتبر است')
        return
    if data=='admin_cancel_wizard':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        tg_clear_admin_wizard(); tg_answer(cb.get('id',''),'لغو شد'); tg_edit(chat_id,mid,'عملیات لغو شد.',[[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='admin_plan_noprice':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        wiz=tg_admin_wizard()
        if wiz.get('type')!='plan' or wiz.get('step')!='price': tg_answer(cb.get('id',''),'عملیات منقضی شده است'); return
        data2=wiz.get('data',{}); data2['price']=''; arr=tg_plans(); arr.append(data2); set_setting('telegram_plans',json.dumps(arr[:20],ensure_ascii=False)); tg_clear_admin_wizard(); tg_answer(cb.get('id',''),'پلن ساخته شد'); tg_edit(chat_id,mid,f'🎉 پلن «{html.escape(str(data2.get("name","پلن")))}» ساخته شد.\n\nحجم: {data2.get("gb")} GB\nمدت: {data2.get("days")} روز\nقیمت: بدون قیمت',[[{'text':'➕ افزودن پلن دیگر','callback_data':'admin_addplan'},{'text':'🛒 مدیریت پلن‌ها','callback_data':'admin_plans'}],[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='admin_tickets':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        c=db(); rows=c.execute("SELECT * FROM telegram_tickets WHERE status='open' ORDER BY id DESC LIMIT 10").fetchall(); c.close(); lines=['<b>🎫 تیکت‌های باز</b>']
        for r in rows: lines.append(f'\n#{r["id"]} · کاربر <code>{r["telegram_user_id"]}</code>\n{html.escape(r["text"])}')
        lines += ['','پاسخ: <code>/reply TICKET_ID متن</code>']
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'\n'.join(lines),[[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='admin_broadcast':
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>📢 پیام همگانی</b>\n\nمتن را با این دستور ارسال کن:\n<code>/broadcast متن پیام</code>',[[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
    if data=='plans':
        tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'<b>پلن‌های فروش VPNSTAN</b>\nیک پلن را انتخاب کنید:',tg_plan_keyboard()); return
    if data=='myorders':
        c=db(); rows=c.execute('SELECT * FROM telegram_orders WHERE telegram_user_id=? ORDER BY id DESC LIMIT 10',(uid,)).fetchall(); c.close(); labels={'awaiting_payment':'منتظر پرداخت','pending_admin':'منتظر تأیید','approved':'تأیید شده','rejected':'رد شده','created':'ثبت شده'}; lines=['<b>سفارش‌های شما</b>']; lines += [f"#{r['id']} · {html.escape(r['plan_name'])} · {labels.get(r['status'],r['status'])}" for r in rows]; tg_answer(cb.get('id','')); tg_edit(chat_id,mid,'\n'.join(lines) if rows else 'هنوز سفارشی ندارید.',[[{'text':'🛒 پلن‌ها','callback_data':'plans'}]]); return
    if data.startswith('plan:'):
        try:i=int(data.split(':',1)[1]); plan=tg_plans()[i]
        except Exception: tg_answer(cb.get('id',''),'پلن پیدا نشد'); return
        username=cb.get('from',{}).get('username') or cb.get('from',{}).get('first_name') or str(uid)
        c=db(); cur=c.execute('INSERT INTO telegram_orders(telegram_user_id,username,plan_name,gb,days,price,status,created_at) VALUES(?,?,?,?,?,?,?,?)',(uid,username,str(plan.get('name','VPNSTAN')),float(plan['gb']),int(plan['days']),str(plan.get('price','')),'awaiting_payment',int(time.time()))); oid=cur.lastrowid; c.commit(); c.close()
        price=f"\n💳 قیمت: <b>{html.escape(str(plan.get('price','')))}</b>" if str(plan.get('price','')).strip() else ''
        pay=tg_payment_text()
        tg_answer(cb.get('id',''),'سفارش ثبت شد')
        tg_edit(chat_id,mid,f"<b>سفارش #{oid}</b>\nپلن: {html.escape(str(plan.get('name','')))}\nحجم: {plan['gb']} GB\nاعتبار: {plan['days']} روز{price}\n\n{pay}",[[{'text':'✅ پرداخت کردم','callback_data':f'paid:{oid}'}],[{'text':'🔙 بازگشت به پلن‌ها','callback_data':'plans'}]])
        return
    if data.startswith('paid:'):
        try: oid=int(data.split(':',1)[1])
        except: tg_answer(cb.get('id',''),'سفارش نامعتبر'); return
        c=db(); order=c.execute('SELECT * FROM telegram_orders WHERE id=?',(oid,)).fetchone()
        if not order or int(order['telegram_user_id'])!=uid: c.close(); tg_answer(cb.get('id',''),'سفارش پیدا نشد'); return
        if order['status'] not in ('awaiting_payment','created'): c.close(); tg_answer(cb.get('id',''),'این سفارش قبلاً بررسی شده است'); return
        c.execute("UPDATE telegram_orders SET status='pending_admin' WHERE id=?",(oid,)); c.commit(); c.close(); tg_answer(cb.get('id',''),'برای ادمین ارسال شد')
        tg_send(chat_id,f"<b>سفارش #{oid}</b> ثبت شد و منتظر تأیید ادمین است.")
        if admin:
            uname=html.escape(order['username'] or str(uid)); price=html.escape(order['price'] or 'بدون قیمت')
            tg_send(admin,f"<b>سفارش جدید #{oid}</b>\nکاربر: @{uname}\nTelegram ID: <code>{uid}</code>\nپلن: {html.escape(order['plan_name'])}\nحجم: {order['gb']} GB\nاعتبار: {order['days']} روز\nقیمت: {price}",[[{'text':'✅ تأیید و ساخت کانفیگ','callback_data':f'approve:{oid}'},{'text':'❌ رد سفارش','callback_data':f'reject:{oid}'}]])
        return
    if data.startswith('approve:') or data.startswith('reject:'):
        if uid!=admin: tg_answer(cb.get('id',''),'فقط ادمین ربات مجاز است'); return
        action,raw=data.split(':',1)
        try: oid=int(raw)
        except: tg_answer(cb.get('id',''),'شناسه نامعتبر'); return
        c=db(); order=c.execute('SELECT * FROM telegram_orders WHERE id=?',(oid,)).fetchone(); c.close()
        if not order: tg_answer(cb.get('id',''),'سفارش پیدا نشد'); return
        if action=='reject':
            c=db(); c.execute("UPDATE telegram_orders SET status='rejected' WHERE id=?",(oid,)); c.commit(); c.close(); tg_send(order['telegram_user_id'],f'❌ سفارش <b>#{oid}</b> رد شد. برای پیگیری با پشتیبانی تماس بگیرید.'); tg_answer(cb.get('id',''),'سفارش رد شد'); return
        if order['status'] not in ('pending_admin','awaiting_payment'): tg_answer(cb.get('id',''),'این سفارش قبلاً پردازش شده است'); return
        try:
            cid,sub,row=tg_create_client(order)
            c=db(); c.execute("UPDATE telegram_orders SET status='approved',client_id=? WHERE id=?",(cid,oid)); c.commit(); c.close()
            tg_send(order['telegram_user_id'],f"<b>✅ سفارش #{oid} تأیید شد</b>\n\nنام کانفیگ: <code>{html.escape(row['name'])}</code>\nحجم: {order['gb']} GB\nاعتبار: {order['days']} روز\n\n<b>Subscription:</b>\n<code>{html.escape(sub)}</code>",[[{'text':'📋 کپی لینک','url':sub}]] if sub.startswith('http') else None)
            tg_answer(cb.get('id',''),'کانفیگ ساخته شد')
        except Exception as e:
            tg_answer(cb.get('id',''),'ساخت کانفیگ ناموفق بود')
            tg_send(admin,f'⚠️ خطا در ساخت سفارش #{oid}: <code>{html.escape(str(e))}</code>')

def tg_handle_message(msg):
    chat=msg.get('chat',{}); uid=int(chat.get('id',0)); text=str(msg.get('text','')).strip(); admin=tg_admin_id()

    # Wallet receipt flow: after "پرداخت کردم", the next photo is attached to the order
    # and forwarded to the configured admin with approve/reject controls.
    photos=msg.get('photo') or []
    if photos:
        c=db(); order=c.execute("SELECT * FROM telegram_wallet_orders WHERE telegram_user_id=? AND status='awaiting_receipt' ORDER BY id DESC LIMIT 1",(uid,)).fetchone(); c.close()
        if order:
            photo_id=str(photos[-1].get('file_id') or '')
            if photo_id:
                caption=str(msg.get('caption') or '').strip()
                c=db(); c.execute("UPDATE telegram_wallet_orders SET status='pending_admin', receipt_file_id=?, receipt_caption=? WHERE id=?",(photo_id,caption,int(order['id']))); c.commit(); c.close()
                tg_send(uid,f"✅ رسید شارژ <b>#{int(order['id'])}</b> دریافت شد.\n\nرسید برای ادمین ارسال شد و بعد از بررسی، موجودی کیف پولت شارژ می‌شود.")
                if admin:
                    uname=str(chat.get('username') or chat.get('first_name') or uid)
                    cap=(f"<b>💳 رسید جدید شارژ کیف پول</b>\n\nدرخواست: <code>#{int(order['id'])}</code>\nکاربر: @{html.escape(uname)}\nTelegram ID: <code>{uid}</code>\nمبلغ: <b>{tg_money(order['amount'])} تومان</b>")
                    if caption: cap += f"\nتوضیح کاربر: {html.escape(caption)}"
                    tg_send_photo(admin,photo_id,cap,[[{'text':'✅ تأیید شارژ','callback_data':f'wallet_approve:{int(order["id"])}'},{'text':'❌ رد رسید','callback_data':f'wallet_reject:{int(order["id"])}'}]])
                return
        if not text:
            if admin: tg_send(admin,f'<b>📷 تصویر جدید</b>\nکاربر: <code>{uid}</code>')
            tg_send(uid,'📷 تصویر دریافت شد. اگر این تصویر رسید پرداخت نیست، پیام خود را به‌صورت متن ارسال کن.')
            return

    if not text:return

    if uid==tg_admin_id():
        wiz=tg_admin_wizard()
        if text=='/cancel':
            tg_clear_admin_wizard(); tg_send(uid,'❌ عملیات لغو شد.',tg_admin_keyboard()); return
        if wiz.get('type')=='plan':
            step=wiz.get('step'); data2=wiz.get('data',{})
            try:
                if step=='name':
                    if len(text)<2: raise ValueError()
                    data2['name']=text; tg_set_admin_wizard({'type':'plan','step':'gb','data':data2}); tg_send(uid,'✅ نام ثبت شد.\n\n<b>مرحله ۲ از ۴</b>\nحجم پلن را به GB بفرست؛ مثلاً <code>50</code>.',[[{'text':'❌ لغو','callback_data':'admin_cancel_wizard'}]]); return
                if step=='gb':
                    gb=float(text.replace(',','.'));
                    if gb<=0: raise ValueError()
                    data2['gb']=gb; tg_set_admin_wizard({'type':'plan','step':'days','data':data2}); tg_send(uid,'✅ حجم ثبت شد.\n\n<b>مرحله ۳ از ۴</b>\nمدت پلن را به روز بفرست؛ مثلاً <code>30</code>.',[[{'text':'❌ لغو','callback_data':'admin_cancel_wizard'}]]); return
                if step=='days':
                    days=int(text);
                    if days<=0: raise ValueError()
                    data2['days']=days; tg_set_admin_wizard({'type':'plan','step':'price','data':data2}); tg_send(uid,'✅ مدت ثبت شد.\n\n<b>مرحله ۴ از ۴</b>\nقیمت را به تومان بفرست؛ مثلاً <code>100000</code>.',[[{'text':'⏭ بدون قیمت','callback_data':'admin_plan_noprice'},{'text':'❌ لغو','callback_data':'admin_cancel_wizard'}]]); return
                if step=='price':
                    price=text.replace(',','').replace('٬','').strip()
                    if not price.isdigit(): raise ValueError()
                    data2['price']=price; arr=tg_plans(); arr.append(data2); set_setting('telegram_plans',json.dumps(arr[:20],ensure_ascii=False)); tg_clear_admin_wizard(); tg_send(uid,f'🎉 پلن «{html.escape(str(data2["name"]))}» با موفقیت ساخته شد.\n\nحجم: {data2["gb"]} GB\nمدت: {data2["days"]} روز\nقیمت: {tg_money(price)} تومان',[[{'text':'➕ افزودن پلن دیگر','callback_data':'admin_addplan'},{'text':'🛒 مدیریت پلن‌ها','callback_data':'admin_plans'}],[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); return
            except Exception:
                tg_send(uid,'⚠️ مقدار واردشده معتبر نیست. دوباره همین مرحله را وارد کن یا /cancel بزن.'); return
        if wiz.get('type')=='wallet':
            try:
                amount=float(text.replace(',','').replace('٬','').strip()); target=int(wiz.get('data',{}).get('uid',0))
                if amount<=0 or target<=0: raise ValueError()
                c=db(); c.execute('UPDATE telegram_users SET wallet=wallet+? WHERE telegram_user_id=?',(amount,target)); c.commit(); c.close(); tg_clear_admin_wizard(); tg_send(uid,f'✅ {tg_money(amount)} تومان به کیف پول کاربر <code>{target}</code> اضافه شد.',[[{'text':'👥 کاربران','callback_data':'admin_users'}],[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]]); tg_send(target,f'💰 <b>کیف پول شما شارژ شد</b>\nمبلغ: {tg_money(amount)} تومان\nموجودی جدید: {tg_money(tg_wallet(target))} تومان')
            except Exception: tg_send(uid,'⚠️ مبلغ نامعتبر است؛ یک عدد مثل 200000 بفرست.')
            return
        if wiz.get('type')=='card':
            step=wiz.get('step')
            if step=='number':
                card=text.replace(' ','').replace('-','')
                if not card.isdigit() or len(card)!=16:
                    tg_send(uid,'⚠️ شماره کارت باید دقیقاً ۱۶ رقم باشد.'); return
                tg_set_admin_wizard({'type':'card','step':'name','data':{'card':card}}); tg_send(uid,'✅ شماره کارت ثبت شد.\n\n<b>مرحله ۲ از ۲</b>\nنام صاحب کارت را بفرست؛ مثلاً: <code>علی رضایی</code>.',[[{'text':'❌ لغو','callback_data':'admin_cancel_wizard'}]]); return
            if step=='name':
                name=text.strip()
                if len(name)<2: tg_send(uid,'⚠️ نام صاحب کارت را وارد کن.'); return
                card=wiz.get('data',{}).get('card',''); set_setting('telegram_card_number',card); set_setting('telegram_card_name',name); tg_clear_admin_wizard(); tg_send(uid,f'✅ اطلاعات کارت ذخیره شد.\n\nشماره کارت: <code>{html.escape(card)}</code>\nبه نام: <b>{html.escape(name)}</b>',[[{'text':'🛠 مدیریت ربات','callback_data':'admin'},{'text':'💳 اطلاعات پرداخت','callback_data':'admin_card'}]]); return

    if text.startswith('/claimadmin'):
        # First private user can claim admin only when no admin ID has been configured yet.
        current=tg_admin_id()
        if current:
            if uid==current: tg_send(uid,'✅ شما از قبل ادمین ربات هستید.',[[{'text':'🛠 مدیریت ربات','callback_data':'admin'}]])
            else: tg_send(uid,'⛔ ادمین ربات قبلاً تعیین شده است.')
            return
        if str(chat.get('type',''))!='private':
            tg_send(uid,'این دستور را در گفت‌وگوی خصوصی ربات ارسال کنید.')
            return
        set_setting('telegram_admin_id',str(uid)); tg_user(uid,msg)
        tg_send(uid,f'✅ این حساب به‌عنوان ادمین ربات ثبت شد.\nTelegram ID: <code>{uid}</code>',tg_admin_keyboard())
        return
    if text.startswith('/start'):
        tg_user(uid,msg); kb=tg_main_keyboard(uid);
        if uid==tg_admin_id(): kb.append([{'text':'🛠 مدیریت ربات','callback_data':'admin'}])
        tg_send(uid,'<b>'+html.escape(settings().get('telegram_welcome_text','به فروشگاه VPNSTAN خوش آمدید.'))+'</b>',kb)
    elif uid==tg_admin_id() and text.startswith('/setrenewprices '):
        try:
            a=text.split()[1:]; assert len(a)==3; [int(float(x)) for x in a]
            set_setting('telegram_renew_7_price',a[0]); set_setting('telegram_renew_30_price',a[1]); set_setting('telegram_renew_90_price',a[2])
            tg_send(uid,'✅ قیمت‌های تمدید ذخیره شد.',[[{'text':'💰 قیمت‌ها','callback_data':'admin_prices'},{'text':'🛠 مدیریت ربات','callback_data':'admin'}]])
        except Exception: tg_send(uid,'فرمت صحیح: /setrenewprices 30000 100000 250000')
    elif uid==tg_admin_id() and text.startswith('/setvolprices '):
        try:
            a=text.split()[1:]; assert len(a)==3; [int(float(x)) for x in a]
            set_setting('telegram_add_5_price',a[0]); set_setting('telegram_add_10_price',a[1]); set_setting('telegram_add_25_price',a[2])
            tg_send(uid,'✅ قیمت‌های حجم اضافه ذخیره شد.',[[{'text':'💰 قیمت‌ها','callback_data':'admin_prices'},{'text':'🛠 مدیریت ربات','callback_data':'admin'}]])
        except Exception: tg_send(uid,'فرمت صحیح: /setvolprices 30000 50000 100000')
    elif text.startswith('/wallet'):
        tg_send(uid,f'<b>💳 موجودی کیف پول:</b> {tg_money(tg_wallet(uid))}',[[{'text':'🏠 منوی اصلی','callback_data':'home'}]])
    elif text.startswith('/trial'):
        tg_send(uid,'برای دریافت تست رایگان از دکمه «🎁 تست رایگان» استفاده کنید.',[[{'text':'🎁 تست رایگان','callback_data':'trial'}]])
    elif text.startswith('/ref'):
        tg_send(uid,'برای دعوت دوستان از دکمه «🤝 دعوت دوستان» استفاده کنید.',[[{'text':'🤝 دعوت دوستان','callback_data':'ref'}]])
    elif text.startswith('/plans'):
        tg_send(uid,'<b>پلن‌های فروش VPNSTAN</b>\nیک پلن را انتخاب کنید:',tg_plan_keyboard())
    elif text.startswith('/my') or text.startswith('/orders'):
        c=db(); rows=c.execute('SELECT * FROM telegram_orders WHERE telegram_user_id=? ORDER BY id DESC LIMIT 10',(uid,)).fetchall(); c.close()
        if not rows: tg_send(uid,'هنوز سفارشی ندارید.'); return
        lines=['<b>سفارش‌های شما</b>']
        labels={'awaiting_payment':'منتظر پرداخت','pending_admin':'منتظر تأیید','approved':'تأیید شده','rejected':'رد شده','created':'ثبت شده'}
        for r in rows: lines.append(f"#{r['id']} · {html.escape(r['plan_name'])} · {labels.get(r['status'],r['status'])}")
        tg_send(uid,'\n'.join(lines),[[{'text':'🛒 پلن‌ها','callback_data':'plans'}]])
    elif uid==tg_admin_id() and text.startswith('/admin'):
        tg_send(uid,'<b>🛠 مدیریت ربات VPNSTAN</b>\nهمه مدیریت فروشگاه از داخل همین ربات انجام می‌شود.',tg_admin_keyboard())
    elif uid==tg_admin_id() and text.startswith('/setcard '):
        card=text.split(' ',1)[1].strip().replace(' ','')
        if not card.isdigit() or len(card)!=16: tg_send(uid,'شماره کارت باید ۱۶ رقمی باشد.'); return
        set_setting('telegram_card_number',card); tg_send(uid,f'✅ شماره کارت ثبت شد: <code>{html.escape(card)}</code>')
    elif uid==tg_admin_id() and text.startswith('/setcardname '):
        name=text.split(' ',1)[1].strip(); set_setting('telegram_card_name',name); tg_send(uid,'✅ نام صاحب کارت ثبت شد.')
    elif uid==tg_admin_id() and text.startswith('/setwelcome '):
        set_setting('telegram_welcome_text',text.split(' ',1)[1].strip()); tg_send(uid,'✅ متن خوش‌آمدگویی تغییر کرد.')
    elif uid==tg_admin_id() and text.startswith('/settrial '):
        try:
            parts=text.split(); enabled=parts[1].lower() in ('1','on','yes','فعال'); gb=float(parts[2]); days=int(parts[3]); set_setting('telegram_trial_enabled','1' if enabled else '0'); set_setting('telegram_trial_gb',str(max(.1,gb))); set_setting('telegram_trial_days',str(max(1,days))); tg_send(uid,'✅ تنظیمات تست رایگان ذخیره شد.')
        except Exception: tg_send(uid,'فرمت: /settrial on 1 1')
    elif uid==tg_admin_id() and text.startswith('/setref '):
        try: set_setting('telegram_referral_reward',str(max(0,float(text.split(' ',1)[1])))); tg_send(uid,'✅ پاداش دعوت تغییر کرد.')
        except: tg_send(uid,'فرمت: /setref 1')
    elif uid==tg_admin_id() and text.startswith('/setchannel '):
        set_setting('telegram_mandatory_channel',text.split(' ',1)[1].strip()); tg_send(uid,'✅ کانال اجباری ذخیره شد.')
    elif uid==tg_admin_id() and text.startswith('/addplan '):
        try:
            parts=[x.strip() for x in text.split(' ',1)[1].split('|')]; name=parts[0]; gb=float(parts[1]); days=int(parts[2]); price=parts[3] if len(parts)>3 else ''; arr=tg_plans(); arr.append({'name':name,'gb':gb,'days':days,'price':price}); set_setting('telegram_plans',json.dumps(arr[:20],ensure_ascii=False)); tg_send(uid,'✅ پلن اضافه شد.')
        except Exception: tg_send(uid,'فرمت: /addplan نام | حجم | روز | قیمت')
    elif uid==tg_admin_id() and text.startswith('/delplan '):
        try:
            idx=int(text.split(' ',1)[1])-1; arr=tg_plans(); arr.pop(idx); set_setting('telegram_plans',json.dumps(arr,ensure_ascii=False)); tg_send(uid,'✅ پلن حذف شد.')
        except Exception: tg_send(uid,'شماره پلن نامعتبر است.')
    elif uid==tg_admin_id() and text.startswith('/reply '):
        try:
            parts=text.split(' ',2); tid=int(parts[1]); reply=parts[2]; c=db(); t=c.execute('SELECT * FROM telegram_tickets WHERE id=?',(tid,)).fetchone();
            if not t: c.close(); tg_send(uid,'تیکت پیدا نشد.'); return
            c.execute("UPDATE telegram_tickets SET status='closed',admin_reply=? WHERE id=?",(reply,tid)); c.commit(); c.close(); tg_send(t['telegram_user_id'],f'<b>🎫 پاسخ پشتیبانی #{tid}</b>\n\n{html.escape(reply)}'); tg_send(uid,'✅ پاسخ ارسال شد.')
        except Exception: tg_send(uid,'فرمت: /reply TICKET_ID متن')
    elif uid==tg_admin_id() and text.startswith('/walletadd '):
        try:
            parts=text.split(); target=int(parts[1]); amount=float(parts[2]); tg_user(target); c=db(); c.execute('UPDATE telegram_users SET wallet=wallet+? WHERE telegram_user_id=?',(amount,target)); c.commit(); c.close(); tg_send(uid,f'موجودی {target} به اندازه {tg_money(amount)} افزایش یافت.')
        except Exception: tg_send(uid,'فرمت: /walletadd USER_ID AMOUNT')
    elif uid==tg_admin_id() and text.startswith('/stats'):
        c=db(); users=c.execute('SELECT COUNT(*) n FROM telegram_users').fetchone()['n']; orders=c.execute('SELECT COUNT(*) n FROM telegram_orders').fetchone()['n']; approved=c.execute("SELECT COUNT(*) n FROM telegram_orders WHERE status='approved'").fetchone()['n']; c.close(); tg_send(uid,f'<b>📊 آمار ربات</b>\nکاربران: {users}\nسفارش‌ها: {orders}\nتأییدشده: {approved}')
    elif uid==tg_admin_id() and text.startswith('/broadcast '):
        msgtext=text.split(' ',1)[1]; c=db(); ids=[r['telegram_user_id'] for r in c.execute('SELECT telegram_user_id FROM telegram_users').fetchall()]; c.close(); sent=0
        for target in ids:
            try: tg_send(target,msgtext); sent+=1
            except: pass
        tg_send(uid,f'ارسال شد: {sent} کاربر')
    elif text and not text.startswith('/'):
        tg_user(uid,msg); c=db(); cur=c.execute('INSERT INTO telegram_tickets(telegram_user_id,text,created_at) VALUES(?,?,?)',(uid,text,int(time.time()))); tid=cur.lastrowid; c.commit(); c.close(); tg_send(uid,'پیام شما برای پشتیبانی ثبت شد.'); admin=tg_admin_id()
        if admin: tg_send(admin,f'<b>🎫 تیکت جدید #{tid}</b>\nکاربر: <code>{uid}</code>\n\n{html.escape(text)}')

def telegram_bot_loop():
    offset=0
    while not TG_STOP.is_set():
        try:
            st=settings(); token=(st.get('telegram_token') or '').strip(); enabled=st.get('telegram_enabled','0')=='1'
            if not token or not enabled: time.sleep(3); continue
            # Drop pending updates when bot is first enabled only through an explicit fresh offset.
            updates=tg_api('getUpdates',{'offset':offset,'timeout':20,'allowed_updates':['message','callback_query']},30)
            for u in updates or []:
                offset=max(offset,int(u.get('update_id',0))+1)
                try:
                    if u.get('callback_query'): tg_handle_callback(u['callback_query'])
                    elif u.get('message'): tg_handle_message(u['message'])
                except Exception as e: print('TELEGRAM UPDATE ERROR:',e,flush=True)
        except Exception as e:
            print('TELEGRAM BOT:',e,flush=True); time.sleep(5)

class H(BaseHTTPRequestHandler):
    def log_message(self,fmt,*a): print(fmt%a,flush=True)
    def do_HEAD(self):
        u=urllib.parse.urlparse(self.path); p=u.path
        if p.startswith('/sub/'):
            sid=p.split('/')[-1]; s,rows=load_sub(self,sid)
            if not rows:self.send_response(404); self.end_headers(); return
            r=rows[0]; tr=traffic_for(r['id']); total=int(float(r['gb'])*1024**3); exp=r['expiry_at']; self.send_response(200); self.send_header('Subscription-Userinfo',f'upload={tr["upload"]}; download={tr["download"]}; total={total}; expire={exp}'); self.send_header('Profile-Title',base64.b64encode(s.get('panel_title','vpnstan').encode()).decode()); self.send_header('Profile-Update-Interval','1'); self.send_header('Cache-Control','no-store, no-cache, must-revalidate'); self.end_headers(); return
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
            raw=enc.encode(); self.send_response(200); self.send_header('Content-Type','text/plain; charset=utf-8'); self.send_header('Subscription-Userinfo',f'upload={up}; download={down}; total={total}; expire={exp}'); self.send_header('Profile-Title',base64.b64encode(s.get('panel_title','vpnstan').encode()).decode()); self.send_header('Profile-Update-Interval','1'); self.send_header('Cache-Control','no-store, no-cache, must-revalidate'); self.send_header('Support-Url',s.get('support_url','')); self.send_header('Profile-Web-Page-Url',f'https://{host_for(self,s)}/{s.get("sub_path","sub").strip("/")}/{sid}?html=1'); self.send_header('Announce',base64.b64encode(s.get('announce','').encode()).decode()); self.send_header('Content-Disposition',f'inline; filename="{sid}.txt"'); self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store, no-cache, must-revalidate'); self.send_header('Pragma','no-cache'); self.end_headers(); self.wfile.write(raw); return
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
            self.send_response(200); self.send_header('Content-Type','text/plain; charset=utf-8'); self.send_header('Cache-Control','no-store, no-cache, must-revalidate'); self.send_header('Subscription-Userinfo',f'upload={tr["upload"]}; download={tr["download"]}; total={total}; expire={exp}'); self.send_header('Profile-Title',base64.b64encode((s.get('panel_title','vpnstan')+' DNS').encode()).decode()); self.send_header('Profile-Update-Interval','1'); self.send_header('Profile-Web-Page-Url',f'https://{host_for(self,s)}/dns/{r["sub_id"]}'); self.send_header('Content-Disposition',f'inline; filename="dns-{r["sub_id"]}.txt"'); self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store, no-cache, must-revalidate'); self.send_header('Pragma','no-cache'); self.end_headers(); self.wfile.write(raw); return
        if p.startswith('/dns/'):
            sid=p.split('/')[-1]; s,rows=load_sub(self,sid)
            if not rows:return send(self,404,{'error':'not found'})
            r=rows[0]; d=client_data(self,r,s); title=html.escape(s.get('panel_title','vpnstan')); name=html.escape(r['name']);
            page=f'''<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Cache-Control" content="no-store"><title>{title} DNS</title><style>body{{margin:0;background:#0a1020;color:#eef3ff;font-family:Tahoma,Arial}}.wrap{{max-width:760px;margin:auto;padding:24px}}.card{{background:#111a2d;border:1px solid #263654;border-radius:20px;padding:24px;margin:14px 0}}.code{{direction:ltr;text-align:left;font:600 15px Consolas;word-break:break-all;background:#070d18;border:1px solid #263654;border-radius:14px;padding:16px}}.muted{{color:#9aabc7}}button{{border:0;border-radius:12px;padding:12px 18px;background:#6178ff;color:white;font-weight:700;cursor:pointer}}</style><div class=wrap><div class=card><div class=muted>VPNSTAN • DNS اختصاصی</div><h1>{name}</h1><p class=muted>این اشتراک فقط برای DNS-over-HTTPS اختصاصی همین کاربر است.</p><h3>لینک DNS اختصاصی</h3><div class=code id=doh>{d['dnsUrl']}</div><button onclick=copyDoh()>کپی لینک DNS</button></div><div class=card><b>حجم اختصاص‌داده‌شده: {d['totalText']}</b><p>مصرف‌شده: {d['usedText']}</p><p>باقی‌مانده: {d['remainingText']}</p><p>دانلود: {d['downloadText']}</p><p>آپلود/درخواست DNS: {d['uploadText']}</p><p>انقضا: {html.escape(d['expiryText'])}</p><p class=muted>DNSهای عمومی مثل 1.1.1.1 و 8.8.8.8 در این اشتراک استفاده نمی‌شوند. حجم فقط برای درخواست‌هایی که از این لینک اختصاصی عبور کنند محاسبه می‌شود.</p></div></div><script>function copyDoh(){{navigator.clipboard.writeText(document.getElementById('doh').textContent.trim()).then(()=>alert('کپی شد'))}}</script></html>'''.encode(); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(page))); self.end_headers(); self.wfile.write(page); return
        if p.startswith('/qr/'): return qr_svg(self,p.split('/')[-1])
        if p.startswith('/sub-status/'):
            sid=p.split('/')[-1]
            s,rows=load_sub(self,sid)
            if not rows:return send(self,404,{'error':'subscription not found'})
            r=rows[0]; tr=traffic_for(r['id']); total=int(float(r['gb'])*1024**3); used=tr['upload']+tr['download']; remain=max(0,total-used)
            return send(self,200,{'upload':tr['upload'],'download':tr['download'],'used':used,'remaining':remain,'total':total,'usedText':fmt_bytes(used),'remainingText':fmt_bytes(remain),'uploadText':fmt_bytes(tr['upload']),'downloadText':fmt_bytes(tr['download']),'percent':round((used/total*100) if total else 0,2),'online':bool(tr['last_seen'] and int(time.time())-tr['last_seen']<=20),'lastSeen':tr['last_seen']})
        if p.startswith('/subjson/'):
            sid=p.split('/')[-1]; s,rows=load_sub(self,sid); out=[]; host=host_for(self,s); port=int(s.get('node_port','443'))
            for r in rows:
                proto=(r['protocol'] or 'vless')
                if proto=='vless':
                    out.append({'protocol':'vless','tag':r['name'],'settings':{'vnext':[{'address':host,'port':port,'users':[{'id':r['uuid'],'encryption':'none'}]}]},'streamSettings':{'network':'ws','security':'tls','tlsSettings':{'serverName':host},'wsSettings':{'path':s.get('ws_path','/ws')}}})
                elif proto=='vmess':
                    out.append({'protocol':'vmess','tag':r['name'],'settings':{'vnext':[{'address':host,'port':port,'users':[{'id':r['uuid'],'alterId':0,'security':'auto'}]}]},'streamSettings':{'network':'ws','security':'tls','tlsSettings':{'serverName':host},'wsSettings':{'path':s.get('vmess_path','/vmess')}}})
            return send(self,200,out)
        if p=='/api/me':
            u=current_user(self)
            if not u: return send(self,200,{'authenticated':False,'user':None})
            perms={'clients_view':True,'clients_create':True,'clients_edit':True,'clients_delete':True,'configs_view':True,'dns_view':True,'settings_view':True}
            if u['role']!='admin' and int(u['panel_id'] or 0):
                c=db(); r=c.execute('SELECT permissions_json FROM child_panels WHERE id=?',(u['panel_id'],)).fetchone(); c.close(); perms=permission_map(r) if r else {}
            return send(self,200,{'authenticated':True,'user':{'id':u['id'],'username':u['username'],'role':u['role'],'panel_id':int(u['panel_id'] or 0),'permissions':perms}})
        if p=='/api/admin/users':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            c=db(); rows=c.execute('SELECT id,username,role,enabled,created_at,panel_id FROM panel_users ORDER BY id').fetchall(); c.close()
            return send(self,200,{'success':True,'users':[dict(r) for r in rows]})
        if p=='/api/admin/panels':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            c=db(); rows=c.execute('SELECT id,name,panel_key,enabled,detected_ip,allowed_ip,permissions_json,created_at FROM child_panels ORDER BY id DESC').fetchall(); c.close()
            out=[]
            for r in rows:
                d=dict(r); d['permissions']=permission_map(r); d.pop('permissions_json',None); out.append(d)
            return send(self,200,{'success':True,'panels':out,'detected_ip':client_ip(self)})
        if p.startswith('/api/admin/panels/') and p.endswith('/permissions'):
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try: pid=int(p.split('/')[4]); d=body(self); perms=d.get('permissions') or {}
            except Exception: return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            allowed={'clients_view','clients_create','clients_edit','clients_delete','configs_view','dns_view','settings_view'}; clean={k:bool(perms.get(k)) for k in allowed}
            c=db(); c.execute('UPDATE child_panels SET permissions_json=? WHERE id=?',(json.dumps(clean,ensure_ascii=False),pid)); c.commit(); c.close(); return send(self,200,{'success':True})
        if p.startswith('/api/admin/panels/') and p.endswith('/toggle'):
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try: pid=int(p.split('/')[4])
            except: return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            c=db(); c.execute('UPDATE child_panels SET enabled=1-enabled WHERE id=?',(pid,)); c.commit(); c.close(); return send(self,200,{'success':True})
        if p.startswith('/api/admin/panels/') and p.endswith('/delete'):
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try: pid=int(p.split('/')[4])
            except: return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            c=db(); users=c.execute('SELECT id FROM panel_users WHERE panel_id=?',(pid,)).fetchall(); c.execute('DELETE FROM panel_users WHERE panel_id=?',(pid,)); c.execute('DELETE FROM child_panels WHERE id=?',(pid,)); c.commit(); c.close(); return send(self,200,{'success':True,'deletedUsers':len(users)})
        if p=='/api/dns-info':
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            domain=os.environ.get('RAILWAY_TCP_PROXY_DOMAIN','').strip()
            port=os.environ.get('RAILWAY_TCP_PROXY_PORT','').strip()
            return send(self,200,{'success':True,'enabled':DNS_TCP_ENABLED,'internalPort':DNS_TCP_PORT,'tcpHost':domain,'tcpPort':port,'ready':bool(domain and port),'message':'برای DNSChanger باید TCP Proxy ریلیوی را روی پورت داخلی 5354 فعال کنید. سپس Host و Port نمایش داده می‌شود.'})
        if p=='/api/telegram/status':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            st=settings(); token=st.get('telegram_token','').strip(); admin_id=st.get('telegram_admin_id','').strip(); enabled=st.get('telegram_enabled','0')=='1'
            bot=None; err=''
            if token:
                try: bot=tg_api('getMe',{},10)
                except Exception as e: err=str(e)
            return send(self,200,{'success':True,'enabled':enabled,'configured':bool(token),'connected':bool(bot),'bot':bot,'botId':(bot or {}).get('id') if bot else None,'error':err,'adminId':admin_id,'adminConfigured':bool(admin_id),'plans':tg_plans()})
        if p=='/api/telegram/save':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:d=body(self); token=str(d.get('token','')).strip(); admin_id=str(d.get('adminId','')).strip(); enabled=bool(d.get('enabled'))
            except:return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            # The token field is intentionally optional on subsequent saves so loading the page never erases it.
            if not token: token=settings().get('telegram_token','').strip()
            if not admin_id: admin_id=settings().get('telegram_admin_id','').strip()
            bot=None
            if enabled:
                if not token: return send(self,400,{'success':False,'msg':'توکن BotFather را وارد کنید'})
                try: bot=tg_api('getMe',{},10)
                except Exception as e:return send(self,400,{'success':False,'msg':'توکن ربات معتبر نیست: '+str(e)})
                if admin_id:
                    try: int(admin_id)
                    except: return send(self,400,{'success':False,'msg':'آیدی ادمین باید عددی باشد'})
            # Plans are managed ONLY inside Telegram. Preserve any existing plans and allow zero plans at connection time.
            payment=str(d.get('paymentText','')).strip()
            set_setting('telegram_token',token); set_setting('telegram_admin_id',admin_id); set_setting('telegram_enabled','1' if enabled else '0')
            if payment: set_setting('telegram_payment_text',payment)
            set_setting('telegram_card_number',str(d.get('cardNumber','')).strip().replace(' ',''))
            set_setting('telegram_card_name',str(d.get('cardName','')).strip())
            set_setting('telegram_welcome_text',str(d.get('welcomeText','به فروشگاه VPNSTAN خوش آمدید.')).strip() or 'به فروشگاه VPNSTAN خوش آمدید.')
            set_setting('telegram_support_text',str(d.get('supportText','برای پشتیبانی پیام خود را ارسال کنید.')).strip() or 'برای پشتیبانی پیام خود را ارسال کنید.')
            set_setting('telegram_mandatory_channel',str(d.get('mandatoryChannel','')).strip())
            try: set_setting('telegram_referral_reward',max(0,float(d.get('referralReward',1))))
            except: set_setting('telegram_referral_reward','1')
            set_setting('telegram_trial_enabled','1' if bool(d.get('trialEnabled',True)) else '0')
            try: set_setting('telegram_trial_gb',max(0.1,float(d.get('trialGb',1))))
            except: set_setting('telegram_trial_gb','1')
            try: set_setting('telegram_trial_days',max(1,int(d.get('trialDays',1))))
            except: set_setting('telegram_trial_days','1')
            return send(self,200,{'success':True,'enabled':enabled,'connected':bool(bot),'bot':bot,'botId':(bot or {}).get('id') if bot else None,'adminId':admin_id,'plans':tg_plans()})
        if p=='/api/telegram/test':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:r=tg_api('getMe',{},10); return send(self,200,{'success':True,'bot':r})
            except Exception as e:return send(self,400,{'success':False,'msg':str(e)})
        if p=='/api/backup/export':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:
                raw=export_backup_bytes()
                self.send_response(200); self.send_header('Content-Type','application/octet-stream'); self.send_header('Content-Disposition','attachment; filename=VPNSTAN-v28-backup.vpnstan'); self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(raw); return
            except Exception as e:
                print('BACKUP EXPORT:',e,flush=True); return send(self,500,{'success':False,'msg':'ساخت بکاپ ناموفق بود: '+str(e)})
        if p=='/api/backup/import':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:
                n=int(self.headers.get('Content-Length','0'))
                if n<=0 or n>140*1024*1024: raise ValueError('فایل بکاپ نامعتبر یا بیش از حد بزرگ است.')
                raw=self.rfile.read(n)
                payload=import_backup_bytes(raw)
                restart_xray()
                return send(self,200,{'success':True,'msg':'بکاپ با موفقیت بازیابی شد. برای اعمال کامل اطلاعات، دوباره وارد پنل شوید.','panelVersion':payload.get('panel_version'),'createdAt':payload.get('created_at')})
            except Exception as e:
                print('BACKUP IMPORT:',e,flush=True); return send(self,400,{'success':False,'msg':'بازیابی بکاپ ناموفق بود: '+str(e)})
        if p=='/api/settings':
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            if not has_permission(self,'settings_view'): return send(self,403,{'success':False,'msg':'دسترسی تنظیمات برای این پنل فعال نیست'})
            return send(self,200,{'success':True,'settings':settings()})
        if p=='/api/clients':
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            if not has_permission(self,'clients_view'): return send(self,403,{'success':False,'msg':'دسترسی مشاهده کانفیگ‌ها برای این پنل فعال نیست'})
            s=settings(); c=db(); scope=panel_scope(self)
            rows=c.execute('SELECT * FROM clients WHERE panel_id=? ORDER BY id DESC',(scope,)).fetchall() if scope is not None else c.execute('SELECT * FROM clients ORDER BY id DESC').fetchall(); c.close(); return send(self,200,{'success':True,'clients':[client_data(self,r,s) for r in rows]})
        if p.startswith('/api/client/'):
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            try: cid=int(p.rsplit('/',1)[1])
            except: return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            c=db(); scope=panel_scope(self); r=c.execute('SELECT * FROM clients WHERE id=? AND panel_id=?',(cid,scope)).fetchone() if scope is not None else c.execute('SELECT * FROM clients WHERE id=?',(cid,)).fetchone(); c.close()
            if not r:return send(self,404,{'success':False,'msg':'کاربر پیدا نشد'})
            return send(self,200,{'success':True,'client':client_data(self,r,settings())})
        if p=='/api/system':
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            alive=bool(XRAY_PROC and XRAY_PROC.poll() is None)
            try: log=open('/opt/vpnstan/data/xray.log','rb').read()[-6000:].decode('utf-8','replace')
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
            c=db(); r=c.execute('SELECT * FROM panel_users WHERE username=? AND enabled=1',(str(d.get('username','')).strip(),)).fetchone()
            if r and hmac.compare_digest(r['password_hash'],hash_password(d.get('password',''))):
                if int(r['panel_id'] or 0):
                    pinfo=c.execute('SELECT enabled,allowed_ip FROM child_panels WHERE id=?',(r['panel_id'],)).fetchone()
                    if not pinfo or not pinfo['enabled']: c.close(); return send(self,403,{'success':False,'msg':'این پنل غیرفعال شده است'})
                    aip=(pinfo['allowed_ip'] or '').strip()
                    if aip and client_ip(self) not in [x.strip() for x in aip.split(',') if x.strip()]: c.close(); return send(self,403,{'success':False,'msg':'آی‌پی شما برای این پنل مجاز نیست'})
                t=secrets.token_urlsafe(32); SESSIONS[t]=time.time()+86400; SESSION_USERS[t]=r['id']; c.close(); return send(self,200,{'success':True,'user':{'username':r['username'],'role':r['role'],'panel_id':int(r['panel_id'] or 0)}},{'Set-Cookie':f'vpnstan_session={t}; Path=/; HttpOnly; SameSite=Lax'})
            c.close(); return send(self,401,{'success':False,'msg':'نام کاربری یا رمز عبور اشتباه است'})
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
        if p=='/api/admin/panels/create':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:
                d=body(self); name=str(d.get('name','')).strip(); username=str(d.get('username','')).strip(); password=str(d.get('password','')); allowed_ip=str(d.get('allowed_ip','')).strip(); perms=d.get('permissions') or {}
                if len(name)<2 or len(name)>80 or len(username)<3 or len(password)<4: raise ValueError
                allowed={'clients_view','clients_create','clients_edit','clients_delete','configs_view','dns_view','settings_view'}; clean={k:bool(perms.get(k)) for k in allowed}
            except Exception: return send(self,400,{'success':False,'msg':'نام پنل، نام کاربری یا رمز نامعتبر است'})
            c=db(); now=int(time.time()); key=secrets.token_urlsafe(10); detected=client_ip(self)
            try:
                cur=c.execute('INSERT INTO child_panels(name,panel_key,enabled,detected_ip,allowed_ip,permissions_json,created_at) VALUES(?,?,?,?,?,?,?)',(name,key,1,detected,allowed_ip,json.dumps(clean,ensure_ascii=False),now)); pid=cur.lastrowid
                c.execute('INSERT INTO panel_users(username,password_hash,role,enabled,created_at,panel_id) VALUES(?,?,?,?,?,?)',(username,hash_password(password),'user',1,now,pid)); c.commit(); c.close(); return send(self,201,{'success':True,'panel':{'id':pid,'name':name,'panel_key':key,'detected_ip':detected,'allowed_ip':allowed_ip,'permissions':clean}})
            except sqlite3.IntegrityError:
                c.rollback(); c.close(); return send(self,409,{'success':False,'msg':'نام پنل یا نام کاربری قبلاً استفاده شده است'})
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
        if p=='/api/dns-info':
            if not authed(self): return send(self,401,{'success':False,'msg':'نیاز به ورود دارید'})
            domain=os.environ.get('RAILWAY_TCP_PROXY_DOMAIN','').strip()
            port=os.environ.get('RAILWAY_TCP_PROXY_PORT','').strip()
            return send(self,200,{'success':True,'enabled':DNS_TCP_ENABLED,'internalPort':DNS_TCP_PORT,'tcpHost':domain,'tcpPort':port,'ready':bool(domain and port),'message':'برای DNSChanger باید TCP Proxy ریلیوی را روی پورت داخلی 5354 فعال کنید. سپس Host و Port نمایش داده می‌شود.'})
        if p=='/api/telegram/status':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            st=settings(); token=st.get('telegram_token','').strip(); admin_id=st.get('telegram_admin_id','').strip(); enabled=st.get('telegram_enabled','0')=='1'
            bot=None; err=''
            if token:
                try: bot=tg_api('getMe',{},10)
                except Exception as e: err=str(e)
            return send(self,200,{'success':True,'enabled':enabled,'configured':bool(token),'connected':bool(bot),'bot':bot,'botId':(bot or {}).get('id') if bot else None,'error':err,'adminId':admin_id,'adminConfigured':bool(admin_id),'plans':tg_plans()})
        if p=='/api/telegram/save':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:d=body(self); token=str(d.get('token','')).strip(); admin_id=str(d.get('adminId','')).strip(); enabled=bool(d.get('enabled'))
            except:return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            if not token: token=settings().get('telegram_token','').strip()
            if not admin_id: admin_id=settings().get('telegram_admin_id','').strip()
            bot=None
            if enabled:
                if not token: return send(self,400,{'success':False,'msg':'توکن BotFather را وارد کنید'})
                try: bot=tg_api('getMe',{},10)
                except Exception as e:return send(self,400,{'success':False,'msg':'توکن ربات معتبر نیست: '+str(e)})
                if admin_id:
                    try: int(admin_id)
                    except: return send(self,400,{'success':False,'msg':'آیدی ادمین باید عددی باشد'})
            set_setting('telegram_token',token); set_setting('telegram_admin_id',admin_id); set_setting('telegram_enabled','1' if enabled else '0')
            return send(self,200,{'success':True,'enabled':enabled,'connected':bool(bot),'bot':bot,'botId':(bot or {}).get('id') if bot else None,'adminId':admin_id,'plans':tg_plans()})
        if p=='/api/telegram/test':
            if not is_admin(self): return send(self,403,{'success':False,'msg':'فقط ادمین دسترسی دارد'})
            try:r=tg_api('getMe',{},10); return send(self,200,{'success':True,'bot':r,'botId':r.get('id')})
            except Exception as e:return send(self,400,{'success':False,'msg':str(e)})
        if p=='/api/settings':
            if not has_permission(self,'settings_view'): return send(self,403,{'success':False,'msg':'دسترسی تنظیمات برای این پنل فعال نیست'})
            try:d=body(self); allowed={'node_host','node_port','ws_path','vmess_path','xhttp_path','grpc_service','grpc_path','httpupgrade_path','vmess_xhttp_path','vmess_grpc_path','vmess_httpupgrade_path','trojan_ws_path','trojan_xhttp_path','trojan_grpc_path','trojan_httpupgrade_path','sub_path','panel_title','support_url','announce','update_interval','wg_endpoint','wg_server_public_key','dns_server','dns_profile','theme'}
            except:return send(self,400,{'success':False,'msg':'درخواست نامعتبر'})
            if 'node_port' in d:
                try: port=int(d['node_port']); assert 1<=port<=65535
                except:return send(self,400,{'success':False,'msg':'پورت نامعتبر است'})
            for k,v in d.items():
                if k in allowed:set_setting(k,str(v).strip())
            restart_xray(); return send(self,200,{'success':True,'settings':settings()})
        if p=='/api/clients/create':
            if not has_permission(self,'clients_create'): return send(self,403,{'success':False,'msg':'دسترسی ساخت کانفیگ برای این پنل فعال نیست'})
            try:
                d=body(self); name=str(d.get('name','')).strip(); gb=float(d.get('gb',0)); days=int(d.get('days',0)); protocol=str(d.get('protocol','vless')).lower(); transport=str(d.get('transport','ws')).lower(); carrier_profile=str(d.get('carrierProfile',st.get('carrier_profile','auto'))).lower() if False else str(d.get('carrierProfile',settings().get('carrier_profile','auto'))).lower(); sub_count=int(d.get('subCount',1) or 1); st=settings(); dns_server=('internal' if protocol=='dns' else st.get('dns_server','')); scope=panel_scope(self) or 0
                if carrier_profile not in ('auto','all','mci','irancell','rightel','mokhaberat','shatel_mobile','aptel','samantel','asiatech','hiweb','mobinnet','custom','mtni') or protocol not in ('vless','vmess','trojan','wireguard','dns') or transport not in ('ws','xhttp','grpc','httpupgrade') or (protocol in ('wireguard','dns') and transport!='ws') or not name or gb<=0 or days<=0 or len(name)>80 or sub_count<1 or sub_count>20: raise ValueError
                if protocol=='dns' and sub_count!=1: raise ValueError
            except:return send(self,400,{'success':False,'msg':'نام، حجم، مدت یا تعداد کانفیگ نامعتبر است'})
            now=int(time.time()); sub_id=secrets.token_urlsafe(18); rows=[]
            c=db()
            for i in range(sub_count):
                cname=name if sub_count==1 else f'{name}-{i+1:02d}'
                cuuid=str(uuid.uuid4()); dns_token=secrets.token_urlsafe(24) if protocol=='dns' else ''
                r=(cname,cuuid,sub_id,gb,days,now,now+days*86400,protocol,transport,dns_server,'','10.66.0.2/32',dns_token,scope)
                c.execute('INSERT INTO clients(name,uuid,sub_id,gb,days,created_at,expiry_at,protocol,transport,dns_server,wg_private_key,wg_address,dns_token,panel_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',r)
                rows.append(c.execute('SELECT * FROM clients WHERE uuid=?',(cuuid,)).fetchone())
            c.commit(); c.close();
            # Keep the last selected carrier profile as the default for regenerated configs.
            c2=db(); c2.execute("INSERT INTO settings(k,v) VALUES('carrier_profile',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",(carrier_profile,)); c2.commit(); c2.close();
            restart_xray(); first=rows[0]
            return send(self,201,{'success':True,'count':sub_count,'subId':sub_id,'client':client_data(self,first,settings()),'clients':[client_data(self,r,settings()) for r in rows]})
        if p.startswith('/api/clients/') and p.endswith('/edit'):
            if not has_permission(self,'clients_edit'): return send(self,403,{'success':False,'msg':'دسترسی ویرایش کانفیگ برای این پنل فعال نیست'})
            try:
                cid=int(p.split('/')[3]); d=body(self)
                name=str(d.get('name','')).strip(); gb=float(d.get('gb',0)); days=int(d.get('days',0)); protocol=str(d.get('protocol','vless')).lower(); transport=str(d.get('transport','ws')).lower()
                if not name or gb<=0 or days<=0 or len(name)>80 or protocol not in ('vless','vmess','trojan','wireguard','dns') or transport not in ('ws','xhttp','grpc','httpupgrade') or (protocol in ('wireguard','dns') and transport!='ws'): raise ValueError
            except Exception:
                return send(self,400,{'success':False,'msg':'نام، حجم، مدت یا پروتکل نامعتبر است'})
            c=db(); scope=panel_scope(self); old=c.execute('SELECT * FROM clients WHERE id=? AND panel_id=?',(cid,scope)).fetchone() if scope is not None else c.execute('SELECT * FROM clients WHERE id=?',(cid,)).fetchone()
            if not old: c.close(); return send(self,404,{'success':False,'msg':'کلاینت پیدا نشد'})
            expiry=int(time.time())+days*86400
            dns_token=old['dns_token'] or (secrets.token_urlsafe(24) if protocol=='dns' else '')
            if protocol!='dns': dns_token=''
            dns_server='internal' if protocol=='dns' else ''
            c.execute('UPDATE clients SET name=?,gb=?,days=?,expiry_at=?,protocol=?,transport=?,dns_server=?,dns_token=?,enabled=1 WHERE id=?',(name,gb,days,expiry,protocol,transport,dns_server,dns_token,cid)); c.commit(); row=c.execute('SELECT * FROM clients WHERE id=?',(cid,)).fetchone(); c.close(); restart_xray(); return send(self,200,{'success':True,'client':client_data(self,row,settings())})
        if p.startswith('/api/clients/') and p.endswith('/toggle'):
            if not has_permission(self,'clients_edit'): return send(self,403,{'success':False,'msg':'دسترسی تغییر وضعیت برای این پنل فعال نیست'})
            try:cid=int(p.split('/')[3])
            except:return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            c=db(); scope=panel_scope(self); c.execute('UPDATE clients SET enabled=1-enabled WHERE id=?'+(' AND panel_id=?' if scope is not None else ''),(cid,scope) if scope is not None else (cid,)); c.commit(); c.close(); restart_xray(); return send(self,200,{'success':True})
        if p.startswith('/api/clients/') and p.endswith('/delete'):
            if not has_permission(self,'clients_delete'): return send(self,403,{'success':False,'msg':'دسترسی حذف کانفیگ برای این پنل فعال نیست'})
            try:cid=int(p.split('/')[3])
            except:return send(self,400,{'success':False,'msg':'شناسه نامعتبر'})
            c=db(); scope=panel_scope(self); r=c.execute('SELECT id FROM clients WHERE id=?'+(' AND panel_id=?' if scope is not None else ''),(cid,scope) if scope is not None else (cid,)).fetchone()
            if not r:
                c.close(); return send(self,404,{'success':False,'msg':'کلاینت پیدا نشد'})
            c.execute('DELETE FROM clients WHERE id=?',(cid,))
            c.execute('DELETE FROM traffic WHERE client_id=?',(cid,))
            c.commit(); c.close(); restart_xray(); return send(self,200,{'success':True})
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
        raw=open(f,'rb').read(); self.send_response(200); self.send_header('Content-Type',mime); self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store, no-cache, must-revalidate'); self.send_header('Pragma','no-cache'); self.end_headers(); self.wfile.write(raw)

if __name__=='__main__':
    init_db(); restart_xray(); threading.Thread(target=collector_loop,daemon=True).start(); threading.Thread(target=dns_tcp_server,daemon=True).start(); threading.Thread(target=telegram_bot_loop,daemon=True).start(); print(f'vpnstan panel listening on 127.0.0.1:{PANEL_PORT}',flush=True); ThreadingHTTPServer(('127.0.0.1',PANEL_PORT),H).serve_forever()

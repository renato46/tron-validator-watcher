import socket, ssl, os, sys, time, json
from concurrent.futures import ThreadPoolExecutor

HOSTS = ['198.244.203.87','198.244.253.242','198.244.253.243','35.195.69.111',
         '35.241.236.239','57.128.187.18','57.128.187.3','51.68.54.178']
PORTS = [80,443,8081,8006,9000,9090,9100,9323,10250,10244,20244,6443,2379,3000,8080,8443,9710,9711,79,111]
FULL = os.environ.get('FULL','1')=='1'
FASTPORTS = [80,443,8081,9000]
DEVDOMAINS = ['internal.ton.devnet.kiln.fi','stake.devnet.kiln.fi','evm-notifications-webhook.devnet.kiln.fi',
              'ledger-vault-komainu-eth-dapp.devnet.kiln.fi','widget.devnet.kiln.fi','status.thegraph.private.devnet.kiln.fi']
DEVIP='35.241.236.239'

def egress():
    import urllib.request
    try: return urllib.request.urlopen('https://ifconfig.me/ip',timeout=8).read().decode().strip()
    except Exception as e: return 'ERR '+str(e)[:60]

def tcp_banner(ip, port):
    t0=time.time()
    try:
        s=socket.create_connection((ip,port),timeout=6)
    except Exception as e:
        return {'port':port,'open':False,'err':str(e)[:50],'ms':int((time.time()-t0)*1000)}
    buf=b''; s.settimeout(4.0)
    try:
        while len(buf)<200:
            d=s.recv(200)
            if not d: break
            buf+=d
    except Exception: pass
    if not buf:
        try:
            s.sendall(b'SSH-2.0-probe\r\n'); s.settimeout(4.0); buf+=s.recv(200)
        except Exception: pass
    s.close()
    return {'port':port,'open':True,'banner':buf.decode('utf-8','replace')[:120],'nbytes':len(buf),'ms':int((time.time()-t0)*1000)}

def connect_only(ip, port, to=3):
    t0=time.time()
    try:
        s=socket.create_connection((ip,port),timeout=to); s.close()
        return {'port':port,'open':True,'ms':int((time.time()-t0)*1000)}
    except Exception as e:
        return {'port':port,'open':False,'err':str(e)[:40],'ms':int((time.time()-t0)*1000)}

def http_probe(ip, port, hostheader=None, tls=False, path='/', sni=None, to=5):
    try:
        raw=socket.create_connection((ip,port),timeout=to); raw.settimeout(to)
    except Exception as e:
        return {'port':port,'path':path,'tls':tls,'open':False,'err':str(e)[:50]}
    if tls:
        try:
            ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            raw=ctx.wrap_socket(raw,server_hostname=sni or hostheader or ip)
        except Exception as e:
            return {'port':port,'path':path,'tls':tls,'open':True,'tls_err':str(e)[:80]}
    hh=hostheader or ip
    req=(f'GET {path} HTTP/1.0\r\nHost: {hh}\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n').encode()
    try: raw.sendall(req)
    except Exception as e: return {'port':port,'path':path,'tls':tls,'open':True,'send_err':str(e)[:50]}
    buf=b''
    try:
        while len(buf)<400:
            d=raw.recv(400)
            if not d: break
            buf+=d
    except Exception: pass
    raw.close()
    txt=buf.decode('utf-8','replace'); parts=txt.split('\r\n\r\n')
    return {'port':port,'path':path,'tls':tls,'open':True,'head':parts[0][:160],
            'body':(parts[1][:160] if len(parts)>1 else '')}

def main():
    out=[]
    def log(s):
        print('PROBE',s); sys.stdout.flush(); out.append(s)
    eip=egress()
    log('EGRESS_IP='+eip)
    log('FULL='+str(FULL)+' HOSTS='+str(len(HOSTS)))
    # banner on 22 for all hosts (parallel)
    with ThreadPoolExecutor(max_workers=8) as ex:
        futs={h:ex.submit(tcp_banner,h,22) for h in HOSTS}
        for h in HOSTS:
            r=futs[h].result(); log('SSH22 '+h+' '+json.dumps(r,ensure_ascii=False))
    # port scan
    ports = PORTS if FULL else FASTPORTS
    jobs=[(h,p) for h in HOSTS for p in ports]
    def scan(job):
        h,p=job; return h,connect_only(h,p)
    with ThreadPoolExecutor(max_workers=8) as ex:
        res=list(ex.map(scan,jobs))
    for h,r in res:
        if r.get('open'):
            log('PORT %s %s OPEN %dms'%(h,json.dumps(r),r.get('ms',0)))
    # detail probes on open HTTP-ish ports
    opens=[(h,p) for h,r in res if r.get('open')]
    def detail(job):
        h,p=job
        tls = p in (443,8443,6443,9323)
        return h,p,http_probe(h,p,tls=tls,path='/',to=5)
    with ThreadPoolExecutor(max_workers=8) as ex:
        for h,p,r in list(ex.map(detail, opens)):
            log('DETAIL %s:%s %s'%(h,p,json.dumps(r,ensure_ascii=False)))
    # devnet vhosts (only FULL job)
    if FULL:
        def vjob(args):
            dom,port,path=args
            tls=(port==443)
            return dom,port,path,http_probe(DEVIP,port,hostheader=dom,tls=tls,path=path,sni=(dom if tls else None),to=6)
        vjobs=[(d,p,path) for d in DEVDOMAINS for p in (80,443) for path in ('/','/health','/version')]
        with ThreadPoolExecutor(max_workers=8) as ex:
            for dom,port,path,r in list(ex.map(vjob,vjobs)):
                log('VHOST %s %s%s %s'%(dom,port,path,json.dumps(r,ensure_ascii=False)))
        # 57.128.187.3:8081 host-header trial(s)
        for hh in ['relay-kiln.cardano.mainnet.kiln.fi','relay-kiln-4-2.cardano.mainnet.kiln.fi','relay-kiln']:
            r=http_probe('57.128.187.3',8081,hostheader=hh,path='/',to=6)
            log('P8081 %s %s'%(hh,json.dumps(r,ensure_ascii=False)))
    # controls
    log('CTRL_pos_get = %s'%json.dumps(http_probe('1.1.1.1',443,tls=True,hostheader='one.one.one.one',sni='one.one.one.one',to=6),ensure_ascii=False))
    log('CTRL_neg_rand = %s'%json.dumps(connect_only('57.128.187.3',65001,to=3),ensure_ascii=False))
    print('=== PROBE PLAIN ===')
    print('\n'.join(out))

main()

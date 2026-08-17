# Dork Corpus & GitHub Code-Search Dorks

> Reference content for the `offensive-osint` skill. Originally §18 + §19 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 18. Dork Corpus — 80+ templates, 9 categories

Substitute `{domain}` with the target domain (e.g., `example.com`) and `{company}` with the company name (e.g., `Acme Corporation`). Run via Google, Bing, Brave, DuckDuckGo, Yandex, Baidu — engines surface different results.

### 18.1 Files

```
site:{domain} filetype:env
site:{domain} ext:env OR ext:ini OR ext:cfg OR ext:conf
site:{domain} ext:sql OR ext:sqlite OR ext:dump OR ext:bak
site:{domain} ext:pem OR ext:key OR ext:p12 OR ext:pfx
site:{domain} ext:log
site:{domain} intitle:"index of"
site:{domain} inurl:.git OR inurl:/.git/
site:{domain} inurl:backup OR inurl:.bak OR inurl:old
site:{domain} ext:yml OR ext:yaml
site:{domain} ext:properties
```

### 18.2 Admin / login panels

```
site:{domain} inurl:admin OR inurl:login OR inurl:sso OR inurl:dashboard
site:{domain} intitle:"phpMyAdmin"
site:{domain} intitle:"Jenkins"
site:{domain} intitle:"Grafana"
site:{domain} intitle:"Kibana"
site:{domain} intitle:"Splunk"
site:{domain} (intitle:"login" OR intitle:"sign in")
site:{domain} intitle:"GitLab"
site:{domain} intitle:"Swagger" OR intitle:"OpenAPI"
site:{domain} inurl:phpinfo
```

### 18.3 Secrets / credential leakage

```
"{domain}" ("api_key" OR "apikey" OR "access_token")
"{domain}" (password OR passwd OR pwd)
site:pastebin.com "{domain}"
site:ghostbin.com "{domain}"
site:rentry.co "{domain}"
site:gist.github.com "{domain}"
site:hastebin.com "{domain}"
"{domain}" "BEGIN RSA PRIVATE KEY"
```

### 18.4 Cloud / CI / shadow-IT

```
site:s3.amazonaws.com "{domain}"
site:storage.googleapis.com "{domain}"
site:blob.core.windows.net "{domain}"
site:digitaloceanspaces.com "{domain}"
site:trello.com "{domain}"
site:*.atlassian.net "{domain}"
site:dev.azure.com "{domain}"
site:bitbucket.org "{domain}"
site:firebaseio.com "{domain}"
site:herokuapp.com "{domain}"
```

### 18.5 Docs / intel mining

```
site:{domain} filetype:pdf (confidential OR internal OR restricted)
site:{domain} filetype:xlsx OR filetype:csv
site:{domain} filetype:docx
site:scribd.com "{company}"
"{company}" filetype:pdf (salary OR payroll OR org-chart OR "organization chart")
site:linkedin.com/in "{company}"
site:slideshare.net "{company}"
```

### 18.6 Vuln indicators

```
site:{domain} intext:"sql syntax" OR intext:"you have an error in your sql"
site:{domain} intext:"Warning: mysql_"
site:{domain} intext:"Fatal error:" intext:"on line"
site:{domain} intext:"stack trace" OR intext:"Traceback (most recent call last)"
"Apache/2.4.49" site:{domain}
"Server: nginx/1.14" site:{domain}
site:{domain} inurl:wp-content OR inurl:wp-includes
```

### 18.7 Internal tool exposure

```
site:{domain} intitle:"Splunk"
site:{domain} intitle:"Grafana"
site:{domain} intitle:"Kibana"
site:{domain} intitle:"Prometheus Time Series"
site:{domain} intitle:"Jaeger UI"
site:{domain} intitle:"AlertManager"
site:{domain} intitle:"Argo CD"
site:{domain} intitle:"Sonarqube"
site:{domain} intitle:"Sentry"
site:{domain} intitle:"Confluence"
site:{domain} intitle:"Jira"
site:{domain} intitle:"GitLab"
site:{domain} intitle:"Gitea"
site:{domain} intitle:"Drone CI"
site:{domain} inurl:"/jenkins/"
```

### 18.8 Backup / dump file extensions

```
site:{domain} ext:bak OR ext:backup OR ext:old OR ext:orig OR ext:save OR ext:swp
site:{domain} ext:tar OR ext:tar.gz OR ext:tgz OR ext:zip OR ext:rar OR ext:7z
site:{domain} ext:db OR ext:sqlite OR ext:sqlite3 OR ext:mdb
site:{domain} ext:dump OR ext:rdb OR ext:bson
site:{domain} (intext:"-- MySQL dump" OR intext:"PostgreSQL database dump")
site:{domain} ext:pcap OR ext:pcapng OR ext:cap
site:{domain} ext:core OR ext:hprof OR ext:dmp
```

### 18.9 Sector-specific (healthcare / finance / gov)

```
# Healthcare
site:{domain} (filetype:pdf OR filetype:xlsx) (HIPAA OR PHI OR "patient records")
site:{domain} ("DICOM" OR "HL7" OR "ICD-10")

# Finance
site:{domain} (filetype:pdf OR filetype:xlsx) (SOC OR "audit report" OR "internal control")
site:{domain} (filetype:pdf OR filetype:xlsx) ("Form 10-K" OR "Form 10-Q" OR earnings)
site:{domain} ("SWIFT" OR "BIC" OR IBAN OR "wire transfer")

# Gov / public sector
site:{domain} (filetype:pdf OR filetype:doc) (FOUO OR "controlled unclassified" OR CUI)
site:{domain} (filetype:pdf OR filetype:xlsx) ("personnel security" OR clearance)
```

### 18.10 Result classification

After running, score each result via URL signature → title hint → snippet regex:
- **CRITICAL URL signatures:** `.pem`, `.p12`, `.pfx`, `.key` extensions; `id_rsa` filename.
- **HIGH URL signatures:** `/.env`, `/.git/`, database dumps, `wp-config.bak`, `/phpmyadmin`, `/jenkins`, `/phpinfo.php`.
- **MEDIUM URL signatures:** `/admin`, `/login`, `/swagger`, `.log`, `/backup`, `.DS_Store`.
- Snippet content (e.g., a secret regex hit in the snippet) overrides URL signature only if higher severity.
- Confidence: snippet-only match = TENTATIVE (operator must visit URL to confirm; tag detectability=medium).

---

## 19. GitHub Code-Search Dorks for Targets — 13 dorks

Apply each template to `{target}` (root domain stem like `acme`), `{domain}` (full root domain like `acme.com`), and optionally `{company}` (`Acme Corporation`):

```
"{target}" filename:.env
"{target}" filename:.env.example
"{target}" filename:config
"{target}" AWS_ACCESS_KEY_ID
"{target}" AWS_SECRET_ACCESS_KEY
"{target}" password
"{target}" api_key
"{target}" secret
"{target}" authorization: Bearer
"{target}" filename:id_rsa
"{target}" filename:.git-credentials
"{target}" filename:wp-config.php
"@{domain}" password                        # emails + password context
```

**Requirements:** GitHub personal access token (any scope; recommend a fine-grained PAT with read-only repo access). Rate limit per token; concurrency cap ≤5.

**For each result:**
1. Fetch the file (or relevant fragment) via the GitHub Contents API.
2. Run the secret catalog (§17).
3. If a secret hits → `SECRET_LEAK` finding with catalog severity, evidence = repo URL + file path + matched secret (truncated, last 4 chars only).
4. Optional: clone the repo to a tempdir, run `trufflehog`/`gitleaks` for full history scan.

---


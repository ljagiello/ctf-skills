# Tooling Quick-Install

> Reference content for the `offensive-osint` skill. Originally §46 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 46. Tooling Quick-Install

One-liner installs for the most-used external recon tools. All assume Linux/Mac with go/python/git installed.

### 46.1 Subdomain enumeration

```bash
# Subfinder (passive, fast)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass (thorough, slow)
go install github.com/owasp-amass/amass/v4/...@master

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# DNSx (resolution + brute)
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Puredns (brute-force with wildcard handling)
go install github.com/d3mondev/puredns/v2@latest
```

### 46.2 HTTP probing & enrichment

```bash
# httpx (tech-detect, status, JARM, favicon)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Gowitness (screenshots)
go install github.com/sensepost/gowitness@latest

# Aquatone (screenshots + clustering)
go install github.com/michenriksen/aquatone@latest
```

### 46.3 Vulnerability scanning

```bash
# Nuclei (template scanner)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -ut    # update templates

# Naabu (port scan)
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Masscan (fast port scan; requires sudo)
git clone https://github.com/robertdavidgraham/masscan && cd masscan && make
```

### 46.4 Content discovery

```bash
# Ffuf (fuzzer / dirbuster)
go install github.com/ffuf/ffuf/v2@latest

# Gobuster
go install github.com/OJ/gobuster/v3@latest

# Feroxbuster (recursive content disco)
cargo install feroxbuster
```

### 46.5 JS / endpoint extraction

```bash
# Katana (crawler)
go install github.com/projectdiscovery/katana/cmd/katana@latest

# GoSpider
go install github.com/jaeles-project/gospider@latest

# LinkFinder (JS endpoint regex)
git clone https://github.com/GerbenJavado/LinkFinder && cd LinkFinder && pip install -r requirements.txt

# Subjs (extract JS URLs from HTML)
go install github.com/lc/subjs@latest
```

### 46.6 Wayback / archive

```bash
# gau (get all urls from Wayback + others)
go install github.com/lc/gau/v2/cmd/gau@latest

# Waybackurls
go install github.com/tomnomnom/waybackurls@latest
```

### 46.7 Cloud / AWS

```bash
# AWS CLI
pip install awscli
# or: brew install awscli

# Cloud_enum (S3/Azure/GCP enum)
git clone https://github.com/initstring/cloud_enum && cd cloud_enum && pip install -r requirements.txt

# S3Scanner
pip install s3scanner

# CloudSploit
git clone https://github.com/aquasecurity/cloudsploit && cd cloudsploit && npm install
```

### 46.8 Identity / SSO

```bash
# o365creeper / o365enum
git clone https://github.com/gremwell/o365enum

# CredMaster (per-protocol auth probe)
git clone https://github.com/knavesec/CredMaster
```

### 46.9 Mobile

```bash
# google-play-scraper (Python)
pip install google-play-scraper

# androguard (APK static analysis)
pip install androguard
# or: brew install androguard

# apkleaks (secret scan in APK)
pip install apkleaks
```

### 46.10 TLS / cert

```bash
# sslyze
pip install sslyze

# testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git

# JARM
pip install pyjarm

# Cert-spotter / certgraph
go install github.com/lanrat/certgraph@latest
```

### 46.11 Misc utilities

```bash
# Anew (line-dedup that streams)
go install github.com/tomnomnom/anew@latest

# Gf (regex-based grep templates)
go install github.com/tomnomnom/gf@latest

# Hakrawler (web crawler)
go install github.com/hakluke/hakrawler@latest

# Trufflehog (secret scanner)
go install github.com/trufflesecurity/trufflehog@latest

# Gitleaks
go install github.com/zricethezav/gitleaks/v8@latest

# jq (JSON parsing)
sudo apt install jq    # or brew install jq
```

### 46.12 Frameworks / orchestration

```bash
# ProjectDiscovery's "PDTM" (manages the full PD toolkit)
go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest
pdtm -install-all

# reconftw (scripted recon framework)
git clone https://github.com/six2dez/reconftw && cd reconftw && ./install.sh

# Axiom (distributed recon on cloud nodes)
git clone https://github.com/pry0cc/axiom && cd axiom && ./interact/axiom-configure
```

---


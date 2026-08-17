#!/usr/bin/env python3
"""Agent for implementing external attack surface management (EASM).

Combines Shodan, Censys, ProjectDiscovery tools (subfinder, httpx, nuclei),
and a custom exposure scoring algorithm for comprehensive ASM.

DISCLAIMER: This tool is intended for authorized security testing and attack
surface management only. Ensure you have written authorization before scanning
any targets. Unauthorized scanning of systems you do not own or have explicit
permission to test is illegal and unethical.
"""

import json
import subprocess
import argparse
import math
from datetime import datetime
from collections import defaultdict

try:
    import shodan
except ImportError:
    shodan = None

try:
    from censys.search import CensysHosts, CensysCerts
except ImportError:
    CensysHosts = None
    CensysCerts = None


# --------------------------------------------------------------------------- #
#  Port risk weights based on OWASP attack surface analysis methodology
# --------------------------------------------------------------------------- #
PORT_RISK_WEIGHTS = {
    # Management / remote access (highest risk)
    22: 8.0,    # SSH
    23: 9.5,    # Telnet (unencrypted)
    3389: 8.5,  # RDP
    5900: 8.0,  # VNC
    5985: 7.5,  # WinRM HTTP
    5986: 7.0,  # WinRM HTTPS
    # Web services
    80: 3.0,    # HTTP
    443: 2.5,   # HTTPS
    8080: 5.0,  # Alt HTTP (often dev/admin)
    8443: 4.5,  # Alt HTTPS
    8888: 6.0,  # Often dev panels
    # Databases (high risk if exposed)
    3306: 9.0,  # MySQL
    5432: 9.0,  # PostgreSQL
    1433: 9.0,  # MSSQL
    1521: 9.0,  # Oracle
    27017: 9.5, # MongoDB
    6379: 9.5,  # Redis
    9200: 8.5,  # Elasticsearch
    5601: 8.0,  # Kibana
    # Message queues
    5672: 7.5,  # RabbitMQ
    9092: 7.5,  # Kafka
    # File sharing
    21: 8.0,    # FTP
    445: 9.0,   # SMB
    139: 8.5,   # NetBIOS
    # Email
    25: 6.0,    # SMTP
    110: 6.5,   # POP3
    143: 6.0,   # IMAP
    # DNS
    53: 5.0,    # DNS
    # SNMP
    161: 8.0,   # SNMP
    162: 7.5,   # SNMP Trap
}

# Services that indicate sensitive data handling
SENSITIVE_SERVICE_INDICATORS = {
    "mysql", "postgresql", "mongodb", "redis", "elasticsearch",
    "oracle", "mssql", "couchdb", "cassandra", "memcached",
    "rabbitmq", "kafka", "activemq",
}

# Technologies known to have frequent vulnerabilities
HIGH_RISK_TECHNOLOGIES = {
    "apache": 3.0,
    "nginx": 2.0,
    "iis": 4.0,
    "tomcat": 5.0,
    "jboss": 6.0,
    "weblogic": 7.0,
    "wordpress": 6.0,
    "drupal": 5.0,
    "joomla": 5.5,
    "phpmyadmin": 8.0,
    "jenkins": 7.0,
    "gitlab": 5.0,
    "grafana": 4.0,
    "kibana": 5.0,
    "solr": 6.0,
    "struts": 8.0,
    "coldfusion": 7.0,
    "exchange": 7.5,
    "sharepoint": 6.0,
}


class SubdomainEnumerator:
    """Discovers subdomains using subfinder and amass."""

    def __init__(self, domain):
        self.domain = domain
        self.subdomains = set()

    def run_subfinder(self):
        """Run subfinder for passive subdomain enumeration."""
        print(f"[+] Running subfinder against {self.domain}")
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.domain, "-all", "-silent"],
                capture_output=True, text=True, timeout=300,
            )
            found = set(result.stdout.strip().split("\n")) if result.stdout.strip() else set()
            self.subdomains.update(found)
            print(f"[+] subfinder found {len(found)} subdomains")
        except FileNotFoundError:
            print("[-] subfinder not installed. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        except subprocess.TimeoutExpired:
            print("[-] subfinder timed out after 300s")
        return self.subdomains

    def run_amass(self):
        """Run amass for deeper passive enumeration."""
        print(f"[+] Running amass passive enum against {self.domain}")
        try:
            result = subprocess.run(
                ["amass", "enum", "-d", self.domain, "-passive"],
                capture_output=True, text=True, timeout=600,
            )
            found = set(result.stdout.strip().split("\n")) if result.stdout.strip() else set()
            self.subdomains.update(found)
            print(f"[+] amass found {len(found)} subdomains")
        except FileNotFoundError:
            print("[-] amass not installed. Install: go install -v github.com/owasp-amass/amass/v4/...@master")
        except subprocess.TimeoutExpired:
            print("[-] amass timed out after 600s")
        return self.subdomains

    def enumerate_all(self):
        """Run all enumeration tools and merge results."""
        self.run_subfinder()
        self.run_amass()
        self.subdomains.discard("")
        print(f"[+] Total unique subdomains: {len(self.subdomains)}")
        return sorted(self.subdomains)


class ServiceFingerprinter:
    """Probes live hosts and fingerprints services using httpx."""

    def __init__(self, subdomains):
        self.subdomains = subdomains
        self.results = []

    def run_httpx(self):
        """Run httpx for HTTP probing and technology detection."""
        if not self.subdomains:
            print("[-] No subdomains to probe")
            return []

        print(f"[+] Running httpx against {len(self.subdomains)} subdomains")
        input_data = "\n".join(self.subdomains)
        try:
            result = subprocess.run(
                [
                    "httpx", "-sc", "-cl", "-ct", "-title", "-tech-detect",
                    "-favicon", "-cdn", "-cname", "-follow-redirects",
                    "-json", "-silent",
                ],
                input=input_data,
                capture_output=True, text=True, timeout=600,
            )
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        self.results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            print(f"[+] httpx found {len(self.results)} live hosts")
        except FileNotFoundError:
            print("[-] httpx not installed. Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        except subprocess.TimeoutExpired:
            print("[-] httpx timed out after 600s")
        return self.results


class ShodanScanner:
    """Discovers exposed services and vulnerabilities via Shodan API."""

    def __init__(self, api_key):
        if shodan is None:
            raise ImportError("pip install shodan")
        self.api = shodan.Shodan(api_key)
        self.results = []

    def search_domain(self, domain):
        """Search Shodan for all hosts associated with a domain."""
        print(f"[+] Searching Shodan for hostname:{domain}")
        try:
            results = self.api.search(f"hostname:{domain}", limit=500)
            self.results.extend(results.get("matches", []))
            print(f"[+] Shodan returned {results['total']} results")
        except shodan.APIError as e:
            print(f"[-] Shodan API error: {e}")
        return self.results

    def search_org(self, org_name):
        """Search Shodan for all hosts in an organization."""
        print(f'[+] Searching Shodan for org:"{org_name}"')
        try:
            results = self.api.search(f'org:"{org_name}"', limit=500)
            self.results.extend(results.get("matches", []))
            print(f"[+] Shodan returned {results['total']} results")
        except shodan.APIError as e:
            print(f"[-] Shodan API error: {e}")
        return self.results

    def search_ssl_cert(self, domain):
        """Search Shodan for hosts with SSL certificates matching domain."""
        print(f"[+] Searching Shodan for ssl.cert.subject.cn:{domain}")
        try:
            results = self.api.search(f"ssl.cert.subject.cn:{domain}", limit=500)
            self.results.extend(results.get("matches", []))
            print(f"[+] Shodan SSL cert search returned {results['total']} results")
        except shodan.APIError as e:
            print(f"[-] Shodan API error: {e}")
        return self.results

    def get_host_details(self, ip):
        """Get detailed information for a specific IP."""
        try:
            return self.api.host(ip)
        except shodan.APIError as e:
            print(f"[-] Shodan host lookup failed for {ip}: {e}")
            return None

    def get_all_results(self):
        """Return deduplicated results."""
        seen_ips = set()
        deduped = []
        for result in self.results:
            ip = result.get("ip_str", "")
            port = result.get("port", 0)
            key = f"{ip}:{port}"
            if key not in seen_ips:
                seen_ips.add(key)
                deduped.append(result)
        return deduped


class CensysScanner:
    """Discovers internet-facing assets through Censys host and cert search."""

    def __init__(self, api_id, api_secret):
        if CensysHosts is None:
            raise ImportError("pip install censys")
        self.hosts_api = CensysHosts(api_id=api_id, api_secret=api_secret)
        self.certs_api = CensysCerts(api_id=api_id, api_secret=api_secret)
        self.results = []

    def search_hosts(self, domain, max_pages=5):
        """Search Censys for hosts matching domain."""
        print(f"[+] Searching Censys hosts for {domain}")
        query = f"services.tls.certificates.leaf.subject.common_name: {domain}"
        try:
            count = 0
            for page in self.hosts_api.search(query, per_page=100, pages=max_pages):
                for host in page:
                    self.results.append({
                        "ip": host.get("ip"),
                        "services": host.get("services", []),
                        "location": host.get("location", {}),
                        "autonomous_system": host.get("autonomous_system", {}),
                        "source": "censys",
                    })
                    count += 1
            print(f"[+] Censys returned {count} hosts")
        except Exception as e:
            print(f"[-] Censys search error: {e}")
        return self.results

    def search_certificates(self, domain, max_pages=3):
        """Search Censys certificate transparency logs."""
        print(f"[+] Searching Censys certificates for {domain}")
        subdomains = set()
        try:
            for page in self.certs_api.search(
                f"parsed.names: {domain}", per_page=100, pages=max_pages
            ):
                for cert in page:
                    names = cert.get("parsed", {}).get("names", [])
                    for name in names:
                        if name.endswith(domain):
                            subdomains.add(name)
            print(f"[+] Censys certs revealed {len(subdomains)} subdomains")
        except Exception as e:
            print(f"[-] Censys cert search error: {e}")
        return subdomains


class VulnerabilityScanner:
    """Runs vulnerability scans using Nuclei."""

    def __init__(self, targets):
        self.targets = targets
        self.findings = []

    def run_nuclei(self, severity="critical,high", tags=None):
        """Run nuclei against targets with specified severity/tags."""
        if not self.targets:
            print("[-] No targets for nuclei scan")
            return []

        print(f"[+] Running nuclei against {len(self.targets)} targets")
        input_data = "\n".join(self.targets)
        cmd = ["nuclei", "-json", "-silent", "-severity", severity]
        if tags:
            cmd.extend(["-tags", tags])

        try:
            result = subprocess.run(
                cmd, input=input_data,
                capture_output=True, text=True, timeout=1800,
            )
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        finding = json.loads(line)
                        self.findings.append({
                            "template_id": finding.get("template-id", ""),
                            "name": finding.get("info", {}).get("name", ""),
                            "severity": finding.get("info", {}).get("severity", ""),
                            "host": finding.get("host", ""),
                            "matched_at": finding.get("matched-at", ""),
                            "type": finding.get("type", ""),
                            "description": finding.get("info", {}).get("description", ""),
                            "tags": finding.get("info", {}).get("tags", []),
                            "reference": finding.get("info", {}).get("reference", []),
                            "cvss_score": finding.get("info", {}).get(
                                "classification", {}
                            ).get("cvss-score", 0),
                            "cve_id": finding.get("info", {}).get(
                                "classification", {}
                            ).get("cve-id", ""),
                        })
                    except json.JSONDecodeError:
                        continue
            print(f"[+] nuclei found {len(self.findings)} vulnerabilities")
        except FileNotFoundError:
            print("[-] nuclei not installed. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        except subprocess.TimeoutExpired:
            print("[-] nuclei timed out after 1800s")
        return self.findings


class ExposureScorer:
    """Calculates exposure scores using OWASP attack surface analysis principles.

    The scoring algorithm implements a weighted formula derived from:
    - OWASP Relative Attack Surface Quotient (RSQ)
    - Carnegie Mellon damage-potential-to-effort ratio
    - CVSS-based vulnerability weighting

    Final score is normalized to 0-100 range.
    """

    def __init__(self):
        self.weights = {
            "open_ports": 0.25,
            "vulnerabilities": 0.30,
            "technology_risk": 0.15,
            "exposure_level": 0.15,
            "data_sensitivity": 0.15,
        }

    def score_open_ports(self, ports):
        """Score based on open ports and their associated risk.

        Uses PORT_RISK_WEIGHTS to assign higher scores to management ports,
        databases, and legacy protocols.
        """
        if not ports:
            return 0.0

        total_risk = 0.0
        for port in ports:
            weight = PORT_RISK_WEIGHTS.get(port, 4.0)
            total_risk += weight

        # Normalize: more ports = higher risk, but with diminishing returns
        # Using log scale to prevent linear explosion with many ports
        normalized = min(100.0, (total_risk / len(ports)) * 10 * math.log2(len(ports) + 1))
        return round(normalized, 2)

    def score_vulnerabilities(self, vulns):
        """Score based on discovered vulnerabilities weighted by CVSS.

        Critical (9.0-10.0): weight 10
        High (7.0-8.9): weight 7
        Medium (4.0-6.9): weight 4
        Low (0.1-3.9): weight 2
        """
        if not vulns:
            return 0.0

        total_weight = 0.0
        for vuln in vulns:
            cvss = vuln.get("cvss_score", 0)
            if isinstance(cvss, str):
                try:
                    cvss = float(cvss)
                except ValueError:
                    cvss = 5.0

            if cvss >= 9.0:
                total_weight += 10.0
            elif cvss >= 7.0:
                total_weight += 7.0
            elif cvss >= 4.0:
                total_weight += 4.0
            else:
                total_weight += 2.0

        # Normalize with diminishing returns
        normalized = min(100.0, total_weight * math.log2(len(vulns) + 1))
        return round(normalized, 2)

    def score_technology_risk(self, technologies):
        """Score based on technology stack risk assessment."""
        if not technologies:
            return 0.0

        total_risk = 0.0
        matched = 0
        for tech in technologies:
            tech_lower = tech.lower()
            for known_tech, risk in HIGH_RISK_TECHNOLOGIES.items():
                if known_tech in tech_lower:
                    total_risk += risk
                    matched += 1
                    break

        if matched == 0:
            return 10.0  # Unknown tech gets baseline risk

        normalized = min(100.0, (total_risk / matched) * 12 * math.log2(matched + 1))
        return round(normalized, 2)

    def score_exposure_level(self, asset):
        """Score based on how exposed the asset is.

        Factors: internet-reachable, authentication required, CDN protection.
        """
        score = 50.0  # Base score for internet-facing asset

        # No HTTPS = higher risk
        if asset.get("scheme") == "http":
            score += 15.0

        # CDN protection reduces exposure
        if asset.get("cdn"):
            score -= 20.0

        # Authentication indicators reduce exposure
        status_code = asset.get("status_code", 200)
        if status_code in (401, 403):
            score -= 25.0

        # Default/login pages increase risk
        title = (asset.get("title") or "").lower()
        if any(kw in title for kw in ["login", "admin", "dashboard", "panel", "console"]):
            score += 20.0

        return round(max(0.0, min(100.0, score)), 2)

    def score_data_sensitivity(self, services, ports):
        """Score based on potential data sensitivity.

        Database ports, email services, and file shares indicate sensitive data handling.
        """
        score = 0.0
        service_set = set()
        for svc in (services or []):
            service_set.add(svc.lower() if isinstance(svc, str) else "")

        # Check for sensitive service indicators
        for indicator in SENSITIVE_SERVICE_INDICATORS:
            if indicator in service_set:
                score += 15.0

        # Check for database ports
        db_ports = {3306, 5432, 1433, 1521, 27017, 6379, 9200}
        exposed_db_ports = set(ports or []) & db_ports
        score += len(exposed_db_ports) * 20.0

        # File sharing ports
        file_ports = {21, 445, 139, 2049}
        exposed_file_ports = set(ports or []) & file_ports
        score += len(exposed_file_ports) * 15.0

        return round(min(100.0, score), 2)

    def calculate_asset_score(self, asset):
        """Calculate the overall exposure score for an asset.

        Returns a dict with component scores and weighted total (0-100).
        """
        ports = asset.get("ports", [])
        vulns = asset.get("vulnerabilities", [])
        technologies = asset.get("technologies", [])
        services = asset.get("services", [])

        component_scores = {
            "open_ports": self.score_open_ports(ports),
            "vulnerabilities": self.score_vulnerabilities(vulns),
            "technology_risk": self.score_technology_risk(technologies),
            "exposure_level": self.score_exposure_level(asset),
            "data_sensitivity": self.score_data_sensitivity(services, ports),
        }

        weighted_total = sum(
            component_scores[key] * self.weights[key]
            for key in self.weights
        )

        return {
            "host": asset.get("host", asset.get("ip", "unknown")),
            "total_score": round(weighted_total, 2),
            "risk_level": self._risk_level(weighted_total),
            "component_scores": component_scores,
            "weights": self.weights,
        }

    def _risk_level(self, score):
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "INFORMATIONAL"

    def score_all_assets(self, assets):
        """Score all assets and return sorted by risk."""
        scored = [self.calculate_asset_score(a) for a in assets]
        scored.sort(key=lambda x: x["total_score"], reverse=True)
        return scored


class ASMPipeline:
    """Orchestrates the full attack surface management pipeline."""

    def __init__(self, domain, shodan_key=None, censys_id=None, censys_secret=None):
        self.domain = domain
        self.shodan_key = shodan_key
        self.censys_id = censys_id
        self.censys_secret = censys_secret
        self.subdomains = []
        self.live_hosts = []
        self.shodan_results = []
        self.censys_results = []
        self.nuclei_findings = []
        self.assets = []

    def enumerate_subdomains(self):
        """Phase 1: Discover subdomains."""
        enumerator = SubdomainEnumerator(self.domain)
        self.subdomains = enumerator.enumerate_all()

        # Enrich with Censys certificate transparency
        if self.censys_id and self.censys_secret:
            try:
                censys = CensysScanner(self.censys_id, self.censys_secret)
                ct_subdomains = censys.search_certificates(self.domain)
                combined = set(self.subdomains) | ct_subdomains
                self.subdomains = sorted(combined)
                print(f"[+] After CT enrichment: {len(self.subdomains)} subdomains")
            except Exception as e:
                print(f"[-] Censys CT search failed: {e}")

        return self.subdomains

    def fingerprint_services(self):
        """Phase 2: Probe live hosts and fingerprint technologies."""
        fingerprinter = ServiceFingerprinter(self.subdomains)
        self.live_hosts = fingerprinter.run_httpx()
        return self.live_hosts

    def discover_shodan(self):
        """Phase 3: Enrich with Shodan data."""
        if not self.shodan_key:
            print("[!] Shodan API key not provided, skipping")
            return []

        try:
            scanner = ShodanScanner(self.shodan_key)
            scanner.search_domain(self.domain)
            scanner.search_ssl_cert(self.domain)
            self.shodan_results = scanner.get_all_results()
        except Exception as e:
            print(f"[-] Shodan scanning failed: {e}")
        return self.shodan_results

    def discover_censys(self):
        """Phase 4: Enrich with Censys data."""
        if not self.censys_id or not self.censys_secret:
            print("[!] Censys API credentials not provided, skipping")
            return []

        try:
            scanner = CensysScanner(self.censys_id, self.censys_secret)
            self.censys_results = scanner.search_hosts(self.domain)
        except Exception as e:
            print(f"[-] Censys scanning failed: {e}")
        return self.censys_results

    def scan_vulnerabilities(self):
        """Phase 5: Run vulnerability scans."""
        targets = []
        for host in self.live_hosts:
            url = host.get("url", "")
            if url:
                targets.append(url)
        if not targets:
            targets = [f"https://{sub}" for sub in self.subdomains[:100]]

        scanner = VulnerabilityScanner(targets)
        self.nuclei_findings = scanner.run_nuclei()
        return self.nuclei_findings

    def _build_asset_inventory(self):
        """Merge all data sources into a unified asset inventory."""
        asset_map = defaultdict(lambda: {
            "host": "",
            "ip": "",
            "ports": [],
            "services": [],
            "technologies": [],
            "vulnerabilities": [],
            "status_code": 200,
            "title": "",
            "cdn": False,
            "scheme": "https",
        })

        # Merge httpx results
        for host in self.live_hosts:
            key = host.get("host", host.get("input", ""))
            asset = asset_map[key]
            asset["host"] = key
            asset["status_code"] = host.get("status_code", 200)
            asset["title"] = host.get("title", "")
            asset["cdn"] = host.get("cdn", False)
            asset["scheme"] = host.get("scheme", "https")
            techs = host.get("tech", [])
            if isinstance(techs, list):
                asset["technologies"].extend(techs)
            port = host.get("port", 0)
            if port:
                asset["ports"].append(port)

        # Merge Shodan results
        for result in self.shodan_results:
            ip = result.get("ip_str", "")
            hostnames = result.get("hostnames", [])
            key = hostnames[0] if hostnames else ip
            asset = asset_map[key]
            asset["ip"] = ip
            asset["host"] = asset["host"] or key
            port = result.get("port", 0)
            if port and port not in asset["ports"]:
                asset["ports"].append(port)
            product = result.get("product", "")
            if product and product not in asset["services"]:
                asset["services"].append(product)
            for cve in result.get("vulns", []):
                asset["vulnerabilities"].append({
                    "cve_id": cve,
                    "cvss_score": result.get("vulns", {}).get(cve, {}).get(
                        "cvss", 5.0
                    ) if isinstance(result.get("vulns"), dict) else 5.0,
                    "source": "shodan",
                })

        # Merge Censys results
        for result in self.censys_results:
            ip = result.get("ip", "")
            key = ip
            asset = asset_map[key]
            asset["ip"] = ip
            asset["host"] = asset["host"] or ip
            for svc in result.get("services", []):
                port = svc.get("port", 0)
                if port and port not in asset["ports"]:
                    asset["ports"].append(port)
                svc_name = svc.get("service_name", "")
                if svc_name and svc_name not in asset["services"]:
                    asset["services"].append(svc_name)

        # Merge Nuclei findings
        for finding in self.nuclei_findings:
            host = finding.get("host", "")
            # Match to existing asset or create new entry
            matched_key = None
            for key in asset_map:
                if key in host or host in key:
                    matched_key = key
                    break
            if matched_key is None:
                matched_key = host
            asset_map[matched_key]["vulnerabilities"].append({
                "cve_id": finding.get("cve_id", ""),
                "name": finding.get("name", ""),
                "severity": finding.get("severity", ""),
                "cvss_score": finding.get("cvss_score", 5.0),
                "template_id": finding.get("template_id", ""),
                "source": "nuclei",
            })

        # Deduplicate technologies and ports
        for asset in asset_map.values():
            asset["ports"] = sorted(set(asset["ports"]))
            asset["technologies"] = list(set(asset["technologies"]))
            asset["services"] = list(set(asset["services"]))

        self.assets = list(asset_map.values())
        return self.assets

    def score_assets(self):
        """Phase 6: Calculate exposure scores for all assets."""
        if not self.assets:
            self._build_asset_inventory()

        scorer = ExposureScorer()
        return scorer.score_all_assets(self.assets)

    def run_full_scan(self):
        """Execute the complete ASM pipeline."""
        print(f"\n{'='*60}")
        print(f"  ATTACK SURFACE MANAGEMENT SCAN: {self.domain}")
        print(f"{'='*60}\n")

        # Phase 1: Subdomain enumeration
        print("[*] Phase 1: Subdomain Enumeration")
        self.enumerate_subdomains()

        # Phase 2: Service fingerprinting
        print("\n[*] Phase 2: Service Fingerprinting")
        self.fingerprint_services()

        # Phase 3: Shodan enrichment
        print("\n[*] Phase 3: Shodan Asset Discovery")
        self.discover_shodan()

        # Phase 4: Censys enrichment
        print("\n[*] Phase 4: Censys Asset Discovery")
        self.discover_censys()

        # Phase 5: Vulnerability scanning
        print("\n[*] Phase 5: Vulnerability Scanning")
        self.scan_vulnerabilities()

        # Phase 6: Build inventory and score
        print("\n[*] Phase 6: Asset Inventory and Exposure Scoring")
        self._build_asset_inventory()
        scored_assets = self.score_assets()

        # Build final report
        report = {
            "scan_id": f"asm-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            "domain": self.domain,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_subdomains": len(self.subdomains),
                "live_hosts": len(self.live_hosts),
                "shodan_services": len(self.shodan_results),
                "censys_hosts": len(self.censys_results),
                "total_vulnerabilities": len(self.nuclei_findings),
                "total_assets": len(self.assets),
                "critical_assets": sum(
                    1 for a in scored_assets if a["risk_level"] == "CRITICAL"
                ),
                "high_risk_assets": sum(
                    1 for a in scored_assets if a["risk_level"] == "HIGH"
                ),
                "medium_risk_assets": sum(
                    1 for a in scored_assets if a["risk_level"] == "MEDIUM"
                ),
                "low_risk_assets": sum(
                    1 for a in scored_assets if a["risk_level"] in ("LOW", "INFORMATIONAL")
                ),
                "average_score": round(
                    sum(a["total_score"] for a in scored_assets) / max(len(scored_assets), 1), 2
                ),
            },
            "scored_assets": scored_assets,
            "subdomains": self.subdomains,
            "vulnerabilities": self.nuclei_findings,
            "raw_data": {
                "httpx_hosts": len(self.live_hosts),
                "shodan_matches": len(self.shodan_results),
                "censys_matches": len(self.censys_results),
            },
        }

        return report


def main():
    parser = argparse.ArgumentParser(
        description="Attack Surface Management Agent"
    )
    parser.add_argument("--domain", help="Target domain")
    parser.add_argument("--domain-list", help="File with list of target domains")
    parser.add_argument(
        "--action",
        required=True,
        choices=["enumerate", "fingerprint", "shodan", "censys", "vuln_scan", "score", "full_scan"],
    )
    parser.add_argument("--shodan-key", help="Shodan API key")
    parser.add_argument("--censys-id", help="Censys API ID")
    parser.add_argument("--censys-secret", help="Censys API secret")
    parser.add_argument("--input", help="Input file from previous scan (JSON)")
    parser.add_argument("--output", default="asm_report.json")
    args = parser.parse_args()

    domains = []
    if args.domain:
        domains.append(args.domain)
    elif args.domain_list:
        with open(args.domain_list) as f:
            domains = [line.strip() for line in f if line.strip()]
    else:
        print("[-] Provide --domain or --domain-list")
        return

    all_reports = []
    for domain in domains:
        pipeline = ASMPipeline(
            domain=domain,
            shodan_key=args.shodan_key,
            censys_id=args.censys_id,
            censys_secret=args.censys_secret,
        )

        if args.action == "enumerate":
            subdomains = pipeline.enumerate_subdomains()
            report = {
                "domain": domain,
                "subdomains": subdomains,
                "count": len(subdomains),
            }
        elif args.action == "fingerprint":
            pipeline.enumerate_subdomains()
            hosts = pipeline.fingerprint_services()
            report = {"domain": domain, "live_hosts": hosts, "count": len(hosts)}
        elif args.action == "shodan":
            results = pipeline.discover_shodan()
            report = {"domain": domain, "shodan_results": results, "count": len(results)}
        elif args.action == "censys":
            results = pipeline.discover_censys()
            report = {"domain": domain, "censys_results": results, "count": len(results)}
        elif args.action == "vuln_scan":
            pipeline.enumerate_subdomains()
            pipeline.fingerprint_services()
            findings = pipeline.scan_vulnerabilities()
            report = {"domain": domain, "vulnerabilities": findings, "count": len(findings)}
        elif args.action == "score":
            if args.input:
                with open(args.input) as f:
                    prev_data = json.load(f)
                assets = prev_data.get("scored_assets", prev_data.get("assets", []))
                scorer = ExposureScorer()
                scored = scorer.score_all_assets(assets)
                report = {"domain": domain, "scored_assets": scored}
            else:
                report = pipeline.run_full_scan()
        elif args.action == "full_scan":
            report = pipeline.run_full_scan()
        else:
            print(f"[-] Unknown action: {args.action}")
            continue

        all_reports.append(report)

    output = all_reports[0] if len(all_reports) == 1 else {"domains": all_reports}
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n[+] Report saved to {args.output}")

    # Print summary
    for report in all_reports:
        if "summary" in report:
            s = report["summary"]
            print(f"\n{'='*60}")
            print(f"  ASM SUMMARY: {report.get('domain', 'N/A')}")
            print(f"{'='*60}")
            print(f"  Subdomains discovered: {s.get('total_subdomains', 0)}")
            print(f"  Live hosts: {s.get('live_hosts', 0)}")
            print(f"  Total vulnerabilities: {s.get('total_vulnerabilities', 0)}")
            print(f"  Assets scored: {s.get('total_assets', 0)}")
            print(f"  Average exposure score: {s.get('average_score', 0)}")
            print(f"  CRITICAL: {s.get('critical_assets', 0)}")
            print(f"  HIGH: {s.get('high_risk_assets', 0)}")
            print(f"  MEDIUM: {s.get('medium_risk_assets', 0)}")
            print(f"  LOW: {s.get('low_risk_assets', 0)}")


if __name__ == "__main__":
    main()

# Cloud + Containers Principles

This file is the entry point for cloud and container security testing. Specific techniques live under `scenarios/<area>/<scenario>.md`. Use `INDEX.md` to pick a scenario by trigger.

## Decision tree

| Fingerprint | Family | Where to start |
|---|---|---|
| AWS access key / target on AWS | `scenarios/aws/recon-and-iam-privesc.md` | `aws sts`, Pacu, ScoutSuite |
| MinIO / self-hosted S3 (port 9000/8333) | `scenarios/aws/minio-self-hosted-s3.md` | `mc admin info`, hidden buckets |
| Lambda / serverless / SaaS / OAuth | `scenarios/aws/serverless-and-saas.md` | Function injection, subdomain takeover |
| Azure target / `*.blob.core.windows.net` | `scenarios/azure/recon-and-storage.md` | `az login`, ROADtools, MicroBurst |
| GCP target / `metadata.google.internal` | `scenarios/gcp/recon-and-iam.md` | `gcloud`, `gsutil`, IAM privesc |
| Shell inside Docker container | `scenarios/docker/container-recon-and-escape.md` | `/proc/1/cgroup`, mount info, escape |
| Kubernetes cluster / pod foothold | `scenarios/kubernetes/recon-and-rbac.md` | `kubectl auth can-i`, kubelet 10250, SA pivot |

## Sequencing principles

1. **Identity first.** `aws sts get-caller-identity` / `az account show` / `gcloud auth list` before any other enumeration. Confirms credentials work and reveals current context.
2. **Read source / config before brute-forcing.** Cloud SDK pulls metadata in one call; brute-forcing wastes API calls and trips rate limits.
3. **LocalStack / MinIO use default test/test creds.** Never spray; just use defaults.
4. **Container detection first**: `/proc/1/cgroup` and `/.dockerenv` distinguish containerization. Mount info reveals bind mounts and host paths.
5. **kubelet is often weaker than API server.** Test 10250 unauthenticated before assuming the cluster is hardened.
6. **SA tokens chain across namespaces.** Foothold pod's default SA may be useless, but pivoting through pod listings in another namespace can find a privileged SA.
7. **Cloud metadata SSRF requires platform-specific headers.** AWS IMDSv2 = PUT + token; GCP = `Metadata-Flavor: Google`; Azure = `Metadata: true`.
8. **DynamoDB credentials reuse OS-level passwords.** On LocalStack-backed labs, the DDB users table almost always has SSH-equivalent passwords.
9. **Versioned buckets retain pre-cleanup content.** Use `list_object_versions` to recover deleted/overwritten secrets.
10. **Pod logs > kubectl exec** when network egress is restricted — write output to stdout, read via `pods/log` API.

## Cross-cutting gotchas

- **IMDSv2** requires PUT request + custom header — most SSRF can't reach AWS metadata; older IMDSv1 instances are still common.
- **GCP metadata requires `Metadata-Flavor: Google`** — without it, the service refuses.
- **Azure storage anonymous access** requires `?comp=list` query parameter; HEAD doesn't enumerate.
- **MinIO blocks `..` in object keys** (`XMinioInvalidResourceName`) — path traversal in keys does NOT work.
- **`mc admin update` cannot upload malicious binary** — minisign signature validation. `mc admin service restart/stop` doesn't bypass systemd.
- **Privileged-container escape via cgroup release_agent** requires `CAP_SYS_ADMIN` AND modern kernel quirks.
- **kubelet 10250 needs `https://` and `--insecure`** — it uses self-signed certs.
- **`image: alpine` may fail on air-gapped clusters** — reuse a local-registry image discovered in existing pod specs.
- **Multi-replica Deployment** means each request may hit a different pod — file written to one isn't visible from another. Use stdout + pods/log.
- **Lambda payloads must match expected event schema** — wrong shape fails before reaching the injection sink.
- **PowerShell rev-shell stream input length cap** ~300 bytes/send — long commands silently fail.
- **Domain DC user-profile path** lives at `C:\Users\<sam>.<DOMAIN>\` not `C:\Users\<sam>\` — search both forms for `user.txt`.
- **GhostScript EPS RCE** triggers via `/DCTDecode filter` after the `%pipe%` device — the suffix is required.
- **Roundcube `_from=email` fails** — must use numeric identity ID from `<select name="_from">`.

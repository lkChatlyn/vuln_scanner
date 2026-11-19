# vuln_scanner

One rule per CVE, run against a Docker host and all of its running containers.
Each rule rates the target as one of:

| State | Meaning | Result |
|---|---|---|
| **VULN** | Affected version, vulnerable feature in use, no mitigation | fails |
| **PARTIALLY_MITIGATED** | Not patched, but a workaround that only reduces the risk is in place (e.g. PHP `session.upload_progress.enabled=0` for CVE-2026-109619). The detail lists what is and isn't in place | fails: upgrade still needed |
| **MITIGATED** | Feature not used, loaded or configured, or a full workaround is in place | passes |
| **PATCHED** | A fixed version is deployed | passes |
| **UNKNOWN** | The rule couldn't read what it needs (for example, no permission) | fails, so it's never assumed safe |
| **N/A** | Product not present on the target | skipped, hidden unless `-a` |
| **SKIPPED** | Container has no shell (distroless or scratch image), so it can't be checked | listed, doesn't fail the run |

The rules form a [Cinc Auditor](https://cinc.sh/start/auditor/) profile, the free build of Chef InSpec.

## Setup (on the Docker host)

```bash
curl -L https://omnitruck.cinc.sh/install.sh | sudo bash -s -- -P cinc-auditor
sudo apt-get install -y jq
git clone https://github.com/lkChatlyn/vuln_scanner.git /opt/vuln_scanner
```

## Running

```bash
sudo /opt/vuln_scanner/scan.sh
```

```
Docker host  1 VULN, 1 PARTIALLY_MITIGATED, 1 MITIGATED
    VULN                 CVE-2026-98432        kernel 6.1.180, distro package older than the fixed one
    PARTIALLY_MITIGATED  CVE-2026-80844        kernel 6.1.180, unprivileged user namespaces disabled; upgrade to remove the remaining risk

shop_app (3 replicas)  1 VULN, 1 PARTIALLY_MITIGATED, 1 MITIGATED
    VULN                 CVE-2026-109618       PHP 8.4.20, fixed in 8.4.27
    PARTIALLY_MITIGATED  CVE-2026-109619       PHP 8.4.20, session.upload_progress.enabled=0; upgrade to remove the remaining risk

portainer_agent  1 SKIPPED
    SKIPPED              no shell in container (distroless/scratch image), cannot be checked

proxy_web  9 MITIGATED, 2 PATCHED  ok

12 targets (19 containers + host, one replica per service), 2 VULN, 2 PARTIALLY_MITIGATED, 10 MITIGATED, 2 PATCHED, 1 SKIPPED, 8 with no affected software
```

Results are grouped per container and host, worst first. Each header line counts the results for that target. VULN, PARTIALLY_MITIGATED, UNKNOWN, ERROR and SKIPPED are always listed. MITIGATED and PATCHED results are only counted (use `-d` to list them), and targets where no rule applies are left out.

Replicas are scanned and listed once. Containers of the same Swarm service or Compose service that run the same image are one target, shown as e.g. `windmill_worker (3 replicas)`, and only one replica is scanned. Replicas on a different image, for example halfway through a rolling update, stay separate (`windmill_worker img 1a2b3c4d5e6f`). Other containers are scanned one by one even when they share an image, because their config can differ.

Options:
- `-j <n>`: scan n targets in parallel (default 4). Each target takes about 2 s, mostly Cinc Auditor's startup time. Each parallel job needs about 150–200 MB of RAM.
- `-n`: containers only, skip the host (also skips the kernel and Go rules, see below)
- `-d`: also list MITIGATED and PATCHED results, with the reason
- `-a`: also list N/A results
- `-v`: print Cinc Auditor's full output
- `-p <git-url>`: run rules from a repo without cloning it
- `-k`: keep the raw JSON report for each target (large, deleted by default)

The result is the table above. It's also saved as `reports/<timestamp>/summary.tsv` next to the script, along with a `.log` file for any target that errored.

The exit code is `1` if anything is VULN, PARTIALLY_MITIGATED, UNKNOWN or ERROR, so the script can run from cron or a monitoring check.

To run a single rule against a single container:

```bash
cinc-auditor exec . -t docker://<container> --controls CVE-2026-115560
```

## How the rules work

- **Shared facts, read once per target.** Rules don't run commands themselves. They ask a facts resource (`nginx_facts`, `php_facts`, `os_facts`, ...), which reads everything for that product in one shell call and caches it. Adding rules for a product you already check costs almost nothing. A container without any known product costs about 11 quick commands. See [libraries/facts.rb](libraries/facts.rb).
- **One evaluator.** `cve_eval` turns version, fixed versions, mitigations and partial workarounds into PATCHED / MITIGATED / PARTIALLY_MITIGATED / VULN / UNKNOWN. See [libraries/cve_state.rb](libraries/cve_state.rb).
- **Distro packages.** Debian, Ubuntu and Alpine backport fixes without changing the upstream version (Debian's Apache 2.4.62 can be fixed). Where the advisory lists a fixed distro package, the installed package version decides. Vendor packages on another branch, such as nginx.org's own build in the official nginx image, are compared by upstream version instead.
- **Host-only rules.** Kernel and Go rules run only on the Docker host:
  - Containers share the host kernel.
  - The host sees every container's processes, including distroless ones without a shell, so it can read the Go version each running binary was built with. The detail names the container: `portainer_agent:agent (go1.25.4)`.
- **Conditions in application code** can't be checked, such as "only if the app serves HTTP/2 itself". Those rules report VULN for an unpatched version and add the condition to the detail, e.g. `...; only if the app serves HTTP/2`.

## Adding a CVE

1. Copy [templates/CVE-YYYY-NNNNN.rb](templates/CVE-YYYY-NNNNN.rb) to `controls/<CVE-ID>.rb`.
2. Fill in the facts to use, the fixed versions per branch, the mitigations (`mitigated:`) and partial workarounds (`partial:`). If a product isn't covered yet, add a `*_facts` resource to `libraries/facts.rb`.
3. Test it against one container, then commit:

```bash
cinc-auditor exec . -t docker://<container> --controls <CVE-ID>
```

When a vendor ships a fix for a CVE you could previously only mitigate, add the version to `fixed`. Targets running that version then show as PATCHED.

## Rules

| Product | CVE | CVSS | Issue |
|---|---|---|---|
| nginx | CVE-2026-113425 | 8.1 | mail proxy use-after-free |
| nginx | CVE-2026-118899 | 7.5 | TLS 1.3 infinite loop reading request bodies |
| nginx | CVE-2026-121810 | 5.9 | HTTP/3 use-after-free |
| nginx | CVE-2026-123007 | 8.1 | HTTP/2 flow-control heap overflow |
| nginx | CVE-2026-123633 | 8.1 | HTTP/2 use-after-free when worker_connections run out |
| nginx | CVE-2026-123634 | 6.5 | DNS resolver use-after-free |
| nginx | CVE-2026-15176 | 8.1 | alias + rewrite buffer overflow |
| nginx | CVE-2026-93479 | 8.1 | map regex capture buffer overflow |
| nginx | CVE-2026-97205 | 8.1 | async I/O use-after-free with SSI |
| Apache httpd | CVE-2026-106023 | 7.5 | mod_md NULL dereference |
| Apache httpd | CVE-2026-119618 | 9.8 | mod_http2 assign_headers() remote code execution |
| Apache httpd | CVE-2026-57941 | 5.6 | mod_http2 session buffer use-after-free |
| Apache httpd | CVE-2026-63292 | 8.1 | mod_vhost_alias stack overflow |
| Tomcat | CVE-2026-101296 | 7.4 | JNDIRealm SASL authentication bypass |
| Tomcat | CVE-2026-101356 | 9.1 | HTTP/2 async data mixed between users |
| PHP | CVE-2026-109618 | 9.2 | request memory corruption RCE (PHP2Shell) |
| PHP | CVE-2026-109619 | 9.2 | stale global state RCE (PHP2Shell) |
| PHP | CVE-2026-115560 | n/a | session serializer mismatch RCE |
| PHP | CVE-2026-126714 | 9.2 | partially overwritten session files RCE |
| Node.js | CVE-2026-105482 | 7.4 | DNS hostname truncation at NUL |
| Node.js | CVE-2026-105483 | n/a | TLS Unicode hostname validation bypass |
| Node.js | CVE-2026-106069 | 7.4 | TLS hostname verification bypass |
| Node.js | CVE-2026-111497 | 9.8 | Brotli decoder remote code execution |
| Node.js | CVE-2026-123863 | 8.2 | HTTP/2 session teardown crash |
| Node.js | CVE-2026-123864 | 7.4 | HTTPS heap memory disclosure |
| Node.js | CVE-2026-123865 | 7.5 | HTTP/2 shutdown resource exhaustion |
| Node.js | CVE-2026-123866 | 7.5 | HTTP/2 response memory disclosure |
| Node.js | CVE-2026-123872 | 8.1 | TLS client certificate authentication bypass |
| Node.js | CVE-2026-123874 | 7.5 | HTTP/2 file streaming use-after-free |
| Node.js | CVE-2026-126051 | 7.5 | TLS handshake crash |
| Java | CVE-2026-114938 | 9.8 | Java4Shell Base64 intrinsic RCE on x86-64 AVX-512 |
| Java | CVE-2026-114939 | 7.4 | JGSS (Kerberos) flaw |
| Java | CVE-2026-114940 | 7.4 | JSSE TLS flaw |
| Java | CVE-2026-114941 | 7.0 | HotSpot compiler flaw |
| Java | CVE-2026-114942 | 7.0 | core libraries flaw |
| Java | CVE-2026-86144 | 7.8 | JavaFX WebView bundled libxml2 |
| .NET | CVE-2026-102870 | 8.8 | Blazor WebAssembly debug proxy RCE |
| .NET | CVE-2026-114148 | 7.8 | ASP.NET Core runtime tarball ownership privilege escalation |
| .NET | CVE-2026-114149 | 7.5 | ASP.NET Core multipart DoS |
| Python | CVE-2026-19445 | 8.1 | ssl SNI callback use-after-free |
| Rails | CVE-2026-122006 | 9.8 | Active Storage arbitrary file write via ImageMagick (was CVE-2026-126082) |
| Rails | CVE-2026-126080 | 7.5 | Active Support safe_constantize DoS |
| Rails | CVE-2026-126081 | 7.5 | Strong Parameters bypass via each_key |
| Rails | CVE-2026-126083 | 7.4 | client IP spoofing via Forwarded header |
| Rails | CVE-2026-126186 | 8.8 | Active Storage file read / RCE in video previews and analysis |
| Go (running binaries) | CVE-2026-56866 | 8.7 | Transport desync after rejected CONNECT (host) |
| Go (running binaries) | CVE-2026-78659 | 7.5 | HTTP/2 trailer memory exhaustion (host) |
| Go (running binaries) | CVE-2026-78660 | 7.5 | HTTP/2 client accepts malformed framing headers (host) |
| Go (running binaries) | CVE-2026-78663 | n/a | HTTP/2 flow-control refund bypass (host) |
| Go (running binaries) | CVE-2026-78667 | 7.5 | Range header CPU exhaustion in FileServer (host) |
| Go (running binaries) | CVE-2026-78669 | n/a | HTTP/2 SETTINGS CPU exhaustion (host) |
| Go (running binaries) | CVE-2026-94439 | 6.5 | request smuggling after CONNECT 2xx (host) |
| Go (running binaries) | CVE-2026-94440 | 7.5 | multipart MIME header memory limit bypass (host) |
| Go (running binaries) | CVE-2026-97031 | 7.5 | crypto/tls ECH memory exhaustion (host) |
| Go (running binaries) | CVE-2026-97032 | n/a | HTTP/2 HPACK encoder race crash (host) |
| Go toolchain | CVE-2026-97033-97043 | 7.4 | cgo/linker code execution when building untrusted code |
| Linux kernel | CVE-2026-68121 | 7.8 | PPPoEject PPPoE use-after-free (host) |
| Linux kernel | CVE-2026-74469 | 8.3 | DiagSpill SCTP diag privilege escalation (host) |
| Linux kernel | CVE-2026-80844 | 8.3 | DirtyAH6 IPv6 AH/XFRM privilege escalation (host) |
| Linux kernel | CVE-2026-81000 | 7.8 | TUNderflow TUN privilege escalation (host) |
| Linux kernel | CVE-2026-98432 | 9.8 | remote IPv4 TCP use-after-free (host) |
| sudo | CVE-2026-82474 | 7.8 | execveat/fexecve bypass of ptrace intercept mode |
| sudo | CVE-2026-96512 | 7.8 | TZ bypass of NOTBEFORE/NOTAFTER |
| curl | CVE-2026-92392 | 8.1 | HTTP/2 upload use-after-free |
| OpenSSL | CVE-2026-84782 | 8.2 | DTLS retransmission heap disclosure |

Not covered:
- **CVE-2026-126082:** rejected as a duplicate of CVE-2026-122006, which is the rule here.
- **CVE-2026-82455** (RubyGems symlink): the CVE was rejected, and the RubyGems maintainers say it's not a vulnerability.
- **CVE-2026-97033 – CVE-2026-97043** (Go cgo/linker): build-time only, covered by one rule (`CVE-2026-97033-97043`) that checks installed Go toolchains.

## Limits

- **Containers need `sh`.** Cinc Auditor runs its checks through `docker exec`, so distroless or scratch images show as SKIPPED. The Go rules still cover them from the host.
- **Unreadable config.** Checks run as the container's default user. If a config file can't be read, the result is UNKNOWN, not MITIGATED.
- **PHP ini files.** The PHP CLI reads `php.ini`, and Debian's packaged PHP keeps separate ini files for the CLI and for FPM/Apache. The PHP facts also read `php_admin_*` / `php_*` overrides from FPM pool and Apache config.
- **Bundled runtimes and libraries aren't seen:** self-contained .NET apps, libcurl without the `curl` binary, OpenSSL copies bundled into other software, and JavaFX jars bundled into an app.
- **Rails apps** are found by `Gemfile.lock` up to 5 directories deep. App code is searched for `each_key` and `safe_constantize` only.
- **Python on distros** may carry backported fixes that the version number doesn't show.

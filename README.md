# vuln_scanner

One rule per CVE, run against a Docker host and all of its running containers.
Each rule rates the target as one of:

| State | Meaning | Result |
|---|---|---|
| **VULN** | Affected version, vulnerable feature in use, no mitigation | fails |
| **MITIGATED** | Feature not used, loaded or configured, or a workaround is in place | passes |
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
TARGET                 CVE              STATE      DETAIL
shop_app.1             CVE-2026-115560  VULN       PHP 8.4.27, upload_progress on, serialize_handler=php_serialize
proxy_web.1            CVE-2026-123007  MITIGATED  nginx 1.28.1, HTTP/2 and HTTP/3 disabled
portainer_agent        -                SKIPPED    no shell in container (distroless/scratch image), cannot be checked

12 targets, 1 VULN, 1 MITIGATED, 1 SKIPPED, 9 with no affected software
```

Swarm task IDs are dropped from container names (`web.1.olm76d…` becomes `web.1`).

Options:
- `-j <n>`: scan n targets in parallel (default 4). Each target takes about 2 s, mostly Cinc Auditor's startup time. Each parallel job needs about 150–200 MB of RAM.
- `-n`: containers only, skip the host
- `-a`: also list N/A results
- `-v`: print Cinc Auditor's full output
- `-p <git-url>`: run rules from a repo without cloning it
- `-k`: keep the raw JSON report for each target (large, deleted by default)

The result is the table above. It's also saved as `reports/<timestamp>/summary.tsv` next to the script, along with a `.log` file for any target that errored.

The exit code is `1` if anything is VULN, UNKNOWN or ERROR, so the script can run from cron or a monitoring check.

To run a single rule against a single container:

```bash
cinc-auditor exec . -t docker://<container> --controls CVE-2026-115560
```

## Adding a CVE

1. Copy `templates/CVE-YYYY-NNNNN.rb` to `controls/<CVE-ID>.rb`.
2. Fill in:
   - `only_if`: how to tell the product is present
   - how to read the version
   - the exposure check (config, modules, ini values)
   - the fixed versions per branch
3. Test it against one container (command above), then commit.

When a vendor ships a fix for a CVE you previously only mitigated, add the version to `fixed`. Targets running that version then show as PATCHED.

## Rules

| CVE | Product | Status of the rule |
|---|---|---|
| CVE-2026-115560 | PHP | Complete. There's no fixed release yet, so only VULN or MITIGATED for now. |
| CVE-2026-123007 | nginx (assumed) | Template. Product and fixed versions still need confirming. |
| CVE-2026-119618 | ? | Not written. No public record found yet. |
| CVE-2026-98432 | ? | Not written. No public record found yet. |

## Limits

- Containers need `sh`. Cinc Auditor runs its checks through `docker exec`, so distroless or scratch images show as SKIPPED.
- Checks run as the container's default user. If it can't read a config file, the result is UNKNOWN, not MITIGATED.
- For PHP, the CLI reads `php.ini`. Debian's packaged PHP keeps separate ini files for the CLI and for FPM/Apache, which can differ. The PHP rule also greps FPM pool and Apache config for `php_admin_*` overrides. Official `php:` images share one ini directory.

# appsec-pipeline-lab

A small multi-tenant API and the AppSec pipeline around it. It shows how I build security into the
SDLC: threat model first, requirements with tests as evidence, and CI that finds, ranks and blocks real risk.

## What's inside

| Area | What | Where |
|---|---|---|
| API | Spring Boot 4 notes API, OAuth2 resource server, tenant + owner scoped access | `app/` |
| Identity | Keycloak realm with OIDC client and a `tenant` claim | `keycloak/`, `compose.yml` |
| Tests as evidence | Security requirements SR-01 to SR-05 as MockMvc tests (BOLA, authN, validation, deny by default) | `app/src/test/` |
| SAST | Semgrep (Java + OWASP Top 10 rules) | CI `sast` |
| SCA | Trivy dependency scan | CI `sca` |
| Secrets | Gitleaks over the full git history | CI `secrets` |
| SBOM | Syft, SPDX JSON | CI `sbom` |
| DAST | OWASP ZAP baseline against the running API | CI `dast` |
| Triage | Ranks all findings by CISA KEV, EPSS and CVSS; fails the build on P1; keeps accepted false positives auditable | `triage/` |
| Threat model | STRIDE with data flow and trust boundaries | `docs/threat-model.md` |
| Verification | OWASP ASVS L1 checklist, requirement traceability | `docs/` |

Pipelines exist for both **GitHub Actions** (`.github/workflows/appsec.yml`) and **GitLab CI** (`.gitlab-ci.yml`).

## Run it

```bash
# API tests (no Keycloak needed)
cd app && ./mvnw test

# Triage tool tests
cd triage && python3 -m unittest -v

# Full local stack: Keycloak on :8180, API on :8080
podman compose up --build
```

## Why the triage step matters

Scanners produce hundreds of findings. Most teams sort by CVSS and drown. This pipeline asks two
better questions: *is this CVE being exploited right now* (CISA KEV) and *how likely is exploitation*
(EPSS). Known-exploited bugs and leaked secrets block the build; the rest gets a fix-by date.

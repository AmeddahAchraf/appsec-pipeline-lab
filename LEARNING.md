# 7-day plan: from scaffold to real experience

This repo was scaffolded with AI. The experience comes from you running it, breaking it, and writing the
security docs yourself. Do every step by hand at least once, and be able to explain each file in an
interview. Already working: the API with 9 passing tests, and the triage tool with 9 passing tests.

## Day 1: run the stack
- `podman compose up --build`. **Not tested yet:** the Keycloak realm import (custom `tenant` attribute
  needs the declarative user profile in `notes-realm.json`). If the claim is missing, fixing it is your first task.
- Get a token for alice (password in `keycloak/notes-realm.json`) and call the API:
  ```bash
  TOKEN=$(curl -s -d client_id=notes-cli -d grant_type=password -d username=alice -d password=... \
    http://localhost:8180/realms/notes/protocol/openid-connect/token | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
  curl -H "Authorization: Bearer $TOKEN" localhost:8080/api/notes
  ```
- Decode the token at jwt.io. Find `iss`, `sub`, `tenant`, `exp`. Explain why the API trusts them.
- Talking point: *"How does a resource server validate a JWT?"* (JWKS, signature, issuer, expiry)

## Day 2: threat model
- Fill T2 to T8 in `docs/threat-model.md` yourself first. Then ask AI: "What did I miss?"
- Add one threat you found on your own.
- Talking point: *"Walk me through a threat model you did."*

## Day 3: ASVS check
- Fill every Status in `docs/asvs-checklist.md` against the code and the official ASVS text.
- Fix at least one Fail (likely: security headers / CSP), add a test, add an SR row.
- Talking point: *"Which ASVS level fits a banking API and why?"*

## Day 4: GitHub pipeline green
- Create the repo on your GitHub, push, watch `appsec.yml` run. Fix what breaks (image tags, ZAP JRE, paths).
- Read the triage report in the job summary. Explain every P1 to P3 line.
- Talking point: *"CVSS vs EPSS vs KEV: how do you prioritise?"*

## Day 5: GitLab pipeline
- Mirror the repo to GitLab.com and get `.gitlab-ci.yml` green.
- Talking point: *"How would you roll SAST/DAST/SCA out to 20 teams without blocking them?"*
  (start in report-only mode, tune false positives, then gate on P1)

## Day 6: break it on purpose
- Create a branch that removes the owner check in `NoteController.owned`. Watch the SR-01 tests fail.
- Use Burp Suite Community or ZAP manually: log in as bob, try alice's note id. Write up what you saw.
- Add a vulnerable dependency (an old log4j-core) and watch the triage step block the build with P1.

## Day 7: publish and update the CV
- Write a short "What I built and learned" section at the end of the README. Optional: a blog post.
- In `linkedin/cv/master.json`, set `appsec-pipeline-lab` to `"status": "done"` and rebuild the CVs.
- Only add skills to the CV that you can now demo: threat modelling (STRIDE), OWASP ASVS, ZAP (DAST),
  Trivy, Semgrep, Gitleaks, GitLab CI, CVSS/EPSS/KEV triage, OAuth2/OIDC with Keycloak.

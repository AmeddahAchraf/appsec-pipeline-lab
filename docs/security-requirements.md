# Security requirements and traceability

Every requirement links to the control that implements it and the test that proves it.
If a requirement has no test, it is not done.

| ID | Requirement | Control (where) | Evidence (test) | ASVS 4.0.3 | Threat |
|---|---|---|---|---|---|
| SR-01 | A user can only read or delete their own notes, inside their own tenant. Foreign ids return 404 | `NoteRepository.findByIdAndTenantIdAndOwnerId`, `NoteController.owned` | `sr01_ownerCanReadOwnNote`, `sr01_otherUserInSameTenantGets404`, `sr01_sameUserIdInOtherTenantGets404` | V4.2.1 | T1 |
| SR-02 | Every API call needs a valid token. Owner and tenant always come from the token, never from the request | `SecurityConfig`, `NoteController.create` | `sr02_requestsWithoutTokenAreRejected`, `sr02_ownerIsTakenFromTokenNotBody` | V4.1.1 | T2, T3 |
| SR-03 | Input is validated against size limits before it reaches the database | `NoteRequest` bean validation | `sr03_oversizedTitleIsRejected` | V5.1.3 | T5 |
| SR-04 | A token without a tenant claim is rejected | `NoteController.tenant` | `sr04_tokenWithoutTenantIsForbidden` | V4.1.3 | T4 |
| SR-05 | Anything not explicitly allowed is denied | `SecurityConfig` (`anyRequest().denyAll()`) | `sr05_unknownPathsAreDenied` | V4.1.3 | |
| SR-06 | Errors never expose stack traces or internal messages | `application.properties` (`server.error.*`) | TODO: add a test | V7.4.1 | T6 |
| SR-07 | No secrets in the repository or its history | Gitleaks in CI, triage fails on P1 | CI job `secrets` | V14.3 | T7 |
| SR-08 | Dependencies with known exploited CVEs block the build | Trivy + `triage/prioritize.py --fail-on P1` | CI job `triage` | V14.2.1 | T7 |

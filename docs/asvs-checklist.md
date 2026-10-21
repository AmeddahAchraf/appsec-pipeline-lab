# OWASP ASVS checklist (Level 1, API-relevant subset)

Check each requirement against the code yourself and fill in the status: **Pass**, **Fail**, **N/A** (say why).
Requirement IDs follow ASVS 4.0.3. Open the official text at https://owasp.org/www-project-application-security-verification-standard/
while you work and correct any row that does not match it. ASVS 5.0 renumbers some items; note both if you switch.

| ASVS | Requirement (short) | Status | Evidence or note |
|---|---|---|---|
| V2.1.1 | Passwords are at least 12 characters | | Handled by Keycloak password policy? Check the realm |
| V3.5.3 | Stateless tokens are signed and validated | | |
| V4.1.1 | Access control is enforced on a trusted service layer | | SR-02 |
| V4.1.3 | Least privilege: deny by default | | SR-05 |
| V4.2.1 | Protection against IDOR / BOLA | Pass | SR-01 and its tests |
| V5.1.3 | Input is validated (allow lists, length, type) | | SR-03 |
| V5.3.4 | Queries are parameterised (no SQL injection) | | JPA derived queries |
| V7.4.1 | Generic error message on unexpected errors | | SR-06 |
| V8.3.1 | Sensitive data is not sent in URLs | | |
| V9.1.1 | TLS for all client connections | | Local lab uses HTTP. Where would TLS terminate in production? |
| V13.1.3 | API URLs do not expose sensitive data (keys, tokens) | | |
| V13.2.1 | HTTP methods are restricted per endpoint | | |
| V14.2.1 | Components are up to date with no known vulnerabilities | | Trivy + triage |
| V14.4.1 | Responses set a correct Content-Type with charset | | Check with ZAP output |
| V14.4.3 | A Content Security Policy header is set | | ZAP will flag it. Fix or accept with reason |

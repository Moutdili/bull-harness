## Sensitive information disclosure
When: backups, configs, debug/metrics/actuator, logs, `.git`, exports, verbose errors.
Do:
1. Open each candidate once and look for actual values: keys, tokens, passwords, connection strings, other users' data.
2. Check whether a found secret is live with ONE harmless read-only call on the program's own service, if the rules allow it.
3. Record version banners and stack traces as facts (useful for other cards), not as findings.
Never: use a leaked credential to go further than proving it is valid, download whole backups or databases.

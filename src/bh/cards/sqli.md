## SQL injection
When: search, filter, sort or id parameters; database errors in responses.
Do:
1. `bh-sqli '<url with the parameter>'` (or `--data` for a body). It runs Boolean/Error/Union only, never time-based.
2. If it finds a point, confirm by hand with ONE read-only extraction: database version or the current database name.
3. If bh-sqli says not injectable but errors appear: try the matching quote/paren closure by hand (`'`, `')`, `'))`),
   then a boolean pair (`AND 1=1` vs `AND 1=2`) and compare the two answers twice.
4. Authenticated parameters: `bh-sqli ... --as user-a`.
Never: time-based or stacked payloads, UPDATE/DELETE/INSERT, dumping tables (one value proves it).

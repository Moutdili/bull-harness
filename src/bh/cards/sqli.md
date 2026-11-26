## SQL injection
When: search, filter, sort or id parameters; database errors in responses.
Do:
1. By hand, one parameter at a time: does a quote or a parenthesis (`'`, `')`, `'))`) change the answer or raise a
   database error? Authenticated parameters: `q -a user-a ...`.
2. Then a boolean pair (`AND 1=1` vs `AND 1=2`, closed like step 1) and compare the two answers twice.
3. A point found: confirm with ONE read-only extraction (database version or the current database name).
Never: time-based or stacked payloads, UPDATE/DELETE/INSERT, dumping tables (one value proves it).

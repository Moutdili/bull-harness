## Open redirect
When: `redirect`, `next`, `return`, `url`, `to` parameters; login/logout/callback routes.
Do:
1. Supply an external domain (`https://example.com`) and read the Location header / meta refresh / JS redirect.
2. Try the usual parser confusions only if the first is filtered: `//example.com`, `https:example.com`, `/\example.com`.
3. Look for a chain: OAuth `redirect_uri`, token in fragment or query sent to the external domain.
Report alone only if the program pays for open redirects (check the exclusions); otherwise keep it as a fact for chaining.

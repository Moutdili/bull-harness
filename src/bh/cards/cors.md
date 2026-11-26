## CORS
When: authenticated JSON APIs, especially behind cookie sessions.
Do:
1. Send the authenticated request with `Origin: https://<payload-host>` and read `Access-Control-Allow-Origin` and
   `Access-Control-Allow-Credentials`.
2. If reflected with credentials, check that the response holds sensitive data of the identity.
3. Variants only if the first is refused: `null` origin, a lookalike subdomain of an in-scope domain.
`<payload-host>`: the payload hosts of your scope block; none listed: `bh-note blocked other "no payload host declared"`.
Report only the credentialed read of sensitive data; a wildcard on public data is not a finding.

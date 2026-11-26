## Server-side request forgery
When: parameters that take a URL or host (`url`, `src`, `webhook`, `callback`, image/PDF/preview features).
Do:
1. Feed an in-scope URL you control the content of (an in-scope page, not a third party) and see if the server fetches it:
   the content of that page read and returned or rendered by the server is the proof; error messages that name the
   fetch are a lead.
2. Redirect-based variants only through in-scope redirectors, toward an in-scope page.
Proof: a request received on a host of ours that the scope declares as a listener, or step 1. No listener declared by
the scope and nothing rendered back: `bh-note blocked oob-needed "<url and parameter>"`.
Never: aim the server at a loopback, link-local, cloud metadata or internal address or name, in any spelling (decimal,
hex, IPv6, a DNS name that resolves to one, a redirect to one): the program forbids it and it proves nothing here.
Never: scan internal ranges, hit third-party hosts through the target.

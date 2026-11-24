## Server-side request forgery
When: parameters that take a URL or host (`url`, `src`, `webhook`, `callback`, image/PDF/preview features).
Do:
1. Feed an in-scope URL you control the content of (an in-scope page, not a third party) and see if the server fetches it:
   response content, timing, error messages that name the fetch.
2. Look for protocol and host handling in errors: `http://127.0.0.1`, `http://169.254.169.254/` (cloud metadata),
   internal hostnames seen in JS or headers. One request each.
3. Redirect-based bypasses only through in-scope redirectors.
Note: the sandbox has no out-of-band listener. A blind SSRF is a lead for the human (todo), not a finding.
Never: scan internal ranges, hit third-party hosts through the target.

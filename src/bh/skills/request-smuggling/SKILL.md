---
name: request-smuggling
description: Use when a proxy or CDN sits in front of the app and the program is the local lab (platform local) or its rules allow request smuggling in writing. Lab only; anywhere else one blocked note.
---
<!--
Source: strix/skills/vulnerabilities/http_request_smuggling.md, Strix (https://github.com/usestrix/strix), Copyright
2025 OmniSecure Inc., Apache License 2.0.
Also: inputs/skills-audit/FUSIONS.md, section "Classes T41", row "Contrebande" (Hermes http-request-smuggling,
http-desync-attacks, no licence stated): CL.TE and TE.CL, and the gate that may reframe the request.
Modified from Strix (Apache-2.0) by bull-harness: lab only, and detection by a request the back end waits on;
removed: the differential confirmation ("two rapid identical requests"), smuggled requests to restricted paths,
capture of a following user's request, cache poisoning through desync, header obfuscation lists, HTTP/2 downgrade
tooling.
-->

# HTTP request smuggling (lab only)

## When
- Only on a program with `platform: local` (the lab), or on a program whose rules allow request smuggling in
  writing (quote the line in a `bh-note fact`).
- Why: a desync is shared by nature. A prefix left on a front-to-back connection is read as the start of the next
  request on that connection, which on a real service is a third party's. "Only on our requests" cannot hold.

## Do
1. Not the lab and no written permission: `bh-note blocked other "request smuggling: not allowed by this program"`,
   then stop. This line is the whole skill on such a program.
2. Lab: map the chain from the answers (`server`, `via`, `x-cache`, a CDN or proxy header) and from the lab's
   own description. No chain of two parsers: nothing to test.
3. Detection without leaving anything queued: a request the back end must WAIT on, never one it reads past.
   - CL.TE probe: `Content-Length` covering the body, `Transfer-Encoding: chunked`, a chunked body that never
     sends its last chunk. A back end that reads chunked waits until its timeout.
   - TE.CL probe: a complete chunked body, `Content-Length` larger than what is sent. A back end that reads
     `Content-Length` waits.
   Send each with `q -t 15 -i -X POST -H 'Transfer-Encoding: chunked' -d '<body>' <url>` and note the time.
4. Twin control: the same request with consistent framing (one of the two headers, the right length). It must
   answer at once.
5. Three runs of probe and control, one after the other. A timeout on the probe every time and none on the
   control is the result.
6. The gate sits between you and the lab. If its journal (`bh-web net` or the flow of your `q`) shows the request
   reframed (one length, no `Transfer-Encoding`), the probe never reached the target: `bh-note blocked other
   "request smuggling: the gate reframes the request"`.

## Proof
A CANDIDATE fact, lab only: `bh-note fact "CANDIDATE: smuggling <CL.TE|TE.CL> on <url>" -s "<probe and control
times, 3 runs>" -e <raw bytes of both requests>`. The proof is the timing pair with its twin control; proof.json
cannot carry a framing conflict (each step is one clean request).

## Never
- Any request that leaves a prefix queued on a shared connection: no smuggled request, no "differential" second
  request, no capture, no attempt to reach a restricted path through the desync.
- Any smuggling probe outside the lab or without written permission, even "just a timing".
- More than three probe runs per variant: each one holds a back-end worker until its timeout.

## False positives
- (Strix) Latency or slow processing unrelated to framing: the control is slow too.
- (Strix) A server that closes the connection after each request: no reuse, no desync.
- (Strix) HTTP/2 end to end, with no downgrade to HTTP/1.1 behind the front end.
- (Strix) A proxy that normalises `Transfer-Encoding` and `Content-Length` before forwarding: the ambiguity is gone.
- A timeout caused by `q`'s own limit on a slow route: compare with the control's time, not with zero.

## Watch
- The lab's report says which pair of parsers disagrees; a real program never gets the probe.
- Header obfuscation variants are a list to loop: one form each of CL.TE and TE.CL is enough to learn the lab.

---
name: firebase
description: Use when the bundle holds a Firebase config (apiKey, projectId) or the app calls Firestore, the Realtime Database or Firebase Storage. Tests rules per identity; the key is never the finding.
---
<!--
Source: strix/skills/technologies/firebase.md, Strix (https://github.com/usestrix/strix), Copyright 2025 OmniSecure
Inc., Apache License 2.0.
Modified from Strix (Apache-2.0) by bull-harness: rewritten into our form, between our two identities, hosts left to
the gate; its "Validation Requirements" turned into our Proof; removed: anonymous sign-in and any account creation,
unauthenticated writes and uploads to the program's buckets, object ACL and IAM sweeps, prefix listing of buckets,
signed-URL guessing, function calls toward metadata endpoints, blind enumeration by length or timing, rules-review
tooling and whitebox sections.
-->

# Firebase

## When
- The bundle or `/__/firebase/init.json` gives a config: `apiKey`, `authDomain`, `projectId`, `storageBucket`.
- The app calls `firestore.googleapis.com`, `<project>.firebaseio.com`, `firebasestorage.googleapis.com`, or
  `cloudfunctions.net` / `run.app` functions.
- First, one `q` per host: these are Google hosts, in scope only if your scope names them. A refusal of the gate
  is final: test through the app's own API instead.

## Do
1. Config as a fact: `bh-note fact "firebase config" -s "<projectId, bucket, auth domain>" -k recon`. The
   `apiKey` is public by design.
2. Paths from the app, not from guesses: collection and document paths in the bundles and in `bh-web net`.
3. Firestore, per collection the app uses, smallest read:
   `q -n 600 '<firestore url>/v1/projects/<project>/databases/(default)/documents/<collection>?pageSize=1'`
   anonymous, then as each identity (`q -a <identity> ...`, if the gate holds a session for that host).
   Denied anonymous and readable by any signed-in user (`auth != null`) is the classic gap: compare what the two
   identities read.
4. Cross-identity: as the second identity, read the first identity's document by its path
   (`.../documents/<collection>/<first identity's doc id>`). Its marker = the proof.
5. Realtime Database: `q -n 300 '<db url>/<path the app uses>.json?limitToFirst=1'` (with `orderBy="$key"`).
   Never the root `/.json` of a database that may hold other people's data.
6. Storage: read one object the app itself references, through both doors (`firebasestorage.googleapis.com/v0/b/
   <bucket>/o/<object>` and `storage.googleapis.com/<bucket>/<object>`), anonymous and as each identity. A 403 on
   one door says nothing about the other.
7. Writes only as your identities, on your own documents: set a field to the value it has, then the same write as
   the other identity on the first one's document. Read back. Privilege fields (`role`, `isAdmin`): skill
   `mass-assignment`.
8. Functions: call the app's own function as each identity and anonymous, with the first identity's ids in the
   body as the second. A function trusting a `uid` from the body is the bug.

## Proof
proof.json, the marker planted first in the owner identity's own document:
- `setup`: the owner reading its document, expecting the marker;
- `attack`: the same read as the other identity, expecting the marker;
- `control`: the same read with `"as": null`, expecting a permission error.
If the anonymous read also returns the marker, the gap is a public read: keep this proof, attach the anonymous
answer (`-e`) and say so in `--summary`.

## Never
- Sign in anonymously, sign up, or create any account, even where the project allows it:
  `bh-note blocked account "open sign-up: needs an enrolled identity"`.
- Write, upload or delete anything unauthenticated, or in a path that is not one of your identities'.
- Page through a collection, list a bucket's prefixes, or read a second record of other people: one record of
  someone else's data shown on screen is `bh-note blocked third-party-data "<path, no content>"`.
- Call a function toward an internal address or a metadata endpoint.

## False positives
- The `apiKey` and the whole client config: public by design (skill `false-positive-traps`).
- (Strix) A 403 from the GCS door while the Firebase rules door answers: test both before concluding either way.
- (Strix) App Check absent: it is not authorization; the rules decide.
- An empty list or `{}` on a collection: readable and empty, not a leak and not protection.
- Seed or demo documents: the vector is real, the impact is not shown.

## Watch
- Rules are not filters: a query the client sends may be refused while a single document read is allowed.
- A tenant model (`orgs/<org>/...`): skill `multi-tenant`.
- An ID token minted for another project or audience accepted by a function: skill `jwt`.

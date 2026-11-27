---
name: nosql-injection
description: Use when a login, search or filter takes JSON or `param[key]=` values on a document database, or a login uses a directory filter. Operator injection, proved on your own account.
---
<!--
Source: hermes/bug-bounty/nosql-injection/SKILL.md; merged from hermes/bug-bounty/ldap-injection-exploitation (no author or licence stated).
Modified: translated; "log in as admin", character-by-character extraction of other users' passwords, `$where` time delays and wordlist fuzzing removed; proof moved to our own account.
Role: hunter. No class id exists yet (see out/README.md).
False positives merged from Strix strix/skills/vulnerabilities/nosql_injection.md (Copyright 2025 OmniSecure Inc.,
Apache-2.0).
Modified from Strix (Apache-2.0) by bull-harness: its four "False Positives" lines condensed into three, marked
"(Strix)". modified (bull-harness W3-H): class standard completes the existing class `nosqli` (classes_more.json).
-->

# NoSQL operator injection

## When
- A JSON body or a bracket-style query string (`user[$ne]=`) reaches a query: login, search, filters,
  GraphQL arguments named `filter` or `where`.
- Errors that name a document database or a query operator.

## Do
1. Baseline on your own account: correct password (success) and wrong password (refusal). Keep both answers.
2. Replace a string by an operator object, your own username kept as a string:
   `q -j '{"username":"<user-a's login>","password":{"$ne":""}}' <login url>`
   Then, one each: `{"$gt":""}`, `{"$regex":".*"}`. The form variant: `password[$ne]=`.
3. Read the answer against the baseline: the success answer without the password = injection.
4. On search and filters: an operator that widens the result (`{"$ne": null}` on a field of your own object)
   compared with the plain value. Stop at the first answer that shows another identity's object and prove it
   between user-a and user-b with the skill `proof-package`.
5. Directory-backed login (variant): a `*` as password, or a filter-closing value in the login field, on your
   own username, compared with the wrong-password answer.

## Proof
proof.json on user-a's own login:
- `attack`: the operator in place of the password, expecting the success marker (a field only a logged-in
  answer holds);
- `control`: a wrong password string, expecting the refusal.
State in `--not-proven` that no other account was entered.

## Never
- An operator in the username field (`{"$ne": ...}`, `{"$in": [...]}`): it logs you into someone else.
- Blind extraction of any value, of any account, character by character.
- `$where` with JavaScript or a delay: server-side code and a denial-of-service risk. A sign that `$where` is
  evaluated: stop, `bh-note blocked server-exec "<where, no content>"`.
- Repeated logins: three attempts per variant at most; a lockout on a test account ends the test.

## False positives
- A 400 "expected string" is the control working.
- A 500 on an object is a robustness bug unless the body leaks the query.
- The same refusal for the operator and the wrong password: not injectable there.
- (Strix) A query builder that casts the input to a string before the query (Mongoose `strict` mode): the
  operator object arrives as `[object Object]` and fails like a wrong password.
- (Strix) An input sanitiser that strips keys starting with `$` before the driver sees them.
- (Strix) A different answer caused by a validation error, not by the operator running: read the body, not the
  status.

## Watch
- An anomaly on one operator: one variant that keeps the syntax, then two close controls at most, before
  widening.
- Type confusion on the same fields without operators: skill `type-confusion`.

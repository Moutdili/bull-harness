## GraphQL
When: `/graphql`, `/gql`, `/graphiql` endpoints.
Do:
1. One introspection query; if disabled, read operation names from JS (bh-crawl output) instead.
2. List queries and mutations that take ids or user references: test them with the IDOR card method (two identities).
3. Check field-level authorization: a field reachable through another type that the direct query refuses.
4. Batching / aliases only to compare authorization, never to multiply requests.
Never: deep nested queries or large batches (denial of service), mutations on objects you do not own.

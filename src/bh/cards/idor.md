## IDOR / BOLA
When: routes or parameters carry object ids (`/{id}`, `user_id`, `order`, `uuid`), and you have two identities.
Do:
1. As user-a, create or find user-a's own objects; note their ids from your own responses (never enumerate).
2. As user-b, do the same. You now hold one object per identity.
3. Replay user-a's read of its own object with user-b's id, via `--as user-a` / `X-BH-Identity: user-a`.
4. Repeat for every verb the route supports on objects you own (GET, then PUT/PATCH/DELETE on user-b's own test object only).
5. Try the id in other places: JSON body, query string, GraphQL variables, nested routes (`/orders/{id}/items`).
Watch: numeric vs UUID ids, ids leaked in other responses (lists, emails, exports), tenant/org ids.
Never: read a third user's object more than once, or write to any object that is not user-a's or user-b's.

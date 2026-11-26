## Cross-site scripting
When: parameters reflected in HTML or JS, stored user content (comments, profile, feedback).
Do:
1. Send a unique marker (`bhx12345`) and find EVERY place it comes back (response, other pages, other users' views
   of your own content). Note the context: HTML text, attribute, script, URL.
2. Pick the payload for that context only, and check whether it comes back unencoded.
3. Stored: inject only into objects user-a owns, and view them as user-b.
Never: store a payload where real users will see it (public pages, support tickets), use payloads that call out to third parties.

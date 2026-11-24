## File upload
When: upload, avatar, import, attachment or media routes.
Do:
1. Upload a harmless file as user-a and find where and how it is served back (URL, Content-Type, Content-Disposition, domain).
2. Content-type confusion: SVG or HTML with a benign marker served inline from the main domain.
3. Name handling: path characters in the filename (`../`, `;`, NUL) — check where it lands, do not overwrite anything.
4. Import features (CSV, XML, ZIP): formula injection, XXE markers, archive paths, with benign content.
Never: upload executable payloads, web shells or large files; never overwrite another user's file.

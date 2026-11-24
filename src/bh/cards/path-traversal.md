## Path traversal / local file read
When: parameters naming files, templates or pages; download and view routes.
Do:
1. Find how the parameter maps to a file (extension added? directory prefixed?) with a legitimate value first.
2. Try `../` sequences toward a well-known readable file, then encoded forms (`%2e%2e%2f`, `..%2f`, `....//`).
3. Compare with the control: same value without the traversal.
Never: read secrets beyond the marker that proves it (one known system file), write files.

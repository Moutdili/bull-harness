---
name: podman-disk-reclaim
description: Use when the host disk is full or container storage is large, before any `podman ... prune`. Measures with `podman system df`, removes by named ids, and never prunes volumes blind.
---
Source: hermes/devops/disk-space-reclamation/SKILL.md (author: Hermes, licence: MIT).
Modified: translated; paths of another machine removed; its helper script was not repatriated; the "In this repository" lines are ours.
Role: harness developer and orchestrator, on the host. Deleting is hard to undo: the destructive level needs the operator's go on a named list.

# Reclaiming disk space under rootless Podman

## When
"The disk is full", "why is container storage this big", after a series of rebuilds.

## Rule of diagnosis
`podman system df`, never `du`. `du` on the overlay directory overstates (shared layers, hard links) and
the space reported as freed will not match. Use `du` only to locate a large directory.

```
podman system df
podman ps -a --format '{{.Names}} {{.Image}} {{.Status}}'
```

## Do
1. Measure before: `podman system df` and `df -h` on the home filesystem.
2. Inventory images that no container uses, with age and origin.
3. Present a plan in levels:
   a. dangling images and stopped containers: no risk;
   b. orphan volumes: after looking inside;
   c. tagged images not in use: a named list with size and age.
4. Execute a and b. For c, remove by explicit ids (`podman rmi -f <ids>`), never a blind prune, and only
   after showing each item can be rebuilt (pullable, or its build directory exists).
5. Verify after: `podman ps` (services up and healthy), `podman system df`, `df -h`. Report measured
   numbers, not the sum of image sizes: prunes free less than that sum because layers are shared.

## What is disposable
| Category | Verdict |
|---|---|
| `<none>` images, layers of rebuilds | always |
| Containers exited for weeks | yes |
| Anonymous orphan volumes | yes, after checking their content |
| Upstream images from public registries | yes, pulled again in seconds |
| `localhost/*` images of dead projects | yes, if the build directory still exists |
| Recent `localhost/*` images (two days or less): toolchains, build bases, today's test images | keep: often the work in progress, costly to rebuild |

Before removing a `localhost/*` image, read its origin:
`podman history <image> --format '{{.CreatedBy}}'` and `podman image inspect <image> --format '{{.Created}}'`.

## Order, and the volume trap
1. `podman image prune -f` (dangling only), then `podman container prune -f`, then `podman network prune -f`.
2. Only then `podman volume prune -f`, and only after listing named volumes.
`volume prune` removes every volume no existing container references. A stopped database container that was
just pruned leaves its data volume dangling, and the next volume prune erases the data. List first:
`podman volume ls --format '{{.Name}}'` and `podman volume ls -f dangling=true --format '{{.Name}}'`.

## Pitfalls
- `podman images --format json` can be unparsable (control characters in labels). Use a delimiter format:
  `podman images --format '{{.ID}};{{.Repository}}:{{.Tag}};{{.Size}};{{.CreatedAt}}'`.
- Sizes in a locale with a decimal comma sort wrongly: convert to bytes before sorting or summing.
- `podman ps -a --format '{{.ImageID}}'` gives short ids: compare by prefix.
- Absurd status ages are clock noise: judge age on the image's creation date.
- After pruning images, run `podman ps` again: a service that fell was using one.

## In this repository
- The agent image (Kali, with the arsenal) and the gate image are local builds that take long: keep them.
- Gate flow files and large gate logs have their own retention: `uv run bh prune [--days 14]`.
- Never touch the host directories that hold the board, the lineage or the work directories from here.

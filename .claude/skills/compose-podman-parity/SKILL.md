---
name: compose-podman-parity
description: Use when a compose file or a check must behave the same under podman-compose and docker compose, or when a stack seems to run old code after a rebuild.
---
Source: hermes/devops/compose-ci-parity/SKILL.md (author: Hermes Agent, licence: MIT).
Modified: translated; examples of another project's toolchain removed; kept as is otherwise. Our stack is rootless Podman with podman-compose, and the compose file must stay compatible with docker compose.
Role: harness developer.

# Same checks under podman-compose and docker compose

## When
- A check passes in one runtime and fails in the other.
- A pipeline rebuilds the image for every check, or a network install breaks a job.
- A service is "missing" under podman-compose.

## Principle
One configuration lives in one place. The list of checks lives behind one official entry point; CI and
humans call that entry point and never list the steps again. A check added in one place only does not exist
for the other.

## Do
1. One entry point per suite (a make target or a script). Everything else calls it.
2. One build per run: a build step every check depends on. Never rebuild per check: N checks would mean N
   builds and N network installs.
3. Network installs: one shared script with a bounded retry (3 attempts, then fail), copied into the image
   and called by every stage. Not a loop pasted in each build file.
4. Networks: declare `default:` in the compose file. docker creates it implicitly; podman-compose refuses a
   service that names a network that is not declared.
5. Profiles: pass `--profile <name>` explicitly. docker enables the profile of the targeted service;
   podman-compose does not. Exact symptom: `WARNING:podman_compose:missing services [<service>]`, then exit
   status 1 on a `compose run <service>`. Put the profile in the one variable that holds the compose
   command, not in each rule.
6. Verify through the official entry point, not with an ad hoc build and run: an artefact built off the
   official path proves nothing about what CI does.

## Never
- Explain a red run by "a flaky runner". Reproduce through the official entry point. A truncated download:
  bound the retry and keep it in the one shared script; an unbounded retry hides the problem.
- Call a duplication a defect before reading the history and comments: some are deliberate. Report the
  risk of drift, not a violation.

## Watch
- podman-compose `up` does not recreate containers when the image was rebuilt: after a build,
  `up -d --force-recreate --no-build`. Otherwise the stack runs the old code and the verification lies.
- A pasted CI log may come from an older commit: compare the commit id and line numbers with the branch head
  before diagnosing.
- Count builds by command invocations, not by step lines: a multi-stage build prints a first step per stage
  for one build.
- A file touch may not trigger a watcher: test hot reload with a real content change, check what is served,
  then restore.

## Final check
- The entry point exits 0.
- One build invocation in the output.
- No CI file lists the individual checks any more.

# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.
- This app runs on `splunk_input_runtime` (https://github.com/Bre77/splunk-input-runtime), not `splunklib`/`splunk-sdk`. `lib/requirements.txt` pins it to an exact commit archive URL with a `sha256:` hash recorded in a comment above it (no PyPI package exists yet, so there is no `==version` line to pin against). Bump both the commit and the recorded hash together when the runtime releases a new version; never point at a branch.
- Credential handling goes through `self.context.credentials.protect_input_fields(...)` (see `bin/logic_monitor_websites.py`), not manual `storage_passwords` list/delete/create calls. This preserves the credential identity `(owner=nobody, app=logic_monitor_websites, realm=<stanza name>, username=token)` that existing installs already have - do not change that tuple without a captain-level decision; it strands users' stored secrets.
- This app checkpoints per website, not per input: `bin/logic_monitor_websites.py` writes one file per site at `{checkpoint_dir}/{stanza name}{website id}` (concatenated, no separator). A single input stanza can therefore own many checkpoint files. Any change to that naming resets ingestion position for whichever sites it touches.
- The runner (`Script.run_script`) owns `EventWriter.close()`; app code must not call it explicitly.
- `Bre77/SplunkUI-devcontainer`'s `test-harness/verify-splunklib-app.sh` is app-agnostic - point it at this repo to get a `dependency=splunk_input_runtime` build+import check on both Python 3.9 and 3.13. `test-harness/credential-continuity-gate.sh` is parameterised (`--app-id`, `--kind`, `--field`, `--old-app`/`--new-app`) - run it with `--app-id logic_monitor_websites --kind logic_monitor_websites --field token` to prove credential continuity across the migration.

## Build / vendoring / packaging (`.build.sh`)

- `lib/requirements.txt` lists `splunk_input_runtime` (pinned by commit, see above) and `requests`; `.build.sh` installs it in one `pip install -t lib -r lib/requirements.txt --no-dependencies` pass, relying on Splunk's bundled Python for transitive deps.
- The GitHub repo is named `splunk_logic_monitor_websites`, but the app's package id (`[package] id` in `default/app.conf`, `package.json`'s `name`, already published to Splunkbase) is `logic_monitor_websites`. `.build.sh` renames the archive's top-level directory via `tar --transform` so the `.spl` ships the correct package id regardless of checkout directory name.
- CI (`.github/workflows/validate.yml`) calls `Bre77/splunk_nats`'s reusable build+AppInspect workflow in `build_command` mode.
- Version is recorded in three places that must stay in sync: `package.json` and both `version =` lines in `default/app.conf` (`[launcher]` and `[id]`). A mismatch fails AppInspect.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.

# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Build / vendoring / packaging (`.build.sh`)

- `lib/requirements.txt` lists `splunk-sdk` and `requests`; `.build.sh` installs it in one `pip install -t lib -r lib/requirements.txt --no-dependencies` pass, relying on Splunk's bundled Python for transitive deps.
- The GitHub repo is named `splunk_logic_monitor_websites`, but the app's package id (`[package] id` in `default/app.conf`, `package.json`'s `name`, already published to Splunkbase) is `logic_monitor_websites`. `.build.sh` renames the archive's top-level directory via `tar --transform` so the `.spl` ships the correct package id regardless of checkout directory name.
- CI (`.github/workflows/validate.yml`) calls `Bre77/splunk_nats`'s reusable build+AppInspect workflow in `build_command` mode.
- Keep `default/app.conf`'s `[launcher] version` and `[id] version` in sync; bump both on every Splunkbase-facing release.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.

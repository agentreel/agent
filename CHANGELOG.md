# Changelog

## 0.2.2

- Anonymous CLI telemetry: one event on first run, then at most one daily heartbeat, carrying CLI version, OS type, and recorded session count. Opt out with `AGENTREEL_TELEMETRY=0`, `false`, `off`, or `no`, or `DO_NOT_TRACK=1`. Telemetry is always off in CI.
- README: refreshed logo and layout.

## 0.2.1

- License changed to Apache License 2.0 from this release onward; versions 0.2.0 and earlier remain under the MIT License.
- README: Guard default-on behavior and upload-time scanning (not in hooks during recording), Cursor install notes, and correct GitHub footer link.
- CONTRIBUTING: DCO sign-off required for contributions (`git commit -s`).
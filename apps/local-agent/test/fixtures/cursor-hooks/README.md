# Cursor hook fixtures

`session.jsonl` is one simulated Cursor agent session, one hook call per line:
`{ "delay_ms": <ms since previous hook>, "hook": "<hook name>", "input": <stdin JSON> }`.

Field shapes come from Cursor's hooks reference, https://cursor.com/docs/agent/hooks
(read 2026-11-17, Cursor 2.x):

- Common fields on every agent hook: `conversation_id`, `generation_id`, `model`,
  `hook_event_name`, `cursor_version`, `workspace_roots`, `user_email`, `transcript_path`.
- `sessionStart`: `session_id`, `is_background_agent`, `composer_mode`.
- `sessionEnd`: `session_id`, `reason`, `duration_ms`, `is_background_agent`, `final_status`.
- `beforeSubmitPrompt`: `prompt`, `attachments[] {type, file_path}`.
- `postToolUse`: `tool_name` (Shell, Read, Write, Grep, Delete, Task, `MCP:<tool>`),
  `tool_input` (object), `tool_output` (JSON string, for Shell `{"exitCode", "stdout", "stderr"}`),
  `tool_use_id`, `cwd`, `duration` (ms).
- `postToolUseFailure`: `tool_name`, `tool_input`, `tool_use_id`, `cwd`, `error_message`,
  `failure_type` (error | timeout | permission_denied), `duration`, `is_interrupt`.
- `afterShellExecution`: `command`, `output`, `duration`, `sandbox`.
- `afterMCPExecution`: `tool_name`, `tool_input` (JSON string), `mcp_server_name`,
  `mcp_server_url`/`url` (HTTP servers), `result_json` (JSON string), `duration`.
- `afterFileEdit`: `file_path`, `edits[] {old_string, new_string}`.
- `stop`: `status`, `loop_count`.

What is NOT from the docs (our assumptions, marked so we can re-check against a live Cursor):
- The `tool_input` keys per tool (`target_file` for Read, `working_directory` for Shell).
  The normalizer accepts `file_path`, `target_file`, `path`, `filePath` and `file`.
- The exact JSON inside `tool_output` for Read/Grep/MCP. We only rely on Shell's
  `exitCode`/`stdout`/`stderr`, which the docs show.
- That Cursor fires both `afterShellExecution` and `postToolUse(Shell)` for one command
  (and both `afterFileEdit` and `postToolUse(Write)` for one edit). The viewer de-duplicates.
- Values (paths, ids, versions, the leaked password in the psql command) are made up for the test.

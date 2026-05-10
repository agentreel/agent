import { homedir, platform } from "node:os";
import { join } from "node:path";

// Cursor is a VS Code fork; its history layout matches Code's:
//   <userData>/User/History/<hashId>/{entries.json, <id>.<ext>, ...}
export function defaultCursorHistoryDir(): string {
  const home = homedir();
  switch (platform()) {
    case "darwin":
      return join(home, "Library", "Application Support", "Cursor", "User", "History");
    case "win32": {
      const appData = process.env.APPDATA ?? join(home, "AppData", "Roaming");
      return join(appData, "Cursor", "User", "History");
    }
    default:
      return join(home, ".config", "Cursor", "User", "History");
  }
}

export function cursorHistoryDir(): string {
  return process.env.AGENTREEL_CURSOR_HISTORY_DIR ?? defaultCursorHistoryDir();
}

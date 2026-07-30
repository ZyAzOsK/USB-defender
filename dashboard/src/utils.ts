/**
 * utils.ts — shared helpers for the dashboard UI.
 */

/**
 * Last component of a path, handling both separators.
 *
 * `"D:\\threats\\evil.exe".split("/").pop()` returns the entire string, so
 * every table on Windows showed a full path where a filename belonged. Log
 * rows are also portable — a drive scanned on Windows may be reviewed on
 * Linux — so the separator cannot be inferred from the host platform.
 */
export function basename(path: string | null | undefined): string {
  if (!path) return "—";
  const trimmed = path.replace(/[/\\]+$/, "");
  const parts = trimmed.split(/[/\\]/);
  return parts[parts.length - 1] || path;
}

/** Map a numeric severity to its badge class. */
export function severityClass(severity: number): string {
  if (severity >= 8) return "critical";
  if (severity >= 5) return "medium";
  if (severity > 0) return "low";
  return "clean";
}

/**
 * Normalize a user-typed path before sending it to the API.
 * Mirrors `normalize_target_path` in app/paths.py: undoes shell-escaped
 * spaces, and promotes a bare Windows drive spec to its root, since "D:"
 * means "current directory on D:" rather than the drive itself.
 */
export function normalizePath(input: string): string {
  const path = input.trim().replace(/^["']|["']$/g, "").replace(/\\ /g, " ");
  if (/^[A-Za-z]:$/.test(path)) return path + "\\";
  const stripped = path.replace(/[/\\]+$/, "");
  if (!stripped || /^[A-Za-z]:$/.test(stripped)) return path;
  return stripped;
}

/** Human-readable byte size. */
export function formatSize(bytes: number | null | undefined): string {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

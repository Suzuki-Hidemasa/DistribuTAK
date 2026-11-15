"""Claude Code の PreToolUse フック: コード・設定のファイルの書き換えを止める。

コーディングと実装は作業者（Codex の GPT-6.1 Sol、足りないときは Sonnet 5.5）に任せる決まり（CLAUDE.md「エージェントの体制」）。
Claude Code（オーケストレーター・Fable のレビュアー）が Edit・Write・NotebookEdit で
次のファイルを書き換えようとしたら拒否する。

- core/・plugin/ の中のファイル（Markdown を除く）
- docs/ の中のコード（スクリプト・ソース。2026-11-16、PRC-163 の決まりを引き継いだ）
- それ以外の場所にあるコード・設定の拡張子のファイル（tools/ のスクリプトを含む）

次は止めない。
- どこにある Markdown も（ドキュメントはオーケストレーターが書く）
- docs/ の中のコード以外（.proto のインタフェース仕様・データ・図など）
- エージェントの設定（tools/agents/・.claude/・.agents/）
- Backlog.md のタスク（backlog/）
- リポジトリの外のファイル（一時ファイル・メモリなど）

パスは . と .. を畳んでから判定し、ディレクトリと拡張子は大文字小文字を区別しない。
判定の途中で失敗したら、終了コード 2 で止める側に倒す。
利用者が許したときだけ、環境変数 DISTRIBUTAK_ALLOW_CODE_EDIT=1 で止めないようにできる。

このフックは .claude/settings.json に登録して初めて効く（初期状態では登録していない。CLAUDE.md を見る）。
"""

import json
import os
import posixpath
import sys
from pathlib import PurePosixPath

GUARDED_DIRS = ("core", "plugin")
ALLOWED_DIRS = ("tools/agents", ".claude", ".agents", "backlog")
DOCS_DIR = "docs"
CODE_SUFFIXES = {
    ".py", ".c", ".h", ".cc", ".cpp", ".hpp", ".rs", ".go", ".js", ".mjs", ".ts",
    ".java", ".kt", ".kts", ".gradle", ".aidl", ".pro", ".properties", ".xml",
    ".sh", ".ps1", ".lua", ".proto", ".cmake", ".patch",
    ".toml", ".yaml", ".yml", ".json", ".ini", ".cfg",
}
CODE_NAMES = {"makefile", "cmakelists.txt", "dockerfile", "gradlew", "gradlew.bat"}
# docs/ の中では仕様・データとして扱う拡張子（コードとしては止めない）
DOCS_DATA_SUFFIXES = {".proto", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".xml"}

REASON = (
    "コーディングと実装は作業者（Codex の GPT-6.1 Sol。足りないときは Sonnet 5.5）に任せる決まり（CLAUDE.md「エージェントの体制」）。"
    "このファイル（{path}）はオーケストレーターが書き換えない。"
    "スキル orchestrate の手順で tools/agents/spawn-agent.sh worker に目標を渡して依頼する。"
    "利用者が直接の編集を許したときだけ、DISTRIBUTAK_ALLOW_CODE_EDIT=1 で起動し直す。"
)


def normalize(path: str) -> str:
    """区切りを / にそろえ、. と .. を畳む。"""
    p = path.replace("\\", "/")
    drive = ""
    if len(p) >= 2 and p[1] == ":":
        drive, p = p[:2], p[2:]
    return drive + posixpath.normpath(p or "/")


def repo_relative(file_path: str, project_dir: str) -> str | None:
    """リポジトリの根からの相対パス（小文字）を返す。リポジトリの外なら None。

    .claude/worktrees/<名前>/ の中は、そのワークツリーの根からの相対パスにする。
    """
    fp = normalize(file_path).lower()
    root = normalize(project_dir).lower().rstrip("/")
    if not fp.startswith(root + "/"):
        return None
    rel = fp[len(root) + 1:]
    parts = rel.split("/")
    if len(parts) >= 3 and parts[0] == ".claude" and parts[1] == "worktrees":
        rel = "/".join(parts[3:])
    return rel


def main_repo_root(project_dir: str) -> str:
    """ワークツリーの中で動いていても、元のリポジトリの根を返す。"""
    p = normalize(project_dir)
    idx = p.lower().find("/.claude/worktrees/")
    return p[:idx] if idx >= 0 else p


def under(rel: str, d: str) -> bool:
    return rel == d or rel.startswith(d + "/")


def is_code(p: PurePosixPath) -> bool:
    return p.suffix in CODE_SUFFIXES or p.name in CODE_NAMES


def is_guarded(rel: str) -> bool:
    """rel は小文字のリポジトリ相対パス。"""
    if not rel:
        return False
    p = PurePosixPath(rel)
    if p.suffix == ".md":
        return False
    if any(under(rel, d) for d in ALLOWED_DIRS):
        return False
    if under(rel, DOCS_DIR):
        return is_code(p) and p.suffix not in DOCS_DATA_SUFFIXES
    if p.parts[0] in GUARDED_DIRS:
        return True
    return is_code(p)


def decide(event: dict, project_dir: str, allow_env: str | None) -> str | None:
    """拒否するなら理由の文を、許すなら None を返す。"""
    if allow_env == "1":
        return None
    if event.get("tool_name") not in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        return None
    tool_input = event.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not file_path:
        return None
    rel = repo_relative(file_path, main_repo_root(project_dir))
    if rel is None or not is_guarded(rel):
        return None
    return REASON.format(path=rel)


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    try:
        event = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        project_dir = os.environ.get("CLAUDE_PROJECT_DIR") or event.get("cwd") or os.getcwd()
        reason = decide(event, project_dir, os.environ.get("DISTRIBUTAK_ALLOW_CODE_EDIT"))
    except Exception as e:  # 判定できないときは止める側に倒す
        print(f"guard_code_edit: 判定できなかったので止める（{type(e).__name__}: {e}）", file=sys.stderr)
        return 2
    if reason is None:
        return 0
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

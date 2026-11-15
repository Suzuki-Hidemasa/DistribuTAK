"""guard_code_edit.py の試験。実行: python -I tools/agents/hooks/test_guard_code_edit.py"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guard_code_edit as g  # noqa: E402

ROOT = "/work/DistribuTAK"
WT = ROOT + "/.claude/worktrees/some-work"


def ev(path: str, tool: str = "Edit") -> dict:
    key = "notebook_path" if tool == "NotebookEdit" else "file_path"
    return {"tool_name": tool, "tool_input": {key: path}}


class DecideTest(unittest.TestCase):
    def denied(self, path: str, project: str = ROOT, tool: str = "Edit", allow=None) -> bool:
        return g.decide(ev(path, tool), project, allow) is not None

    def test_guarded_dirs(self):
        self.assertTrue(self.denied(ROOT + "/core/src/main/java/a/B.java"))
        self.assertTrue(self.denied(ROOT + "/plugin/src/main/AndroidManifest.xml", tool="Write"))
        self.assertTrue(self.denied(ROOT + "/plugin/src/test/resources/legacy-state/a.base64"))
        self.assertTrue(self.denied(ROOT + "/core/build.gradle"))

    def test_windows_backslash_and_case(self):
        self.assertTrue(self.denied("\\work\\DistribuTAK\\core\\x.java"))

    def test_worktree_paths(self):
        self.assertTrue(self.denied(WT + "/core/build.sh", project=WT))
        self.assertTrue(self.denied(WT + "/plugin/a.kt", project=ROOT))
        self.assertFalse(self.denied(WT + "/docs/01-requirements.md", project=WT))

    def test_code_suffix_elsewhere(self):
        self.assertTrue(self.denied(ROOT + "/tools/real-device.sh"))
        self.assertTrue(self.denied(ROOT + "/.github/workflows/ci.yml"))

    def test_allowed(self):
        self.assertFalse(self.denied(ROOT + "/core/README.md"))
        self.assertFalse(self.denied(ROOT + "/docs/interfaces/ext-link.proto"))
        self.assertFalse(self.denied(ROOT + "/tools/agents/spawn-agent.sh"))
        self.assertFalse(self.denied(ROOT + "/.claude/settings.json"))
        self.assertFalse(self.denied(ROOT + "/.agents/skills/distributak-worker/SKILL.md"))
        self.assertFalse(self.denied(ROOT + "/CLAUDE.md"))
        self.assertFalse(self.denied(ROOT + "/backlog/config.yml"))
        self.assertFalse(self.denied("/home/user/.claude/jobs/x/tmp/a.py"))

    def test_dot_segments_are_resolved(self):
        self.assertTrue(self.denied(ROOT + "/docs/../core/a.txt"))
        self.assertTrue(self.denied(ROOT + "/.claude/../plugin/probe.java"))
        self.assertTrue(self.denied(ROOT + "/tools/agents/../../core/a.txt"))
        self.assertTrue(self.denied(ROOT + "/./plugin/x.xml"))
        self.assertFalse(self.denied(ROOT + "/core/../docs/legal.md"))

    def test_directory_case_insensitive(self):
        self.assertTrue(self.denied(ROOT + "/Core/notes.txt"))
        self.assertTrue(self.denied(ROOT + "/PLUGIN/board.txt"))
        self.assertFalse(self.denied(ROOT + "/.CLAUDE/settings.json"))
        self.assertFalse(self.denied(ROOT + "/Tools/Agents/x.sh"))

    def test_docs_allows_everything_but_code(self):
        self.assertFalse(self.denied(ROOT + "/docs/interfaces/ext-link.proto"))
        self.assertFalse(self.denied(ROOT + "/docs/specifications/x.pdf"))
        self.assertFalse(self.denied(ROOT + "/docs/data/table.json"))
        self.assertTrue(self.denied(ROOT + "/docs/build.py"))
        self.assertTrue(self.denied(ROOT + "/docs/studies/sim.sh"))
        self.assertTrue(self.denied(ROOT + "/docs/Makefile"))

    def test_other_tools_and_override(self):
        self.assertFalse(self.denied(ROOT + "/core/a.java", tool="Read"))
        self.assertFalse(self.denied(ROOT + "/core/a.java", allow="1"))
        self.assertTrue(self.denied(ROOT + "/core/a.ipynb", tool="NotebookEdit"))


class ProcessTest(unittest.TestCase):
    """フックとして起動したときの入出力（Claude Code と同じ形）。"""

    def run_hook(self, event: dict, env_extra: dict | None = None):
        env = dict(os.environ, CLAUDE_PROJECT_DIR=ROOT)
        env.pop("DISTRIBUTAK_ALLOW_CODE_EDIT", None)
        env.update(env_extra or {})
        return subprocess.run(
            [sys.executable, "-I", str(Path(__file__).with_name("guard_code_edit.py"))],
            input=json.dumps(event, ensure_ascii=False).encode("utf-8"),
            capture_output=True, env=env, check=True,
        )

    def test_deny_json(self):
        r = self.run_hook(ev(ROOT + "/core/日本語/A.java"))
        out = json.loads(r.stdout.decode("utf-8"))
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("core/日本語/a.java", out["hookSpecificOutput"]["permissionDecisionReason"])

    def test_broken_input_blocks(self):
        # 判定に失敗したら終了コード 2（Claude Code が止める）
        env = dict(os.environ, CLAUDE_PROJECT_DIR=ROOT)
        r = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).with_name("guard_code_edit.py"))],
            input=b"{broken", capture_output=True, env=env,
        )
        self.assertEqual(r.returncode, 2)

    def test_allow_is_silent(self):
        self.assertEqual(self.run_hook(ev(ROOT + "/docs/要件.md")).stdout, b"")
        r = self.run_hook(ev(ROOT + "/core/a.java"), {"DISTRIBUTAK_ALLOW_CODE_EDIT": "1"})
        self.assertEqual(r.stdout, b"")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Sudofix Full TUI — btop monitor + Ollama + SAST/SCA + Chunk‑aware Fixes + Modular Editor"""

from tui.system_monitor import SystemMonitor
from tui.llm_info import detect_llm_model
from main import run_llm
import sys
import os
import subprocess
import json
import tempfile
import re
from io import StringIO
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from typing import List, Optional

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    Header, Footer, Input, Button, RadioSet, RadioButton, Label,
    Log, TabbedContent, TabPane, DataTable, Static, Collapsible,
    DirectoryTree
)
from textual.screen import ModalScreen
from textual import work
from textual.binding import Binding

# Import the modular editor components
from tui.editor import FullEditor, DiffEditor

sys.path.insert(0, os.path.dirname(__file__))

# ------------------------------------------------------------------
# Finding data structure – chunk‑aware
# ------------------------------------------------------------------


class Finding:
    def __init__(self, severity: str, type_: str, file: str,
                 start_line: int, end_line: int, description: str,
                 original_code: str = "", fix_suggestion: str = ""):
        self.severity = severity
        self.type = type_
        self.file = file
        self.start_line = start_line
        self.end_line = end_line
        self.description = description
        self.original_code = original_code
        self.fix_suggestion = fix_suggestion

    def to_row(self):
        return (self.severity, self.type, self.file,
                f"{self.start_line}-{self.end_line}", self.description[:50])


# ------------------------------------------------------------------
# Main TUI Application – Modern Warm‑Dark Theme
# ------------------------------------------------------------------
class SudofixTUI(App):
    TITLE = "Sudofix — Security Scanner & Auto-Fixer"
    SUB_TITLE = "Local Ollama • Dry-run: OFF"

    BINDINGS = [
        Binding("ctrl+r", "start", "Start Analysis", show=True),
        Binding("ctrl+c", "cancel", "Cancel", show=True),
        Binding("ctrl+m", "toggle_monitor", "Monitor", show=True),
        Binding("ctrl+d", "toggle_dryrun", "Dry-run", show=True),
        Binding("ctrl+e", "export", "Export", show=True),
        Binding("e", "edit_file", "Edit File", show=True),
        Binding("enter", "open_file", "Open External", show=True),
        Binding("i", "open_file", "Insert Mode", show=True),
        Binding("f", "apply_fix", "Apply Fix", show=True),
        Binding("q", "quit", "Quit"),
    ]

    CSS = """
    Screen {
        background: #191724;
    }
    #app-grid {
        height: 1fr;
    }
    #sidebar {
        width: 35%;
        min-width: 30;
        border: solid #9ccfd8;
        background: #1f1d2e;
        margin: 0 1;
        padding: 0;
    }
    #main-panel {
        width: 65%;
        min-width: 50;
        margin: 0 1;
        padding: 0;
    }
    DirectoryTree {
        background: #191724;
        border: none;
        height: 1fr;
    }
    DirectoryTree > .directory-tree--file {
        color: #e0def4;
    }
    DirectoryTree > .directory-tree--directory {
        color: #9ccfd8;
        text-style: bold;
    }
    DirectoryTree:focus {
        border: solid #c4a7e7;
    }
    TabbedContent {
        height: 1fr;
    }
    TabbedContent > TabPane {
        border: solid #9ccfd8;
        padding: 0 1;
        background: #191724;
    }
    TabbedContent > .tab--active {
        background: #c4a7e7;
        color: #191724;
        text-style: bold;
    }
    SystemMonitor {
        max-height: 30;
    }
    .button-row {
        height: auto;
        margin-bottom: 1;
    }
    Button {
        margin: 0 1 1 0;
        background: #26233a;
        color: #e0def4;
        border: solid #9ccfd8;
    }
    Button:hover {
        background: #c4a7e7;
        color: #191724;
        border: solid #e0def4;
    }
    Input {
        border: solid #9ccfd8;
        background: #191724;
        color: #e0def4;
        margin-bottom: 1;
    }
    Input:focus {
        border: solid #c4a7e7;
    }
    RadioSet {
        background: #191724;
        border: none;
        margin-right: 2;
        color: #e0def4;
    }
    RadioButton {
        color: #e0def4;
    }
    DataTable {
        border: solid #9ccfd8;
        height: 1fr;
        background: #191724;
        color: #e0def4;
    }
    DataTable:focus {
        border: solid #c4a7e7;
    }
    Log {
        border: solid #26233a;
        height: 1fr;
        background: #191724;
        color: #e0def4;
    }
    Collapsible > .collapsible--title {
        background: #9ccfd8;
        color: #191724;
        text-style: bold;
        border: none;
    }
    #status {
        dock: bottom;
        height: 1;
        background: #c4a7e7;
        color: #191724;
        padding: 0 1;
        text-style: bold;
    }
    Label {
        color: #e0def4;
    }
    Static {
        color: #e0def4;
    }
    Header {
        background: #191724;
        color: #e0def4;
    }
    Footer {
        background: #191724;
        color: #e0def4;
    }
    """

    def __init__(self):
        super().__init__()
        self.llm_info = {}
        self.dry_run = False
        self.db = None
        self.redis = None
        self.current_repo = os.path.abspath(".")
        self.tree_counter = 0
        self.current_tree = None
        self.selected_file = None
        self.findings: List[Finding] = []

    def compose(self) -> ComposeResult:
        self.llm_info = detect_llm_model()
        self.sub_title = f"LLM: {self.llm_info.get('model', 'ollama')} ({
            self.llm_info.get('provider', 'Local')})"

        yield Header()

        with Collapsible(title="⚡ System Monitor (Ctrl+M)", collapsed=False, id="monitor"):
            yield SystemMonitor(llm_info=self.llm_info, id="sysmon")

        with Horizontal(id="app-grid"):
            with Vertical(id="sidebar"):
                yield Label("📁 Repository Files", classes="sidebar-title")
                self.tree_counter += 1
                self.current_tree = DirectoryTree(
                    self.current_repo, id=f"file-tree-{self.tree_counter}")
                yield self.current_tree
                yield Button("🔄 Refresh Tree", id="refresh-tree", variant="default")

            with Vertical(id="main-panel"):
                yield Label("Selected Repository:")
                yield Input(value=self.current_repo, id="repo-path")
                yield Button("📂 Set Repository", id="set-repo", variant="primary")

                with Horizontal(classes="button-row"):
                    yield Label("Mode:")
                    yield RadioSet(
                        RadioButton("SAST", id="sast", value=True),
                        RadioButton("SCA", id="sca"),
                        RadioButton("Full", id="full"),
                        id="mode-set"
                    )
                    yield Label("Command:")
                    yield RadioSet(
                        RadioButton("Review", id="review", value=True),
                        RadioButton("Test", id="test"),
                        RadioButton("Doc", id="doc"),
                        id="cmd-set"
                    )
                with Horizontal(classes="button-row"):
                    yield Button("▶ Start", variant="primary", id="start-btn")
                    yield Button("Only SCA", variant="success", id="only-sca-btn")   # ← NEW BUTTON
                    yield Button("Dry-run: OFF", id="dry-btn", variant="warning")
                    yield Button("📄 Export", id="export-btn", variant="default")
                    yield Button("✏️ Edit File (e)", id="edit-btn", variant="default")
                    yield Button("🔧 Apply Fix (f)", id="apply-fix-btn", variant="default")

                with TabbedContent(initial="log-tab"):
                    with TabPane("Live Log", id="log-tab"):
                        yield Log(id="live-log", highlight=True)
                    with TabPane("Findings", id="findings-tab"):
                        yield DataTable(id="findings-table")
                        yield Static("Select a finding, press 'f' → opens file with diff viewer.", id="fix-hint")
                    with TabPane("SCA Fixes", id="sca-tab"):
                        yield Log(id="sca-log")
                    with TabPane("Environment", id="env-tab"):
                        yield Log(id="env-log")
                    with TabPane("History", id="history-tab"):
                        yield Log(id="history-log")

        yield Static("Status: Idle", id="status")
        yield Footer()

    def on_mount(self):
        from controllers.data_base_controller import Postgres
        from controllers.reddis_controller import RedisManager
        self.db = Postgres()
        self.redis = RedisManager()
        self.query_one("#status").update(
            f"Status: Idle | LLM: {self.llm_info['model']}")
        self._init_findings_table()

    def _init_findings_table(self):
        table = self.query_one("#findings-table", DataTable)
        table.clear(columns=True)
        table.add_columns("Severity", "Type", "File", "Lines", "Description")
        table.cursor_type = "row"

    def update_findings_table(self):
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        for f in self.findings:
            table.add_row(*f.to_row())
        if self.findings:
            table.focus()

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self.update_findings_table()
        self.notify(f"Finding: {finding.type} in {finding.file} lines {
                    finding.start_line}-{finding.end_line}", timeout=2)

    # ------------------------------------------------------------------
    # File tree events
    # ------------------------------------------------------------------
    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected):
        self.selected_file = event.path
        if event.path.is_dir():
            self.current_repo = str(event.path)
            self.action_refresh_tree()
            self.notify(f"Repository changed to: {
                        self.current_repo}", timeout=2)
        else:
            self.notify(
                f"Selected: {event.path.name}. Press 'e' to edit.", timeout=2)

    def action_edit_file(self):
        """Open the selected file in the full editor."""
        if self.selected_file is None or not self.selected_file.is_file():
            self.notify("No file selected.", severity="warning")
            return
        try:
            with open(self.selected_file, 'r') as f:
                content = f.read()
        except Exception as e:
            self.notify(f"Cannot read: {e}", severity="error")
            return
        self.push_screen(FullEditor(str(self.selected_file), content))

    def action_open_file(self):
        """Open with external editor (fallback)."""
        if self.selected_file is None or not self.selected_file.is_file():
            self.notify("No file selected.", severity="warning")
            return
        editor = os.environ.get("EDITOR", "vim")
        try:
            subprocess.Popen([editor, str(self.selected_file)])
            self.notify(f"Opening in {editor}", timeout=2)
        except FileNotFoundError:
            self.notify("No editor. Use 'e' for built-in.", severity="error")

    def action_apply_fix(self):
        """Apply fix for the currently selected finding using DiffEditor."""
        table = self.query_one("#findings-table", DataTable)
        if table.cursor_row is None:
            self.notify(
                "Select a finding from the Findings tab first (arrow keys).", severity="warning")
            return
        row = table.cursor_row
        if row >= len(self.findings):
            return
        finding = self.findings[row]

        file_path = Path(self.current_repo) / finding.file
        if not file_path.is_file():
            file_path = Path(finding.file)
            if not file_path.is_file():
                self.notify(f"File not found: {
                            finding.file}", severity="error")
                return

        # If no fix suggestion, open in full editor
        if not finding.fix_suggestion:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                self.push_screen(FullEditor(str(file_path), content))
                self.notify("No fix suggestion – edit manually.", timeout=3)
            except Exception as e:
                self.notify(f"Cannot read file: {e}", severity="error")
            return

        # Show diff editor with original code and proposed fix
        self.push_screen(DiffEditor(
            str(file_path),
            finding.original_code or "// No original code captured",
            finding.fix_suggestion,
            finding.start_line
        ))

    # ------------------------------------------------------------------
    # Pipeline execution with LIVE LOGS
    # ------------------------------------------------------------------

    @work(thread=True)
    def action_only_sca(self):
        """Run ONLY SCA with LIVE output like terminal"""
        repo_path = self.query_one("#repo-path").value.strip() or "."

        log = self.query_one("#live-log", Log)
        log.write(f"\n🚀 Running ONLY SCA on: {repo_path}\n")
        log.write("Live output starting...\n\n")

        self.call_from_thread(self._init_findings_table)
        self.findings.clear()

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.jsonl', delete=False) as f:
            findings_tmp = f.name
        os.environ["SUDOFIX_FINDINGS_FILE"] = findings_tmp

        self.query_one("#status").update("Status: Running SCA Only (Live)...")

        try:
            sca_main_path = Path(__file__).parent.parent/ "sudofix" / "sca" / "main.py"

            if not sca_main_path.exists():
                log.write(f"❌ sca/main.py not found!\n")
                return

            # Force UTF-8 encoding for emojis
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"

            # Use Popen for live streaming
            process = subprocess.Popen(
                [sys.executable, str(sca_main_path), repo_path, "--verbose"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,   # Merge error into output
                text=True,
                cwd=Path(__file__).parent.parent/ "sudofix",
                env=env,
                bufsize=1
            )

            # Read output line by line in real-time
            for line in process.stdout:
                log.write(line)
                self.call_from_thread(log.refresh)   # Force UI update

            # Wait for process to finish
            returncode = process.wait()

            if returncode == 0:
                log.write("\n✅ SCA completed successfully!\n")
            else:
                log.write(f"\n⚠️ SCA finished with code {returncode}\n")

        except Exception as e:
            log.write(f"\n❌ Error: {e}\n")
            import traceback
            log.write(traceback.format_exc())
        finally:
            self._parse_findings_file(findings_tmp)
            os.unlink(findings_tmp)
            os.environ.pop("SUDOFIX_FINDINGS_FILE", None)

        self.call_from_thread(self._finished)
        self.notify("SCA Analysis Complete", severity="success")


    @work(thread=True)
    def action_start(self):
        repo_path = self.query_one("#repo-path").value.strip() or "."
        mode = "sast"
        if self.query_one("#sca").value:
            mode = "sca"
        if self.query_one("#full").value:
            mode = "full"
        command = "review"
        if self.query_one("#test").value:
            command = "test"
        if self.query_one("#doc").value:
            command = "doc"

        log = self.query_one("#live-log", Log)
        log.write(f"\n🚀 Starting {mode.upper()} | {
                  command} | Dry-run={self.dry_run}\n")
        log.write(f"📍 Repository: {repo_path}\n")
        log.write(f"🤖 LLM: {self.llm_info['model']} (Ollama)\n\n")

        self.call_from_thread(self._init_findings_table)
        self.findings.clear()

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.jsonl', delete=False) as f:
            findings_tmp = f.name
        os.environ["SUDOFIX_FINDINGS_FILE"] = findings_tmp

        self.query_one("#status").update("Status: Running...")

        class TeeStream:
            def __init__(self, original, log_widget, app):
                self.original = original
                self.log = log_widget
                self.app = app
                self.buffer = StringIO()

            def write(self, data):
                self.original.write(data)
                self.buffer.write(data)
                self.app.call_from_thread(self.log.write, data)

            def flush(self):
                self.original.flush()
                self.buffer.flush()

            def getvalue(self):
                return self.buffer.getvalue()

        orig_stdout = sys.stdout
        orig_stderr = sys.stderr
        tee_out = TeeStream(orig_stdout, log, self)
        tee_err = TeeStream(orig_stderr, log, self)

        try:
            sys.stdout = tee_out
            sys.stderr = tee_err
            os.environ["PYTHONUNBUFFERED"] = "1"
            run_llm(repo_path, command, mode)
        except Exception as e:
            tee_err.write(f"❌ Crash: {e}\n")
        finally:
            sys.stdout = orig_stdout
            sys.stderr = orig_stderr
            self._parse_findings_file(findings_tmp)
            os.unlink(findings_tmp)
            os.environ.pop("SUDOFIX_FINDINGS_FILE", None)
            os.environ.pop("PYTHONUNBUFFERED", None)
            with open("pipeline.log", "a") as lf:
                lf.write(tee_out.getvalue())
                lf.write(tee_err.getvalue())

        self.call_from_thread(self._finished)

    def _parse_findings_file(self, path: str):
        try:
            with open(path) as f:
                for line in f:
                    data = json.loads(line.strip())
                    finding = Finding(
                        severity=data.get("severity", "INFO"),
                        type_=data.get("type", "unknown"),
                        file=data.get("file", ""),
                        start_line=data.get("start_line", 0),
                        end_line=data.get("end_line", 0),
                        description=data.get("description", ""),
                        original_code=data.get("original_code", ""),
                        fix_suggestion=data.get("fix_suggestion", "")
                    )
                    self.call_from_thread(self.add_finding, finding)
        except Exception as e:
            self.call_from_thread(self.query_one(
                "#live-log").write, f"⚠️ Findings parse error: {e}\n")

    def _finished(self):
        self.query_one("#status").update("Status: Finished")
        self.notify("Analysis Complete", severity="success")
        if not self.findings:
            self.query_one(
                "#live-log").write("\n✅ No vulnerabilities found.\n")

    # ------------------------------------------------------------------
    # Button actions
    # ------------------------------------------------------------------
    def on_button_pressed(self, event):
        if event.button.id == "start-btn":
            self.action_start()
        elif event.button.id == "only-sca-btn":          # ← NEW
            self.action_only_sca()
        elif event.button.id == "dry-btn":
            self.action_toggle_dryrun()
        elif event.button.id == "set-repo":
            self.action_set_repository()
        elif event.button.id == "refresh-tree":
            self.action_refresh_tree()
        elif event.button.id == "export-btn":
            self.action_export()
        elif event.button.id == "edit-btn":
            self.action_edit_file()
        elif event.button.id == "apply-fix-btn":
            self.action_apply_fix()

    def action_set_repository(self):
        new_path = self.query_one("#repo-path").value.strip()
        if not new_path:
            new_path = "."
        new_path = os.path.abspath(new_path)
        if os.path.exists(new_path):
            self.current_repo = new_path
            self.action_refresh_tree()
            self.notify(f"Repository set to: {self.current_repo}", timeout=3)
        else:
            self.notify(f"Path does not exist: {new_path}", severity="error")

    def action_refresh_tree(self):
        if self.current_tree:
            self.current_tree.remove()
        self.tree_counter += 1
        new_tree = DirectoryTree(
            self.current_repo, id=f"file-tree-{self.tree_counter}")
        refresh_btn = self.query_one("#refresh-tree")
        sidebar = self.query_one("#sidebar")
        sidebar.mount(new_tree, before=refresh_btn)
        self.current_tree = new_tree
        self.query_one("#repo-path").value = self.current_repo

    def action_toggle_dryrun(self):
        self.dry_run = not self.dry_run
        btn = self.query_one("#dry-btn")
        btn.label = f"Dry-run: {'ON' if self.dry_run else 'OFF'}"
        self.notify(
            f"Dry-run mode {'enabled' if self.dry_run else 'disabled'}")

    def action_export(self):
        self.notify(
            "Exported to sca_report.md + llm_fixes.md + vulnerabilities.json")

    def action_cancel(self):
        self.query_one(
            "#live-log").write("⚠️ Cancel requested (thread termination limited)\n")

    def action_toggle_monitor(self):
        self.query_one("#monitor").collapsed = not self.query_one(
            "#monitor").collapsed


if __name__ == "__main__":
    SudofixTUI().run()

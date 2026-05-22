#!/usr/bin/env python3
"""Full‑featured text editor and diff viewer for the Sudofix TUI."""

import os
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, TextArea, Button, Static, Input
from textual.screen import ModalScreen
from textual.binding import Binding

# ----------------------------------------------------------------------
# Simple Find/Replace Modal
# ----------------------------------------------------------------------


class FindReplaceModal(ModalScreen):
    """Modal dialog for find and replace."""
    BINDINGS = [Binding("escape", "cancel", "Close")]

    def __init__(self, editor: TextArea):
        super().__init__()
        self.editor = editor

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="find-container"):
            yield Static("Find:", classes="label")
            yield Input(placeholder="Search text...", id="find-input")
            yield Static("Replace with:", classes="label")
            yield Input(placeholder="(leave empty to just find)", id="replace-input")
            with Horizontal():
                yield Button("Find Next", variant="primary", id="find-btn")
                yield Button("Replace & Find", variant="warning", id="replace-btn")
                yield Button("Replace All", variant="error", id="replace-all-btn")
            yield Button("Close", variant="default", id="close-btn")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        find_text = self.query_one("#find-input", Input).value
        replace_text = self.query_one("#replace-input", Input).value
        if event.button.id == "find-btn":
            if find_text:
                self.editor.find(find_text)
        elif event.button.id == "replace-btn":
            if find_text:
                self.editor.replace(replace_text)
                self.editor.find(find_text)  # find next
        elif event.button.id == "replace-all-btn":
            if find_text:
                self.editor.replace_all(replace_text)
        elif event.button.id == "close-btn":
            self.dismiss()

    def action_cancel(self) -> None:
        self.dismiss()


# ----------------------------------------------------------------------
# Full Editor Modal
# ----------------------------------------------------------------------
class FullEditor(ModalScreen):
    """Full‑featured text editor with save, find/replace, and line numbers."""
    BINDINGS = [
        Binding("ctrl+s", "save", "Save", show=True),
        Binding("ctrl+f", "find_replace", "Find/Replace", show=True),
        Binding("escape", "cancel", "Close", show=True),
    ]

    def __init__(self, file_path: str, initial_content: str = ""):
        super().__init__()
        self.file_path = file_path
        self.initial_content = initial_content

    def compose(self) -> ComposeResult:
        yield Header()
        yield TextArea(self.initial_content, id="editor", show_line_numbers=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#editor").focus()

    def action_save(self) -> None:
        editor = self.query_one("#editor", TextArea)
        content = editor.text
        try:
            with open(self.file_path, 'w') as f:
                f.write(content)
            self.notify(f"Saved {os.path.basename(
                self.file_path)}", severity="success")
            self.dismiss(content)
        except Exception as e:
            self.notify(f"Error saving: {e}", severity="error")

    def action_find_replace(self) -> None:
        editor = self.query_one("#editor", TextArea)
        # FIX: use self.app.push_screen (ModalScreen has no push_screen method)
        self.app.push_screen(FindReplaceModal(editor))

    def action_cancel(self) -> None:
        self.dismiss(None)


# ----------------------------------------------------------------------
# Diff Viewer for RAG Fixes
# ----------------------------------------------------------------------
class DiffEditor(ModalScreen):
    """Side‑by‑side diff viewer for reviewing and applying RAG fixes."""
    BINDINGS = [
        Binding("ctrl+s", "accept", "Accept & Save", show=True),
        Binding("escape", "reject", "Reject", show=True),
    ]

    def __init__(self, file_path: str, original_code: str, proposed_code: str, start_line: int = 1):
        super().__init__()
        self.file_path = file_path
        self.original_code = original_code
        self.proposed_code = proposed_code
        self.start_line = start_line

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(f"📝 Review changes for {os.path.basename(self.file_path)} (lines {self.start_line}–…)")
        with Horizontal(id="diff-container"):
            with Vertical(id="original-pane"):
                yield Static("🔴 Original (vulnerable code)", classes="pane-title")
                yield TextArea(self.original_code, id="original", show_line_numbers=True, read_only=False)
            with Vertical(id="proposed-pane"):
                yield Static("🟢 Proposed fix (editable)", classes="pane-title")
                yield TextArea(self.proposed_code, id="proposed", show_line_numbers=True, read_only=False)
        with Horizontal(id="diff-buttons"):
            yield Button("✓ Accept & Save", variant="success", id="accept-btn")
            yield Button("✗ Reject", variant="error", id="reject-btn")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#original").focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "accept-btn":
            self.action_accept()
        elif event.button.id == "reject-btn":
            self.action_reject()

    def action_accept(self) -> None:
        """Replace the original chunk in the file with the edited proposed code."""
        proposed_editor = self.query_one("#proposed", TextArea)
        final_code = proposed_editor.text
        try:
            with open(self.file_path, 'r') as f:
                full_content = f.read()
            # Simple replacement – works if the chunk appears exactly once.
            new_content = full_content.replace(
                self.original_code, final_code, 1)
            with open(self.file_path, 'w') as f:
                f.write(new_content)
            self.notify(f"Fix applied to {os.path.basename(
                self.file_path)}", severity="success")
            self.dismiss(True)
        except Exception as e:
            self.notify(f"Error saving: {e}", severity="error")

    def action_reject(self) -> None:
        self.dismiss(False)

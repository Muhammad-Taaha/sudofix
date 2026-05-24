import os
from typing import Optional, Tuple

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, TextArea, Button, Static, Input
from textual.screen import ModalScreen
from textual.binding import Binding
from textual.widgets.text_area import Selection  # for older Textual


# ----------------------------------------------------------------------
# Find/Replace Modal – works with any Textual version
# (no .find(), no .select_region())
# ----------------------------------------------------------------------
class FindReplaceModal(ModalScreen):
    """Modal dialog for find and replace."""
    BINDINGS = [Binding("escape", "cancel", "Close")]

    def __init__(self, editor: TextArea):
        super().__init__()
        self.editor = editor
        self.last_start_char: Optional[int] = None

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

    # --------------------------------------------------------------
    # Convert (row, col) to character index in the full text
    # --------------------------------------------------------------
    def _location_to_char(self, location: Tuple[int, int]) -> int:
        text = self.editor.text
        lines = text.splitlines(keepends=True)
        row, col = location
        idx = 0
        for i, line in enumerate(lines):
            if i == row:
                idx += min(col, len(line))
                break
            idx += len(line)
        return idx

    # --------------------------------------------------------------
    # Convert character index to (row, col)
    # --------------------------------------------------------------
    def _char_to_location(self, char_pos: int) -> Tuple[int, int]:
        text = self.editor.text
        lines = text.splitlines(keepends=True)
        cumulative = 0
        for row, line in enumerate(lines):
            line_len = len(line)
            if char_pos < cumulative + line_len:
                return (row, char_pos - cumulative)
            cumulative += line_len
        # if at very end
        return (len(lines) - 1, len(lines[-1]) if lines else 0)

    # --------------------------------------------------------------
    # Find substring and return (start_char, end_char) or None
    # --------------------------------------------------------------
    def _find_text(self, needle: str, start_char: int = 0) -> Optional[Tuple[int, int]]:
        text = self.editor.text
        pos = text.find(needle, start_char)
        if pos == -1:
            return None
        return (pos, pos + len(needle))

    # --------------------------------------------------------------
    # Select a range using character indices
    # --------------------------------------------------------------
    def _select_range(self, start_char: int, end_char: int) -> None:
        start_loc = self._char_to_location(start_char)
        end_loc = self._char_to_location(end_char)
        self.editor.selection = Selection(start_loc, end_loc)

    # --------------------------------------------------------------
    # Replace a range and return new text + new cursor char position
    # --------------------------------------------------------------
    def _replace_range(self, start_char: int, end_char: int, replacement: str) -> Tuple[str, int]:
        text = self.editor.text
        new_text = text[:start_char] + replacement + text[end_char:]
        self.editor.text = new_text
        # New cursor position is right after the inserted text
        new_cursor_char = start_char + len(replacement)
        return new_text, new_cursor_char

    # --------------------------------------------------------------
    # Button handlers
    # --------------------------------------------------------------
    def on_button_pressed(self, event: Button.Pressed) -> None:
        find_text = self.query_one("#find-input", Input).value
        replace_text = self.query_one("#replace-input", Input).value

        # ---------- Find Next ----------
        if event.button.id == "find-btn":
            if not find_text:
                self.notify("Enter text to find", severity="error")
                return

            start_char = 0
            if self.last_start_char is not None:
                start_char = self.last_start_char + 1  # move past last match

            match = self._find_text(find_text, start_char)
            if match:
                start_idx, end_idx = match
                self.last_start_char = start_idx
                self._select_range(start_idx, end_idx)
            else:
                self.notify("No more matches", severity="warning")

        # ---------- Replace & Find ----------
        elif event.button.id == "replace-btn":
            if not find_text:
                self.notify("Enter text to find", severity="error")
                return

            # If we have a stored match, replace it
            if self.last_start_char is not None:
                match = self._find_text(find_text, self.last_start_char)
                if match and match[0] == self.last_start_char:
                    start_idx, end_idx = match
                    new_text, new_cursor_char = self._replace_range(
                        start_idx, end_idx, replace_text)
                    # Find next after the replacement
                    next_match = self._find_text(find_text, new_cursor_char)
                    if next_match:
                        self.last_start_char = next_match[0]
                        self._select_range(*next_match)
                    else:
                        self.last_start_char = None
                        self.notify("No further matches", severity="info")
                    return

            # Fallback: replace current selection (if any)
            sel = self.editor.selection
            if sel.start != sel.end:
                start_char = self._location_to_char(sel.start)
                end_char = self._location_to_char(sel.end)
                new_text, new_cursor_char = self._replace_range(
                    start_char, end_char, replace_text)
                # Find next match after replaced area
                next_match = self._find_text(find_text, new_cursor_char)
                if next_match:
                    self.last_start_char = next_match[0]
                    self._select_range(*next_match)
                else:
                    self.last_start_char = None
            else:
                # No selection – find first occurrence
                match = self._find_text(find_text, 0)
                if match:
                    self.last_start_char = match[0]
                    self._select_range(*match)
                else:
                    self.notify(f'"{find_text}" not found', severity="error")

        # ---------- Replace All ----------
        elif event.button.id == "replace-all-btn":
            if not find_text:
                self.notify("Enter text to find", severity="error")
                return

            text = self.editor.text
            parts = []
            cursor = 0
            count = 0
            while True:
                pos = text.find(find_text, cursor)
                if pos == -1:
                    parts.append(text[cursor:])
                    break
                parts.append(text[cursor:pos])
                parts.append(replace_text)
                cursor = pos + len(find_text)
                count += 1
            if count > 0:
                self.editor.text = "".join(parts)
                self.notify(
                    f"Replaced {count} occurrence(s)", severity="information")
            else:
                self.notify(f'"{find_text}" not found', severity="warning")
            self.last_start_char = None

        # ---------- Close ----------
        elif event.button.id == "close-btn":
            self.dismiss()

    def action_cancel(self) -> None:
        self.dismiss()


# ----------------------------------------------------------------------
# Full Editor Modal (unchanged, but ensure it works)
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
        self.app.push_screen(FindReplaceModal(editor))

    def action_cancel(self) -> None:
        self.dismiss(None)


# ----------------------------------------------------------------------
# Diff Viewer for RAG Fixes (unchanged)
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
        proposed_editor = self.query_one("#proposed", TextArea)
        final_code = proposed_editor.text
        try:
            with open(self.file_path, 'r') as f:
                full_content = f.read()
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

"""Actual widget integration tests; skip explicitly when no desktop display exists."""
import json
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

from app import PhishWiseApp
from examples import EXAMPLES


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            probe = tk.Tk()
        except tk.TclError as error:
            raise unittest.SkipTest(f"A graphical desktop is required: {error}")
        probe.destroy()

    def setUp(self):
        self.root = tk.Tk()
        self.app = PhishWiseApp(self.root)
        self.root.update()

    def tearDown(self):
        self.root.destroy()

    def load_and_analyze(self):
        self.app.load_example()
        self.root.update()
        self.app.run_analysis()
        self.root.update()

    def test_load_analyze_and_highlight(self):
        self.load_and_analyze()
        self.assertIsNotNone(self.app.result)
        self.assertEqual(self.app.result["categories_present"], 3)
        self.assertTrue(self.app.editor.tag_ranges("urgency"))
        self.assertEqual(str(self.app.export_button["state"]), "normal")

    def test_edited_text_invalidates_export_and_results(self):
        self.load_and_analyze()
        self.app.editor.insert("end", " Extra text")
        self.root.update()
        self.assertIsNone(self.app.result)
        self.assertFalse(self.app.editor.tag_ranges("urgency"))
        self.assertEqual(str(self.app.export_button["state"]), "disabled")

    def test_clear_resets_everything(self):
        self.load_and_analyze()
        self.app.clear()
        self.root.update()
        self.assertEqual(self.app.editor.get("1.0", "end-1c"), "")
        self.assertIsNone(self.app.result)
        self.assertTrue(all(var.get() == "—" for var in self.app.count_vars.values()))

    def test_empty_input_shows_message(self):
        self.app.run_analysis()
        self.assertIsNone(self.app.result)
        self.assertIn("Paste an email", self.app.status_var.get())

    def test_unicode_highlight_selects_exact_evidence(self):
        self.app.editor.insert("1.0", "你好🙂\nAct now.")
        self.root.update()
        self.app.run_analysis()
        start, end = self.app.editor.tag_ranges("urgency")
        self.assertEqual(self.app.editor.get(start, end), "Act now")
        self.app.focus_finding(self.app.result["findings"][0])
        start, end = self.app.editor.tag_ranges("selected_finding")
        self.assertEqual(self.app.editor.get(start, end), "Act now")

    def test_export_file_and_cancel(self):
        self.load_and_analyze()
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "analysis.json"
            with patch("app.filedialog.asksaveasfilename", return_value=str(destination)):
                self.app.export()
            data = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(data["findings"], self.app.result["findings"])
            self.assertIn("exported_at_utc", data)
            before = destination.read_bytes()
            with patch("app.filedialog.asksaveasfilename", return_value=""):
                self.app.export()
            self.assertEqual(destination.read_bytes(), before)

    def test_export_error_is_handled(self):
        self.load_and_analyze()
        with patch("app.filedialog.asksaveasfilename", return_value="unused.json"), \
             patch("app.Path.write_text", side_effect=OSError("Test write failure")), \
             patch("app.messagebox.showerror") as show_error:
            self.app.export()
        show_error.assert_called_once_with("Could not export", "Test write failure")

    def test_no_matches_does_not_show_safe(self):
        self.app.example_var.set("06 / Subtle request - coverage gap (synthetic)")
        self.load_and_analyze()
        self.assertIn("This is not a safe verdict", self.app.output.get("1.0", "end"))
        self.assertEqual(self.app.result["total_matches"], 0)

    def test_loading_a_new_example_invalidates_results(self):
        self.load_and_analyze()
        name = "02 / Prize offer (synthetic)"
        self.app.example_var.set(name)
        self.app.load_example()
        self.root.update()
        self.assertIsNone(self.app.result)
        self.assertEqual(self.app.editor.get("1.0", "end-1c"), EXAMPLES[name])


if __name__ == "__main__":
    unittest.main()

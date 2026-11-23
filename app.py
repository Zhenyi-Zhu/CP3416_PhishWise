"""Offline Tkinter desktop interface. Run with: python app.py"""
from __future__ import annotations

import json
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from analyzer import CATEGORIES, LIMITATION, MAX_CHARACTERS, VERSION, analyze
from examples import EXAMPLES

BG, INK, MUTED, NAVY, TEAL = "#f3f5f7", "#172d3b", "#526674", "#142e3b", "#086f75"
PALETTES = {
    "urgency": ("#fff0c2", "#735000"),
    "authority": ("#dbeafa", "#184d7d"),
    "threat": ("#ffe0df", "#8b2e30"),
    "reward": ("#e6dcfa", "#543c7b"),
}


class PhishWiseApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.result: dict | None = None
        root.title("PhishWise | Phishing Cue Analysis and Explanation")
        root.geometry("1180x820")
        root.minsize(1000, 720)
        root.configure(bg=BG)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=INK, font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=(12, 8))
        style.configure("Primary.TButton", background=TEAL, foreground="white")
        style.map("Primary.TButton", background=[("active", "#09565c")])
        style.configure("TCombobox", padding=6, font=("Segoe UI", 10))

        header = tk.Frame(root, bg=NAVY, padx=26, pady=19)
        header.pack(fill="x")
        tk.Label(header, text="PhishWise", font=("Segoe UI", 27, "bold"), bg=NAVY, fg="white").pack(side="left")
        tk.Label(header, text="PHISHING CUE ANALYSIS\nAND EXPLANATION", justify="left",
                 font=("Segoe UI", 10), bg=NAVY, fg="#c9dbe2", padx=20).pack(side="left")
        tk.Label(header, text=f"LOCAL & OFFLINE   /   v{VERSION}", font=("Segoe UI", 10, "bold"),
                 bg=NAVY, fg="#9bddd4").pack(side="right")

        body = ttk.Frame(root, padding=(24, 16))
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Read the evidence. Check the context.", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        ttk.Label(body, text="English text only. Matched language is a cue to review, not a verdict about the sender.",
                  foreground=MUTED).pack(anchor="w", pady=(5, 13))

        cards = ttk.Frame(body)
        cards.pack(fill="x", pady=(0, 14))
        self.count_vars = {}
        for col, (key, category) in enumerate(CATEGORIES.items()):
            cards.columnconfigure(col, weight=1, uniform="cards")
            pale, dark = PALETTES[key]
            card = tk.Frame(cards, bg=pale, padx=14, pady=10)
            card.grid(row=0, column=col, sticky="ew", padx=(0, 8 if col < 3 else 0))
            variable = tk.StringVar(value="—")
            self.count_vars[key] = variable
            tk.Label(card, textvariable=variable, bg=pale, fg=dark, font=("Segoe UI", 22, "bold")).pack(side="left")
            tk.Label(card, text=category.label, bg=pale, fg=dark, font=("Segoe UI", 10, "bold"), padx=12).pack(side="left")

        toolbar = ttk.Frame(body)
        toolbar.pack(fill="x", pady=(0, 12))
        self.example_var = tk.StringVar(value=next(iter(EXAMPLES)))
        self.example_box = ttk.Combobox(toolbar, textvariable=self.example_var, values=list(EXAMPLES), state="readonly", width=44)
        self.example_box.pack(side="left", padx=(0, 8))
        ttk.Button(toolbar, text="Load example", command=self.load_example).pack(side="left")
        ttk.Button(toolbar, text="Clear", command=self.clear).pack(side="right", padx=(8, 0))
        self.export_button = ttk.Button(toolbar, text="Export JSON", command=self.export, state="disabled")
        self.export_button.pack(side="right", padx=(8, 0))
        ttk.Button(toolbar, text="Analyze email", style="Primary.TButton", command=self.run_analysis).pack(side="right")

        pane = ttk.Panedwindow(body, orient="horizontal")
        pane.pack(fill="both", expand=True)
        left, right = ttk.Frame(pane), ttk.Frame(pane)
        pane.add(left, weight=1)
        pane.add(right, weight=1)
        ttk.Label(left, text="01  /  EMAIL TEXT", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        ttk.Label(right, text="02  /  FINDINGS & EXPLANATIONS", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        self.editor = ScrolledText(left, wrap="word", font=("Segoe UI", 11), bg="white", fg=INK,
                                   relief="flat", padx=14, pady=12, undo=True, width=42,
                                   insertbackground=INK, spacing3=5)
        self.editor.pack(fill="both", expand=True, padx=(0, 10))
        self.output = ScrolledText(right, wrap="word", font=("Segoe UI", 10), bg="white", fg=INK,
                                   relief="flat", padx=15, pady=12, width=46, cursor="arrow", spacing3=5)
        self.output.pack(fill="both", expand=True)
        for key, (pale, dark) in PALETTES.items():
            self.editor.tag_configure(key, background=pale, foreground=dark)
            self.output.tag_configure(key, foreground=dark, font=("Segoe UI", 11, "bold"))
        self.editor.tag_configure("selected_finding", underline=True)
        self.output.tag_configure("heading", font=("Segoe UI", 13, "bold"), foreground=INK)
        self.output.tag_configure("muted", foreground=MUTED)
        self.output.tag_configure("note", foreground="#8b4b12", font=("Segoe UI", 10, "bold"))
        self.status_var = tk.StringVar(value=f"Ready • Up to {MAX_CHARACTERS:,} characters • Ctrl+Enter to analyze")
        ttk.Label(body, textvariable=self.status_var, foreground=MUTED).pack(anchor="w", pady=(10, 5))
        ttk.Label(body, text=LIMITATION, wraplength=1100, foreground=MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        self._show_intro()
        self.editor.bind("<<Modified>>", self._edited)
        self.editor.edit_modified(False)
        root.bind("<Control-Return>", lambda event: self.run_analysis())
        self.example_box.bind("<<ComboboxSelected>>", lambda event: None)

    def _show_intro(self):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("end", "Start with an email\n\n", "heading")
        self.output.insert("end", "Paste English email text on the left, or load a synthetic example. Then select Analyze email.\n\n")
        self.output.insert("end", "What you will see\n", "heading")
        self.output.insert("end", "Matched phrases, transparent rule IDs, possible influence mechanisms, and checks to make before acting.\n\n")
        self.output.insert("end", "Examples are invented development demonstrations. They do not establish detection accuracy or training effectiveness.", "muted")
        self.output.configure(state="disabled")

    def _reset_result(self):
        self.result = None
        self.export_button.configure(state="disabled")
        for variable in self.count_vars.values():
            variable.set("—")
        for tag in (*CATEGORIES, "selected_finding"):
            self.editor.tag_remove(tag, "1.0", "end")
        self._show_intro()

    def _edited(self, event=None):
        if self.editor.edit_modified():
            self._reset_result()
            self.status_var.set("Text changed • Analyze again to update the findings")
            self.editor.edit_modified(False)

    def load_example(self):
        self.editor.delete("1.0", "end")
        self.editor.insert("1.0", EXAMPLES[self.example_var.get()])
        self._reset_result()
        self.editor.edit_modified(False)
        self.status_var.set("Synthetic example loaded • Select Analyze email")
        self.editor.focus_set()

    def clear(self):
        self.editor.delete("1.0", "end")
        self._reset_result()
        self.editor.edit_modified(False)
        self.status_var.set("Cleared • Paste an email or load an example")
        self.editor.focus_set()

    def _text_index(self, offset: int) -> str:
        # Use the analyzer's Unicode character offset directly.
        return f"1.0 + {offset} chars"

    def focus_finding(self, finding: dict):
        self.editor.tag_remove("selected_finding", "1.0", "end")
        start, end = self._text_index(finding["start"]), self._text_index(finding["end"])
        self.editor.tag_add("selected_finding", start, end)
        self.editor.see(start)
        self.editor.focus_set()

    def run_analysis(self):
        # Clear a pending modified flag before rendering fresh output.
        self.editor.edit_modified(False)
        source = self.editor.get("1.0", "end-1c")
        try:
            result = analyze(source)
        except (TypeError, ValueError) as error:
            self._reset_result()
            self.status_var.set(str(error))
            return
        self._reset_result()
        self.result = result
        for key, count in result["counts"].items():
            self.count_vars[key].set(str(count))
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        # Remove old per-finding callbacks instead of accumulating them across analyses.
        for tag in self.output.tag_names():
            if tag.startswith("finding_"):
                self.output.tag_delete(tag)
        if not result["findings"]:
            self.output.insert("end", "No configured cues matched\n\n", "heading")
            self.output.insert("end", "This is not a safe verdict. The rules cover a small set of English phrases. Subtle payment requests and unfamiliar wording may be missed.\n\n")
            self.output.insert("end", "Review the sender and request independently. This tool does not open or inspect links or attachments.", "muted")
        else:
            self.output.insert("end", f"{result['total_matches']} phrase matches · {result['categories_present']} categories\n", "heading")
            self.output.insert("end", "Counts are occurrences, not a risk score. Click a matched phrase to locate it.\n\n", "muted")
            for i, finding in enumerate(result["findings"], 1):
                key = finding["category"]
                category = CATEGORIES[key]
                tag = f"finding_{i}"
                self.editor.tag_add(key, self._text_index(finding["start"]), self._text_index(finding["end"]))
                self.output.insert("end", f"{i:02d}  {category.label}  /  {finding['rule_id']}\n", key)
                self.output.insert("end", f"“{finding['matched_text']}”\n", tag)
                self.output.tag_configure(tag, underline=True)
                self.output.tag_bind(tag, "<Button-1>", lambda event, f=finding: self.focus_finding(f))
                self.output.insert("end", finding["rationale"] + "\n")
                self.output.insert("end", "Possible influence: " + category.mechanism + "\n")
                if finding["context_note"]:
                    self.output.insert("end", finding["context_note"] + "\n", "note")
                self.output.insert("end", "Check: " + category.check + "\n")
                self.output.insert("end", "Context matters: " + category.caveat + "\n\n", "muted")
        self.output.configure(state="disabled")
        self.output.yview_moveto(0)
        self.export_button.configure(state="normal")
        self.status_var.set(f"Analysis complete • {len(source):,} characters • Local processing only")

    def export(self):
        if self.result is None:
            return
        filename = filedialog.asksaveasfilename(
            title="Export analysis (includes matched excerpts and context)",
            defaultextension=".json", initialfile="phishwise_analysis.json",
            filetypes=[("JSON analysis", "*.json")],
        )
        if not filename:
            return
        payload = dict(self.result, exported_at_utc=datetime.now(timezone.utc).isoformat())
        try:
            Path(filename).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError as error:
            messagebox.showerror("Could not export", str(error))
            return
        self.status_var.set(f"Exported to {Path(filename).name} • Includes matched excerpts and context")


def main():
    root = tk.Tk()
    PhishWiseApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

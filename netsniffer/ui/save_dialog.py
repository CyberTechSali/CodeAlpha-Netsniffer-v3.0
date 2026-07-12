"""A dark-themed, in-app file-save dialog matching the app's own style,
replacing the plain native OS file picker."""

from __future__ import annotations

import os
import tkinter as tk

import customtkinter as ctk


class ThemedMessageDialog(ctk.CTkToplevel):
    """A small dark-themed modal, standing in for tkinter.messagebox so
    popups (overwrite confirmation, validation errors, ...) match the rest
    of the app instead of popping up as a plain native OS dialog."""

    _KIND_STYLE = {
        "confirm": ("❓", "#89b4fa"),
        "error": ("⛔", "#f38ba8"),
        "info": ("ℹ️", "#89b4fa"),
    }

    def __init__(self, parent, title: str, message: str, kind: str = "info") -> None:
        super().__init__(parent)
        self.result: bool | None = None
        icon, accent = self._KIND_STYLE.get(kind, self._KIND_STYLE["info"])

        self.title(title)
        self.configure(fg_color="#181926")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_no)

        header = ctk.CTkFrame(self, height=44, corner_radius=0, fg_color="#12131c")
        header.pack(fill="x")
        ctk.CTkLabel(header, text=f"{icon}  {title}", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color=accent).pack(side="left", padx=15, pady=10)

        ctk.CTkLabel(
            self, text=message, font=ctk.CTkFont(size=12), justify="left",
            wraplength=340
        ).pack(fill="both", expand=True, padx=20, pady=(16, 10))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(0, 15))

        if kind == "confirm":
            ctk.CTkButton(btn_row, text="No", fg_color="#4f5b66", hover_color="#343d46",
                          width=90, command=self._on_no).pack(side="right")
            ctk.CTkButton(btn_row, text="Yes", fg_color="#2eb872", hover_color="#1d8f53",
                          font=ctk.CTkFont(weight="bold"), width=90,
                          command=self._on_yes).pack(side="right", padx=(0, 10))
        else:
            ctk.CTkButton(btn_row, text="OK", fg_color="#3a3b5c", hover_color="#4f507d",
                          width=90, command=self._on_yes).pack(side="right")

        self.after(10, self._center_on_parent)
        self.bind("<Return>", lambda e: self._on_yes())
        self.bind("<Escape>", lambda e: self._on_no())

    def _center_on_parent(self):
        self.update_idletasks()
        try:
            px, py = self.master.winfo_rootx(), self.master.winfo_rooty()
            pw, ph = self.master.winfo_width(), self.master.winfo_height()
            w, h = self.winfo_width(), self.winfo_height()
            self.geometry(f"+{px + (pw - w) // 2}+{py + (ph - h) // 2}")
        except Exception:
            pass

    def _on_yes(self):
        self.result = True
        self.destroy()

    def _on_no(self):
        self.result = False
        self.destroy()


def ask_themed_yesno(parent, title: str, message: str) -> bool:
    dialog = ThemedMessageDialog(parent, title, message, kind="confirm")
    parent.wait_window(dialog)
    return bool(dialog.result)


def show_themed_message(parent, title: str, message: str, kind: str = "error") -> None:
    dialog = ThemedMessageDialog(parent, title, message, kind=kind)
    parent.wait_window(dialog)


class ModernSaveDialog(ctk.CTkToplevel):
    def __init__(self, parent, title="Save File", initialfile="file.txt",
                 filetypes=(("All files", "*.*"),), initialdir=None):
        super().__init__(parent)
        self.filetypes = filetypes
        self.result: str | None = None
        self._entries: list[tuple[str, bool]] = []

        self.current_dir = initialdir or os.path.expanduser("~/Desktop")
        if not os.path.isdir(self.current_dir):
            self.current_dir = os.path.expanduser("~")

        first_ext = filetypes[0][1].replace("*", "") if filetypes else ""
        self.selected_ext = first_ext

        self.title(title)
        self.geometry("560x460")
        self.minsize(480, 380)
        self.configure(fg_color="#181926")
        self.transient(parent)
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._build_ui(title, initialfile)
        self._populate_list()

        self.after(10, self._center_on_parent)
        self.filename_entry.focus_set()
        self.filename_entry.icursor(tk.END)

    # -- layout -----------------------------------------------------
    def _build_ui(self, title, initialfile):
        header = ctk.CTkFrame(self, height=44, corner_radius=0, fg_color="#12131c")
        header.pack(fill="x")
        ctk.CTkLabel(header, text=f"💾  {title}", font=ctk.CTkFont(size=14, weight="bold"),
                     text_color="#89b4fa").pack(side="left", padx=15, pady=10)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=15, pady=10)

        dir_row = ctk.CTkFrame(body, fg_color="transparent")
        dir_row.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(dir_row, text="Directory:", width=75, anchor="w").pack(side="left")
        self.dir_var = tk.StringVar(value=self.current_dir)
        self.dir_entry = ctk.CTkEntry(dir_row, textvariable=self.dir_var)
        self.dir_entry.pack(side="left", fill="x", expand=True, padx=(5, 5))
        self.dir_entry.bind("<Return>", lambda e: self._go_to_typed_dir())
        ctk.CTkButton(dir_row, text="⬆", width=32, fg_color="#3a3b5c", hover_color="#4f507d",
                      command=self._go_up).pack(side="left", padx=(0, 4))
        ctk.CTkButton(dir_row, text="🏠", width=32, fg_color="#3a3b5c", hover_color="#4f507d",
                      command=self._go_home).pack(side="left")

        list_frame = ctk.CTkFrame(body, fg_color="#1e1e2e", corner_radius=8)
        list_frame.pack(fill="both", expand=True, pady=(0, 10))

        self.listbox = tk.Listbox(
            list_frame, bg="#1e1e2e", fg="#cdd6f4", selectbackground="#45475a",
            selectforeground="#ffffff", highlightthickness=0, borderwidth=0,
            font=("Segoe UI", 11), activestyle="none"
        )
        self.listbox.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        list_scroll = ctk.CTkScrollbar(list_frame, command=self.listbox.yview)
        list_scroll.pack(side="right", fill="y", pady=6)
        self.listbox.configure(yscrollcommand=list_scroll.set)
        self.listbox.bind("<Double-Button-1>", self._on_item_double_click)
        self.listbox.bind("<<ListboxSelect>>", self._on_item_select)

        fname_row = ctk.CTkFrame(body, fg_color="transparent")
        fname_row.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(fname_row, text="File name:", width=75, anchor="w").pack(side="left")
        self.filename_var = tk.StringVar(value=initialfile)
        self.filename_entry = ctk.CTkEntry(fname_row, textvariable=self.filename_var)
        self.filename_entry.pack(side="left", fill="x", expand=True, padx=(5, 0))
        self.filename_entry.bind("<Return>", lambda e: self._on_save())

        type_row = ctk.CTkFrame(body, fg_color="transparent")
        type_row.pack(fill="x")
        ctk.CTkLabel(type_row, text="Files of type:", width=75, anchor="w").pack(side="left")
        type_labels = [f"{desc} ({pattern})" for desc, pattern in self.filetypes]
        self.type_var = tk.StringVar(value=type_labels[0] if type_labels else "")
        self.type_menu = ctk.CTkOptionMenu(type_row, values=type_labels, variable=self.type_var,
                                            command=self._on_type_change, width=220)
        self.type_menu.pack(side="left", padx=(5, 0))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=(0, 15))
        ctk.CTkButton(btn_row, text="Cancel", fg_color="#4f5b66", hover_color="#343d46",
                      command=self._on_cancel).pack(side="right")
        ctk.CTkButton(btn_row, text="Save", fg_color="#2eb872", hover_color="#1d8f53",
                      font=ctk.CTkFont(weight="bold"), command=self._on_save).pack(side="right", padx=(0, 10))

    # -- helpers ------------------------------------------------------
    def _center_on_parent(self):
        self.update_idletasks()
        try:
            px, py = self.master.winfo_rootx(), self.master.winfo_rooty()
            pw, ph = self.master.winfo_width(), self.master.winfo_height()
            w, h = self.winfo_width(), self.winfo_height()
            self.geometry(f"+{px + (pw - w) // 2}+{py + (ph - h) // 2}")
        except Exception:
            pass

    def _on_type_change(self, val):
        type_labels = [f"{desc} ({pattern})" for desc, pattern in self.filetypes]
        if val in type_labels:
            idx = type_labels.index(val)
            ext = self.filetypes[idx][1].replace("*", "")
            self.selected_ext = ext
            if ext and ext != ".":
                name, _ = os.path.splitext(self.filename_var.get())
                self.filename_var.set(name + ext)
        self._populate_list()

    def _populate_list(self):
        self.listbox.delete(0, tk.END)
        self.dir_var.set(self.current_dir)
        self._entries = []
        try:
            entries = sorted(
                os.listdir(self.current_dir),
                key=lambda x: (not os.path.isdir(os.path.join(self.current_dir, x)), x.lower())
            )
        except Exception:
            entries = []

        for entry in entries:
            if entry.startswith("."):
                continue
            full = os.path.join(self.current_dir, entry)
            if os.path.isdir(full):
                self.listbox.insert(tk.END, f"📁  {entry}")
                self._entries.append((entry, True))
            else:
                if self.selected_ext and self.selected_ext not in (".*", "") and \
                        not entry.lower().endswith(self.selected_ext.lower()):
                    continue
                self.listbox.insert(tk.END, f"📄  {entry}")
                self._entries.append((entry, False))

    def _on_item_double_click(self, _event):
        sel = self.listbox.curselection()
        if not sel:
            return
        name, is_dir = self._entries[sel[0]]
        if is_dir:
            self.current_dir = os.path.join(self.current_dir, name)
            self._populate_list()
        else:
            self.filename_var.set(name)
            self._on_save()

    def _on_item_select(self, _event):
        sel = self.listbox.curselection()
        if not sel:
            return
        name, is_dir = self._entries[sel[0]]
        if not is_dir:
            self.filename_var.set(name)

    def _go_up(self):
        parent = os.path.dirname(self.current_dir.rstrip(os.sep))
        if parent and os.path.isdir(parent):
            self.current_dir = parent
            self._populate_list()

    def _go_home(self):
        home = os.path.expanduser("~")
        if os.path.isdir(home):
            self.current_dir = home
            self._populate_list()

    def _go_to_typed_dir(self):
        typed = self.dir_var.get().strip()
        if os.path.isdir(typed):
            self.current_dir = typed
            self._populate_list()
        else:
            show_themed_message(self, "Error", "Directory does not exist.", kind="error")

    def _on_save(self):
        filename = self.filename_var.get().strip()
        if not filename:
            show_themed_message(self, "Error", "Please enter a file name.", kind="error")
            return
        if self.selected_ext and self.selected_ext not in (".*", "") and \
                not filename.lower().endswith(self.selected_ext.lower()):
            filename += self.selected_ext

        full_path = os.path.join(self.current_dir, filename)
        if os.path.exists(full_path):
            if not ask_themed_yesno(self, "Confirm Overwrite", f"'{filename}' already exists.\nDo you want to replace it?"):
                return
        self.result = full_path
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


def ask_save_file(parent, title, initialfile, filetypes, initialdir=None) -> str | None:
    """Opens the modern in-app save dialog and blocks until it is closed."""
    dialog = ModernSaveDialog(parent, title=title, initialfile=initialfile,
                               filetypes=filetypes, initialdir=initialdir)
    parent.wait_window(dialog)
    return dialog.result

# app.py
import threading, queue, os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scanner import WebSETScanner

class WebSETApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WebSET — Code Scanner")
        self.geometry("900x600")

        # Tabs: Paste Code | Open Folder
        self.nb = ttk.Notebook(self)
        self.tab_paste = ttk.Frame(self.nb)
        self.tab_folder = ttk.Frame(self.nb)
        self.nb.add(self.tab_paste, text="Paste Code")
        self.nb.add(self.tab_folder, text="Open Folder")
        self.nb.pack(fill="both", expand=True)

        # ----- Paste Code tab
        ptop = ttk.Frame(self.tab_paste, padding=10)
        ptop.pack(fill="both", expand=True)
        ttk.Label(ptop, text="Paste your HTML/JS/CSS below:").pack(anchor="w")
        self.code_text = tk.Text(ptop, height=14, wrap="word")
        self.code_text.pack(fill="both", expand=True, pady=(6, 6))
        self.filename_var = tk.StringVar(value="<pasted> (optional hint)")
        frow = ttk.Frame(ptop)
        frow.pack(fill="x")
        ttk.Label(frow, text="Filename hint (e.g., index.html):").pack(side="left")
        ttk.Entry(frow, textvariable=self.filename_var, width=40).pack(side="left", padx=8)

        # ----- Folder tab
        ftop = ttk.Frame(self.tab_folder, padding=10)
        ftop.pack(fill="x")
        ttk.Label(ftop, text="Project folder:").pack(side="left")
        self.path_var = tk.StringVar()
        ttk.Entry(ftop, textvariable=self.path_var, width=60).pack(side="left", padx=8)
        ttk.Button(ftop, text="Browse…", command=self._pick_folder).pack(side="left")

        # ----- Controls
        ctrl = ttk.Frame(self, padding=(10, 6))
        ctrl.pack(fill="x")
        self.btn_start = ttk.Button(ctrl, text="Start Scan", command=self.start_scan)
        self.btn_stop  = ttk.Button(ctrl, text="Stop", command=self.stop_scan, state="disabled")
        self.btn_start.pack(side="left")
        self.btn_stop.pack(side="left", padx=8)

        self.progress = ttk.Progressbar(ctrl, mode="determinate", maximum=100)
        self.progress.pack(side="left", fill="x", expand=True, padx=10)
        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(ctrl, textvariable=self.status_var, width=40).pack(side="right")

        # ----- Findings table
        tfrm = ttk.Frame(self, padding=10)
        tfrm.pack(fill="both", expand=True)
        cols = ("sev", "title", "path", "evidence")
        self.tree = ttk.Treeview(tfrm, columns=cols, show="headings")
        for col, w in (("sev", 90), ("title", 220), ("path", 280), ("evidence", 400)):
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True)

        # Save report button
        btm = ttk.Frame(self, padding=(10, 0))
        btm.pack(fill="x")
        ttk.Button(btm, text="Save Findings (CSV)", command=self.save_csv).pack(side="right")

        # plumbing
        self.scanner = None
        self.worker  = None
        self.msg_q   = queue.Queue()
        self.after(100, self._drain_queue)

    # ---------- UI actions
    def _pick_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.path_var.set(path)

    def start_scan(self):
        # reset table
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.progress["value"] = 0
        self.status_var.set("Starting…")
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        self.scanner = WebSETScanner()

        def on_progress(pct, msg): self.msg_q.put(("progress", pct, msg))
        def on_finding(f):         self.msg_q.put(("finding", f))

        active_tab = self.nb.index(self.nb.select())
        def run():
            try:
                if active_tab == 0:
                    code = self.code_text.get("1.0", "end-1c")
                    fname = self.filename_var.get().strip() or "<pasted>"
                    if not code.strip():
                        raise ValueError("No code was pasted.")
                    for _ in self.scanner.scan_code(code, filename=fname, on_progress=on_progress, on_finding=on_finding):
                        pass
                else:
                    root = self.path_var.get().strip()
                    if not root or not os.path.isdir(root):
                        raise ValueError("Please choose a valid project folder.")
                    for _ in self.scanner.scan_path(root, on_progress=on_progress, on_finding=on_finding):
                        pass
                self.msg_q.put(("done",))
            except Exception as e:
                self.msg_q.put(("error", str(e)))

        self.worker = threading.Thread(target=run, daemon=True)
        self.worker.start()

    def stop_scan(self):
        if self.scanner:
            self.scanner.stop()
        self.btn_stop.configure(state="disabled")

    def save_csv(self):
        if not self.tree.get_children():
            messagebox.showinfo("Save CSV", "No findings to save yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")],
                                            initialfile="webset_findings.csv")
        if not path:
            return
        import csv
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Severity", "Title", "Path", "Evidence"])
            for iid in self.tree.get_children():
                writer.writerow(self.tree.item(iid, "values"))
        messagebox.showinfo("Saved", f"Findings saved to:\n{path}")

    def _drain_queue(self):
        try:
            while True:
                msg = self.msg_q.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _, pct, text = msg
                    self.progress["value"] = pct
                    self.status_var.set(text)
                elif kind == "finding":
                    _, f = msg
                    self.tree.insert("", "end", values=(f["severity"], f["title"], f["path"], f["evidence"]))
                elif kind == "done":
                    self.status_var.set("Finished")
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                elif kind == "error":
                    _, err = msg
                    self.status_var.set("Error")
                    messagebox.showerror("Scan error", err)
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
        except queue.Empty:
            pass
        finally:
            self.after(100, self._drain_queue)

if __name__ == "__main__":
    app = WebSETApp()
    app.mainloop()

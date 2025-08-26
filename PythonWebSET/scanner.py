# scanner.py
from __future__ import annotations
import os, re, time
from typing import Callable, Dict, Any, Iterable, List, Tuple

Finding = Dict[str, Any]

_HTML_EXT = {".html", ".htm"}
_JS_EXT   = {".js",}
_CSS_EXT  = {".css",}
_ALL_EXT  = _HTML_EXT | _JS_EXT | _CSS_EXT

class WebSETScanner:
    def __init__(self, rules: Dict[str, Any] | None = None):
        self._stop = False
        self.rules = rules or {}

    def stop(self):
        self._stop = True

    # ---------------------------
    # Public entry points
    # ---------------------------
    def scan_code(self, code: str,
                  filename: str = "<pasted>",
                  on_progress: Callable[[int, str], None] | None = None,
                  on_finding: Callable[[Finding], None] | None = None
                 ) -> Iterable[Finding]:
        """Scan a single in-memory code blob."""
        steps = [
            ("Preprocess", lambda: None),
            ("Static Analysis", lambda: None),
            ("Reporting", lambda: None),
        ]
        for i, (label, fn) in enumerate(steps, start=1):
            if self._stop:
                if on_progress: on_progress(100, "Scan cancelled")
                return
            time.sleep(0.2)  # simulate work
            fn()
            if on_progress: on_progress(i * 100 // len(steps), label)

        # Run checks
        for f in self._run_checks(code, filename):
            if on_finding: on_finding(f)
            yield f

    def scan_path(self, root_path: str,
                  on_progress: Callable[[int, str], None] | None = None,
                  on_finding: Callable[[Finding], None] | None = None
                 ) -> Iterable[Finding]:
        """Recursively scan a project folder."""
        files = self._gather_files(root_path)
        total = max(1, len(files))
        for idx, (p, ext) in enumerate(files, start=1):
            if self._stop:
                if on_progress: on_progress(100, "Scan cancelled")
                return
            if on_progress:
                on_progress(int(idx * 100 / total), f"Analyzing {os.path.relpath(p, root_path)}")
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    code = fh.read()
            except Exception as e:
                finding = {
                    "severity": "Low",
                    "title": "Unreadable file",
                    "path": p,
                    "evidence": str(e),
                }
                if on_finding: on_finding(finding)
                yield finding
                continue

            for f in self._run_checks(code, p, ext_hint=ext):
                if on_finding: on_finding(f)
                yield f

        if on_progress: on_progress(100, "Finished")

    # ---------------------------
    # Helpers
    # ---------------------------
    def _gather_files(self, root: str) -> List[Tuple[str, str]]:
        result: List[Tuple[str, str]] = []
        for dirpath, _, filenames in os.walk(root):
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                if ext in _ALL_EXT:
                    result.append((os.path.join(dirpath, name), ext))
        return result

    def _run_checks(self, code: str, origin: str, ext_hint: str | None = None) -> Iterable[Finding]:
        # Very basic rules you can expand with your own signatures
        text = code

        def add(title, sev, evidence):
            return {
                "severity": sev,
                "title": title,
                "path": origin,
                "evidence": evidence[:250],
            }

        # --- HTML checks
        if (ext_hint in _HTML_EXT) or (ext_hint is None and "<html" in text.lower()):
            # Missing CSP
            if not re.search(r"<meta\s+http-equiv=['\"]Content-Security-Policy['\"]", text, re.I):
                yield add("Missing Content Security Policy", "High", "No CSP <meta http-equiv='Content-Security-Policy'> found")

            # Insecure forms (no method or default GET for sensitive inputs)
            if re.search(r"<form[^>]*>", text, re.I):
                if re.search(r"<input[^>]+type=['\"]password['\"]", text, re.I) and not re.search(r"<form[^>]*method=['\"]post['\"]", text, re.I):
                    yield add("Password form not using POST", "High", "A form with password input does not enforce method='POST'")

            # Inline event handlers (XSS risk)
            if re.search(r"\son\w+=['\"][^'\"]+['\"]", text, re.I):
                yield add("Inline event handlers", "Medium", "Found inline on* attributes (e.g., onclick)")

            # Mixed content (http resources)
            if re.search(r"src=['\"]http://", text, re.I) or re.search(r"href=['\"]http://", text, re.I):
                yield add("Mixed content", "Medium", "HTTP resources referenced in HTML")

        # --- JS checks
        if (ext_hint in _JS_EXT) or (ext_hint is None and "function" in text and "var" in text):
            # eval() usage
            if re.search(r"\beval\s*\(", text):
                yield add("Use of eval()", "High", "eval() detected")

            # innerHTML assignment
            if re.search(r"\.innerHTML\s*=", text):
                yield add("Unsafe innerHTML assignment", "Medium", "Direct innerHTML writes can enable XSS")

            # document.write()
            if re.search(r"\bdocument\.write\s*\(", text):
                yield add("document.write usage", "Low", "document.write detected")

        # --- CSS checks
        if (ext_hint in _CSS_EXT) or (ext_hint is None and "{color" in text.lower()):
            # @import http:
            if re.search(r"@import\s+['\"]http://", text, re.I):
                yield add("Insecure CSS import", "Low", "@import over HTTP")

        # Project-agnostic secrets (API keys, JWTs) — very naive
        if re.search(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]", text):
            yield add("Hardcoded secret", "High", "Looks like a secret token/key is embedded")

        # Custom regex rules from self.rules (optional)
        for title, cfg in self.rules.get("regex", {}).items():
            pat = cfg.get("pattern")
            sev = cfg.get("severity", "Low")
            if pat and re.search(pat, text, re.I | re.M):
                yield add(title, sev, f"Matched: {pat}")

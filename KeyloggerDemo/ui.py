import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from admin_reporter import report_unauthorized_decrypt_attempt
from cryptography.fernet import Fernet, InvalidToken
import crypto_utils
from detector import (
    DetectionResult,
    SENSITIVITY_API_TOKEN,
    SENSITIVITY_CREDIT_CARD,
    SENSITIVITY_EMAIL,
    SENSITIVITY_NONE,
    SENSITIVITY_OTP,
    SENSITIVITY_PASSWORD,
    classify_value,
)
from exporter import decrypt_encrypted_logs, export_encrypted_logs


BANNER_TEXT = "For security awareness only — does not capture system-wide input."


@dataclass(frozen=True)
class FieldSpec:
    field_kind: str  # used for detector override
    label: str       # human-readable name
    is_masked_display: bool
    show_char: str


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def format_record_for_display(record: Dict[str, Any]) -> str:
    ts = record.get("timestamp", "?")
    field_name = record.get("field_name", "?")
    sensitivity = record.get("sensitivity_classification", "none")
    protection = record.get("protection_method", "encrypted")
    protected_value = record.get("protected_value", {})
    if protection == "encrypted_inline":
        length = protected_value.get("length", "?")
        ct = protected_value.get("ciphertext_b64", "")
        preview = (ct[:48] + "…") if len(ct) > 52 else ct
        return (
            f"{ts} | {field_name} | sensitivity={sensitivity} | protection={protection} "
            f"| length={length} | ciphertext_preview={preview}"
        )
    return f"{ts} | {field_name} | sensitivity={sensitivity} | protection={protection} | value={protected_value}"


class SecureInputLoggerApp:
    """
    Security-awareness demo app.

    It does NOT capture system-wide keystrokes. It logs only the text entered into this app's
    own Tkinter input widgets (local focus + <KeyRelease> handlers).
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("KeyLogger Demo")

        self.records: List[Dict[str, Any]] = []
        # In-memory key for password/OTP log lines: ciphertext only, no plaintext keystrokes stored.
        self._audit_fernet = Fernet(Fernet.generate_key())

        self._build_ui()

    def _build_ui(self) -> None:
        self.root.geometry("980x560")

        banner = ttk.Label(self.root, text=BANNER_TEXT, foreground="#b00020", font=("TkDefaultFont", 11, "bold"))
        banner.pack(anchor="w", padx=12, pady=(12, 8))

        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True, padx=12, pady=6)

        left = ttk.Frame(main)
        left.pack(side="left", fill="y")

        right = ttk.Frame(main)
        right.pack(side="right", fill="both", expand=True)

        ttk.Label(left, text="Inputs (log events only inside the app):").pack(anchor="w")

        # Field layout: label + entry
        fields: List[FieldSpec] = [
            FieldSpec(field_kind="username", label="username", is_masked_display=False, show_char=""),
            FieldSpec(field_kind="password", label="password", is_masked_display=True, show_char="*"),
            FieldSpec(field_kind="email", label="email", is_masked_display=False, show_char=""),
            FieldSpec(field_kind="otp", label="OTP", is_masked_display=True, show_char="*"),
            FieldSpec(field_kind="generic", label="generic text", is_masked_display=False, show_char=""),
        ]

        self._entries: Dict[str, tk.Entry] = {}
        for idx, spec in enumerate(fields):
            row = ttk.Frame(left)
            row.pack(anchor="w", pady=6, fill="x")

            ttk.Label(row, text=f"{spec.label}:").grid(row=0, column=0, sticky="w", padx=(0, 8))
            show = spec.show_char if spec.is_masked_display else ""
            entry = ttk.Entry(row, width=34, show=show)
            entry.grid(row=0, column=1, sticky="we")
            entry.bind("<KeyRelease>", lambda e, k=spec.field_kind: self._on_field_change(k))
            self._entries[spec.field_kind] = entry

        left.grid_columnconfigure(1, weight=1)

        buttons = ttk.Frame(left)
        buttons.pack(anchor="w", pady=(12, 6), fill="x")

        export_btn = ttk.Button(buttons, text="Export Logs", command=self._export_logs_clicked)
        export_btn.pack(side="left", padx=(0, 10))

        decrypt_btn = ttk.Button(buttons, text="Decrypt for Authorized Viewer", command=self._decrypt_clicked)
        decrypt_btn.pack(side="left")

        # Log display
        ttk.Label(right, text="In-app log (safe representations only):").pack(anchor="w")
        self.log_text = tk.Text(right, height=18, wrap="word")
        self.log_text.pack(fill="both", expand=True, pady=(6, 0))
        self.log_text.configure(state="disabled")

        # Admin notifications for unauthorized decrypt attempts.
        ttk.Label(right, text="Admin Notifications:").pack(anchor="w")
        self.admin_alert_text = tk.Text(right, height=8, wrap="word")
        self.admin_alert_text.pack(fill="x", pady=(6, 0))
        self.admin_alert_text.configure(state="disabled")

        hint = ttk.Label(
            self.root,
            text="Typing in these fields triggers detection + safe logging. Use Export/Decrypt for encrypted file operations.",
        )
        hint.pack(anchor="w", padx=12, pady=(8, 0))

    def _append_log(self, record: Dict[str, Any]) -> None:
        self.records.append(record)
        # Keep the UI responsive by limiting memory growth in demos.
        if len(self.records) > 2000:
            self.records = self.records[-2000:]

        line = format_record_for_display(record)
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _append_admin_alert(self, line: str) -> None:
        self.admin_alert_text.configure(state="normal")
        self.admin_alert_text.insert("end", line + "\n")
        self.admin_alert_text.see("end")
        self.admin_alert_text.configure(state="disabled")

    def _on_field_change(self, field_kind: str) -> None:
        entry = self._entries.get(field_kind)
        if entry is None:
            return
        # For password/OTP: log each key event to the in-app box without reading plaintext.
        # Length comes from widget indices only; payload is Fernet-encrypted (no raw secret in the log).
        if field_kind in {"password", "otp"}:
            try:
                length = int(entry.index(tk.END))
            except Exception:
                length = 0
            if length <= 0:
                return

            ts = _utc_now_iso()
            payload_obj = {"field": field_kind, "length": length, "t": ts}
            payload_bytes = json.dumps(payload_obj, separators=(",", ":")).encode("utf-8")
            ct = self._audit_fernet.encrypt(payload_bytes)
            record = {
                "timestamp": ts,
                "field_name": field_kind,
                "sensitivity_classification": field_kind,
                "protection_method": "encrypted_inline",
                "protected_value": {
                    "length": length,
                    "ciphertext_b64": ct.decode("ascii"),
                },
            }
            self._append_log(record)
            return

        raw_value = entry.get()
        if raw_value is None or raw_value == "":
            return

        # Detector is based on field kind + content patterns; it does not capture key events globally.
        det: DetectionResult = classify_value(raw_value, field_kind)

        # Protect sensitive values immediately so plaintext is never stored in the in-app log.
        protection_method, protected_value = crypto_utils.protect_sensitive_value(
            raw_value, det.sensitivity_classification
        )

        record: Dict[str, Any] = {
            "timestamp": _utc_now_iso(),
            "field_name": field_kind,
            "sensitivity_classification": det.sensitivity_classification,
            "protection_method": protection_method,
            "protected_value": protected_value,
        }

        # Best-effort: drop the plaintext variable as soon as possible.
        try:
            raw_value = ""  # noqa: F841 (intentional; best-effort only)
        except Exception:
            pass
        self._append_log(record)

    def _export_logs_clicked(self) -> None:
        if not self.records:
            messagebox.showinfo("Export Logs", "No log records to export yet.")
            return

        output_path = filedialog.asksaveasfilename(
            title="Save encrypted log file",
            defaultextension=".elog",
            filetypes=[("Encrypted log file", "*.elog"), ("All files", "*.*")],
        )
        if not output_path:
            return

        passphrase = simpledialog.askstring(
            "Export passphrase",
            "Enter a local passphrase to encrypt the exported log file:",
            show="*",
            parent=self.root,
        )
        if not passphrase:
            messagebox.showwarning("Export Logs", "Passphrase is required.")
            return

        try:
            export_encrypted_logs(self.records, output_path, passphrase)
        except Exception as e:
            messagebox.showerror("Export Logs", f"Export failed: {e}")
            return

        messagebox.showinfo(
            "Export Complete",
            f"Encrypted log exported successfully.\n\nFile:\n{output_path}",
        )

    def _decrypt_clicked(self) -> None:
        input_path = filedialog.askopenfilename(
            title="Select encrypted log file",
            filetypes=[("Encrypted log file", "*.elog"), ("All files", "*.*")],
        )
        if not input_path:
            return

        passphrase = simpledialog.askstring(
            "Decrypt passphrase",
            "Enter the passphrase that was used to encrypt this file:",
            show="*",
            parent=self.root,
        )
        if not passphrase:
            messagebox.showwarning("Decrypt", "Passphrase is required.")
            return

        try:
            payload = decrypt_encrypted_logs(input_path, passphrase)
        except Exception as e:
            if isinstance(e, InvalidToken):
                # Wrong passphrase (unauthorized decrypt attempt).
                report, ok, detail = report_unauthorized_decrypt_attempt(input_path=input_path, exc=e)
                self._append_admin_alert(
                    f"{report['timestamp_utc']} | unauthorized_decrypt_attempt | file={report['file']['name']} | report_id={report['report_id']} | admin_report={'ok' if ok else 'failed'}({detail})"
                )
                messagebox.showerror("Decrypt Failed", "Could not decrypt file. Invalid passphrase.")
                return

            messagebox.showerror("Decrypt Failed", f"Could not decrypt file.")
            return

        # Show decrypted (authorized) view inside the app. No plaintext is written to disk.
        decrypted_window = tk.Toplevel(self.root)
        decrypted_window.title("Decrypted Log Viewer (Authorized)")
        decrypted_window.geometry("900x600")

        banner = ttk.Label(decrypted_window, text=BANNER_TEXT, foreground="#b00020", font=("TkDefaultFont", 10, "bold"))
        banner.pack(anchor="w", padx=12, pady=(12, 8))

        txt = tk.Text(decrypted_window, wrap="word")
        txt.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        txt.insert("end", json.dumps(payload, indent=2, ensure_ascii=False))
        txt.configure(state="disabled")


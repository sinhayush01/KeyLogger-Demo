import argparse
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from crypto_utils import mask_by_length, protect_sensitive_value
from exporter import export_encrypted_logs
from ui import SecureInputLoggerApp


DEFAULT_SAMPLE_PASSPHRASE = "demo-viewer-passphrase"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_sample_records() -> List[Dict[str, Any]]:
    # Sample values are for demonstration only.
    records: List[Dict[str, Any]] = []

    # Non-sensitive: username
    protection_method, protected_value = protect_sensitive_value("alice", "none")
    records.append(
        {
            "timestamp": _utc_now_iso(),
            "field_name": "username",
            "sensitivity_classification": "none",
            "protection_method": protection_method,
            "protected_value": protected_value,
        }
    )

    # Sensitive: password
    records.append(
        {
            "timestamp": _utc_now_iso(),
            "field_name": "password",
            "sensitivity_classification": "password",
            "protection_method": "masked",
            "protected_value": {"masked": mask_by_length(12, mask_char="•")},
        }
    )

    # Sensitive: email
    protection_method, protected_value = protect_sensitive_value("bob@example.com", "email")
    records.append(
        {
            "timestamp": _utc_now_iso(),
            "field_name": "email",
            "sensitivity_classification": "email",
            "protection_method": protection_method,
            "protected_value": protected_value,
        }
    )

    # Sensitive: OTP
    records.append(
        {
            "timestamp": _utc_now_iso(),
            "field_name": "otp",
            "sensitivity_classification": "otp",
            "protection_method": "masked",
            "protected_value": {"masked": mask_by_length(6, mask_char="•")},
        }
    )

    # Sensitive: credit card-like sequence (will be masked if you detect it in-app;
    # here we model it directly as a sensitive classification for the sample.)
    records.append(
        {
            "timestamp": _utc_now_iso(),
            "field_name": "generic",
            "sensitivity_classification": "credit_card",
            "protection_method": "masked",
            "protected_value": {"masked": mask_by_length(16, mask_char="•")},
        }
    )

    # Sensitive: API token-like string (salted hash in this demo).
    protection_method, protected_value = protect_sensitive_value("sk-demo-1234567890ABCdefGHijKLMnopQRstuV", "api_token")
    records.append(
        {
            "timestamp": _utc_now_iso(),
            "field_name": "generic",
            "sensitivity_classification": "api_token",
            "protection_method": protection_method,
            "protected_value": protected_value,
        }
    )

    return records


def generate_sample(output_path: str, passphrase: str) -> None:
    sample_records = build_sample_records()
    export_encrypted_logs(sample_records, output_path, passphrase)


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure Input Logger Demo")
    parser.add_argument("--generate-sample", action="store_true", help="Generate a sample encrypted .elog file.")
    parser.add_argument("--sample-out", default="", help="Output path for generated sample .elog file.")
    parser.add_argument("--passphrase", default=DEFAULT_SAMPLE_PASSPHRASE, help="Passphrase for sample generation.")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    if args.generate_sample:
        out_path = args.sample_out or os.path.join(base_dir, "sample_logs", "sample.encrypted.elog")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        generate_sample(out_path, args.passphrase)
        print(f"Sample encrypted log generated:\n{out_path}\nPassphrase: {args.passphrase}")
        return

    import tkinter as tk

    root = tk.Tk()
    app = SecureInputLoggerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()


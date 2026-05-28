import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

import pikepdf


SYMBOLS = r'[!@#$%^&*(),.?":{}|<>]'
RECOVERY_MARKER = b"\n%LOCKITPDF_RECOVERY "


def is_strong_password(pwd: str) -> bool:
    return (
        len(pwd) >= 8
        and re.search(r"[A-Z]", pwd)
        and re.search(r"[a-z]", pwd)
        and re.search(r"\d", pwd)
        and re.search(SYMBOLS, pwd)
    )


def _safe_output_name(file_path: str) -> str:
    return "protected_" + Path(file_path).name.replace("\\", "_").replace("/", "_")


def _write_zip(paths, output_path):
    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        for path in paths:
            zipf.write(path, Path(path).name)


def _normalize_recovery_data(recovery_data):
    if isinstance(recovery_data, dict):
        items = recovery_data.items()
    elif isinstance(recovery_data, list):
        items = []
        for entry in recovery_data:
            if isinstance(entry, dict):
                question = entry.get("question") or entry.get("q")
                answer = entry.get("answer") or entry.get("a")
                items.append((question, answer))
            elif isinstance(entry, (list, tuple)) and len(entry) >= 2:
                items.append((entry[0], entry[1]))
    else:
        items = []

    normalized = []
    for question, answer in items:
        question = str(question or "").strip()
        answer = str(answer or "").strip()
        if question and answer:
            normalized.append((question, answer))

    if not normalized:
        raise ValueError("Add at least one recovery question and answer.")

    return normalized


def encrypt_pdfs_regular(file_paths, encrypt_pwd, output_path):
    if not is_strong_password(encrypt_pwd):
        raise ValueError(
            "Weak password. Use at least 8 characters, including uppercase, lowercase, number, and symbol."
        )

    with tempfile.TemporaryDirectory() as temp_dir:
        encrypted_files = []
        for file_path in file_paths:
            with pikepdf.open(file_path) as pdf:
                target = os.path.join(temp_dir, _safe_output_name(file_path))
                pdf.save(
                    target,
                    encryption=pikepdf.Encryption(
                        user=encrypt_pwd,
                        owner=encrypt_pwd,
                        R=6,
                        allow=pikepdf.Permissions(extract=False),
                    ),
                )
            encrypted_files.append(target)

        if len(encrypted_files) > 1:
            _write_zip(encrypted_files, output_path)
        else:
            shutil.copyfile(encrypted_files[0], output_path)


def encrypt_pdfs_with_recovery(file_paths, encrypt_pwd, recovery_data, output_path):
    if not is_strong_password(encrypt_pwd):
        raise ValueError(
            "Weak password. Use at least 8 characters, including uppercase, lowercase, number, and symbol."
        )

    recovery_items = _normalize_recovery_data(recovery_data)

    with tempfile.TemporaryDirectory() as temp_dir:
        encrypted_files = []
        for file_path in file_paths:
            target = os.path.join(temp_dir, _safe_output_name(file_path))
            recovery_payload = {
                "questions": [
                    {
                        "question": question,
                        "answer_hash": hashlib.sha256(answer.strip().lower().encode("utf-8")).hexdigest(),
                    }
                    for question, answer in recovery_items
                ],
                "password": base64.b64encode(encrypt_pwd.encode("utf-8")).decode("ascii"),
            }
            with pikepdf.open(file_path) as pdf:
                pdf.docinfo["/LockItPDFRecoveryEnabled"] = "true"
                pdf.docinfo["/LockItPDFRecoveryData"] = base64.b64encode(
                    json.dumps(recovery_payload).encode("utf-8")
                ).decode("ascii")
                for question, answer in recovery_items:
                    key = "/" + re.sub(r"[^A-Za-z0-9]+", "", question)[:60]
                    if key == "/":
                        continue
                    pdf.docinfo[key] = hashlib.sha256(answer.strip().lower().encode("utf-8")).hexdigest()
                pdf.docinfo["/RecoveryPassword"] = base64.b64encode(encrypt_pwd.encode("utf-8")).decode("ascii")
                pdf.save(
                    target,
                    encryption=pikepdf.Encryption(
                        user=encrypt_pwd,
                        owner=encrypt_pwd,
                        R=6,
                        metadata=False,
                        allow=pikepdf.Permissions(extract=False),
                    ),
                )
            with open(target, "ab") as encrypted_pdf:
                encrypted_pdf.write(RECOVERY_MARKER)
                encrypted_pdf.write(
                    base64.b64encode(json.dumps(recovery_payload).encode("utf-8"))
                )
                encrypted_pdf.write(b"\n")
            encrypted_files.append(target)

        if len(encrypted_files) > 1:
            _write_zip(encrypted_files, output_path)
        else:
            shutil.copyfile(encrypted_files[0], output_path)


def recover_password(pdf_path, recovery_answers):
    try:
        with pikepdf.open(pdf_path, password="") as pdf:
            meta = pdf.docinfo
            for question, answer in recovery_answers.items():
                key = "/" + re.sub(r"[^A-Za-z0-9]+", "", question)[:60]
                stored_hash = meta.get(key)
                if not stored_hash or str(stored_hash) != hashlib.sha256(answer.encode("utf-8")).hexdigest():
                    return "Recovery failed: incorrect answers."
            return str(meta.get("/RecoveryPassword", "No recovery password stored."))
    except Exception as exc:
        return f"Error: {exc}"


def main():
    parser = argparse.ArgumentParser(description="LockItPDF encryption backend")
    parser.add_argument("--mode", choices=["regular", "recovery"], required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--recovery-json", default="{}")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()

    try:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        if args.mode == "regular":
            encrypt_pdfs_regular(args.files, args.password, str(output))
        else:
            recovery_data = json.loads(args.recovery_json)
            encrypt_pdfs_with_recovery(args.files, args.password, recovery_data, str(output))
        print(json.dumps({"ok": True, "output": str(output)}))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

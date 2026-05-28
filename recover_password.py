import argparse
import base64
import hashlib
import json
import sys

RECOVERY_MARKER = b"%LOCKITPDF_RECOVERY "


def _load_payload(pdf_path):
    data = open(pdf_path, "rb").read()
    marker_at = data.rfind(RECOVERY_MARKER)
    if marker_at != -1:
        start = marker_at + len(RECOVERY_MARKER)
        end = data.find(b"\n", start)
        if end == -1:
            end = len(data)
        return json.loads(base64.b64decode(data[start:end]).decode("utf-8"))

    raise ValueError(
        "This PDF was not encrypted with the LockItPDF recovery option. "
        "Only PDFs created with 'Encrypt PDFs with Recovery Option' can be recovered here."
    )


def questions(pdf_path):
    payload = _load_payload(pdf_path)
    return [item["question"] for item in payload.get("questions", [])]


def recover(pdf_path, answers):
    payload = _load_payload(pdf_path)
    expected = payload.get("questions", [])
    if len(answers) != len(expected):
        raise ValueError("Answer count does not match the recovery questions.")

    for index, item in enumerate(expected):
        supplied = hashlib.sha256(answers[index].strip().lower().encode("utf-8")).hexdigest()
        if supplied != item.get("answer_hash"):
            raise ValueError("Recovery failed: incorrect answers.")

    return base64.b64decode(payload["password"]).decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="Recover a LockItPDF password")
    parser.add_argument("--pdf", required=True)
    parser.add_argument("--answers-json", default=None)
    args = parser.parse_args()

    try:
        if args.answers_json is None:
            print(json.dumps({"ok": True, "questions": questions(args.pdf)}))
        else:
            answers = json.loads(args.answers_json)
            print(json.dumps({"ok": True, "password": recover(args.pdf, answers)}))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

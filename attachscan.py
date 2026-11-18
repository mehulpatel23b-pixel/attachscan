#!/usr/bin/env python3
"""attachscan - triage the attachments in a reported phishing email.

A user forwards you a mail with `Invoice_2026.pdf.exe`, a password-protected zip or an
HTML file that rebuilds a Windows executable in the browser. Opening it on a workstation
is how incidents start.

attachscan inspects the bytes, never executes anything, and reports what the file really is.

Zero dependencies. Pure standard library. No network, never opens the file.
"""

from __future__ import annotations

import argparse
import email
import io
import json
import os
import re
import sys
import zipfile

__version__ = "1.0.0"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_WEIGHT = {"critical": 40, "high": 22, "medium": 10, "low": 4, "info": 0}
GRADES = [(10, "A"), (25, "B"), (45, "C"), (65, "D"), (85, "E"), (999, "F")]

EXECUTABLE_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "cpl", "hta", "hTA".lower(),
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "ps1xml", "psm1", "reg", "lnk", "url",
    "jar", "xll", "xlam", "one", "iso", "img", "vhd", "vhdx", "chm", "application", "gadget",
    "msc", "scf", "inf",
}

MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"}

ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "bz2", "xz", "cab", "arj", "ace", "lzh", "iso", "img"}

OFFICE_EXT = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "odt"}

TEXT_EXT = {"txt", "csv", "htm", "html", "svg", "xml", "eml", "msg", "md", "log", "json", "js", "vbs", "ps1", "bat", "cmd", "hta"}

SIGNATURES = (
    (b"MZ", "PE executable"),
    (b"\x7fELF", "ELF executable"),
    (b"PK\x03\x04", "zip container (OOXML or archive)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document (legacy Office)"),
    (b"%PDF", "PDF document"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"\x1f\x8b", "gzip stream"),
    (b"MSCF", "CAB archive"),
    (b"\xca\xfe\xba\xbe", "Mach-O binary or Java class"),
    (b"SQLite format 3", "SQLite database"),
)

URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
SMUGGLING_MARKERS = ("atob(", "blob(", "mssaveblob", "createobjecturl", "download=", "application/octet-stream")
OBFUSCATION_MARKERS = ("eval(", "unescape(", "string.fromcharcode", "activexobject", "wscript.shell",
                       "powershell", "frombase64string", "mshta", "certutil", "bitsadmin")
LNK_PAYLOAD_MARKERS = ("powershell", "cmd.exe", "wscript", "mshta", "rundll32", "http://", "https://")


class ScanError(Exception):
    """Raised when an input cannot be read."""


def extensions(name):
    """All lower-case extensions, so `invoice.pdf.exe` yields ['pdf', 'exe']."""
    base = os.path.basename(name or "")
    parts = base.split(".")
    if len(parts) <= 1:
        return []
    return [p.lower() for p in parts[1:] if p]


def sniff(data):
    for signature, label in SIGNATURES:
        if data.startswith(signature):
            return label
    return ""


def printable_ratio(data, sample=4096):
    chunk = data[:sample]
    if not chunk:
        return 0.0
    text = sum(1 for byte in chunk if 32 <= byte < 127 or byte in (9, 10, 13))
    return text / float(len(chunk))


def is_probably_text(data):
    return printable_ratio(data) > 0.90


def inspect_zip(data):
    """Return (entry names, encrypted?, nested dangerous entries)."""
    names, encrypted, nested = [], False, []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                names.append(info.filename)
                if info.flag_bits & 0x1:
                    encrypted = True
                ext = extensions(info.filename)
                if ext and ext[-1] in EXECUTABLE_EXT:
                    nested.append(info.filename)
    except (zipfile.BadZipFile, RuntimeError, OSError, ValueError):
        return [], False, []
    if any(name.lower().endswith("vbaproject.bin") for name in names):
        nested.append("vbaProject.bin")
    return names, encrypted, nested


def scan_bytes(name, data):
    """Return findings for one file, given its display name and bytes."""
    found = []
    exts = extensions(name)
    final_ext = exts[-1] if exts else ""
    detected = sniff(data)

    def add(sev, code, detail, fix):
        found.append({"severity": sev, "code": code, "file": name, "detail": detail, "fix": fix})

    if final_ext in EXECUTABLE_EXT:
        add("critical", "AS-EXECUTABLE",
            "delivered with a %s file, which runs code or launches a payload" % final_ext.upper(),
            "Strip the attachment at the gateway. Never release executables to a user.")
    if len(exts) >= 2 and exts[-1] in EXECUTABLE_EXT and exts[-2] in (OFFICE_EXT | {"pdf", "txt", "jpg", "png", "doc"}):
        add("critical", "AS-DOUBLE-EXTENSION",
            "double extension %s: the visible type is %s, the real one is %s"
            % (name, exts[-2], exts[-1]),
            "The extension Windows uses is the last one. This is deliberate disguise.")
    if final_ext in MACRO_EXT:
        add("high", "AS-MACRO-EXTENSION",
            "macro-enabled Office format (.%s)" % final_ext,
            "Macros in a mail attachment are almost never legitimate. Block the format.")
    detected_lower = detected.lower()
    executable_content = any(word in detected_lower for word in ("executable", "mach-o", "java class", "ole compound"))
    if executable_content and final_ext not in EXECUTABLE_EXT and final_ext not in OFFICE_EXT:
        add("high", "AS-MAGIC-MISMATCH",
            "content is a %s but the file claims to be .%s" % (detected, final_ext or "unknown"),
            "Trust the bytes, not the name. Quarantine and check how it got through.")
    if detected.startswith("zip container") and final_ext in ("docx", "xlsx", "pptx", "zip", ""):
        names, encrypted, nested = inspect_zip(data)
        if encrypted:
            add("high", "AS-ENCRYPTED-ARCHIVE",
                "archive is password protected, so gateway scanning cannot see inside",
                "Refuse password-protected archives in mail. Attackers use the password as an evasion layer.")
        macro_payload = [n for n in nested if n.lower().endswith("vbaproject.bin")]
        if macro_payload and final_ext in ("docx", "xlsx", "pptx"):
            add("high", "AS-MACRO-EMBEDDED",
                "OOXML container holds a VBA project, which the plain extension does not admit",
                "Treat as macro malware: block or hand to the sandbox.")
        payloads = [n for n in nested if n.lower() not in ("vbaproject.bin",)]
        if payloads:
            add("high", "AS-NESTED-PAYLOAD",
                "archive contains runnable entries: %s" % ", ".join(payloads[:4]),
                "Recursive delivery: the archive is a wrapper for an executable.")
    if final_ext in ("html", "htm", "svg") and is_probably_text(data):
        body = data.decode("utf-8", "replace").lower()
        hits = [marker for marker in SMUGGLING_MARKERS if marker in body]
        if len(hits) >= 2:
            add("high", "AS-HTML-SMUGGLING",
                "page rebuilds a file in the browser (%s), the usual way to smuggle a binary past mail filters"
                % ", ".join(sorted(set(hits))[:4]),
                "Block .html and .svg attachments, or open them only in a detonating sandbox.")
    if final_ext in ("js", "jse", "vbs", "vbe", "wsf", "ps1", "hta", "bat", "cmd"):
        body = data.decode("utf-8", "replace").lower()
        hits = [marker for marker in OBFUSCATION_MARKERS if marker in body]
        if hits:
            add("high", "AS-SCRIPT-PAYLOAD",
                "script contains execution or download primitives: %s" % ", ".join(sorted(set(hits))[:5]),
                "Script attachments are payloads. Do not open; submit to the sandbox.")
    if final_ext == "lnk":
        body = data.lower()
        hits = [marker.encode() for marker in LNK_PAYLOAD_MARKERS if marker.encode() in body]
        if hits:
            add("critical", "AS-LNK-PAYLOAD",
                "shortcut file carries a command or URL, the standard first-stage payload",
                "LNK files in email are malicious by default. Block the extension.")
    if is_probably_text(data) and len(data) < 2_000_000:
        body = data.decode("utf-8", "replace")
        urls = URL_RE.findall(body)
        if urls:
            add("medium" if final_ext in ("html", "htm", "svg", "eml") else "low", "AS-EMBEDDED-URLS",
                "%d embedded link(s), first: %s" % (len(urls), urls[0][:80]),
                "Check each destination against your proxy logs before anyone clicks.")
    if final_ext in ARCHIVE_EXT and not detected.startswith("zip container") and final_ext == "zip":
        add("low", "AS-BROKEN-ARCHIVE", "archive header is not a valid zip", "Inspect manually, it may be truncated or fake.")
    return found


def scan_path(path, max_bytes=64 * 1024 * 1024):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            data = handle.read(max_bytes)
    except OSError as exc:
        raise ScanError("%s: %s" % (path, exc)) from exc
    findings = scan_bytes(os.path.basename(path), data)
    return {"file": os.path.basename(path), "path": path, "size": size,
            "type": sniff(data) or ("text" if is_probably_text(data) else "unknown"),
            "findings": findings}


def iterate_paths(paths):
    for path in paths:
        if os.path.isdir(path):
            for root, _dirs, files in os.walk(path):
                for name in sorted(files):
                    yield os.path.join(root, name)
        elif os.path.isfile(path):
            yield path
        else:
            raise ScanError("%s: no such file or directory" % path)


def read_eml(path):
    try:
        with open(path, "rb") as handle:
            message = email.message_from_bytes(handle.read())
    except OSError as exc:
        raise ScanError("%s: %s" % (path, exc)) from exc
    attachments, subject = [], message.get("Subject", "") or ""
    for part in message.walk():
        name = part.get_filename()
        payload = part.get_payload(decode=True) if not part.is_multipart() else None
        if name:
            attachments.append((name, payload or b""))
    return subject, attachments


def score(findings):
    total = min(100, sum(SEVERITY_WEIGHT[f["severity"]] for f in findings))
    return total, next(g for threshold, g in GRADES if total <= threshold)


def build_report(results, errors=None):
    findings = [f for result in results for f in result["findings"]]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"]))
    risk, grade = score(findings)
    counts = {sev: sum(1 for f in findings if f["severity"] == sev)
              for sev in ("critical", "high", "medium", "low", "info")}
    return {
        "summary": {
            "files": len(results),
            "flags": len(findings),
            "risk": risk,
            "grade": grade,
            "counts": counts,
            "gate": "FAIL" if counts["critical"] or counts["high"] else "PASS",
        },
        "files": results,
        "findings": findings,
        **({"errors": errors} if errors else {}),
    }


def render(payload):
    s, lines = payload["summary"], []
    lines.append("attachscan %s" % __version__)
    lines.append("files   : %d   findings: %d  (critical %d, high %d, medium %d)"
                 % (s["files"], s["flags"], s["counts"]["critical"], s["counts"]["high"], s["counts"]["medium"]))
    lines.append("risk    : %d/100  grade %s  gate %s" % (s["risk"], s["grade"], s["gate"]))
    lines.append("")
    lines.append("%-26s %-8s %-24s %s" % ("FILE", "SEVERITY", "RULE", "DETAIL"))
    lines.append("-" * 108)
    for f in payload["findings"]:
        lines.append("%-26s %-8s %-24s %s"
                     % (f["file"][:26], f["severity"].upper(), f["code"], f["detail"]))
    if not payload["findings"]:
        lines.append("no findings: every attachment is inert")
    else:
        lines.append("")
        lines.append("fixes")
        lines.append("-" * 108)
        for f in payload["findings"]:
            if f["severity"] in ("critical", "high"):
                lines.append("[%s] %s  %s" % (f["severity"][:4].upper(), f["code"], f["file"]))
                lines.append("      %s" % f["fix"])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="attachscan",
        description="Triage email attachments before anyone opens them.")
    parser.add_argument("paths", nargs="*", help="files or directories to inspect")
    parser.add_argument("--eml", action="append", default=[], help="raw .eml file to extract attachments from (repeatable)")
    parser.add_argument("--max-mb", type=float, default=64.0, help="largest file to read, in MB (default 64)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "low", "info", "none"],
                        help="lowest severity that fails the run (default high)")
    parser.add_argument("--version", action="version", version="attachscan " + __version__)
    args = parser.parse_args(argv)

    if not args.paths and not args.eml:
        parser.print_usage(sys.stderr)
        sys.stderr.write("attachscan: give a file, a directory, or --eml FILE\n")
        return 2

    results, errors = [], []
    limit = int(args.max_mb * 1024 * 1024)
    try:
        for path in iterate_paths(args.paths):
            try:
                results.append(scan_path(path, max_bytes=limit))
            except ScanError as exc:
                errors.append(str(exc))
    except ScanError as exc:
        errors.append(str(exc))

    for path in args.eml:
        try:
            subject, attachments = read_eml(path)
        except ScanError as exc:
            errors.append(str(exc))
            continue
        for name, data in attachments:
            findings = scan_bytes(name, data)
            results.append({"file": name, "path": path, "size": len(data),
                            "type": sniff(data) or "unknown", "findings": findings,
                            "source": "eml", "subject": subject})

    if not results and errors:
        for err in errors:
            sys.stderr.write("attachscan: %s\n" % err)
        return 2

    payload = build_report(results, errors or None)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render(payload))
        for err in errors:
            print("warning: %s" % err, file=sys.stderr)

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f["severity"]] <= threshold for f in payload["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())

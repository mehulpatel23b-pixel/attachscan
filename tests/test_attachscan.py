"""Tests for attachscan. Run: python3 -m pytest -q  (nothing is executed, no network)"""

import io
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attachscan as ats  # noqa: E402


def zip_bytes(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def encrypted_zip_bytes(entries):
    raw = bytearray(zip_bytes(entries))
    for marker, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        index = 0
        while True:
            index = raw.find(marker, index)
            if index < 0:
                break
            raw[index + offset:index + offset + 2] = b"\x01\x00"
            index += 4
    return bytes(raw)


def codes_for(name, data):
    return {f["code"] for f in ats.scan_bytes(name, data)}


def test_extensions_returns_every_suffix():
    assert ats.extensions("Invoice_2026.PDF.exe") == ["pdf", "exe"]
    assert ats.extensions("notes") == []
    assert ats.extensions("archive.tar.gz") == ["tar", "gz"]


def test_executable_attachment_is_critical():
    found = ats.scan_bytes("setup.exe", b"MZ\x90\x00payload")
    assert found[0]["severity"] == "critical"
    assert "AS-EXECUTABLE" in {f["code"] for f in found}


def test_double_extension_is_flagged():
    found = ats.scan_bytes("Invoice_2026.pdf.exe", b"MZ\x90\x00")
    assert "AS-DOUBLE-EXTENSION" in {f["code"] for f in found}


def test_macro_enabled_office_extension():
    assert "AS-MACRO-EXTENSION" in codes_for("Remittance.xlsm", b"PK\x03\x04fake")


def test_magic_mismatch_between_bytes_and_name():
    found = ats.scan_bytes("receipt.pdf", b"MZ\x90\x00this is an executable")
    assert "AS-MAGIC-MISMATCH" in {f["code"] for f in found}


def test_ooxml_with_vba_project():
    data = zip_bytes({"word/document.xml": "<x/>", "word/vbaProject.bin": "macro"})
    found = codes_for("Report.docx", data)
    assert "AS-MACRO-EMBEDDED" in found


def test_nested_executable_in_archive():
    data = zip_bytes({"notes.txt": "hi", "payload.exe": "MZ"})
    assert "AS-NESTED-PAYLOAD" in codes_for("docs.zip", data)


def test_encrypted_archive_is_evasion():
    data = encrypted_zip_bytes({"invoice.pdf": "secret"})
    assert "AS-ENCRYPTED-ARCHIVE" in codes_for("secure_docs.zip", data)


def test_html_smuggling_markers():
    body = (b"<script>var b=atob('TVqQAAMAAAAEAAAA');"
            b"var blob=new Blob([b]);a.download='invoice.exe';</script>")
    found = codes_for("statement.html", body)
    assert "AS-HTML-SMUGGLING" in found


def test_script_payload_markers():
    body = b"var x=new ActiveXObject('WScript.Shell'); eval(unescape('%41'))"
    assert "AS-SCRIPT-PAYLOAD" in codes_for("update.js", body)


def test_lnk_with_command_is_critical():
    data = b"\x4c\x00\x00\x00" + b"powershell -w hidden -enc AAAA" + b"\x00" * 40
    found = ats.scan_bytes("Invoice.lnk", data)
    assert "AS-LNK-PAYLOAD" in {f["code"] for f in found}
    assert any(f["severity"] == "critical" for f in found)


def test_embedded_urls_reported():
    body = b"<a href='https://pay-secure.example/login'>click</a>"
    found = {f["code"]: f for f in ats.scan_bytes("page.html", body)}
    assert "AS-EMBEDDED-URLS" in found
    assert found["AS-EMBEDDED-URLS"]["severity"] == "medium"


def test_clean_text_file_has_no_findings():
    assert ats.scan_bytes("notes.txt", b"remember the milk\n") == []


def test_scan_path_reports_type_and_size(tmp_path):
    path = tmp_path / "clean.txt"
    path.write_text("hello", encoding="utf-8")
    result = ats.scan_path(str(path))
    assert result["file"] == "clean.txt"
    assert result["size"] == 5
    assert result["findings"] == []


def test_eml_mode_extracts_attachments(tmp_path):
    from email.message import EmailMessage

    message = EmailMessage()
    message["Subject"] = "Your invoice"
    message["From"] = "billing@example.net"
    message["To"] = "you@example.com"
    message.set_content("Please see attached.")
    message.add_attachment(b"MZ\x90\x00", maintype="application", subtype="octet-stream",
                           filename="invoice.pdf.exe")
    path = tmp_path / "phish.eml"
    path.write_bytes(bytes(message))

    subject, attachments = ats.read_eml(str(path))
    assert subject == "Your invoice"
    assert attachments and attachments[0][0] == "invoice.pdf.exe"
    assert ats.main(["--eml", str(path), "--fail-on", "high"]) == 1


def test_cli_json_and_exit_codes(tmp_path, capsys):
    bad = tmp_path / "evil.png.exe"
    bad.write_bytes(b"MZ\x90\x00")
    assert ats.main([str(bad), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["gate"] == "FAIL"
    assert payload["summary"]["grade"] in "ABCDEF"
    assert payload["findings"]

    clean = tmp_path / "notes.txt"
    clean.write_text("ok", encoding="utf-8")
    assert ats.main([str(clean)]) == 0

    directory = tmp_path / "box"
    directory.mkdir()
    (directory / "a.txt").write_text("x", encoding="utf-8")
    assert ats.main([str(directory), "--json"]) == 0


def test_cli_missing_input_and_bad_path():
    assert ats.main([]) == 2
    assert ats.main(["/nonexistent/path/file.bin"]) == 2


def test_fail_on_none_disables_gate(tmp_path):
    bad = tmp_path / "setup.scr"
    bad.write_bytes(b"MZ")
    assert ats.main([str(bad), "--fail-on", "none"]) == 0

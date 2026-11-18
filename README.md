# attachscan

**Triage the attachments in a reported phishing email without opening them.**

Users forward suspicious mail all day. The attachment is where the incident actually starts:
`Invoice_2026.pdf.exe`, a macro-laden `.xlsm`, a password-protected zip the gateway could not read,
or an HTML file that rebuilds a Windows executable in the browser.

`attachscan` reads the bytes, names what they really are, and never executes anything.

<p>
  <img src="https://img.shields.io/badge/python-3.8%2B-0d1117?style=flat-square&logo=python&logoColor=39D353" alt="python" />
  <img src="https://img.shields.io/badge/runtime%20dependencies-zero-0d1117?style=flat-square" alt="zero dependencies" />
  <img src="https://img.shields.io/badge/network-none-0d1117?style=flat-square" alt="no network" />
  <img src="https://img.shields.io/badge/executes-nothing-0d1117?style=flat-square" alt="executes nothing" />
  <img src="https://img.shields.io/badge/license-MIT-0d1117?style=flat-square" alt="MIT" />
</p>

## Why

Mail gateways already scan attachments, so the ones that reach a user are the ones the gateway
could not see: encrypted archives, double extensions that the OS resolves differently from the
scanner, HTML that reassembles a binary at runtime, and shortcut files that carry a command line.
Triage on a workstation is where these get opened by accident.

This tool answers three questions per file: what does the extension claim, what do the bytes say,
and does the difference matter.

## Install

One file, standard library only.

```bash
git clone https://github.com/mehulpatel23b-pixel/attachscan.git
cd attachscan
python3 attachscan.py --help
```

## Usage

```bash
# a folder of attachments pulled from a reported mail
python3 attachscan.py ./attachments

# straight from the raw message
python3 attachscan.py --eml examples/phish-sample.eml

# both, as JSON for your ticket system
python3 attachscan.py ./attachments --eml mail.eml --json

# pipeline gate on medium and above
python3 attachscan.py ./attachments --fail-on medium
```

Sample output:

```text
attachscan 1.0.0
files   : 1   findings: 3  (critical 2, high 1, medium 0)
risk    : 100/100  grade F  gate FAIL

FILE                       SEVERITY RULE                     DETAIL
--------------------------------------------------------------------------------------------
Invoice_2026.pdf.exe       CRITICAL AS-DOUBLE-EXTENSION      double extension: the visible type is pdf, the real one is exe
Invoice_2026.pdf.exe       CRITICAL AS-EXECUTABLE            delivered with a EXE file, which runs code or launches a payload
Invoice_2026.pdf.exe       HIGH     AS-MAGIC-MISMATCH         content is a PE executable but the file claims to be .exe
```

## Rules

| Rule | Severity | What it catches |
| :-- | :-- | :-- |
| `AS-EXECUTABLE` | critical | executable or launcher extension (`.exe .scr .hta .lnk .iso .js ...`) |
| `AS-DOUBLE-EXTENSION` | critical | a document-looking name whose real type is executable |
| `AS-LNK-PAYLOAD` | critical | shortcut carrying a command line or URL |
| `AS-MAGIC-MISMATCH` | high | bytes are a PE/ELF/Mach-O while the name says otherwise |
| `AS-MACRO-EXTENSION` | high | macro-enabled Office format |
| `AS-MACRO-EMBEDDED` | high | `vbaProject.bin` hidden inside a `.docx/.xlsx/.pptx` |
| `AS-ENCRYPTED-ARCHIVE` | high | password-protected archive that defeats gateway scanning |
| `AS-NESTED-PAYLOAD` | high | archive containing a runnable entry |
| `AS-HTML-SMUGGLING` | high | HTML that rebuilds a file in the browser (`atob`, `Blob`, `download=`) |
| `AS-SCRIPT-PAYLOAD` | high | script with `eval`, `ActiveXObject`, `certutil`, `bitsadmin` |
| `AS-EMBEDDED-URLS` | medium / low | links inside the file, newest campaign landing pages |
| `AS-BROKEN-ARCHIVE` | low | a `.zip` whose header is not a valid zip |

## Inputs

- **Files and directories.** Walks a folder recursively, so `~/Downloads` works as well as a
  single file.
- **Raw `.eml`.** Extracts each attachment from the MIME tree and scans it in memory. Nothing is
  written to disk, so a malicious sample does not land anywhere.
- **Size cap.** `--max-mb` (default 64) bounds what is read.

## Scoring and exit codes

Weights are critical 40, high 22, medium 10, low 4, capped at 100. Grade A is 0-10, B to 25,
C to 45, D to 65, E to 85, F above.

| Code | Meaning |
| :-- | :-- |
| `0` | Nothing at or above `--fail-on` (default `high`) |
| `1` | Threshold breached |
| `2` | No input, or nothing readable |

## Design

- **Never executes.** Files are read as bytes and inspected with `zipfile`, signature matching and
  regex. No shell, no Office, no interpreter.
- **Truth over names.** The extension is treated as a claim; the magic bytes are treated as evidence.
- **Zero dependencies.** `zipfile`, `email` and `re` only, so it runs on a locked-down responder host.
- **Explainable.** Every finding names the file, the reason and the action.

## Ethics

Defensive triage of mail reported to you. It writes nothing to disk from a message, sends nothing,
and does not detonate anything.

## License

MIT. See [LICENSE](LICENSE).

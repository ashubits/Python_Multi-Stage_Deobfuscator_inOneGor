# 🐍 Python Multi-Stage Deobfuscator (Tkinter GUI)

A simple, graphical tool built with Tkinter for static analysis of Python malware that employs common multi-stage obfuscation techniques involving reverse string slicing, Base64 encoding, and Zlib compression/decompression.

The tool automatically processes payloads chained in the typical format:  
`exec((_)(b'...'))`

---

## ✨ Features

- **Multi-Stage Decryption**  
  Automatically detects and loops through successive layers of reverse → Base64 → Zlib decompression.

- **Graphical Interface**  
  Uses the built-in Tkinter library for easy file browsing and clean output display.

- **Non-Executional Safety**  
  Analyzes the payload statically without ever executing the potential malicious code.

- **Final Payload Export**  
  Automatically saves the final, clear-text code to a file named `payload.txt` in the script's directory.

- **Robust Pattern Matching**  
  Includes fallback logic to find encoded payloads, even if the surrounding Python structure is slightly malformed or missing.

---

## 💻 Dependencies

This tool uses only standard Python libraries:

- Python 3.6+
- `base64`
- `zlib`
- `re` (Regular Expressions)
- `tkinter` (Standard GUI library)
- `os`

> No external `pip install` commands are required if you have a standard Python installation.

---

## 🛠️ Usage Manual

Follow these steps to analyze an obfuscated Python script:

### 1. Prepare the Script

- Save the provided deobfuscator code as a Python file (e.g., `deobfuscator.py`).
- Ensure the obfuscated Python code you want to analyze (the one-liner) is saved in a separate text file (e.g., `malware_input.txt`).

### 2. Run the Tool

Open your terminal or command prompt and run the script:

```bash
python deobfuscator.py

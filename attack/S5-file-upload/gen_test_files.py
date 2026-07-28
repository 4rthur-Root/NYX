"""Génère des fichiers test avec signatures YARA détectables."""

import os

OUTPUT = os.path.join(os.path.dirname(__file__), "payloads")
os.makedirs(OUTPUT, exist_ok=True)

FILES = [
    {
        "name": "facture_2026-07.pdf",
        "patterns": [
            "main.rc4EncryptDecrypt",
            "main.processFile",
        ],
    },
    {
        "name": "note_interne.docm",
        "patterns": [
            "NtQueryInformationThread",
            "StackWalk64",
        ],
    },
    {
        "name": "rapport_financier.xls",
        "patterns": [
            "/Client/Login?id=",
            "Microsoft.CSharp",
            "StrReverse",
        ],
    },
    {
        "name": "mise_a_jour_critique.exe",
        "patterns": [
            "You will receive decrypting key after the payment.",
            "Go build",
        ],
    },
]

def main():
    for entry in FILES:
        path = os.path.join(OUTPUT, entry["name"])
        content = "\r\n".join(entry["patterns"])
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        size = os.path.getsize(path)
        print(f"  {entry['name']:45s} {size:3d} bytes — patterns: {', '.join(entry['patterns'])}")
    print(f"\n{len(FILES)} fichiers générés dans {OUTPUT}/")

if __name__ == "__main__":
    main()

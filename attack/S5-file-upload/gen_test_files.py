"""Génère des fichiers test avec signatures YARA détectables.

Chaque fichier est un exécutable PE déguisé (extension anodine, header MZ).
Les patterns YARA sont placés après le header — les règles SUSP_*/MAL_*
vérifient uint16(0) == 0x5a4d puis recherchent leurs chaînes.
"""

import os

OUTPUT = os.path.join(os.path.dirname(__file__), "payloads")
os.makedirs(OUTPUT, exist_ok=True)

MZ_HEADER = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"

FILES = [
    {
        "name": "facture_2026-07.pdf",
        "target": "MAL_Sindoor_Decryptor_Aug25",
        "patterns": [
            "Go build",
            "main.rc4EncryptDecrypt",
            "main.processFile",
            "main.deriveKeyAES",
            "use RC4 instead of AES",
        ],
    },
    {
        "name": "note_interne.docm",
        "target": "SUSP_NET_Msil_Suspicious_Use_StrReverse",
        "patterns": [
            ", PublicKeyToken=",
            ".NETFramework,Version=",
            "Microsoft.CSharp",
            "Microsoft.VisualBasic",
            "StrReverse",
        ],
    },
    {
        "name": "rapport_financier.xls",
        "target": "MAL_DNSPIONAGE_Malware_Nov18",
        "patterns": [
            ".0ffice36o.com",
            "/Client/Login?id=",
        ],
    },
    {
        "name": "mise_a_jour_critique.exe",
        "target": "MAL_RANSOM_DarkBit_Feb23_1",
        "patterns": [
            "You will receive decrypting key after the payment.",
            "Go build",
            "C:/updatescheck/main.go",
        ],
    },
]


def main():
    for entry in FILES:
        path = os.path.join(OUTPUT, entry["name"])
        payload = "\r\n".join(entry["patterns"]).encode("utf-8")
        data = MZ_HEADER + payload
        with open(path, "wb") as f:
            f.write(data)
        print(f"  {entry['name']:45s} {len(data):3d} bytes — patterns: {', '.join(entry['patterns'])}")
    print(f"\n{len(FILES)} fichiers générés dans {OUTPUT}/")


if __name__ == "__main__":
    main()

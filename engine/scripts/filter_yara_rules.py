import re
import sys
from pathlib import Path

SIG_BASE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/signature-base")
OUTPUT = Path("engine/rules/yara")
OUTPUT.mkdir(parents=True, exist_ok=True)

def is_pe_rule(name: str, body: str) -> bool:
    name_upper = name.upper()
    if any(x in name_upper for x in ["WIN", "PE", "DLL", "EXE", "MALWARE"]):
        return True
    if "uint16(0) == 0x5a4d" in body or "uint16(0)==0x5a4d" in body:
        return True
    tag_m = re.match(r"\S+\s*:\s*([^:{]+)", body)
    if tag_m:
        tags = tag_m.group(1).upper().split()
        if any(t in ["PE", "WIN", "DLL", "EXE"] for t in tags):
            return True
    return False

filtered = []

for yar_file in sorted((SIG_BASE / "yara").glob("*.yar")):
    content = yar_file.read_text(encoding="utf-8", errors="replace")
    parts = re.split(r"^rule\s+", content, flags=re.MULTILINE)
    for part in parts[1:]:
        name = part.split("{")[0].strip().split()[0] if "{" in part else part.strip().split()[0]
        body = part
        if not (name.startswith("SUSP_") or name.startswith("MAL_")):
            continue
        if not is_pe_rule(name, body):
            continue
        filtered.append(f"rule {name}{body}")

OUTPUT.mkdir(parents=True, exist_ok=True)
out_path = OUTPUT / "susp_mal_pe.yar"
out_path.write_text("\n\n".join(filtered), encoding="utf-8")
print(f"Écrit {len(filtered)} règles dans {out_path}")

# Clean up old test.yar
old = OUTPUT / "test.yar"
if old.exists():
    old.unlink()
    print("Supprimé test.yar")

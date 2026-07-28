import re
import sys
from pathlib import Path

SIG_BASE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/signature-base")
OUTPUT = Path("engine/rules/yara")
OUTPUT.mkdir(parents=True, exist_ok=True)


def is_pe_rule(name: str, full_part: str) -> bool:
    name_upper = name.upper()
    if any(x in name_upper for x in ["WIN", "PE", "DLL", "EXE", "MALWARE"]):
        return True
    if "uint16(0) == 0x5a4d" in full_part or "uint16(0)==0x5a4d" in full_part:
        return True
    # Tags are on the declaration line before the opening brace
    tag_m = re.match(r"\S+\s*:\s*([^:{]+)", full_part)
    if tag_m:
        tags = tag_m.group(1).upper().split()
        if any(t in ["PE", "WIN", "DLL", "EXE"] for t in tags):
            return True
    return False


filtered = []

for yar_file in sorted((SIG_BASE / "yara").glob("*.yar")):
    content = yar_file.read_text(encoding="utf-8", errors="replace")
    # Strip C-style comments /* ... */ — they may wrap commented-out rules
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    parts = re.split(r"^rule\s+", content, flags=re.MULTILINE)
    for part in parts[1:]:
        if "{" not in part:
            continue
        # The split removed "rule ", so part starts with the rule name
        brace_pos = part.index("{")
        decl = part[:brace_pos].strip()
        name = decl.split()[0].split(":")[0]
        if not (name.startswith("SUSP_") or name.startswith("MAL_")):
            continue
        if not is_pe_rule(name, part):
            continue
        # Skip rules with environment-specific identifiers (Thor extensions)
        if re.search(r'\b(filename|extension|filepath|filetype)\b', part):
            continue
        body = part[brace_pos:]
        filtered.append(f"rule {decl} {body}")

OUTPUT.mkdir(parents=True, exist_ok=True)
out_path = OUTPUT / "susp_mal_pe.yar"
header = 'import "pe"\n\n'
out_path.write_text(header + "\n\n".join(filtered), encoding="utf-8")
print(f"Écrit {len(filtered)} règles dans {out_path}")

old = OUTPUT / "test.yar"
if old.exists():
    old.unlink()
    print("Supprimé test.yar")

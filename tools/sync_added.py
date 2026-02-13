#!/usr/bin/env python3
import re
import sys
from pathlib import Path

def parse_rules(text: str) -> list[str]:
    rules: list[str] = []
    # 先按行切，再把每行按空白拆
    for line in re.split(r"[\r\n]+", text):
        line = line.strip()
        if not line:
            continue
        if line.startswith(("#", "//", ";")):
            continue

        parts = re.split(r"\s+", line)
        for p in parts:
            p = p.strip()
            if not p:
                continue
            # 去掉可能存在的行内注释（极简处理）
            p = re.split(r"\s*(#|//|;)\s*", p, maxsplit=1)[0].strip()
            if p:
                rules.append(p)

    # 去重（保持顺序）
    seen = set()
    out = []
    for r in rules:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out

def main():
    if len(sys.argv) != 3:
        print("Usage: sync_added.py <surge/added.list> <mihomo/added.yaml>")
        sys.exit(2)

    src, dst = sys.argv[1], sys.argv[2]
    src_path = Path(src)
    dst_path = Path(dst)

    rules = parse_rules(src_path.read_text(encoding="utf-8"))

    yml_lines = ["payload:"]
    yml_lines += [f"  - {r}" for r in rules]
    dst_path.write_text("\n".join(yml_lines) + "\n", encoding="utf-8")

if __name__ == "__main__":
    main()

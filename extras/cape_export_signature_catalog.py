#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import ast
import csv
import json
import sys

DEFAULT_ROOT = Path('/opt/CAPEv2/modules/signatures')


def literal_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def literal_int(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def extract_from_file(path: Path):
    text = path.read_text(encoding='utf-8', errors='ignore')
    tree = ast.parse(text, filename=str(path))
    rows = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            desc = name = None
            sev = None
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name):
                            if target.id == 'description':
                                desc = literal_str(stmt.value)
                            elif target.id == 'name':
                                name = literal_str(stmt.value)
                            elif target.id == 'severity':
                                sev = literal_int(stmt.value)
            if desc:
                rows.append({
                    'file': str(path),
                    'class_name': node.name,
                    'name': name or path.stem,
                    'description_en': desc,
                    'severity': '' if sev is None else sev,
                    'description_ko': ''
                })
    return rows


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_ROOT
    if not root.exists():
        print(f'ERROR: signature root not found: {root}')
        sys.exit(1)

    rows = []
    for py in sorted(root.rglob('*.py')):
        try:
            rows.extend(extract_from_file(py))
        except Exception as e:
            rows.append({
                'file': str(py), 'class_name': '', 'name': py.stem,
                'description_en': f'__PARSE_ERROR__: {e}', 'severity': '', 'description_ko': ''
            })

    rows.sort(key=lambda r: (r['description_en'].lower(), r['name'].lower()))

    out_json = Path('cape_signature_catalog.json')
    out_csv = Path('cape_signature_catalog.csv')
    out_json.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding='utf-8')
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['file', 'class_name', 'name', 'description_en', 'severity', 'description_ko'])
        w.writeheader()
        w.writerows(rows)

    uniq = len({(r['name'], r['description_en']) for r in rows if not str(r['description_en']).startswith('__PARSE_ERROR__')})
    print(f'Exported {len(rows)} rows ({uniq} unique name/description pairs)')
    print(f'JSON: {out_json.resolve()}')
    print(f'CSV : {out_csv.resolve()}')


if __name__ == '__main__':
    main()

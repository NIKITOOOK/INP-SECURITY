"""Read-only ZIP source discovery. Never extracts, imports, or runs archive code."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

ARCHIVES = (
    'deepseek-harness-master.zip', 'langgraph-main.zip', 'Guardrails-develop.zip',
    'pydantic-ai-main.zip', 'openai-agents-python-main.zip',
    'agent-control-standard-integration.zip', 'agent-framework-main.zip',
    'CheatSheetSeries-master.zip', 'GenAI-Red-Team-Lab-main.zip',
    'GenAI-Data-Security-Initiative-main.zip', 'OpenHands-main.zip',
    'hermes-agent-main.zip', 'goose-main.zip', 'dify-main.zip',
)
TERMS = re.compile(r'guardrail|prompt.inject|spotlight|sandwich|approv|interrupt|sandbox|security|middleware|tool_node|usage', re.I)
MAX_READ = 256 * 1024


def read_text(archive, name):
    info = archive.getinfo(name)
    if info.file_size > MAX_READ:
        raise ValueError(f'Member exceeds {MAX_READ} byte read limit: {name}')
    with archive.open(info) as stream:
        data = stream.read(MAX_READ + 1)
    if len(data) > MAX_READ:
        raise ValueError('Read limit exceeded')
    return data.decode('utf-8', errors='replace')


def catalog(source):
    rows = []
    for filename in ARCHIVES:
        path = source / filename
        row = {'archive': filename, 'status': 'missing'}
        if path.is_file():
            with path.open('rb') as stream:
                row['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            try:
                with zipfile.ZipFile(path) as archive:
                    names = archive.namelist()
                    licenses = [n for n in names if len(n.split('/')) <= 3 and Path(n).name.lower().startswith(('license', 'copying')) and not n.endswith('/')]
                    row.update(status='directory_read', entries=len(names),
                               license_files=licenses,
                               license_excerpts={n: read_text(archive, n)[:2000] for n in licenses},
                               candidates=[n for n in names if TERMS.search(n) and not n.endswith('/')][:160])
            except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
                row.update(status='error', error=str(exc))
        rows.append(row)
    return {'scope': 'ZIP metadata and selected text only; not malware, CRC, or dependency audit', 'archives': rows}


def main():
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-dir', type=Path, required=True)
    parser.add_argument('--archive', choices=ARCHIVES)
    parser.add_argument('--pattern', help='Regex against member paths; prints at most 100 matches')
    parser.add_argument('--read', help='Exact member path, at most 256 KiB')
    parser.add_argument('--output', type=Path, help='Write generated JSON inventory')
    args = parser.parse_args()
    if args.archive:
        with zipfile.ZipFile(args.source_dir / args.archive) as archive:
            if args.read:
                print(read_text(archive, args.read))
            else:
                pattern = re.compile(args.pattern or TERMS.pattern, re.I)
                matches = [n for n in archive.namelist() if pattern.search(n)]
                print('\n'.join(matches[:100])[:40000])
    else:
        result = json.dumps(catalog(args.source_dir), indent=2, ensure_ascii=False)
        if args.output:
            args.output.write_text(result + '\n', encoding='utf-8')
            print(f'Inventory saved: {args.output}')
        else:
            print(result)


if __name__ == '__main__':
    main()

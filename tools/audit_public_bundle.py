#!/usr/bin/env python3
"""Audit the public Git bundle of the AI Agent Security Lab.

Read-only: reads files, calls `git ls-files` / `git check-ignore` / `git status`
and writes one report. It does not stage, commit, push or modify tracked files.

Usage (from the project root):
    runtime\\langgraph-py\\Scripts\\python.exe tools\\audit_public_bundle.py
Optional: --out <path> to change the report location.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EXCLUDE_ANYWHERE = {".git"}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".iso"}

SECRET_PATTERNS = [
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("assigned secret", re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*[\"'][^\"'\s]{6,}[\"']")),
    ("bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}")),
]

PRIVACY_PATTERNS = [
    ("absolute C: user path", re.compile(r"[Cc]:[\\/]Users[\\/]")),
    ("codex attachment path", re.compile(r"\.codex[\\/]attachments")),
]

LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
TITLE_RE = re.compile(r"<title>(.*?)</title>", re.S)


def run_git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return proc.stdout


def rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return ""


def collect_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_ANYWHERE]
        for name in filenames:
            files.append(Path(dirpath) / name)
    return files


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_path = Path(args.out) if args.out else root / "AUDIT" / "Аудит_публичного_комплекта.md"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    tracked = [line for line in run_git(root, "ls-files").splitlines() if line.strip()]
    tracked_set = set(tracked)
    ignored = [line for line in run_git(root, "status", "--ignored", "--short").splitlines() if line.startswith("!!")]
    ignored_entries = sorted({line[3:].strip().rstrip("/") for line in ignored})

    manifest_path = root / "wiki" / "public-files.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else []
    manifest_set = set(manifest)

    # --- 1. manifest integrity -------------------------------------------------
    missing_on_disk: list[str] = []
    present_but_ignored: list[str] = []
    present_not_tracked: list[str] = []
    for item in manifest:
        target = root / item
        if not target.exists():
            missing_on_disk.append(item)
            continue
        probe = run_git(root, "check-ignore", "--", item).strip()
        if probe:
            present_but_ignored.append(item)
        if item not in tracked_set:
            present_not_tracked.append(item)

    # --- 2. bundle inventory ---------------------------------------------------
    manifest_files = [root / item for item in manifest if (root / item).exists()]
    sizes = sorted(((p.stat().st_size, rel(root, p)) for p in manifest_files), reverse=True)
    bundle_bytes = sum(size for size, _ in sizes)
    heavy = [(size, name) for size, name in sizes if size > 300_000]

    # --- 3. secret and privacy scan -------------------------------------------
    secret_hits: list[str] = []
    privacy_hits: dict[str, list[str]] = {}
    for path in manifest_files:
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        text = read_text(path)
        if not text:
            continue
        for label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line_no = text.count("\n", 0, match.start()) + 1
                secret_hits.append(f"{rel(root, path)}:{line_no} — {label}")
        for label, pattern in PRIVACY_PATTERNS:
            count = len(pattern.findall(text))
            if count:
                privacy_hits.setdefault(label, []).append(f"{rel(root, path)} ({count})")

    # --- 4. wiki site staleness ------------------------------------------------
    site = root / "wiki" / "site"
    stale_pages: list[str] = []
    orphan_pages: list[str] = []
    page_count = 0
    if site.is_dir():
        pages = sorted(site.glob("p*.html"))
        page_count = len(pages)
        for page in pages:
            html = read_text(page)
            key = None
            for item in manifest:
                if item.endswith(".md") and item in html:
                    key = item
                    break
            if key is None:
                orphan_pages.append(page.name)
                continue
            source_file = root / key
            if source_file.exists() and source_file.stat().st_mtime > page.stat().st_mtime:
                delta = source_file.stat().st_mtime - page.stat().st_mtime
                stale_pages.append(f"{page.name} ← {key} (отстаёт на {delta / 60:.0f} мин)")

    # --- 5. markdown link check (public set only) ------------------------------
    broken_links: list[str] = []
    for item in manifest:
        if not item.endswith(".md"):
            continue
        path = root / item
        if not path.exists():
            continue
        text = read_text(path)
        for match in LINK_RE.finditer(text):
            href = match.group(1).strip()
            if href.startswith(("http://", "https://", "mailto:", "#")):
                continue
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", href):
                continue  # absolute local path, deliberately not shipped
            target = (path.parent / href.split("#", 1)[0]).resolve()
            if href.split("#", 1)[0] and not target.exists():
                broken_links.append(f"{item} → {href}")

    # --- 6. report ------------------------------------------------------------
    now = datetime.now().strftime("%d.%m.%Y %H:%M")
    lines: list[str] = []
    add = lines.append
    add("# Аудит публичного комплекта")
    add("")
    add(f"Дата прогона: {now}. Скрипт: `tools/audit_public_bundle.py` (read-only).")
    add("")
    add("Проверяются четыре вопроса: сохранность версии и истории, передача команде,")
    add("проверяемость происхождения и лицензий, пригодность как резервной основы.")
    add("")

    add("## 1. Манифест публичного комплекта")
    add("")
    add(f"- Записей в `wiki/public-files.json`: **{len(manifest)}**.")
    add(f"- Есть на диске: **{len(manifest_files)}**; отсутствуют: **{len(missing_on_disk)}**.")
    add(f"- Присутствуют, но скрыты `.gitignore`: **{len(present_but_ignored)}**.")
    add(f"- Присутствуют, но не в индексе Git: **{len(present_not_tracked)}**.")
    add(f"- Объём комплекта: **{bundle_bytes / 1024:.0f} КиБ**.")
    add("")
    if missing_on_disk:
        add("Отсутствуют на диске:")
        for item in missing_on_disk:
            add(f"- `{item}`")
        add("")
    if present_but_ignored:
        add("**Скрыты `.gitignore`, хотя заявлены публичными:**")
        for item in present_but_ignored:
            add(f"- `{item}`")
        add("")
    if present_not_tracked:
        add("Ожидают добавления в индекс (норма для новой сборки):")
        for item in present_not_tracked:
            add(f"- `{item}`")
        add("")

    add("## 2. Крупные файлы комплекта")
    add("")
    if heavy:
        for size, name in heavy:
            add(f"- {size / 1024:.0f} КиБ — `{name}`")
    else:
        add("- Файлов крупнее 300 КиБ нет.")
    add("")

    add("## 3. Секреты и приватные пути")
    add("")
    add(f"- Найдено секретоподобных строк: **{len(secret_hits)}**.")
    for hit in secret_hits[:40]:
        add(f"- {hit}")
    add("")
    if privacy_hits:
        add("Абсолютные локальные пути в публичных файлах (не секрет, но выдают машину автора):")
        for label, hits in sorted(privacy_hits.items()):
            add(f"- {label}: {len(hits)} файл(ов)")
            for hit in sorted(hits):
                add(f"  - `{hit}`")
    else:
        add("- Абсолютных путей `C:\\Users\\...` не найдено.")
    add("")

    add("## 4. Сборка Wiki")
    add("")
    add(f"- HTML-страниц в `wiki/site`: **{page_count}**.")
    add(f"- Устаревших страниц: **{len(stale_pages)}**.")
    for item in stale_pages:
        add(f"- {item}")
    if orphan_pages:
        add(f"- Страниц без соответствия манифесту: {len(orphan_pages)}: {', '.join(orphan_pages[:10])}")
    add("")

    add("## 5. Ссылки в публичных Markdown")
    add("")
    add(f"- Битых относительных ссылок: **{len(broken_links)}**.")
    for item in broken_links[:60]:
        add(f"- {item}")
    add("")

    add("## 6. Полностью игнорируемые пути (для справки)")
    add("")
    for item in ignored_entries:
        add(f"- `{item}`")
    add("")

    add("## 7. Индекс Git")
    add("")
    add(f"- Отслеживается файлов: **{len(tracked)}**.")
    status = [line for line in run_git(root, "status", "--short").splitlines() if line.strip()]
    add(f"- Изменено/не добавлено записей: **{len(status)}**.")
    add("")

    out_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"report: {rel(root, out_path)}")
    print(f"manifest={len(manifest)} on_disk={len(manifest_files)} missing={len(missing_on_disk)} ignored_but_public={len(present_but_ignored)}")
    print(f"secrets={len(secret_hits)} privacy_files={sum(len(v) for v in privacy_hits.values())} stale_pages={len(stale_pages)} broken_links={len(broken_links)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

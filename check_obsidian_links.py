#!/usr/bin/env python3
"""Detect and fix plain .md references for Obsidian wiki links.

This script scans markdown files in a project, skipping common build/vendor
directories, and finds plain-text references to other markdown files that are
not already links. With --fix it converts them to Obsidian wiki links.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".obsidian",
    "node_modules",
    "build",
    "dist",
    "out",
    "target",
    "__pycache__",
    ".next",
    ".nuxt",
    ".cache",
    "coverage",
}


CODE_FENCE_RE = re.compile(r"```[\s\S]*?```")
INLINE_CODE_RE = re.compile(r"`[^`\n]*`")
WIKI_LINK_RE = re.compile(r"\[\[[^\]]+\]\]")
MD_LINK_RE = re.compile(r"\[[^\]]+\]\([^)]+\)")
AUTO_LINK_RE = re.compile(r"<[^>]+>")
PLAIN_MD_REF_RE = re.compile(r"(?P<ref>[A-Za-z0-9_./\- ]+?\.md(?:#[^\s)\]]+)?)")


@dataclass
class Finding:
    file_path: Path
    start: int
    end: int
    raw_ref: str
    replacement: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find/fix unlinked .md references for Obsidian."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Project root to scan (default: current directory).",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Apply fixes in-place (convert plain refs to [[wiki links]]).",
    )
    parser.add_argument(
        "--ignore-dir",
        action="append",
        default=[],
        help="Additional directory name to ignore (can be passed multiple times).",
    )
    return parser.parse_args()


def iter_markdown_files(root: Path, ignored_dirs: set[str]) -> Iterable[Path]:
    for path in root.rglob("*.md"):
        parts = set(path.parts)
        if ignored_dirs.intersection(parts):
            continue
        yield path


def collect_note_index(files: list[Path], root: Path) -> set[str]:
    """Store vault-relative paths (posix, lowercased) for note existence checks."""
    index: set[str] = set()
    for file_path in files:
        rel = file_path.relative_to(root).as_posix().lower()
        index.add(rel)
    return index


def mask_ranges(text: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for pattern in (CODE_FENCE_RE, INLINE_CODE_RE, WIKI_LINK_RE, MD_LINK_RE, AUTO_LINK_RE):
        for match in pattern.finditer(text):
            ranges.append((match.start(), match.end()))
    ranges.sort()
    return ranges


def in_masked_range(start: int, ranges: list[tuple[int, int]]) -> bool:
    for left, right in ranges:
        if left <= start < right:
            return True
        if left > start:
            return False
    return False


def normalize_heading(fragment: str) -> str:
    # Keep heading readable in Obsidian links, but trim accidental spaces.
    return fragment.strip()


def to_wiki_link(target_rel: str, heading: str | None) -> str:
    base = target_rel[:-3] if target_rel.lower().endswith(".md") else target_rel
    if heading:
        return f"[[{base}#{normalize_heading(heading)}]]"
    return f"[[{base}]]"


def split_ref(raw_ref: str) -> tuple[str, str | None]:
    if "#" not in raw_ref:
        return raw_ref, None
    ref, heading = raw_ref.split("#", 1)
    return ref, heading


def resolve_target(
    source_file: Path, root: Path, ref_path: str, note_index: set[str]
) -> str | None:
    ref_clean = ref_path.strip().replace("\\", "/")
    if not ref_clean or "://" in ref_clean:
        return None

    # Absolute-from-root-ish input (starts with /foo/bar.md)
    candidates: list[Path] = []
    if ref_clean.startswith("/"):
        candidates.append(root / ref_clean.lstrip("/"))
    else:
        candidates.append((source_file.parent / ref_clean).resolve())
        candidates.append((root / ref_clean).resolve())

    for candidate in candidates:
        try:
            rel = candidate.relative_to(root).as_posix().lower()
        except ValueError:
            continue
        if rel in note_index:
            return rel
    return None


def find_unlinked_refs(file_path: Path, root: Path, note_index: set[str]) -> list[Finding]:
    text = file_path.read_text(encoding="utf-8")
    masked = mask_ranges(text)
    findings: list[Finding] = []

    for match in PLAIN_MD_REF_RE.finditer(text):
        start, end = match.span("ref")
        if in_masked_range(start, masked):
            continue

        raw_ref = match.group("ref").strip()
        ref_path, heading = split_ref(raw_ref)
        target_rel = resolve_target(file_path, root, ref_path, note_index)
        if not target_rel:
            continue

        replacement = to_wiki_link(target_rel, heading)
        findings.append(Finding(file_path, start, end, raw_ref, replacement))

    return findings


def apply_fixes(file_path: Path, findings: list[Finding]) -> int:
    if not findings:
        return 0
    text = file_path.read_text(encoding="utf-8")
    updated = text
    for finding in sorted(findings, key=lambda item: item.start, reverse=True):
        updated = updated[: finding.start] + finding.replacement + updated[finding.end :]
    if updated != text:
        file_path.write_text(updated, encoding="utf-8")
        return len(findings)
    return 0


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    ignored_dirs = DEFAULT_IGNORED_DIRS.union(set(args.ignore_dir))

    md_files = sorted(iter_markdown_files(root, ignored_dirs))
    if not md_files:
        print("No markdown files found.")
        return 0

    note_index = collect_note_index(md_files, root)
    all_findings: dict[Path, list[Finding]] = {}
    total = 0

    for file_path in md_files:
        findings = find_unlinked_refs(file_path, root, note_index)
        if findings:
            all_findings[file_path] = findings
            total += len(findings)

    if total == 0:
        print("OK: no unlinked markdown references found.")
        return 0

    print(f"Found {total} unlinked markdown reference(s) in {len(all_findings)} file(s):")
    for file_path, findings in all_findings.items():
        rel = file_path.relative_to(root).as_posix()
        print(f"\n- {rel}")
        for finding in findings:
            print(f"  * '{finding.raw_ref}' -> {finding.replacement}")

    if not args.fix:
        print("\nRun with --fix to apply replacements.")
        return 1

    changed_refs = 0
    changed_files = 0
    for file_path, findings in all_findings.items():
        applied = apply_fixes(file_path, findings)
        if applied:
            changed_files += 1
            changed_refs += applied

    print(
        f"\nApplied fixes: {changed_refs} replacement(s) in {changed_files} file(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

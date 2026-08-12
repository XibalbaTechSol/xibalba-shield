#!/usr/bin/env python3
"""Generate deterministic in-page TOCs for every canonical wiki article."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WIKI = ROOT / "docs" / "wiki"
CATEGORIES = ("concepts", "entities", "architecture", "queries")
TOC_HEADING = "## Table of contents"


def article_paths() -> list[Path]:
    return sorted(
        path
        for category in CATEGORIES
        for path in (WIKI / category).glob("*.md")
    )


def without_code_fences(markdown: str) -> list[str]:
    lines: list[str] = []
    in_fence = False
    for line in markdown.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append(line)
    return lines


def heading_text(raw: str) -> str:
    value = re.sub(r"!\[([^]]*)\]\([^)]+\)", r"\1", raw)
    value = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", value)
    value = re.sub(r"[`*_~]", "", value)
    return re.sub(r"<[^>]+>", "", value).strip()


def slugify(title: str) -> str:
    return re.sub(r"(^-|-$)", "", re.sub(r"[^a-z0-9]+", "-", title.lower()))


def headings(markdown: str) -> list[tuple[int, str, str]]:
    found: list[tuple[int, str, str]] = []
    counts: dict[str, int] = {}
    for line in without_code_fences(markdown):
        match = re.match(r"^(##|###)\s+(.+?)\s*#*\s*$", line)
        if not match:
            continue
        title = heading_text(match.group(2))
        if title.lower() == "table of contents":
            continue
        base = slugify(title)
        count = counts.get(base, 0)
        counts[base] = count + 1
        anchor = base if count == 0 else f"{base}-{count}"
        found.append((len(match.group(1)), title, anchor))
    return found


def strip_existing_toc(markdown: str) -> str:
    pattern = re.compile(
        r"\n## Table of contents\n.*?(?=\n##\s+|\Z)",
        re.DOTALL,
    )
    return pattern.sub("", markdown).rstrip() + "\n"


def render(markdown: str) -> str:
    clean = strip_existing_toc(markdown)
    items = headings(clean)
    if not items:
        frontmatter_end = clean.find("\n---\n", 4) if clean.startswith("---\n") else -1
        insert_at = frontmatter_end + 5 if frontmatter_end >= 0 else 0
        clean = clean[:insert_at].rstrip() + "\n\n## Overview\n\n" + clean[insert_at:].lstrip()
        items = headings(clean)
    toc = [TOC_HEADING, ""]
    toc.extend(f"{'  ' if level == 3 else ''}- [{title}](#{anchor})" for level, title, anchor in items)
    block = "\n".join(toc) + "\n"
    first_section = re.search(r"^##\s+", clean, re.MULTILINE)
    if first_section:
        return clean[: first_section.start()].rstrip() + "\n\n" + block + "\n" + clean[first_section.start():]
    return clean.rstrip() + "\n\n" + block


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale: list[str] = []
    for path in article_paths():
        source = path.read_text(encoding="utf-8")
        try:
            generated = render(source)
        except ValueError as error:
            raise SystemExit(f"{path.relative_to(ROOT)}: {error}") from error
        if generated == source:
            continue
        stale.append(str(path.relative_to(ROOT)))
        if not args.check:
            path.write_text(generated, encoding="utf-8")
    if stale:
        action = "need TOC regeneration" if args.check else "updated"
        print(f"{len(stale)} wiki pages {action}:")
        print("\n".join(f"- {path}" for path in stale))
        return 1 if args.check else 0
    print(f"TOCs current for {len(article_paths())} wiki pages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

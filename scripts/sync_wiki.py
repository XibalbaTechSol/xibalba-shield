#!/usr/bin/env python3
"""
Syncs docs/wiki/ (this repo's compiled wiki) into the separate GitHub Wiki
repo (<repo>.wiki.git), flattened.

Why flattened: GitHub Wiki's rendered page URLs
(github.com/OWNER/REPO/wiki/PAGE) only exist for files at the wiki repo's
ROOT. A file under a subdirectory (concepts/foo.md, entities/bar.md) has no
such route and 302-redirects to raw.githubusercontent.com instead --
literal unrendered markdown text. docs/wiki/ itself keeps its
concepts/entities/ subdirectories unchanged (browsed via GitHub's normal
repo file browser, a different rendering path that DOES support
directories) -- only this mirror needs flattening.

This mirrors integrity-core's scripts/sync_wiki.py exactly, minus the
extra top-level docs (INTERFACE_CONTRACT.md/TESTING.md/guides/) that repo
has and this one doesn't.

Usage:
    python scripts/sync_wiki.py <path-to-wiki-repo-checkout>

The destination must already be a git checkout of the wiki repo (this
script only writes files -- committing/pushing is the caller's job, see
.github/workflows/sync-wiki.yml).
"""

from __future__ import annotations

import os
import re
import shutil
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_WIKI = os.path.join(REPO_ROOT, "docs", "wiki")
WIKI_CATEGORIES = ("concepts", "entities", "architecture", "queries")


def build_source_map() -> dict[str, str]:
    """Maps a docs/-relative logical path -> the flat basename it becomes
    in the wiki repo. Asserts no basename collisions across categories."""
    sources: dict[str, str] = {}

    for sub in WIKI_CATEGORIES:
        directory = os.path.join(SRC_WIKI, sub)
        if not os.path.isdir(directory):
            continue
        for fname in os.listdir(directory):
            if fname.endswith(".md"):
                sources[f"wiki/{sub}/{fname}"] = fname

    for fname in ("WIKI_INDEX.md", "WIKI_LOG.md", "WIKI_SCHEMA.md", "index.md"):
        sources[f"wiki/{fname}"] = fname

    basenames = list(sources.values())
    dupes = {b for b in basenames if basenames.count(b) > 1}
    if dupes:
        raise SystemExit(
            f"sync_wiki.py: filename collision(s) across concepts/entities "
            f"would overwrite each other once flattened: {sorted(dupes)}. "
            f"Rename one of the source files before syncing."
        )
    return sources


def rewrite_links(content: str, current_docs_relpath: str, basename_registry: set[str]) -> str:
    """Rewrites every relative markdown link in `content` (a file originally
    at `current_docs_relpath`, relative to docs/) to a flat sibling
    reference. Links that don't resolve to a known wiki-mirrored file are
    left untouched."""
    current_dir = os.path.dirname(current_docs_relpath)

    def repl(m: re.Match) -> str:
        text, link = m.group(1), m.group(2)
        if link.startswith(("http://", "https://", "mailto:")):
            return m.group(0)
        path_part, _, frag = link.partition("#")
        if not path_part or path_part.endswith("/"):
            return m.group(0)
        resolved = os.path.normpath(os.path.join(current_dir, path_part)).replace(os.sep, "/")
        basename = os.path.basename(resolved)
        if basename in basename_registry:
            new_link = basename + (("#" + frag) if frag else "")
            return f"[{text}]({new_link})"
        return m.group(0)

    return re.sub(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)", repl, content)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: sync_wiki.py <path-to-wiki-repo-checkout>")
    dst = sys.argv[1]
    if not os.path.isdir(os.path.join(dst, ".git")):
        raise SystemExit(f"{dst} is not a git checkout (no .git/) -- refusing to write into it")

    sources = build_source_map()
    basename_registry = set(sources.values())

    # Wipe the destination content. The GitHub Wiki is a generated mirror:
    # its navigation is rebuilt below from canonical docs/wiki metadata, so
    # direct edits in the wiki UI cannot become a second source.
    for fname in os.listdir(dst):
        if fname == ".git":
            continue
        path = os.path.join(dst, fname)
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif fname.endswith(".md"):
            os.remove(path)

    published_pages: list[tuple[str, str, str]] = []
    for sub in WIKI_CATEGORIES:
        directory = os.path.join(SRC_WIKI, sub)
        if not os.path.isdir(directory):
            continue
        for fname in os.listdir(directory):
            if not fname.endswith(".md"):
                continue
            with open(os.path.join(SRC_WIKI, sub, fname), encoding="utf-8") as f:
                content = f.read()
            content = rewrite_links(content, f"wiki/{sub}/{fname}", basename_registry)
            with open(os.path.join(dst, fname), "w", encoding="utf-8") as f:
                f.write(content)
            title_match = re.search(r"^title:\s*(.+)$", content, re.MULTILINE)
            title = title_match.group(1).strip() if title_match else fname.removesuffix(".md").replace("-", " ").title()
            published_pages.append((sub, title, fname))

    for fname in ("WIKI_INDEX.md", "WIKI_LOG.md", "WIKI_SCHEMA.md"):
        with open(os.path.join(SRC_WIKI, fname), encoding="utf-8") as f:
            content = f.read()
        content = rewrite_links(content, f"wiki/{fname}", basename_registry)
        with open(os.path.join(dst, fname), "w", encoding="utf-8") as f:
            f.write(content)

    # index.md is the source of truth; mirrored to both Home.md (GitHub
    # Wiki's required landing-page filename) and index.md (kept for anyone
    # who clones the wiki repo directly and expects a normal README-style entry).
    with open(os.path.join(SRC_WIKI, "index.md"), encoding="utf-8") as f:
        content = f.read()
    content = rewrite_links(content, "wiki/index.md", basename_registry)
    with open(os.path.join(dst, "Home.md"), "w", encoding="utf-8") as f:
        f.write(content)
    with open(os.path.join(dst, "index.md"), "w", encoding="utf-8") as f:
        f.write(content)

    # GitHub-specific chrome is generated from the same canonical page set.
    # It is deliberately not preserved from the destination wiki checkout.
    sidebar = ["## Master contents", "", "[Home](Home.md)", ""]
    category_labels = {
        "concepts": "Concepts",
        "entities": "Entities",
        "architecture": "Architecture",
        "queries": "Open queries",
    }
    for category in WIKI_CATEGORIES:
        pages = sorted((title, fname) for page_category, title, fname in published_pages if page_category == category)
        if not pages:
            continue
        sidebar.extend((f"### {category_labels[category]}", ""))
        sidebar.extend(f"- [{title}]({fname})" for title, fname in pages)
        sidebar.append("")
    with open(os.path.join(dst, "_Sidebar.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(sidebar) + "\n")
    with open(os.path.join(dst, "_Footer.md"), "w", encoding="utf-8") as f:
        f.write(
            "Generated from [xibalba-shield/docs/wiki]"
            "(https://github.com/XibalbaTechSol/xibalba-shield/tree/main/docs/wiki). "
            "Edit the canonical repository files, not this mirror.\n"
        )

    print(f"Synced {len(sources)} source files -> {dst} (flat, {len(os.listdir(dst)) - 1} files)")


if __name__ == "__main__":
    main()

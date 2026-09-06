#!/usr/bin/env python3
"""Assemble the mdBook sources from the canonical Markdown in the repo.

The docs live where they are useful to a reader of the repository — `README.md`,
`CONCEPT.md`, `docs/*.md` — and this script projects them into the flat page set
mdBook wants. Nothing here is a second copy of the prose: the repo files stay the
single source of truth and every page is regenerated on each build, so the site
cannot drift from them the way a wiki does.

Two things are fixed up on the way through:

* **Links.** A repo-relative link (`docs/CLI_COMMANDS.md`) means nothing on the
  rendered site; it is rewritten to the page that file became. Links to files
  that are *not* in the book (source, licence, workflows) are rewritten to
  GitHub so they keep working.
* **Obsidian wikilinks.** `[[Page|label]]` is not Markdown and renders literally.
  Known pages become real links; anything else degrades to its label text.

Output (all under `target/`, which is git-ignored):
  target/book-src/   generated mdBook sources
  target/book/       rendered site, plus sitemap.xml and robots.txt
"""

from __future__ import annotations

import posixpath
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_OUT = ROOT / "target" / "book-src"
BUILD_OUT = ROOT / "target" / "book"

REPO_URL = "https://github.com/LargoScript/n0xis"
SITE_URL = "https://largoscript.github.io/n0xis/"


@dataclass(frozen=True)
class Page:
    """One chapter: where its prose lives, and how it is presented."""

    source: str  # repo-relative path of the canonical Markdown
    slug: str  # generated file name, without extension
    title: str  # SUMMARY entry and <title>; also the SEO-visible name
    blurb: str  # <meta name="description"> for this page


# Order is the reading order in the sidebar. A page absent from this list is
# absent from the site — MAP.md (an Obsidian navigation hub, replaced here by
# SUMMARY.md) and the internal phase briefs are deliberately not published.
PAGES: tuple[Page, ...] = (
    Page(
        "README.md",
        "index",
        "Introduction",
        "N0xis is a reverse-engineering and live-memory toolkit for Windows and "
        "Linux: one analysis pipeline over static PE/ELF files and live processes.",
    ),
    Page(
        "docs/CLI_COMMANDS.md",
        "cli-reference",
        "CLI Reference",
        "Every n0xis command: arguments, target selection, and the versioned "
        "JSON schema each one returns.",
    ),
    Page(
        "CONCEPT.md",
        "architecture",
        "Architecture",
        "How N0xis is built: source adapters, the OS-free analysis core, the SSA "
        "decompiler pipeline, and the seams that keep them apart.",
    ),
    Page(
        "docs/n0xhud/CONCEPT.md",
        "n0xhud",
        "N0xHUD",
        "The companion-window frontend — a window over the analysis engine, "
        "sharing the same crates as the CLI and MCP frontends.",
    ),
    Page(
        "ROADMAP.md",
        "roadmap",
        "Roadmap & build history",
        "Phase-by-phase history of how N0xis was built, what is verified against "
        "real targets, and the analysis capabilities that remain unbuilt.",
    ),
    Page(
        "CHANGELOG.md",
        "changelog",
        "Changelog",
        "Released versions of N0xis and what changed in each.",
    ),
    Page(
        "docs/PRODUCT_POLICY.md",
        "product-policy",
        "Product policy",
        "The standing rules every change is checked against: modularity, "
        "anti-hardcode, sound-over-complete, and no half-finished features.",
    ),
    Page(
        "docs/COMMUNITY_ROADMAP.md",
        "community",
        "Community roadmap",
        "What outside contributors can pick up, and how the plugin seam lets "
        "external tools extend N0xis without touching the core.",
    ),
    Page(
        "CONTRIBUTING.md",
        "contributing",
        "Contributing",
        "How to build, test and contribute to N0xis, including the boundary law "
        "the CI enforces.",
    ),
)

# Canonical source path -> generated page slug.
BY_SOURCE = {p.source: p.slug for p in PAGES}

# Wikilink target -> slug, for the handful of `[[...]]` links that survive in
# prose. Anything not listed degrades to plain text rather than a broken link.
WIKI_TARGETS = {
    "README": "index",
    "CONCEPT": "architecture",
    "ROADMAP": "roadmap",
    "CLI_COMMANDS": "cli-reference",
    "PRODUCT_POLICY": "product-policy",
    "COMMUNITY_ROADMAP": "community",
    "CONTRIBUTING": "contributing",
    "CHANGELOG": "changelog",
    "docs/n0xhud/CONCEPT": "n0xhud",
}


def rewrite_wikilinks(text: str) -> str:
    """`[[Target|label]]` / `[[Target]]` -> a real link, or just the label."""

    def repl(m: re.Match[str]) -> str:
        target, _, label = m.group(1).partition("|")
        target, label = target.strip(), (label.strip() or target.strip())
        # An `#anchor` suffix has no meaning once the page is renamed; drop it.
        base = target.split("#", 1)[0]
        slug = WIKI_TARGETS.get(base) or WIKI_TARGETS.get(base.split("/")[-1])
        return f"[{label}]({slug}.md)" if slug else label

    return re.sub(r"\[\[([^\]]+)\]\]", repl, text)


def rewrite_links(text: str, page: Page) -> str:
    """Repo-relative Markdown links -> book pages, or absolute GitHub URLs."""
    here = Path(page.source).parent

    def repl(m: re.Match[str]) -> str:
        label, target = m.group(1), m.group(2)
        if re.match(r"^(https?:|mailto:|#)", target):
            return m.group(0)
        path, _, anchor = target.partition("#")
        anchor = f"#{anchor}" if anchor else ""
        if not path:  # pure in-page anchor
            return m.group(0)
        # Resolve relative to the file the link was written in. normpath is what
        # collapses `docs/../CONCEPT.md` to `CONCEPT.md`; a plain join leaves the
        # `..` in place and the link then names a file that does not exist.
        resolved = posixpath.normpath(posixpath.join(here.as_posix(), path))
        # Not `lstrip("./")`: that strips a *set* of characters, so a link to
        # `.github/workflows/ci.yml` would lose its leading dot.
        resolved = resolved.removeprefix("./")
        if slug := BY_SOURCE.get(resolved):
            return f"[{label}]({slug}.md{anchor})"
        # Not a published page: point at the file on GitHub so it still works.
        return f"[{label}]({REPO_URL}/blob/main/{resolved}{anchor})"

    return re.sub(r"\[([^\]]*)\]\(([^)]+)\)", repl, text)


def strip_html_comments(text: str) -> str:
    """Drop authoring notes (e.g. the README's "hero GIF goes here" marker)."""
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)


def build_sources() -> None:
    if SRC_OUT.exists():
        shutil.rmtree(SRC_OUT)
    SRC_OUT.mkdir(parents=True)

    for page in PAGES:
        src = ROOT / page.source
        if not src.exists():
            sys.exit(f"build_book: missing source {page.source}")
        text = src.read_text(encoding="utf-8")
        text = strip_html_comments(text)
        text = rewrite_wikilinks(text)
        text = rewrite_links(text, page)
        # mdBook takes the page's <title> from SUMMARY.md, so the body keeps its
        # own H1. A one-line provenance note tells a reader of the site which
        # file in the repo they should edit.
        note = (
            f"<!-- Generated from {page.source} by scripts/build_book.py. "
            "Edit that file, not this one. -->\n\n"
        )
        (SRC_OUT / f"{page.slug}.md").write_text(note + text, encoding="utf-8")

    summary = ["# Summary\n"]
    for page in PAGES:
        summary.append(f"- [{page.title}]({page.slug}.md)")
    (SRC_OUT / "SUMMARY.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print(f"build_book: generated {len(PAGES)} pages into {SRC_OUT.relative_to(ROOT)}")


def write_seo_assets() -> None:
    """A sitemap and robots.txt — mdBook ships neither, and search engines want both."""
    urls = "\n".join(
        f"  <url><loc>{SITE_URL}{p.slug}.html</loc></url>" for p in PAGES
    )
    (BUILD_OUT / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{urls}\n</urlset>\n",
        encoding="utf-8",
    )
    (BUILD_OUT / "robots.txt").write_text(
        f"User-agent: *\nAllow: /\nSitemap: {SITE_URL}sitemap.xml\n", encoding="utf-8"
    )
    print("build_book: wrote sitemap.xml and robots.txt")


def postprocess_html() -> None:
    """Per-page metadata, and an "Edit" link that points at the real source.

    Two fixes mdBook cannot make itself. It emits one book-wide description for
    every page, which search engines treat as duplicate boilerplate; rewriting it
    per page is what lets each chapter rank for its own subject instead of
    competing with its siblings. And `edit-url-template` resolves against the
    *generated* sources under `target/`, so the pencil icon would send a reader
    to a file that is rebuilt on every deploy — it is redirected to the canonical
    Markdown the page was made from.
    """
    for page in PAGES:
        html = BUILD_OUT / f"{page.slug}.html"
        if not html.exists():
            continue
        text = html.read_text(encoding="utf-8")
        blurb = page.blurb.replace('"', "&quot;")
        text, n = re.subn(
            r'<meta name="description" content="[^"]*">',
            f'<meta name="description" content="{blurb}">',
            text,
            count=1,
        )
        if n == 0:  # no tag to replace — insert one
            text = text.replace(
                "</head>", f'<meta name="description" content="{blurb}">\n</head>', 1
            )
        og = (
            f'<meta property="og:title" content="{page.title} · N0xis">\n'
            f'<meta property="og:description" content="{blurb}">\n'
            f'<meta property="og:type" content="website">\n'
            f'<meta property="og:url" content="{SITE_URL}{page.slug}.html">\n'
        )
        text = text.replace("</head>", og + "</head>", 1)
        # Redirect the edit pencil from target/book-src/<slug>.md to the source.
        text = text.replace(
            f"/edit/main/{SRC_OUT.relative_to(ROOT).as_posix()}/{page.slug}.md",
            f"/edit/main/{page.source}",
        )
        html.write_text(text, encoding="utf-8")
    print(f"build_book: rewrote metadata and edit links on {len(PAGES)} pages")


def main() -> None:
    build_sources()
    if "--sources-only" in sys.argv:
        return
    result = subprocess.run(["mdbook", "build", str(ROOT)], check=False)
    if result.returncode != 0:
        sys.exit(result.returncode)
    write_seo_assets()
    postprocess_html()
    print(f"build_book: site ready in {BUILD_OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()

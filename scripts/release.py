#!/usr/bin/env python3
"""Build a release, write its manifest, sign it, and with --publish tag it and put it up.

    python3 scripts/release.py --tag v0.3.8 --key /path/outside/the/repo/release.pem
    python3 scripts/release.py --tag v0.3.8 --key ... --publish

A dry run by default: everything except the tag and the upload, into --out. See docs/design/UPDATE.md.

Each refusal here is one a copy in the field could not recover from:

- The tag and the workspace version differ. There is one declaration of the version.
- A private key inside the repository. It never leaves the owner's machine, and a file in a work tree
  is one `git add` from leaving.
- Publishing while the binary's built-in key is the placeholder, or not this signing key's. Every copy
  of that release would refuse every manifest after it, and no later release could reach them.
- Publishing what this run did not just build (--prebuilt, --base-url exist for the verification).

Signing goes through the openssl command, so what signs is not what verifies: the client is on ring.
The signature file is lines of hex, one per --key, so that a change of key can be signed by both.

The release goes up as a draft and turns public only once all its files are there, because
`releases/latest/download/manifest.json` is what clients ask for, and a release that is latest and has
no manifest yet would answer them with a 404.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "Structio-labs/N0xis"
# Where a tag is pushed: this repository has no remote called `origin`, and a release must not depend on
# what a checkout's remotes are called, or it tags locally and dies halfway through a publish.
PUSH_TO = "git@github.com:Structio-labs/N0xis.git"
WINDOWS = "x86_64-pc-windows-gnu"
TRUST_SOURCE = ROOT / "crates/n0xis-update/src/trust.rs"

# component -> platform -> (published asset, name when installed, cargo target, built file).
# The asset names are the four the README's download links rest on.
COMPONENTS = {
    "n0xis": {
        "linux-x86_64": ("n0xis-linux-x86_64", "n0xis", None, "n0xis"),
        "windows-x86_64": ("n0xis-windows-x86_64.exe", "n0xis.exe", WINDOWS, "n0xis.exe"),
    },
    "n0xis-mcp": {
        "linux-x86_64": ("n0xis-mcp-linux-x86_64", "n0xis-mcp", None, "n0xis-mcp"),
        "windows-x86_64": ("n0xis-mcp-windows-x86_64.exe", "n0xis-mcp.exe", WINDOWS, "n0xis-mcp.exe"),
    },
}


def refuse(message):
    print(f"refused: {message}", file=sys.stderr)
    sys.exit(1)


def run(*cmd, **kwargs):
    return subprocess.run(cmd, check=True, **kwargs)


def workspace_version():
    with open(ROOT / "Cargo.toml", "rb") as f:
        return tomllib.load(f)["workspace"]["package"]["version"]


def built_in_key():
    """What the binary this source builds will hold."""
    text = TRUST_SOURCE.read_text()
    found = re.findall(r'pub const RELEASE_PUBLIC_KEY: &str = "([^"]*)";', text)
    if len(found) != 1:
        refuse(f"found {len(found)} declarations of RELEASE_PUBLIC_KEY in {TRUST_SOURCE}")
    return found[0]


def public_key_of(key_path):
    """The raw 32 bytes of an ed25519 key's public half, in hex: DER ends with them."""
    der = subprocess.run(["openssl", "pkey", "-in", str(key_path), "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
    if len(der) != 44:
        refuse(f"{key_path} is not an ed25519 key")
    return der[-32:].hex()


def check_keys(keys, publish):
    for key in keys:
        resolved = Path(key).resolve()
        if resolved.is_relative_to(ROOT):
            refuse(f"the private key {key} is inside the repository, and it must never be")
        if not resolved.is_file():
            refuse(f"no key file at {key}")
    if not publish:
        return
    if not keys:
        refuse("--publish needs a --key")
    built_in = built_in_key()
    public = [public_key_of(k) for k in keys]
    if built_in not in public:
        refuse(f"the binary's built-in key is {built_in!r}, and no --key is that key: every copy of this release would refuse its own manifest")


def cargo_scope():
    """The memory cap every heavy build here runs in."""
    if shutil.which("systemd-run") and not os.environ.get("N0XIS_RELEASE_SCOPED"):
        return ["systemd-run", "--user", "--scope", "-q", "--nice=19", "-p", "MemoryMax=6G", "--"]
    return []


def build():
    """The four binaries. Returns a function from (cargo target, file name) to its path."""
    for target in sorted({entry[2] for platforms in COMPONENTS.values() for entry in platforms.values()}, key=str):
        cmd = [*cargo_scope(), "cargo", "build", "--release", "-p", "n0xis-cli", "-p", "n0xis-mcp"]
        cmd += ["--target", target] if target else []
        print(f"build: {target or 'host'}", flush=True)
        run(*cmd, cwd=ROOT)
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    return lambda target, name: target_dir / (Path(target) / "release" if target else "release") / name


def assemble(out, locate, base_url):
    """Copy the binaries to their asset names and write sha256sums.txt. Returns the manifest."""
    components = {}
    sums = []
    for component, platforms in COMPONENTS.items():
        for platform, (asset, installed, target, built) in platforms.items():
            source = locate(target, built)
            if not source.is_file():
                refuse(f"{source} is not there")
            shutil.copyfile(source, out / asset)
            os.chmod(out / asset, 0o755)
            data = (out / asset).read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            sums.append(f"{digest}  {asset}\n")
            components.setdefault(component, {})[platform] = {"url": f"{base_url}/{asset}", "size": len(data), "sha256": digest, "file": installed}
    (out / "sha256sums.txt").write_text("".join(sorted(sums, key=lambda line: line.split()[1])))
    return components


def sign(out, keys):
    """manifest.json.sig: one line of hex per key, each checked before it is written."""
    manifest = out / "manifest.json"
    lines = []
    with tempfile.TemporaryDirectory() as temp:
        for n, key in enumerate(keys):
            raw = Path(temp) / f"{n}.sig"
            public = Path(temp) / f"{n}.pub"
            run("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(manifest), "-out", str(raw))
            run("openssl", "pkey", "-in", str(key), "-pubout", "-out", str(public))
            run("openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public), "-in", str(manifest), "-sigfile", str(raw), stdout=subprocess.DEVNULL)
            lines.append(raw.read_bytes().hex())
    (out / "manifest.json.sig").write_text("\n".join(lines) + "\n")


def release_notes(version):
    """This version's section of the changelog; a release with none is a refusal."""
    text = (ROOT / "CHANGELOG.md").read_text()
    found = re.search(rf"^## \[{re.escape(version)}\].*?(?=^## \[|\Z)", text, re.M | re.S)
    if not found:
        refuse(f"CHANGELOG.md has no section for {version}")
    return found.group(0)


def publish(tag, version, out):
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, check=True, capture_output=True, text=True).stdout
    if status.strip():
        refuse("the work tree has changes, so what was built is not what the tag would name")
    exists = subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"], cwd=ROOT, capture_output=True).returncode == 0
    if exists:
        refuse(f"the tag {tag} already exists")
    notes = out / "notes.md"
    notes.write_text(release_notes(version))
    run("git", "tag", tag, cwd=ROOT)
    run("git", "push", PUSH_TO, f"refs/tags/{tag}", cwd=ROOT)
    assets = [str(p) for p in sorted(out.iterdir()) if p != notes]
    run("gh", "release", "create", tag, "--repo", REPOSITORY, "--draft", "--title", tag, "--notes-file", str(notes), *assets)
    run("gh", "release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest")
    print(f"published {tag}. The manifest for the project's own domain is {out / 'manifest.json'}, with its .sig")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tag", required=True, help="the release tag, e.g. v0.3.8")
    ap.add_argument("--key", action="append", default=[], help="an ed25519 private key file outside the repository; twice to co-sign across a change of key")
    ap.add_argument("--next-key", help="the public key (64 hex digits) the next releases will be signed by")
    ap.add_argument("--out", help="where the release is assembled (default target/release-<tag>)")
    ap.add_argument("--publish", action="store_true", help="tag and create the release; the default is a dry run")
    ap.add_argument("--prebuilt", help="take the binaries from this directory, by their asset names, instead of building")
    ap.add_argument("--base-url", help="where the manifest says the files are (default this tag's release)")
    args = ap.parse_args()

    version = workspace_version()
    if args.tag != f"v{version}":
        refuse(f"the tag {args.tag} is not the workspace version {version}")
    if args.publish and (args.prebuilt or args.base_url):
        refuse("a published release is built here and lives at its own address")
    if args.next_key and not re.fullmatch(r"[0-9a-f]{64}", args.next_key):
        refuse("--next-key is 64 lower-case hex digits")
    check_keys(args.key, args.publish)
    if args.publish:
        release_notes(version)
    base_url = (args.base_url or f"https://github.com/{REPOSITORY}/releases/download/{args.tag}").rstrip("/")
    if not base_url.startswith("https://"):
        refuse("the client refuses anything but https, so a manifest naming anything else would be dead")

    out = Path(args.out) if args.out else ROOT / "target" / f"release-{args.tag}"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    if args.prebuilt:
        prebuilt = Path(args.prebuilt)
        by_built = {(entry[2], entry[3]): entry[0] for platforms in COMPONENTS.values() for entry in platforms.values()}
        locate = lambda target, name: prebuilt / by_built[(target, name)]  # noqa: E731
    else:
        locate = build()
    manifest = {"version": version, "components": assemble(out, locate, base_url)}
    if args.next_key:
        manifest["next_key"] = args.next_key
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    if args.key:
        sign(out, args.key)
        print(f"signed by {', '.join(public_key_of(k) for k in args.key)}")
    else:
        print("NOT SIGNED: no --key, so no client would accept this")
    if built_in_key() not in [public_key_of(k) for k in args.key]:
        print(f"NOT PUBLISHABLE: the binary's built-in key is {built_in_key()!r}")

    if args.publish:
        publish(args.tag, version, out)
    else:
        print(f"dry run: {version} assembled in {out}; nothing was tagged or uploaded")


if __name__ == "__main__":
    main()

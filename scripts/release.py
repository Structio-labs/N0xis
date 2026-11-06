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
- A change of key that strands older copies: a key the binary of any earlier release holds is not among
  the signers, so copies of that release cannot verify this one. --strand-older-copies says that is meant.
- A version below one already tagged. Marked latest, it would be what every client is told, and the copies
  above it would be frozen where they are for as long as it stands.
- A built binary that does not state this version when run, which a stale target directory can give. All
  four are run, the Windows two under wine, and with --publish one that could not be run is a refusal.
- Publishing what this run did not just build (--prebuilt, --base-url exist for the verification).
- Windows files that were not swept on a real Windows: no result of scripts/windows_sweep.py for exactly
  these bytes, or one with a case that failed or a command with no case. Development and CI are not that
  (Wine and a runner run the tests, and nobody runs the commands as a person would). There is no list of
  known failures: --skip-windows-sweep "<reason>" publishes anyway, and the reason goes in the release
  notes, with any failure named beside it, so that whoever downloads it can read why.

Signing goes through the openssl command, so what signs is not what verifies: the client is on ring.
The signature file is lines of hex, one per --key, so that a change of key can be signed by both.

The release goes up as a draft and turns public only once all its files are there, because
`releases/latest/download/manifest.json` is what clients ask for, and a release that is latest and has
no manifest yet would answer them with a 404. If that fails after the tag was pushed, the same command
run again finishes it: a tag at HEAD with no published release is what such a failure leaves.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
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
TRUST_RELATIVE = "crates/n0xis-update/src/trust.rs"
TRUST_SOURCE = ROOT / TRUST_RELATIVE
# How long a built file has to answer --version. Wine starting cold is what it allows for.
RUN_BOUND = 120
# What a Windows sweep is of, and where its results wait. Not in --out, which is cleared on each run and
# uploaded whole; by digest, so that a result can only ever speak for the bytes it ran.
SWEPT_FILES = ("n0xis.exe", "n0xis-mcp.exe")
SWEPTS = ROOT / "target" / "windows-sweep"

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


def key_in(text, where):
    found = re.findall(r'pub const RELEASE_PUBLIC_KEY: &str = "([^"]*)";', text)
    if len(found) != 1:
        refuse(f"found {len(found)} declarations of RELEASE_PUBLIC_KEY in {where}")
    return found[0]


def built_in_key():
    """What the binary this source builds will hold."""
    return key_in(TRUST_SOURCE.read_text(), TRUST_SOURCE)


def version_numbers(text):
    found = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(-.*)?", text)
    return tuple(int(n) for n in found.groups()[:3]) if found else None


def plain_tags():
    """Every `vX.Y.Z` tag as (numbers, tag). Numbers, since v1.2.10 is above v1.2.9 and sorts below it."""
    # An export is no checkout, and a dry run from one has no tags. Publishing needs a checkout anyway.
    tags = subprocess.run(["git", "tag", "--list", "v*"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    return [(tuple(int(n) for n in found.groups()), tag) for tag in tags if (found := re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", tag))]


def key_at(tag):
    """The key the binary of `tag` holds, in lower case, or None.

    None where the tag has no such file or holds what the client cannot read as a key, the placeholder
    among them: nothing in the field can be stranded by a copy that verifies nothing. The client reads
    hex of either case. A file that is there and does not read is a refusal, since it cannot be told.
    """
    unreadable = f"{TRUST_RELATIVE} at {tag} cannot be read, so what its copies can verify cannot be told"
    listed = subprocess.run(["git", "ls-tree", f"refs/tags/{tag}", "--", TRUST_RELATIVE], cwd=ROOT, capture_output=True, text=True)
    if listed.returncode != 0:
        refuse(unreadable)
    if not listed.stdout.strip():
        return None
    shown = subprocess.run(["git", "show", f"refs/tags/{tag}:{TRUST_RELATIVE}"], cwd=ROOT, capture_output=True, text=True, errors="replace")
    if shown.returncode != 0:
        refuse(unreadable)
    key = key_in(shown.stdout, f"{TRUST_RELATIVE} at {tag}")
    return key.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", key) else None


def keys_of_earlier_releases(version):
    """Each distinct key a binary below this version holds, with the newest tag holding it. Every tag and
    not the last: a copy of any of them may still be out there, whatever was published after it."""
    below = sorted(entry for entry in plain_tags() if entry[0] < version_numbers(version))
    return {key: tag for _, tag in below if (key := key_at(tag))}


def public_key_of(key_path):
    """The raw 32 bytes of an ed25519 key's public half, in hex: DER ends with them."""
    der = subprocess.run(["openssl", "pkey", "-in", str(key_path), "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
    if len(der) != 44:
        refuse(f"{key_path} is not an ed25519 key")
    return der[-32:].hex()


def why_not_publishable(keys, version, strand):
    """What stands between these signers and a release, in words, or None. One place for the refusal
    and for what a dry run says about it."""
    public = [public_key_of(k) for k in keys]
    built_in = built_in_key()
    if built_in not in public:
        return f"the binary's built-in key is {built_in!r}, and no --key is that key: every copy of this release would refuse its own manifest"
    # Its own tag is not above it: that is what a failed upload leaves, and check_existing_tag judges it.
    above = [tag for numbers, tag in plain_tags() if numbers >= version_numbers(version) and tag != f"v{version}"]
    if above:
        return f"{', '.join(sorted(above))} already exists, and this release is {version}: as the latest it would hold back every copy above it"
    stranded = {key: tag for key, tag in keys_of_earlier_releases(version).items() if key not in public}
    if stranded and not strand:
        held = "; ".join(f"the binary of {tag} holds the key {key}" for key, tag in stranded.items())
        return f"{held}, and no --key is that key: every copy of it would refuse this release for good. Sign with it as well, or say that is meant with --strand-older-copies"
    return None


def check_keys(keys, publish, version, strand=False):
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
    problem = why_not_publishable(keys, version, strand)
    if problem:
        refuse(problem)


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
    # From cargo: a configuration or a workspace can move it, and a guess could assemble a stale build.
    metadata = subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=ROOT, check=True, capture_output=True, text=True).stdout
    target_dir = Path(json.loads(metadata)["target_directory"])
    return lambda target, name: target_dir / (Path(target) / "release" if target else "release") / name


def states_version(path, version, runner=()):
    """What running it said, or a refusal unless that has this version as a word of it."""
    env = {**os.environ, "WINEDEBUG": "-all"} if runner else None
    try:
        p = subprocess.run([*runner, str(path), "--version"], stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace", timeout=RUN_BOUND, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        refuse(f"{path} did not answer --version: {e}")
    said = p.stdout.strip()
    if p.returncode != 0 or version not in said.split():
        refuse(f"{path} --version said {said!r} (exit {p.returncode}), and this release is {version}: that is not what would be published")
    return said


def check_built(locate, version, publishing):
    """Run all of what was built, because a file with the right name proves nothing about what is in it.
    The field finds out what a file that was not run does, so only a dry run may leave one unrun."""
    for platforms in COMPONENTS.values():
        for _, _, target, built in platforms.values():
            path = locate(target, built)
            if target is None:
                print(f"ran {path} --version: {states_version(path, version)}")
            elif shutil.which("wine"):
                print(f"ran wine {path} --version: {states_version(path, version, runner=('wine',))}")
            elif publishing:
                refuse(f"{path} could not be run, because there is no wine on the path, and what was not run is not published")
            else:
                print(f"NOT RUN: {path}, because there is no wine on the path")


def file_digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sweep_of(locate, version):
    """What the last sweep of this version recorded, or None if it ran other bytes or there was none. A
    record that is there and does not read is a refusal: it would otherwise pass for one or the other."""
    path = SWEPTS / f"{version}.json"
    if not path.is_file():
        return None
    try:
        sweep = json.loads(path.read_text())
        rows, binaries = sweep["rows"], sweep["binaries"]
        known = all(row["result"] in ("passed", "failed", "not-run") for row in rows)
        readable = known and rows and isinstance(sweep["uncovered"], list) and sweep["windows"] and sweep["commands"] > 0
        other = [name for name in SWEPT_FILES if binaries.get(name) != file_digest(locate(WINDOWS, name))]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        refuse(f"the sweep record {path} cannot be read: {e!r}")
    if not readable:
        refuse(f"the sweep record {path} is not a record of a sweep")
    return None if other else sweep


def cases(rows, result):
    return [f"{row['case']} ({row['why']})" if row.get("why") else row["case"] for row in rows if row["result"] == result]


def said_of_windows(locate, version, reason):
    """(what stands between these files and a release, or None; what the release notes say about Windows)."""
    if reason is not None and not reason.strip():
        return "--skip-windows-sweep needs its reason, because the reason is what readers of the release get", ""
    sweep = sweep_of(locate, version)
    failed = cases(sweep["rows"], "failed") if sweep else []
    uncovered = sweep["uncovered"] if sweep else []
    if reason is not None:
        if sweep and not failed and not uncovered:
            return "a clean sweep of these binaries exists, so there is nothing to skip", ""
        note = f"**Not verified on a real Windows for this release:** {reason.strip()}\n"
        if failed or uncovered:
            note += f"Failed there: {'; '.join(failed) or 'none'}. No case for: {', '.join(uncovered) or 'none'}.\n"
        return None, note
    if sweep is None:
        return "no Windows sweep of these exact binaries: run scripts/windows_sweep.py on them, or say why not with --skip-windows-sweep", ""
    if failed:
        return f"the Windows sweep of these binaries failed {len(failed)} cases: {'; '.join(failed[:10])}", ""
    if uncovered:
        return f"the Windows sweep has no case for {len(uncovered)} commands: {', '.join(uncovered[:10])}", ""
    note = f"Run on a real Windows ({sweep['windows']}) on these exact files before publishing: {sweep['commands']} commands, {len(cases(sweep['rows'], 'passed'))} cases, none failed.\n"
    not_run = cases(sweep["rows"], "not-run")
    if not_run:
        note += f"Not run there: {'; '.join(not_run)}.\n"
    return None, note


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


def state_of_the_release(tag):
    """"published", "draft" or None. Anything but gh saying there is none is not knowing, and a refusal."""
    p = subprocess.run(["gh", "release", "view", tag, "--repo", REPOSITORY, "--json", "isDraft"], cwd=ROOT, capture_output=True, text=True)
    if p.returncode == 0:
        return "draft" if json.loads(p.stdout)["isDraft"] else "published"
    if "release not found" in p.stderr:
        return None
    refuse(f"cannot tell whether {tag} is published: {p.stderr.strip()}")


def check_existing_tag(tag):
    """A tag may stay only as what a failed upload left: at HEAD, with no published release."""
    commit = lambda name: subprocess.run(["git", "rev-parse", "-q", "--verify", f"{name}^{{commit}}"], cwd=ROOT, capture_output=True, text=True).stdout.strip()  # noqa: E731
    at = commit(f"refs/tags/{tag}")
    if at != commit("HEAD"):
        refuse(f"the tag {tag} already exists at {at}, and that is not HEAD")
    state = state_of_the_release(tag)
    if state == "published":
        refuse(f"{tag} is already published")
    return state


def say_how_to_recover(tag, out, assets, failed):
    again = shlex.join(["python3", "scripts/release.py", *sys.argv[1:]])
    print(
        f"""refused: {shlex.join(failed.cmd)} failed (exit {failed.returncode}), and no client can see a release yet.

To finish, from this same commit, either run the same command again:
    {again}
or, with what is already in {out}, finish by hand:
    {shlex.join(["gh", "release", "create", tag, "--repo", REPOSITORY, "--draft", "--title", tag, "--notes-file", str(out / "notes.md"), *assets])}
    (or, if the draft exists: {shlex.join(["gh", "release", "upload", tag, "--repo", REPOSITORY, "--clobber", *assets])})
    {shlex.join(["gh", "release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest"])}

To give up on this tag instead:
    {shlex.join(["gh", "release", "delete", tag, "--repo", REPOSITORY, "--yes"])}
    {shlex.join(["git", "push", PUSH_TO, f":refs/tags/{tag}"])}
    {shlex.join(["git", "tag", "-d", tag])}""",
        file=sys.stderr,
    )
    sys.exit(1)


def publish(tag, version, out, of_windows=""):
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, check=True, capture_output=True, text=True).stdout
    if status.strip():
        refuse("the work tree has changes, so what was built is not what the tag would name")
    exists = subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"], cwd=ROOT, capture_output=True).returncode == 0
    state = check_existing_tag(tag) if exists else None
    notes = out / "notes.md"
    notes.write_text(f"{release_notes(version).rstrip()}\n\n{of_windows}" if of_windows else release_notes(version))
    assets = [str(p) for p in sorted(out.iterdir()) if p != notes]
    try:
        if not exists:
            run("git", "tag", tag, cwd=ROOT)
        run("git", "push", PUSH_TO, f"refs/tags/{tag}", cwd=ROOT)
        if state == "draft":
            run("gh", "release", "upload", tag, "--repo", REPOSITORY, "--clobber", *assets)
        else:
            run("gh", "release", "create", tag, "--repo", REPOSITORY, "--draft", "--title", tag, "--notes-file", str(notes), *assets)
        run("gh", "release", "edit", tag, "--repo", REPOSITORY, "--draft=false", "--latest")
    except subprocess.CalledProcessError as failed:
        say_how_to_recover(tag, out, assets, failed)
    print(f"published {tag}. The manifest for the project's own domain is {out / 'manifest.json'}, with its .sig")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tag", required=True, help="the release tag, e.g. v0.3.8")
    ap.add_argument("--key", action="append", default=[], help="an ed25519 private key file outside the repository; twice to co-sign across a change of key")
    ap.add_argument("--next-key", help="the public key (64 hex digits) the next releases will be signed by")
    ap.add_argument("--out", help="where the release is assembled (default target/release-<tag>)")
    ap.add_argument("--publish", action="store_true", help="tag and create the release; the default is a dry run")
    ap.add_argument("--strand-older-copies", action="store_true", help="publish though no --key is a key an earlier release holds, so that its copies refuse this one for good")
    ap.add_argument("--skip-windows-sweep", metavar="REASON", help="publish without a clean sweep of these binaries on a real Windows; the reason goes in the release notes")
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
    check_keys(args.key, args.publish, version, args.strand_older_copies)
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
        check_built(locate, version, args.publish)
    manifest = {"version": version, "components": assemble(out, locate, base_url)}
    windows_problem, of_windows = said_of_windows(locate, version, args.skip_windows_sweep)
    if windows_problem and args.publish:
        refuse(windows_problem)
    if args.next_key:
        manifest["next_key"] = args.next_key
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    if args.key:
        sign(out, args.key)
        print(f"signed by {', '.join(public_key_of(k) for k in args.key)}")
    else:
        print("NOT SIGNED: no --key, so no client would accept this")
    problem = why_not_publishable(args.key, version, args.strand_older_copies)
    if problem:
        print(f"NOT PUBLISHABLE: {problem}")
    if windows_problem:
        print(f"NOT PUBLISHABLE: {windows_problem}")

    if args.publish:
        publish(args.tag, version, out, of_windows)
    else:
        print(f"dry run: {version} assembled in {out}; nothing was tagged or uploaded")


if __name__ == "__main__":
    main()

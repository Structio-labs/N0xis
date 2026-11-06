# Updates: the tool offers, the user decides

Status: accepted 2026-11-05 in its form (the owner: offer the update, the user decides). Built in `crates/n0xis-update`, with the release side in `scripts/release.py`.

## 1. What it does

Today there is no update mechanism and no network client in the tree: a user downloads a release by hand.

- **It never replaces itself unasked.** A binary swapped under a running script or a long server session is a
  different tool mid-work.
- **It never asks a question at the terminal,** because a prompt hangs any script.
- **In a terminal,** at most once a day, one line on stderr: `[n0x] 0.3.7 is available: n0x update`. The check
  never delays a command: its result is shown by a later run.
- **In a script or a pipe,** nothing: no request and no line, unless asked. "A terminal" means standard error is one, so `2>&1`, CI and a scheduler stay silent, and `--quiet` silences it anywhere. The line never goes to standard output, the JSON is untouched, and the exit code never depends on the check. A test holds each of these.
- `n0x update --check` answers in the usual envelope, for the GUI and for anything else that wants to ask.
- **The GUI** asks through that same command and shows its own dialog, so there is no second copy of the logic. It needs nothing here beyond that, and the CLI does not wait for it.
- **The MCP server** interrupts nothing during a session: its version, and that a newer one exists, are in what it states at the start.
- `n0x update` installs, `n0x update --rollback` goes back.
- Settings, with a command to read and change them (`n0x config get`, `n0x config set`; there is none today, only a
  project's own configuration), kept in the user's configuration directory, one file the GUI also reads through
  the same command, never a copy of its own:
  - `update.check`, on by default: the daily check and the line above. `N0X_NO_UPDATE_CHECK=1` also turns it off.
    It is the only request the tool makes on its own, it carries nothing about what is being analysed, and the
    README says so.
  - `update.auto`, off by default: install without being asked, for whoever turns it on. The new binary is put in
    place by the check's own process, between runs, under the same checks as `n0x update`; a run already started
    keeps the file it started from, and the previous binary stays for `--rollback`. A notice says what was installed.
- **A configuration directory that is not yours does not exist.** On Unix the directory, or its nearest existing ancestor,
  must be owned by the effective user and not be writable by everyone, or it is treated as absent: the defaults with
  `update.auto` off, no remembered keys, no stamp and so no daily check, no detached process, no writes. An explicit
  `update` and `--rollback` still work, from the built-in key and the two frozen addresses. `config set` refuses as
  `config-not-yours` and `config get` says what it goes by. One function decides this, and everything reaches the
  directory through it, the override included, so `sudo -E` reads nothing of the user's.

## 2. The contract, which cannot be changed later

A copy in the field cannot be repaired by shipping a repair, so what a client computes about where things come
from is frozen when it ships. **The client asks; it never derives.**

- Each release publishes `manifest.json`: its version, and for each component and platform the file's URL, size
  and sha256. A component is a whole file: `n0xis` and `n0xis-mcp` are two self-contained binaries of about 13 MB, each replaced only when it changed. Deltas are not worth their complexity at that size. A later GUI or a signature pack is one more entry. Unknown fields are ignored, so it can grow: binary deltas, if size ever calls for them, are an optional field beside the whole file, which is always published, so a delta only ever speeds things up and an old client is never stranded. File names and layouts are not in the client.
- The only thing frozen in the client is the manifest's address, and the repository has moved before. So it is a
  domain the project controls, serving that one static file, with GitHub as the second address and an override in the
  configuration. The binaries stay in the releases, named by the manifest. No login is needed: the repository is public.
- The manifest is signed (ed25519). A digest from the same place guards against damage, not against a stolen
  token, and this is a tool that runs on the user's machine. The public keys are in the binary, the private key
  never leaves the owner's machine, and a signed manifest can name the next key, so a key can be replaced.
- No digest or no valid signature means no install, reported as itself: an unperformed check never reads as a
  passed one.
- One declaration of the version: a release refuses to publish if the tag and the workspace version differ.
- The four asset names the README links stay published beside the manifest.

### The form it took

What every shipped client reads, and so what every later release must keep publishing:

```json
{ "version": "0.3.8",
  "next_key": "<optional: 64 hex digits, the ed25519 public key the next releases are signed by>",
  "components": {
    "n0xis": { "linux-x86_64": { "url": "https://…", "size": 13000000, "sha256": "<64 hex>", "file": "n0xis" },
               "windows-x86_64": { "url": "https://…", "size": 13000000, "sha256": "<64 hex>", "file": "n0xis.exe" } },
    "n0xis-mcp": { "…": "the same" } } }
```

- `manifest.json.sig`, beside the manifest wherever it is: lines of hex, one ed25519 signature of the manifest's exact bytes
  on each. Any line verifying under any key held is enough, and a line that does not read as a signature is skipped.
- `version` is semver. `components` is required, and an entry is read only when this client is about to use it, so a later
  component of another shape cannot make the document unreadable.
- `file` is the name the file has when installed. A component other than the running one is replaced only if a file of that name
  is already beside the binary, and one with no `file` is left alone, so a later component is never added to an old client's directory.
- **A next key is remembered as the signed statement that named it.** `update-keys.json` in the user's configuration directory
  holds `{"chain":[{"manifest":"<hex of the exact bytes>","signature":"<the .sig text>"}]}`, at most 1 MiB and 32 records. On
  load the client starts from the key in the binary and walks in order: a record that verifies under the keys so far and names a
  `next_key` adds it, and anything else is skipped. So writing that file grants nothing, and it does nothing under the placeholder.
  A client that never saw that manifest verifies by the old key for as long as a release is signed by both; one that sees neither
  fetches by hand. Nothing revokes a key in a copy already shipped.
- **Every frozen address is asked, and the highest version that verifies is the answer.** The next keys of each verified manifest
  are remembered, whether or not it was the highest. An override, when set and verified, decides alone: that is the user's explicit
  pin, and nothing else is asked. An address that answers with anything that does not verify is passed over like a dead one: beside a
  success it is a line in `tried`, and the refusal when none answers is the most serious thing any of them did.
- **What this does not stop:** whoever holds both addresses can hold a copy at any version that was ever published, by serving an
  old signed manifest at both. Nothing expires, because an expiry would strand copies whenever releases pause.

## 3. The install

Prepare, then commit, under one lock. There is no undo: undoing was disk work done while swapping, it failed
on a full disk, and it poisoned the file `--rollback` goes back to.

**The lock.** `<file>.update-lock` beside the running binary, taken by `update`, `--rollback` and the detached
`update.auto` install. The kernel releases it on a kill, so it cannot go stale, and the file stays. Held means the refusal
`update-in-progress`, or a silent skip in the detached copy. Under the lock anything of ours beside a file is a dead run's, so it is
swept first, and the names are fixed. On Windows the aside keeps a pid, since a running exe cannot be removed.

**Prepare: every byte on the disk, nothing installed touched.** For each component to change, in full before any commit:

- Download to `<file>.update-new`, created new and mode 0600 whatever the umask.
- After it is closed, read the file back and check size and digest: the digest is of what will be installed, not of the stream.
- For the running component only, execute it: `--version`, standard input null, a bounded time (30 s), a retry on `ETXTBSY`. It must
  exit 0 and print the manifest's version as a word of its output, or the refusal is `does-not-run`. `--rollback` lives inside the file
  being replaced, so a file that cannot start cannot be gone back from. Other components are never executed, since a later one may
  not answer. **Every later `n0xis` must keep answering `--version`.**
- Copy the current file to `<file>.previous-new`, on the disk, hashing as it copies, and write its record to `<file>.previous.json.new`.
- The final mode of both files is the current one masked to 0o777: setuid is not carried over.
- A target or a sibling that is not a regular file after resolving links is refused as `not-a-regular-file`, and a symlinked sibling is
  resolved the way the running binary's path is, so the link stays a link.

Any failure here, a full disk included, removes the temporaries and leaves every installed file byte for byte unchanged, and only
then is that said. A directory the user cannot write to is a refusal naming the file to fetch: never `sudo`.

**Commit: renames only, so no space is needed.** Other components first and the running one last, so that a run killed part way is still
the old binary and running it again finishes the job. For each:

1. `<file>.previous-new` over `<file>.previous`.
2. `<file>.previous.json.new` over `<file>.previous.json`: `{"from":"<version>","to":"<version>","sha256":"<of .previous>"}`. It lives beside
   the file it describes, not in the configuration directory, so two copies do not share one and it needs no configuration.
3. `<file>.update-new` over `<file>`. On Windows a running `.exe` can be renamed and not overwritten, so it is renamed to
   `<file>.aside-<pid>` first; if the second rename fails it is renamed back and that is reported.
4. On Unix, fsync the directory.

**No undo across components.** Each is its own fact. A commit failure on one is `install-failed` with `error.components` stating for each
whether it is in place, and a non-zero exit. Two self-contained binaries at different versions harm nothing.

**Rollback**, under the lock. `.previous` must be a regular file with no link and its sha256 must equal the record's, or the refusal is
`previous-does-not-match` with the target unchanged. If it equals the target, it says nothing changed. Otherwise it renames into place, the record
goes, and the hold on `update.auto` stays where a configuration directory exists. One shot, no roll forward: a second run is `no-previous`.
`from` and `to` come only from a record that matched. The other files of the same install, found as a `<file>.previous.json` beside the binary or behind a link
beside it whose `to` is the same, go back first and each by its own record; a sibling last replaced by an earlier install stays.

**A kill at any point leaves the target as old or new and runnable**, except the one window on Windows between the two renames of step 3,
where for a moment there is no target. That cannot be closed there: a running exe cannot be replaced in one step.

**Accepted:** `cp` over the binary while a detached check runs from it can give `Text file busy`. That needs a terminal, since a script starts no check.

## 4. Where it lives

An adapter crate holds the network client. `n0xis-contracts`, `-arch` and `-core` never depend on it, and the
boundary check holds that. Only the two doors link it, so no analysis path can reach the network.

## 5. Verification

Rung 1, against a local server with planted manifests: a tampered file, a wrong digest, a bad signature, a
truncated download, a claimed size past what is sent, an older version, unknown fields, a dead first address, a stale first
address beside a newer second, a planted key file, a garbage signed file, a file altered on the disk during its download.
Each ends in the stated refusal, with the installed binary byte for byte unchanged. Rollback is run, not assumed,
on Linux and under Wine. A kill at each step and a full disk are run against the real binaries too, outside the repository's tests, since
they need `LD_PRELOAD` and a tmpfs. An old client against a newer manifest is tested by keeping a built old client as a fixture.

## 6. Steps

1. The release side: a script that builds, writes the manifest, signs it, refuses a version mismatch, publishes.
2. `update --check` and `update`, with the planted server.
3. The notice in a terminal.

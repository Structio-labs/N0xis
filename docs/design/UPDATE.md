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
- `n0x update` installs, `n0x update --rollback` goes back, for the running file, and `n0x update --rollback <bare name>` for a file beside it.
- Settings, with a command to read and change them (`n0x config get`, `n0x config set`; there is none today, only a
  project's own configuration), kept in the user's configuration directory, one file the GUI also reads through
  the same command, never a copy of its own:
  - `update.check`, on by default: the daily check and the line above. `N0X_NO_UPDATE_CHECK=1` also turns it off.
    It is the only request the tool makes on its own, it carries nothing about what is being analysed, and the
    README says so.
  - `update.auto`, off by default: install without being asked, for whoever turns it on. The new binary is put in
    place by the check's own process, between runs, under the same checks as `n0x update` and from the manifest that check
    fetched, so there is no second answer to disagree with the first; a run already started keeps the file it started from, and the
    previous binary stays for `--rollback`. A notice says what was installed, written only from what moved, and only by the file that moved: the state is shared by a user's copies and holds that file's path, so
    another copy at that version neither says the line nor uses it up. It holds one install, so with two copies under `update.auto` the later one's line is the one said.
- **A configuration directory that is not yours does not exist.** On Unix the directory, or its nearest existing ancestor,
  must be owned by the effective user and not be writable by everyone, or it is treated as absent: the defaults with
  `update.auto` off, no remembered keys, no stamp and so no daily check, no detached process, no writes. An explicit
  `update` and `--rollback` still work, from the built-in key and the two frozen addresses, and the hold beside the binary still holds. `config set` refuses as
  `config-not-yours` and `config get` says what it goes by. One function decides this, and everything reaches the
  directory through it, the override included, so `sudo -E` reads nothing of the user's.
  It tests write by everyone only, since group-writable directories are common with private user groups and a signature still decides what is
  installed. A group member can set the override and `update.auto`, not a key.
- **A script run in a terminal** gets the daily check, since its standard error is one, and under `update.auto`, which the user turned on, a swap
  can land between its commands.

## 2. The contract, which cannot be changed later

A copy in the field cannot be repaired by shipping a repair, so what a client computes about where things come
from is frozen when it ships. **The client asks; it never derives.**

- Each release publishes `manifest.json`: its version, and for each component and platform the file's URL, size
  and sha256. A component is a whole file: `n0xis` and `n0xis-mcp` are two self-contained binaries of about 13 MB, each replaced only when it changed. Deltas are not worth their complexity at that size. A later GUI or a signature pack is one more entry. Unknown fields are ignored, so it can grow: binary deltas, if size ever calls for them, are an optional field beside the whole file, which is always published, so a delta only ever speeds things up and an old client is never stranded. File names and layouts are not in the client.
- The only thing frozen in the client is the manifest's address, and the repository has moved before. So it is a
  domain the project controls, serving that one static file, with GitHub as the second address. An override in the
  configuration replaces both, which is the way out if both die. The binaries stay in the releases, named by the manifest. No login is
  needed: the repository is public.
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
- **Only the running component's own entry can refuse.** An entry of another component that does not decode, with a file of its name beside
  the binary, makes that component `skipped`, with its code and reason in the answer, and the running file's update goes on with exit 0. A later
  component of a new shape would otherwise stop every old copy. `--check` and `update` agree.
- **A next key is remembered as the signed statement that named it.** `update-keys.json` in the user's configuration directory
  holds `{"chain":[{"manifest":"<hex of the exact bytes>","signature":"<the .sig text>"}]}`, at most 1 MiB and 32 records. On
  load the client starts from the key in the binary and walks in order: a record that verifies under the keys so far and names a
  `next_key` adds it, and anything else is skipped. So writing that file grants nothing, and it does nothing under the placeholder.
  When a key is remembered only the records that walk kept are written back, then the new one, so junk cannot crowd out a real key and a file past
  its bound is cleaned rather than kept. A read that fails for any reason but the file not being there means nothing is written.
  A client that never saw that manifest verifies by the old key for as long as a release is signed by both; one that sees neither
  fetches by hand. Nothing revokes a key in a copy already shipped.
- **Every frozen address is asked, and the highest version that verifies is the answer.** The next keys of each verified manifest
  are remembered, whether or not it was the highest. An address that answers with anything that does not verify is passed over like a dead
  one: beside a success it is a line in `tried`, and the refusal when none answers is the most serious thing any of them did.
- **An override, when set, is the only address.** It replaces the two frozen ones rather than sitting ahead of them: that is the user's explicit
  pin, so nothing else is asked, and a dead or bad pin is a refusal.
- **The highest manifest with no entry for this platform stops there.** It fails closed, as `blocked` with `no-entry`, and the report is true:
  an older manifest elsewhere that does have an entry is not installed instead.
- **What this does not stop:** whoever holds both addresses can hold a copy at any version that was ever published, by serving an
  old signed manifest at both. Nothing expires, because an expiry would strand copies whenever releases pause.

## 3. The install

Prepare, then commit, under the lock. There is no undo: undoing was disk work done while swapping, it failed
on a full disk, and it poisoned the file `--rollback` goes back to.

**The lock.** `<file>.update-lock` beside each file, taken by `update`, `--rollback` and the detached `update.auto` install. An install takes the running
file's and then each sibling's, and a rollback only that of the file it goes back for. The kernel releases it on a kill, so it cannot go stale, and the
file stays. Held means the refusal `update-in-progress`, a sibling `skipped`, or a silent skip in the detached copy. A stalled download can hold it for its
bound, and a rollback in that time says `update-in-progress`, which is true.

**Under the lock, exact names only.** `<file>.update-new`, `<file>.previous-new`, `<file>.previous.json.new`, `<file>.update-hold-new` and, on Windows only,
`<file>.aside-<digits>` are a dead run's, and are swept. Nothing else is touched by a sweep. On Windows the candidate's name ends in `.exe`, as `<file>.update-new.exe`, since
the process API looks for a name with `.exe` added first, and it is always executed by absolute path. **`<file>.previous` belongs to the updater:** an install replaces
what is there.

**Files read or locked must be ours.** The lock, the record, the hold and `.previous` are opened by one helper: on Unix `O_NOFOLLOW | O_NONBLOCK`, and then a regular file whose owner is the
effective user, or nothing. On Windows, a plain open. So a link, a FIFO and, in a sticky directory, a file another user planted are refusals, rather than being followed, hanging the run with the lock
held, or vouching for each other: `not-ours` at the lock and the hold, and `previous-does-not-match` at the record and `.previous`, which are unusable by someone who cannot replace the binary.
The same makes a file written by `sudo n0x update` unusable by the user's own run, and the other way round, and that is a refusal saying so. A plant at a name an install only renames over, such as
another user's `.previous`, fails that rename: `install-failed`, with the target unchanged.

**The file changed under us.** Before the fetch, the running file's metadata is noted: inode, size and mtime on Unix, size and mtime on Windows. After its lock is taken a difference is the refusal `changed-during-update`, moving
nothing, and a silent skip in the detached copy, so a rollback or another updater landing during a fetch cannot produce a false `from` or move the target to something older. A file already holding what the manifest names is `unchanged` before
this is asked, since moving nothing is true however it got there: a run that waited out another at the lock answers that. Each fetch notes its own, so an install this process made is not its own trigger. Only the running file: a sibling's name
comes from the manifest, so it has no before, and its record states no version that could be false.

**Prepare: every byte on the disk, nothing installed touched.** For each component to change, in full before any commit:

- Download to `<file>.update-new`, created new and mode 0600 whatever the umask.
- After it is closed, read the file back and check size and digest: the digest is of what will be installed, not of the stream.
- For the running component only, execute it: `--version`, standard input null, a bounded time (30 s), a retry on `ETXTBSY`. It must
  exit 0 and print the manifest's version as a word of its output, or the refusal is `does-not-run`. `--rollback` lives inside the file
  being replaced, so a file that cannot start cannot be gone back from. Other components are never executed, since a later one may
  not answer. **Every later `n0xis` must keep answering `--version`.**
- Copy the current file to `<file>.previous-new`, on the disk, hashing as it copies, and write its record to `<file>.previous.json.new`.
- The final mode of both files is the current one masked to 0o777: setuid is not carried over.
- A target that is not a regular file after resolving links is refused as `not-a-regular-file`, and a symlinked sibling is
  resolved the way the running binary's path is, so the link stays a link.

Any failure here for the running file, a full disk included, removes the temporaries and leaves every installed file byte for byte unchanged, and only
then is that said. A directory the user cannot write to is a refusal naming the file to fetch: never `sudo`. **Any problem with a sibling here makes that sibling `skipped`, with its
reason,** its temporaries gone, and the running file goes on. The running file is prepared first, so it is never the one left behind by a sibling.

**What `update.auto` reads under the lock.** Only local things: each file's hold, and the file. It acts on the manifest its check fetched, only when that version is newer than the running one,
so there is no second fetch to disagree with the first. A hold at that version or a later one leaves the file alone, and for the running file nothing moves at all; a newer release passes. A hold that does not read is
a refusal rather than nothing to go by.

**Commit: renames only, so no space is needed.** Other components first and the running one last, so that a run killed part way is still
the old binary and running it again finishes the job. For each:

1. `<file>.previous-new` over `<file>.previous`.
2. `<file>.previous.json.new` over `<file>.previous.json`: `{"from":"<version>","to":"<version>","previous_sha256":"<of .previous>","installed_sha256":"<of what step 3 puts in place>"}`. `from` is what the running file states, and `null` for a sibling, which is never executed, so its version is not known.
   It lives beside the file it describes, not in the configuration directory, so two copies do not share one and it needs no configuration.
3. `<file>.update-new` over `<file>`. On Windows a running `.exe` can be renamed and not overwritten, so it is renamed to
   `<file>.aside-<digits>` first; if the second rename fails it is renamed back and that is reported.
4. On Unix, fsync the directory.
5. For an explicit `n0x update`, remove `<file>.update-hold`.

**No undo across components.** Each is its own fact. A commit failure on one is `install-failed` with `error.components` stating for each
whether it is in place, and a non-zero exit. Two self-contained binaries at different versions harm nothing.

**Rollback is one file.** `n0x update --rollback` goes back for the running file, and `n0x update --rollback <bare name>` for the file of that name beside it, by the same function and with that file's own
record, lock and hold. Nothing looks for other records, and nothing else moves: a sibling at another version harms nothing. Under the lock:

1. `.previous` and the record must be ours, as above, and the sha256 of `.previous` must equal the record's `previous_sha256`, or the refusal is `previous-does-not-match` with the target unchanged.
2. The target is hashed. If it equals `.previous`, an install died before its last step, and the answer is that nothing changed. If it is not the record's `installed_sha256`, the refusal is
   `not-what-was-installed`, saying a file was put there by other means: it and `.previous` stay as they are, since going back would destroy a file nothing keeps.
3. **The hold:** `<file>.update-hold`, holding the version rolled back from, is written by rename **before** the swap. If it cannot be written the refusal is `not-writable` and nothing moves. It is beside the binary and
   not in the shared state, so a check in flight has nothing to overwrite and a run with no configuration directory has it too.
4. `.previous` is renamed into place and the record goes. One shot, no roll forward: a second run is `no-previous`.

`from` and `to` come only from a record that matched, and the answer names the one file and the `sha256` of what is there now. A record with no `from` is a sibling's, and its answer states no version: the file and the digest. A kill after the hold and before the swap leaves the target unchanged, and a re-run finishes. A kill after the swap leaves it gone back and held, and a
re-run says `no-previous`. An explicit `n0x update` ends a hold, after it installs.

**A kill at any point leaves the target as old or new and runnable**, except the one window on Windows between the two renames of step 3,
where for a moment there is no target. That cannot be closed there: a running exe cannot be replaced in one step.

**Accepted:**

- `cp` over the binary while a detached check runs from it can give `Text file busy`. That needs a terminal, since a script starts no check.
- A stalled sibling delays the running file up to the download's bound, and an interrupted update installs nothing.
- A sibling that was skipped or failed stays old with the next `update` answering that there is nothing to do, until the next release: the answer is true of the running file.
- A release built on a newer system can raise the glibc floor. Such a client answers `does-not-run` and keeps its file.

## 4. Where it lives

An adapter crate holds the network client. `n0xis-contracts`, `-arch` and `-core` never depend on it, and the
boundary check holds that. Only the two doors link it, so no analysis path can reach the network.

## 5. Verification

Rung 1, against a local server with planted manifests: a tampered file, a wrong digest, a bad signature, a
truncated download, a claimed size past what is sent, an older version, unknown fields, a dead first address, a stale first
address beside a newer second, a planted key file, a garbage signed file, a file altered on the disk during its download, a target put there by hand, a link, a FIFO and another user's file beside the binary,
a later-shaped sibling, a dead override with no public request, a server that changes its answer between fetches, a rollback and another updater landing during a fetch.
Each ends in the stated refusal, with the installed binary byte for byte unchanged. Rollback is run, not assumed,
on Linux and under Wine. A kill at each step and a full disk are run against the real binaries too, outside the repository's tests, since
they need `LD_PRELOAD` and a tmpfs. An old client against a newer manifest is tested by keeping a built old client as a fixture.

Rung 2, the release as published. A client built as an older version with the real key, against real GitHub, from the first release that holds it (0.3.8), on Linux and on
a real Windows 11 with its realtime antivirus on: the dead first address is passed over and the second answers, in a pipe nothing is said and no check starts, on a real
console the first run says nothing and a later one says the line, both files install byte for byte as the manifest names them and then run, and rollback, by itself and by
name, restores each. On Windows also: an install with the MCP server running, which goes on running; `update.auto` installing from the detached check and saying so on a
later run, and leaving alone a version just rolled back from; and a directory the user may not write, refused with the file unchanged. Not run on real Windows: a kill between
its two renames. The leftover `.aside-<pid>` of a running exe stays until the next install sweeps it.

## 6. Steps

1. The release side: a script that builds, writes the manifest, signs it, refuses a version mismatch, publishes. It finds the target directory through `cargo metadata` and runs all four built files with `--version`, standard input null and in a bounded time, the two `.exe` under `wine`, and refuses unless each states this version. With `--publish`
   a file that could not be run is a refusal, and only a dry run may print `NOT RUN`. **A key change must not strand older copies:** each distinct key at every plain `vX.Y.Z` tag below this version must be among the signers, unless `--strand-older-copies` says
   otherwise. No such file, or a placeholder, gives no constraint, and a file that cannot be read refuses. **Never below the highest:** a version not above every plain `vX.Y.Z` tag is refused, its own tag apart, which is what a failed upload leaves. A failed
   upload after the tag was pushed prints the commands that recover, and a re-run accepts a tag at HEAD with no published release.
   **The files that go out were run on a real Windows first.** `python3 scripts/windows_sweep.py --dir target/release-vX.Y.Z` is the step between the dry run and `--publish`. It copies those files to a scratch directory on the machine `--host` names, runs every command the binary's help lists, and writes `target/windows-sweep/X.Y.Z.json`, with the digests of what actually ran, read back from that machine. `release.py` refuses `--publish` on a record of other bytes, or one with a failed case or a command with no case; `--skip-windows-sweep "<reason>"` publishes anyway and puts the reason, and any failure, in the notes. There is no list of known failures. A case ends `passed` or `failed` by what it stated beforehand, or `not-run` with a reason in plain words, and those go in the public notes. A machine that drops off mid-run leaves no record. Inputs are built from `scripts/windows-sweep/` at the start of each run. Real programs come from `--images`, and their absence is `not-run`.
2. `update --check` and `update`, with the planted server.
3. The notice in a terminal.

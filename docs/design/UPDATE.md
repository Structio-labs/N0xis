# Updates: the tool offers, the user decides

Status: accepted 2026-11-05 in its form (the owner: offer the update, the user decides). Nothing is built yet.

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

## 3. The install

The file downloads next to the binary, then size, digest and signature are checked, and only then does it move
into place by rename. The previous binary stays beside it for `--rollback`; startup never deletes it, or rollback
would be unreachable by construction. On Windows a running `.exe` cannot be overwritten but can be renamed, so it
is moved aside first. A directory the user cannot write to is a refusal naming the file to fetch: never `sudo`.

## 4. Where it lives

An adapter crate holds the network client. `n0xis-contracts`, `-arch` and `-core` never depend on it, and the
boundary check holds that. Only the two doors link it, so no analysis path can reach the network.

## 5. Verification

Rung 1, against a local server with planted manifests: a tampered file, a wrong digest, a bad signature, a
truncated download, a claimed size past what is sent, an older version, unknown fields, a dead first address.
Each ends in the stated refusal, with the installed binary byte for byte unchanged. Rollback is run, not assumed,
on Linux and under Wine. An old client against a newer manifest is tested by keeping a built old client as a fixture.

## 6. Steps

1. The release side: a script that builds, writes the manifest, signs it, refuses a version mismatch, publishes.
2. `update --check` and `update`, with the planted server.
3. The notice in a terminal.

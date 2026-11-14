# Feedback: what is sent, and what happens to it

`n0x feedback "what happened"` writes a report to the project. This note says what a report holds, where it goes, how
long it is kept, and how to have it deleted.

## Nothing is sent unless you send it

- `n0x feedback "text"` sends nothing. It shows the report as JSON, exactly the bytes that would be sent, and saves
  them: in the project's `.n0x/feedback/` when you are in a project, otherwise in the system's temporary directory. It
  also prints a link to open an issue in the public repository with your text filled in, and an address to write to.
- `n0x feedback "text" --send` sends it. Only then.
- Nothing sends a report on its own. There is no telemetry, no MCP tool and no server method for feedback.

## What a report holds

```json
{"schema":1,"version":"0.3.9","os":"linux","arch":"x86_64","text":"what you wrote","attachments":[{"type":"png","size":48213,"sha256":"…"}]}
```

- the report format's version, the tool's version, the operating system family (`linux`, `windows`, `macos`) and the
  processor architecture: no OS release, no build, no machine name;
- your text, at most 64 KiB;
- for each file you name with `--attach`: its type, size and sha256, and its bytes are sent after the JSON. Only PNG
  and JPEG are taken, decided by the file's bytes, at most 10 MiB each. The file's name is not sent. A screenshot can
  show anything that was on the screen, so look at it before you attach it.

**Nothing about what you analyse:** no path, no file name, no bytes, no strings, no addresses, nothing from the
project's `.n0x/`. The report has no field for any of it, and the receiver refuses a report with any field it does
not know. Your text is yours: what you write is sent as written.

**Nothing that identifies you or the machine:** no account, no identifier, no fingerprint. The request carries the
tool's version as its user agent.

## Where it goes

To a small service on a server in Germany (EU), behind HTTPS. Its address is not built into the tool: the tool reads
it from the signed release manifest it also checks for updates, so a release that publishes no address sends nothing
and says so. Before it posts, the tool asks the service for a one-time number and does a small amount of computation
on it (a proof of work), which costs one person nothing and makes sending thousands expensive.

Your IP address is seen by the server, as for any connection. It is held in memory only, for the rate limit, and is
never written down with a report or anywhere else.

## How long it is kept

On the server, until the project's own machine fetches it, which is daily; it is deleted from the server once the
copy fetched has been checked against its digest. The server holds a fixed amount of space for reports, and when it
is full it answers that and stores nothing.

On the project's machine, the report is kept for as long as the problem it describes is being worked on.
<!-- OPEN: the retention period on the owner's machine is the owner's to set. -->

Reports are never published or shown anywhere.

## How to have a report deleted

A sent report has an id: `n0x feedback --send` prints it as `data.sent.id`. Write to
[structio.dev@gmail.com](mailto:structio.dev@gmail.com) with that id and it will be deleted, from the server if it is
still there and from the project's machine. Without the id, say roughly when you sent it and what it said.

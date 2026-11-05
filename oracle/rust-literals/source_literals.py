#!/usr/bin/python3 -I
"""Item 3: literals from the .rs source against `strings` rows, on one engine.

usage: heldout.py ENGINE IMAGE SRC_DIR [--list N]

The reader takes string literals of at least 4 characters out of the .rs files:
plain "..." with Rust's escapes, r"..." / r#"..."#, skipping comments and char
literals. It decodes `\\\n` continuations as Rust does. b"..." is left out: bytes
are not text and need not print.

Measured, against the image's non-code sections read by the engine:
  in_binary : literals found as a substring of the image's file bytes
  exact     : of those, reported exactly as a row
  wrong_cut : a cut (row start or end inside a run the engine read) strictly inside
              a literal occurrence, with no other literal starting or ending there.

A format string split by the compiler has pieces, so a literal with `{` is split
at its `{...}` placeholders and `{{`/`}}`, each piece a literal of its own. The
whole also stays a candidate: not every string with a brace goes through format!.
"""
import json, os, re, subprocess, sys

def literals_of(src):
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith('//', i):
            j = src.find('\n', i)
            i = n if j < 0 else j
            continue
        if src.startswith('/*', i):
            d, i = 1, i + 2
            while i < n and d:
                if src.startswith('/*', i): d += 1; i += 2
                elif src.startswith('*/', i): d -= 1; i += 2
                else: i += 1
            continue
        if c == "'":
            # A char literal or a lifetime.
            m = re.match(r"'(\\.[^']*|[^\\'])'", src[i:i + 12])
            if m: i += m.end()
            else: i += 1
            continue
        m = re.match(r'(b?)r(#*)"', src[i:i + 40])
        prev = src[i - 1] if i else ' '
        if m and not (prev.isalnum() or prev == '_'):
            close = '"' + m.group(2)
            j = src.find(close, i + m.end())
            if j < 0: break
            if not m.group(1): out.append(src[i + m.end():j])
            i = j + len(close)
            continue
        if c == '"':
            is_bytes = prev == 'b' and not (i >= 2 and (src[i - 2].isalnum() or src[i - 2] == '_'))
            i += 1
            buf = []
            while i < n and src[i] != '"':
                ch = src[i]
                if ch != '\\':
                    buf.append(ch); i += 1; continue
                e = src[i + 1]
                i += 2
                if e == '\n':
                    while i < n and src[i] in ' \t\n\r': i += 1
                elif e == 'n': buf.append('\n')
                elif e == 't': buf.append('\t')
                elif e == 'r': buf.append('\r')
                elif e == '0': buf.append('\0')
                elif e == 'x': buf.append(chr(int(src[i:i + 2], 16))); i += 2
                elif e == 'u':
                    j = src.index('}', i)
                    buf.append(chr(int(src[i + 1:j].replace('_', ''), 16))); i = j + 1
                else: buf.append(e)
            i += 1
            if not is_bytes: out.append(''.join(buf))
            continue
        i += 1
    return out

def format_pieces(text):
    if '{' not in text and '}' not in text:
        return []
    pieces, cur, i = [], [], 0
    while i < len(text):
        if text.startswith('{{', i) or text.startswith('}}', i):
            cur.append(text[i]); i += 2
        elif text[i] == '{':
            j = text.find('}', i)
            if j < 0: return pieces
            pieces.append(''.join(cur)); cur = []; i = j + 1
        else:
            cur.append(text[i]); i += 1
    pieces.append(''.join(cur))
    return pieces

def main():
    engine, image, src_dir = sys.argv[1:4]
    show = int(sys.argv[sys.argv.index('--list') + 1]) if '--list' in sys.argv else 0
    lits = set()
    files = 0
    for d, _, fs in os.walk(src_dir):
        for f in fs:
            if not f.endswith('.rs'): continue
            files += 1
            try: text = open(os.path.join(d, f), encoding='utf-8').read()
            except UnicodeDecodeError: continue
            for l in literals_of(text):
                lits.add(l)
                lits.update(format_pieces(l))
    lits = {l.encode('utf-8', 'surrogatepass') for l in lits if len(l) >= 4 and '\0' not in l}
    p = subprocess.run([engine, 'strings', '--file', image, '--limit', '0', '--encoding', 'utf8', '--min', '1'], cwd=os.environ.get('N0XIS_MEASURE_DIR', os.getcwd()), capture_output=True, text=True)
    d = json.loads(p.stdout)
    assert d['ok'], d
    rows = d['data']['strings']
    blob = open(image, 'rb').read()
    in_binary = {l for l in lits if l in blob}
    texts = {r['text'].encode() for r in rows}
    exact = in_binary & texts
    # All occurrences of each literal in the concatenated rows' runs: a run is what
    # adjacent rows make up, joined back where the addresses meet.
    rows.sort(key=lambda r: int(r['address'], 16))
    runs = []
    for r in rows:
        a = int(r['address'], 16)
        if runs and runs[-1][0] + len(runs[-1][1]) == a:
            runs[-1][1].extend(r['text'].encode())
        else:
            runs.append([a, bytearray(r['text'].encode())])
    # Occurrences of literals inside the runs, with their extents.
    starts, ends, spans = set(), set(), []
    # Scan fast: a substring search per literal over one joined buffer.
    joined = bytearray()
    index = []  # (offset in joined, address)
    for a, b in runs:
        index.append((len(joined), a, len(b)))
        joined.extend(b); joined.append(0)
    joined = bytes(joined)
    import bisect
    offs = [x[0] for x in index]
    def to_va(o):
        k = bisect.bisect_right(offs, o) - 1
        return index[k][1] + (o - index[k][0])
    for l in in_binary:
        at = joined.find(l)
        while at >= 0:
            va = to_va(at)
            starts.add(va); ends.add(va + len(l)); spans.append((va, va + len(l), l))
            at = joined.find(l, at + 1)
    run_of = {}
    cuts = set()
    prev_end = None
    for r in rows:
        a = int(r['address'], 16)
        if prev_end == a:
            cuts.add(a)
        prev_end = a + r['size']
    spans.sort()
    wrong = []
    for c in sorted(cuts):
        if c in starts or c in ends:
            continue
        hit = [s for s in spans if s[0] < c < s[1]]
        # Only the spans starting within 64 KiB matter; the list is small.
        if hit:
            wrong.append((c, hit[0][2]))
    cut_rows = sum(1 for r in rows if 'cut_by' in r)
    print(json.dumps({
        'image': image.replace(os.path.expanduser('~'), '~'),
        'source_files': files, 'literals_ge4': len(lits), 'in_binary': len(in_binary), 'exact_row': len(exact),
        'rows': len(rows), 'rows_with_cut_by': cut_rows, 'cuts': len(cuts), 'wrong_cuts': len(wrong),
    }))
    for c, l in wrong[:show]:
        print(f'  wrong cut {c:#x} inside {l[:70]!r}')
    if show and '--missed' in sys.argv:
        missed = sorted(in_binary - exact, key=len, reverse=True)
        for l in missed[:show]:
            print(f'  missed {l[:80]!r}')

main()

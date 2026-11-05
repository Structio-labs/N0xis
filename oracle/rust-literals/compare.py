#!/usr/bin/python3 -I
"""Item 4/5: rows of `strings` between two engines on one image.

usage: compare.py OLD NEW IMAGE [--show N]

Every field of each row is compared except `cut_by`, which only the new engine
has; a row that gained `cut_by` is changed anyway, since it was cut. Peak RSS and
wall time per run come from wait4, not from the engine.
"""
import json, os, subprocess, sys, time, resource

def run(engine, image):
    r, w = os.pipe()
    t = time.time()
    pid = os.spawnv(os.P_NOWAIT, '/bin/sh', ['sh', '-c', f'exec "{engine}" strings --file "{image}" --limit 0 --quiet > "{out_file}"'])
    _, _, ru = os.wait4(pid, 0)
    dt = time.time() - t
    os.close(r); os.close(w)
    d = json.load(open(out_file))
    assert d['ok'], d
    return d['data']['strings'], dt, ru.ru_maxrss / 1024

old, new, image = sys.argv[1:4]
show = int(sys.argv[sys.argv.index('--show') + 1]) if '--show' in sys.argv else 50
os.makedirs(os.path.join(os.environ.get('N0XIS_MEASURE_DIR', os.getcwd()), '.n0x'), exist_ok=True)
os.chdir(os.environ.get('N0XIS_MEASURE_DIR', os.getcwd()))
out_file = os.path.join(os.environ.get('N0XIS_MEASURE_DIR', os.getcwd()), f'rows.{os.getpid()}.json')
a, ta, ma = run(old, image)
b, tb, mb = run(new, image)
os.unlink(out_file)
key = lambda r: tuple(sorted((k, json.dumps(v)) for k, v in r.items()))
sa, sb = {key(r): r for r in a}, {key(r): r for r in b}
gone = [sa[k] for k in sa if k not in sb]
came = [sb[k] for k in sb if k not in sa]
print(f'{os.path.basename(image)}: old rows {len(a)} new rows {len(b)}; rows gone {len(gone)} rows new {len(came)}; '
      f'old {ta:.2f}s {ma:.0f} MiB new {tb:.2f}s {mb:.0f} MiB')
gone.sort(key=lambda r: int(r['address'], 16))
came.sort(key=lambda r: int(r['address'], 16))
for r in came[:show]:
    print(f"  + {r['address']} {r['section']} {r.get('cut_by')} {r['text'][:60]!r}")
for r in gone[:show]:
    print(f"  - {r['address']} {r['section']} {r['text'][:60]!r}")

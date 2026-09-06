import json,subprocess,sys
N0X='/run/media/tim/Opus/Projects/N0x/target/release/n0xis'
exe=sys.argv[1]
d=json.loads(subprocess.run([N0X,'function','eh','--file',exe,'--quiet'],capture_output=True,text=True).stdout)['data']
fs=d['functions']; h=lambda x:int(x,16)
starts={h(f['va']) for f in fs}
bad=cont=pads=padfn=0
for f in fs:
    a,e=h(f['va']),h(f['end'])
    for r in f.get('regions') or []:
        ts,te,lp=h(r['try_start']),h(r['try_end']),h(r['landing_pad'])
        pads+=1
        cont+= 1 if a<=ts<te<=e else 0
        bad += 0 if a<=ts<te<=e else 1
        padfn+= 1 if lp in starts else 0
lr=subprocess.run(['llvm-readobj','--unwind',exe],capture_output=True,text=True).stdout
print(f'{exe.split("/")[-1]}')
print(f'  functions={len(fs)}  llvm-readobj={lr.count("RuntimeFunction {")}  {"MATCH" if len(fs)==lr.count("RuntimeFunction {") else "MISMATCH"}')
print(f'  regions={pads}  contained={cont}  outside={bad}   landing pads that are themselves a RUNTIME_FUNCTION start: {padfn}/{pads}')

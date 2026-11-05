"""Rough ceiling: which non-global missed Kvasir facts could a parameter/return TYPE fix?

Classifies every Kvasir fact tier 10 misses at a function program point by the
DWARF type of the parameters it mentions and by what the tracer declared for
them. DWARF is read here for SCORING only.

Usage (from the repo root, after ground_truth.py on the suite binaries):
    python3 scripts/rea_eval/hint_ceiling.py SUITE_TRUTH.jsonl
"""
import json,os,re,sys,collections
sys.path.insert(0,'scripts')
from score_invariants import score
T={}
for l in open(sys.argv[1]):
    t=json.loads(l); T[os.path.basename(t['binary'])[:-4]]=t
def decls(path):
    out=collections.defaultdict(dict); ppt=var=None
    for l in open(path):
        l=l.rstrip('\n')
        if l.startswith('ppt '): ppt=l[4:]; continue
        if l.startswith('variable '): var=l.split(None,1)[1]; continue
        if l.strip().startswith('rep-type') and ppt: out[ppt][var]=l.split()[1]
        if not l.strip(): ppt=None
    return out
def tclass(ty):
    k=ty['kind']
    if k=='pointer':
        p=ty.get('pointee',{}) or {}
        pk=p.get('kind')
        if pk=='int' and p.get('char'): return 'char*'
        if pk=='pointer':
            q=p.get('pointee',{}) or {}
            return 'ptr->ptr->'+('char' if q.get('kind')=='int' and q.get('char') else q.get('kind','?'))
        return 'ptr->'+str(pk)
    if k=='int': return 'unsigned' if ty.get('signed') is False else 'int'
    return k
C=collections.Counter(); ex=collections.defaultdict(list)
for name,t in sorted(T.items()):
    kv=f'bench/ksuite_inv/{name}.kvasir.txt'; tr=f'bench/ksuite_inv/{name}.tracer.t10.txt'
    if not (os.path.exists(kv) and os.path.exists(tr)): continue
    rows,_=score(kv,tr,f'bench/ksuite/{name}.exe')
    D=decls(f'bench/ksuite_traces/{name}.tracer.t10.dtrace')
    fn={f['name']:f for f in t['functions']}
    for r in rows:
        func=re.sub(r"^\.\.|\(\).*$","",r['ppt']); f=fn.get(func)
        if not f: continue
        params=f['params']
        mixed=any(p['type']['kind']=='float' for p in params) and any(p['type']['kind']!='float' for p in params)
        ints=[p for p in params if p['type']['kind']!='float']
        d=D.get(r['ppt'].replace('..','..',1),{}) or D.get(r['ppt'],{})
        roots={p['name']:(i,p['type']) for i,p in enumerate(ints)}
        if f.get('return'): roots['return']=('ret',f['return'])
        for inv in r['missed']:
            if '::' in inv: continue
            toks=[x for x in re.findall(r"\b[A-Za-z_]\w*",inv) if x in roots]
            if not toks: C['no param root']+=1; continue
            if mixed: C['float/int order (unfixable)']+=1; continue
            cl=set()
            for x in toks:
                i,ty=roots[x]; c=tclass(ty)
                an='return' if i=='ret' else f'arg{i}'
                rep=d.get(an)
                sub=[v for v in d if v.startswith(an+'[')]
                if c=='char*':
                    cl.add('H1 char* as string' if rep!='java.lang.String' else 'char* (already string)')
                elif c.startswith('ptr->ptr->char'):
                    cl.add('H5 char** chain')
                elif c in ('ptr->int','ptr->float'):
                    cl.add('H2 scalar pointee array' if not any(v==an+'[..]' and d[v] in ('int[]','double[]') for v in sub) else 'scalar ptr (array present)')
                elif c in ('int','unsigned','enum','bool') and rep=='hashcode':
                    cl.add('H3 scalar typed pointer')
                elif c.startswith('ptr') and rep=='int':
                    cl.add('H3 pointer typed scalar')
                elif c=='unsigned':
                    cl.add('H4 unsigned scalar')
                elif c.startswith('ptr->struct') or c=='struct' or c.startswith('ptr->ptr->struct'):
                    cl.add('struct layout (needs fields)')
                else:
                    cl.add('other:'+c)
            k=' & '.join(sorted(cl)); C[k]+=1
            if len(ex[k])<3: ex[k].append(f'{name}:{func}: {inv}')
tot=sum(C.values())
print('non-global missed',tot)
for k,n in C.most_common(): print(f'{n:5d}  {k}   {ex[k][:2]}')

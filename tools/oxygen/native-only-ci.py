#!/usr/bin/env python3
"""Public-only native rebuild guard and immutable full-run artifact recovery."""
import hashlib, importlib.util, json, os, shutil, stat, subprocess, sys, zipfile
from pathlib import Path, PurePosixPath
R=Path(__file__).resolve().parents[2]
P=json.loads((R/'tools/oxygen/native-only-pins.json').read_text())
def need(v,s):
    if not v:raise ValueError(s)
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()
def git(*x):return subprocess.check_output(['git','-C',str(R),*x],text=True).strip()
def check():
    need(P['ready'] is True,'native plan is not ready')
    subprocess.run(['git','-C',str(R),'merge-base','--is-ancestor',P['base_commit'],'HEAD'],check=True)
    allowed={'.github/workflows/build.yml','tools/oxygen/ci-inputs.json','tools/oxygen/native-only-ci.py','tools/oxygen/native-only-pins.json','build/ntdll-unix/signal_arm64_ios.c'}
    changed=set(git('diff','--name-only',P['base_commit'],'HEAD').splitlines())
    need(changed<=allowed,'unexpected source changes outside reviewed native CI overlay')
    need(sha(R/'build/ntdll-unix/signal_arm64_ios.c')==P['native_source_sha256'],'native source pin mismatch')
    cfg=json.loads((R/'tools/oxygen/ci-inputs.json').read_text())
    need(cfg['source_peer_reviews']['native_split_store']==P['native_peer_go_sha256'],'native review pin mismatch')
    subprocess.run([sys.executable,str(R/'tools/oxygen/verify-ci-inputs.py')],check=True)
    spec=importlib.util.spec_from_file_location('runtime',R/'tools/build/runtime-components.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    # All runtime source globs and gitlinks must still equal the full-build tree.
    paths=set(git('diff','--name-only',P['base_commit']).splitlines())
    import fnmatch
    for name,s in m.CONTRACT.items():
        need(not any(any(fnmatch.fnmatchcase(p,g) for g in s['inputs']) or p in s['pins'] for p in paths),'runtime source inputs changed: '+name)
    return cfg

def recover():
    check();tmp=Path(os.environ['RUNNER_TEMP'])/'native-only-recovery';tmp.mkdir(exist_ok=False)
    records=[]
    for a in P['artifacts']:
        url=f"/repos/{P['repository']}/actions/artifacts/{a['id']}"
        meta=json.loads(subprocess.check_output(['gh','api',url]))
        need(meta['name']==a['name'] and meta['size_in_bytes']==a['bytes'] and meta['expired'] is False and meta['digest']=='sha256:'+a['sha256'],'artifact metadata mismatch')
        need(meta['workflow_run']['id']==P['run_id'] and meta['workflow_run']['head_sha']==P['base_commit'],'artifact source/run mismatch')
        archive=tmp/(str(a['id'])+'.zip')
        with archive.open('xb') as f:subprocess.run(['gh','api',url+'/zip'],stdout=f,check=True)
        need(archive.stat().st_size==a['bytes'] and sha(archive)==a['sha256'],'artifact whole ZIP checksum mismatch')
        dest=R/a['destination'];dest.mkdir(parents=True,exist_ok=True)
        with zipfile.ZipFile(archive) as z:
            seen=set();total=0
            for i in z.infolist():
                p=PurePosixPath(i.filename);mode=i.external_attr>>16;total+=i.file_size
                need(i.filename not in seen and not p.is_absolute() and '..' not in p.parts and '\\' not in i.filename and not stat.S_ISLNK(mode) and not i.flag_bits&1,'unsafe artifact member')
                seen.add(i.filename);need(total<=2*1024**3 and i.file_size<=512*1024**2,'artifact expansion too large')
                target=dest.joinpath(*p.parts);need(dest.resolve()==target.parent.resolve() or dest.resolve() in target.parent.resolve().parents,'artifact path escape')
                need(not target.is_symlink(),'artifact target symlink')
                if i.is_dir():target.mkdir(parents=True,exist_ok=True);continue
                target.parent.mkdir(parents=True,exist_ok=True)
                with z.open(i) as f,target.open('wb') as out:shutil.copyfileobj(f,out,1024*1024)
                if mode&0o777:target.chmod(mode&0o777)
        records.append({k:a[k] for k in ('id','name','bytes','sha256','destination')});archive.unlink()
    (tmp/'receipt.json').write_text(json.dumps({'schema':1,'repository':P['repository'],'run_id':P['run_id'],'base_commit':P['base_commit'],'source_head':git('rev-parse','HEAD'),'sdk':P['sdk'],'artifacts':records},indent=2)+'\n')

def final():
    check();ipa=R/'dist/Madeira.ipa';need(ipa.is_file(),'IPA missing')
    recovery=json.loads((Path(os.environ['RUNNER_TEMP'])/'native-only-recovery/receipt.json').read_text())
    with zipfile.ZipFile(ipa) as z:
        m=json.loads(z.read('Payload/Madeira.app/runtime-build.json'))
        need(m['schema']==1 and m['tree']==git('rev-parse','HEAD^{tree}'),'final source tree mismatch')
        native={i.filename:{'sha256':hashlib.sha256(z.read(i)).hexdigest(),'bytes':i.file_size} for i in z.infolist() if not i.is_dir() and z.open(i).read(4) in (b'\xcf\xfa\xed\xfe',b'\xca\xfe\xba\xbe')}
    receipt={'schema':1,'kind':'source-native-rebuild-over-verified-full-run','source_head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'native_source_sha256':P['native_source_sha256'],'native_peer_go_sha256':P['native_peer_go_sha256'],'ipa_sha256':sha(ipa),'ipa_bytes':ipa.stat().st_size,'runtime_manifest':m,'native_files':native,'artifact_recovery':recovery,'private_inputs':False,'runtime_acceptance':False,'new_UCRT_or_NTDLL_backport_included':False}
    (R/'dist/native-only-receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
if __name__=='__main__':
    need(len(sys.argv)==2 and sys.argv[1] in ('check','recover','final'),'usage: native-only-ci.py check|recover|final')
    {'check':check,'recover':recover,'final':final}[sys.argv[1]]()

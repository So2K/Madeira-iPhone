#!/usr/bin/env python3
"""MIT. Strict public-source/reference/PE gates for a single-UCRT build; no runtime claim."""
import argparse, hashlib, json, os, stat, struct, subprocess, zipfile
from pathlib import Path, PurePosixPath

def need(value, message):
    if not value: raise ValueError(message)
def sha(data): return hashlib.sha256(data).hexdigest()
def git(root, *args): return subprocess.check_output(['git','-C',str(root),*args],text=True).strip()
def write(path, obj):
    with Path(path).open('x') as f: json.dump(obj,f,sort_keys=True,indent=2); f.write('\n')

class PE:
    def __init__(self, data):
        self.b=data
        need(len(data)>=256 and data[:2]==b'MZ','missing/truncated DOS header')
        self.p=self.u('<I',60)[0]
        need(self.take(self.p,4)==b'PE\0\0','missing PE signature')
        self.machine,n=self.u('<HH',self.p+4); size,flags=self.u('<HH',self.p+20)
        self.o=self.p+24
        need(0<n<=96 and size>=240 and flags&0x2000,'invalid DLL/section/optional header')
        need(self.u('<H',self.o)[0]==0x20b and self.u('<I',self.o+108)[0]>=16,'expected PE32+ directories')
        self.base=self.u('<Q',self.o+24)[0]; self.sections=[]
        for i in range(n):
            row=self.u('<8s8I',self.o+size+40*i)
            name,vs,va,raw,ptr,_,_,_,chars=row
            self.take(ptr,raw); self.sections.append((name,va,raw,ptr,chars))
    def take(self, off, size):
        need(0<=off<=len(self.b) and 0<=size<=len(self.b)-off,'PE field outside file')
        return self.b[off:off+size]
    def u(self, fmt, off): return struct.unpack(fmt,self.take(off,struct.calcsize(fmt)))
    def off(self, rva, size=1):
        for _,start,length,raw,_ in self.sections:
            if start<=rva and 0<=size<=length-(rva-start): return raw+rva-start
        raise ValueError('RVA outside file-backed sections')
    def name(self, rva):
        start=self.off(rva); end=self.b.find(b'\0',start,min(start+1024,len(self.b)))
        need(end>=start,'unterminated PE string'); self.off(rva,end-start+1)
        return self.b[start:end].decode('ascii')
    def directory(self, i): return self.u('<II',self.o+112+8*i)
    def executable(self, rva):
        return any(start<=rva<start+length and chars&0x20000000 for _,start,length,_,chars in self.sections)
    def exports(self):
        r,size=self.directory(0); need(r and size>=40,'missing exports')
        row=self.u('<IIHH7I',self.off(r,40)); base,nf,nn,ar,an,ao=row[5:]
        need(0<nn<=nf<=65536,'invalid export counts')
        addresses=self.u('<'+'I'*nf,self.off(ar,4*nf)); names={}; ords={}
        for i,rv in enumerate(addresses):
            if rv:
                self.off(rv); ords[base+i]=self.name(rv) if r<=rv<r+size else None
        for i in range(nn):
            name=self.name(self.u('<I',self.off(an+4*i,4))[0]); j=self.u('<H',self.off(ao+2*i,2))[0]
            need(j<nf and addresses[j] and name not in names,'invalid/duplicate export')
            names[name]={'ordinal':base+j,'forwarder':ords[base+j]}
        return names,ords
    def imports(self, delayed=False):
        r,size=self.directory(13 if delayed else 1); result=[]
        if not r: need(size==0,'inconsistent absent import directory'); return result
        width=32 if delayed else 20
        for i in range(min(size//width,256)):
            row=self.u('<'+'I'*(width//4),self.off(r+i*width,width))
            if not any(row): return result
            if delayed:
                need(row[0]==1,'VA-based/unknown delay descriptor unsupported'); nr,lookup,iat=row[1],row[4],row[3]
            else: nr,lookup,iat=row[3],row[0] or row[4],row[4]
            symbols=[]; slots=[]
            for j in range(4096):
                value=self.u('<Q',self.off(lookup+j*8,8))[0]
                if not value: break
                symbols.append(value&65535 if value>>63 else self.name(value+2))
                slots.append(self.u('<Q',self.off(iat+j*8,8))[0])
            else: raise ValueError('unterminated import thunk table')
            result.append({'dll':self.name(nr).lower(),'symbols':symbols,'initial_iat':slots})
        raise ValueError('unterminated import descriptor table')
    def shape(self):
        r,size=self.directory(10); need(r and size>=208,'missing ARM64EC loadconfig')
        lc=self.off(r,208); mp=self.u('<Q',lc+200)[0]; m=self.off(mp-self.base,88)
        fields=self.u('<22I',m); version,table,count=fields[:3]
        need(self.machine==0x8664 and version==2 and 0<count<=256,'expected AMD64 hybrid PE with CHPEv2')
        ranges=[]
        for i in range(count):
            start,length=self.u('<II',self.off(table+i*8,8)); kind=start&3; start&=~3
            need(length>0 and kind in (0,1,2),'invalid CHPE CodeMap range')
            cursor=start
            while cursor<start+length:
                covering=[(a,n) for _,a,n,_,ch in self.sections if a<=cursor<a+n and ch&0x20000000]
                need(len(covering)==1,'CHPE range crosses an unmapped/nonexec section')
                cursor=min(start+length,covering[0][0]+covering[0][1])
            ranges.append({'start':start,'end':start+length,'type':kind})
        need(any(x['type']==1 for x in ranges) and any(x['type']==2 for x in ranges),'missing EC/x64 ranges')
        return {'machine':self.machine,'CHPE_version':version,'CodeMap':ranges,'AuxiliaryDelayloadIAT':fields[20],'AuxiliaryDelayloadIATCopy':fields[21]}

def reference(archive,pins):
    p=Path(archive); ref=pins['reference']
    need(p.is_file() and not p.is_symlink() and p.stat().st_size==ref['zip_bytes'],'reference ZIP size/type mismatch')
    need(sha(p.read_bytes())==ref['zip_sha256'],'reference ZIP full hash mismatch')
    z=zipfile.ZipFile(p); seen=set()
    for i in z.infolist():
        q=PurePosixPath(i.filename)
        need(i.filename not in seen and not q.is_absolute() and '..' not in q.parts and '\\' not in i.filename,'unsafe/duplicate ZIP member')
        seen.add(i.filename); need(not stat.S_ISLNK(i.external_attr>>16),'ZIP symlink refused')
    prefix=ref['prefix']; manifest=json.loads(z.read(prefix+'manifest.json'))
    need(manifest.get('schema')==1 and isinstance(manifest.get('files'),dict),'invalid reference manifest')
    def read(name):
        need(name in manifest['files'],'provider missing from reference manifest')
        data=z.read(prefix+'files/'+name); need(sha(data)==manifest['files'][name],'reference member hash mismatch'); return data
    b=read('arm64ec-windows/ucrtbase.dll')
    need(len(b)==ref['baseline_pe_bytes'] and sha(b)==ref['baseline_pe_sha256'],'baseline PE mismatch')
    # A pinned archive plus per-member hashes binds the entire untouched seed farm.
    for name in manifest['files']: read(name)
    return z,read,b,manifest

def source(root,tc,pins):
    root=Path(root).resolve(); tc=Path(tc).resolve()
    subprocess.run(['git','-C',str(root),'merge-base','--is-ancestor',pins['source_base_commit'],'HEAD'],check=True)
    allowed={'.github/workflows/build.yml','tools/oxygen/verify-ucrt-only.py','tools/oxygen/ucrt-only-pins.json'}
    changed=set(git(root,'diff','--name-only',pins['source_base_commit'],'HEAD').splitlines())
    need(changed<=allowed,'unreviewed source change after fixed source base')
    need(not git(root,'status','--porcelain','--untracked-files=no'),'tracked checkout dirty')
    need(git(root,'rev-parse','HEAD:wine')==pins['wine_gitlink'] and git(root/'wine','rev-parse','HEAD')==pins['wine_gitlink'],'Wine source pin mismatch')
    need(not git(root/'wine','status','--porcelain','--untracked-files=no'),'Wine tracked source dirty')
    expected={'build/wine-pe/build-modules.sh':pins['builder_sha256'],'tools/build/setup-llvm-mingw.sh':pins['setup_sha256'],'wine/dlls/ucrtbase/Makefile.in':pins['ucrt_makefile_sha256']}
    for name,h in expected.items(): need(sha((root/name).read_bytes())==h,'source recipe hash mismatch: '+name)
    need(tc.name==pins['toolchain_name'],'toolchain directory mismatch')
    for name,value in pins['toolchain_files'].items():
        p=tc/name; need(p.is_file() and p.stat().st_size==value['bytes'] and sha(p.read_bytes())==value['sha256'],'toolchain file mismatch: '+name)
    return {'source_head':git(root,'rev-parse','HEAD'),'source_base':pins['source_base_commit'],'wine_gitlink':pins['wine_gitlink'],'builder_sha256':pins['builder_sha256'],'toolchain_verified':True}

def candidate(data,baseline,read,pins):
    need(65536<=len(data)<=4*1024*1024,'candidate size outside bounded UCRT range')
    p,b=PE(data),PE(baseline); shape=p.shape()
    need(p.exports()==b.exports(),'export names/ordinals/forwarders differ from pinned baseline')
    normal,delayed=p.imports(),p.imports(True)
    need(sorted(i['dll'] for i in normal)==pins['normal_dlls'],'normal DLL names differ')
    need({i['dll']:sorted(i['symbols']) for i in delayed}==pins['delayed_apis'],'delay DLL/API names differ')
    helpers=[]
    for group in delayed:
        for symbol,va in zip(group['symbols'],group['initial_iat']):
            rv=va-p.base; need(p.executable(rv),'initial delay stub outside executable section')
            need(any(x['type']==2 and x['start']<=rv and rv+12<=x['end'] for x in shape['CodeMap']),'delay stub not declared X64')
            code=p.take(p.off(rv,12),12)
            need(code[:3]==b'\x48\x8d\x05' and code[7]==0xe9,'unexpected LLVM x64 delay stub')
            helpers.append({'dll':group['dll'],'symbol':symbol,'rva':rv,'bytes':code.hex(),'CodeMap_type':2})
    for name in ['AuxiliaryDelayloadIAT','AuxiliaryDelayloadIATCopy']:
        need(shape[name]!=0,'missing auxiliary delay table'); p.off(shape[name],40)
    providers={}; checked=[]
    def resolve(dll,symbol,chain=()):
        dll=dll.lower(); dll=dll if dll.endswith('.dll') else dll+'.dll'
        need(len(chain)<32 and (dll,str(symbol)) not in chain,'forwarder cycle/depth')
        if dll not in providers: providers[dll]=PE(read('arm64ec-windows/'+dll)).exports()
        names,ords=providers[dll]
        need(symbol in (ords if isinstance(symbol,int) else names),'missing provider export: '+dll+'!'+str(symbol))
        f=ords[symbol] if isinstance(symbol,int) else names[symbol]['forwarder']
        if f:
            d,s=f.rsplit('.',1); resolve(d,int(s[1:]) if s.startswith('#') else s,chain+((dll,str(symbol)),))
    for group in normal+delayed:
        for s in group['symbols']: resolve(group['dll'],s); checked.append([group['dll'],s])
    return {'sha256':sha(data),'bytes':len(data),'baseline_pe_sha256':sha(baseline),'export_names':len(p.exports()[0]),'export_abi_equal':True,'normal_imports':normal,'delayed_imports':delayed,'architecture':shape,'initial_delay_stubs':helpers,'resolved_import_count':len(checked),'resolved_provider_dlls':sorted(providers),'runtime_delay_first_call_verified':False,'runtime_acceptance':False,'acceptance_required':'Fresh same heap canary plus rand_s/SystemFunction036 delayed first call on iPhone after FEX init; static metadata is not runtime proof.'}

def main():
    a=argparse.ArgumentParser();a.add_argument('mode',choices=['source','reference','candidate']);a.add_argument('--pins',required=True);a.add_argument('--report',required=True);a.add_argument('--repo-root');a.add_argument('--toolchain-root');a.add_argument('--archive');a.add_argument('--dll');x=a.parse_args()
    pins=json.loads(Path(x.pins).read_text())
    if x.mode=='source': result=source(x.repo_root,x.toolchain_root,pins)
    else:
        z,read,baseline,manifest=reference(x.archive,pins)
        try:
            result={'reference':pins['reference'],'reference_manifest_sha256':sha(z.read(pins['reference']['prefix']+'manifest.json')),'reference_files_verified':len(manifest['files']),'reference_key':manifest['key']}
            if x.mode=='candidate': result.update(candidate(Path(x.dll).read_bytes(),baseline,read,pins))
        finally: z.close()
    write(x.report,result)
if __name__=='__main__': main()

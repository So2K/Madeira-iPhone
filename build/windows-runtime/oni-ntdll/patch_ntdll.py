#!/usr/bin/env python3
"""Strict, offline, two-byte ntdll register-allocation backport. Never runs a PE.

New patch/verification utility: MIT (licenses/LICENSE-MIT.txt).
Original Wine binary/proof retain their separate LGPL notices.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import os
import stat
import tempfile

BASE_SHA = '3aca1fee7b0c03c56771f809bb7dae7caa1d6bb952d9b17592d6336019eaae4f'
CANDIDATE_SHA = '153af52414270ff9a373210c0fcecbfad3f54cffddcc88181ef1ddd2dccb8833'
BASE_BYTES = 1572864
IPA_SHA = '362b667b522b183079316d69d1b485b8fd992e918e4e8d2d220642dcf09bbd1f'
RVA = 0x28400
OLD = bytes.fromhex('0bfd5f886b010a0a0bfd0c88acffff35')
NEW = bytes.fromhex('0cfd5f888b010a0a0bfd0c88acffff35')
CONTEXT_RVA = 0x283d0
CONTEXT = bytes.fromhex('fa0300aae01f44a9fe3f40b9fa0b00b45e1700b9481340b90801c05a0911c05a280080520a21c91a48430091ea032a2a0bfd5f886b010a0a0bfd0c88acffff35ec7c099bbf3b03d5491340b9eb2b40f94a030c8b5961009149020034c81f0012691140f9081d080b08711d532801088b01fd5fc81afd09c8c9ffff35bf3b03d5')

class GuardError(RuntimeError): pass
def check(ok, message):
    if not ok: raise GuardError(message)
def sha(data): return hashlib.sha256(data).hexdigest()
def sx(value, bits): return (value ^ (1 << (bits-1))) - (1 << (bits-1))

class PE:
    def __init__(self, data):
        self.data=data
        check(256 <= len(data) <= 4*1024*1024 and data[:2]==b'MZ','Invalid/bounded PE')
        self.pe=struct.unpack_from('<I',data,60)[0]
        check(self.pe+24<=len(data) and data[self.pe:self.pe+4]==b'PE\0\0','PE header')
        machine,nsec,timestamp,_sym,_nsyms,osize,flags=struct.unpack_from('<HHIIIHH',data,self.pe+4)
        self.opt=self.pe+24;self.timestamp=timestamp;self.flags=flags
        check(machine==0x8664 and flags & 0x2000 and flags & 2,'Expected AMD64-header DLL')
        check(0<nsec<=32 and osize>=240 and self.opt+osize+40*nsec<=len(data),'Optional/section bounds')
        check(struct.unpack_from('<H',data,self.opt)[0]==0x20b,'Expected PE32+')
        self.base=struct.unpack_from('<Q',data,self.opt+24)[0]
        self.image_size,self.header_size=struct.unpack_from('<II',data,self.opt+56)
        check(struct.unpack_from('<I',data,self.opt+108)[0]==16,'Exactly16 directories required')
        self.dirs=[struct.unpack_from('<II',data,self.opt+112+8*i) for i in range(16)]
        self.sections=[]
        for i in range(nsec):
            p=self.opt+osize+40*i
            name=data[p:p+8].rstrip(b'\0').decode('ascii')
            vs,rva,rs,off=struct.unpack_from('<4I',data,p+8)
            ch=struct.unpack_from('<I',data,p+36)[0]
            check(off+rs<=len(data) and rva+max(vs,rs)<=self.image_size,'Section bounds')
            self.sections.append(dict(name=name,rva=rva,virtual_bytes=vs,raw_offset=off,raw_bytes=rs,characteristics=ch))
    def at(self,rva,n=1):
        check(0<=rva and 0<=n and rva+n<=self.image_size,'RVA bounds')
        if rva<self.header_size:
            check(rva+n<=min(self.header_size,len(self.data)),'Header RVA bounds');return rva
        matches=[s for s in self.sections if s['rva']<=rva and rva+n<=s['rva']+s['raw_bytes']]
        check(len(matches)==1,'Ambiguous/unbacked RVA')
        return matches[0]['raw_offset']+rva-matches[0]['rva']
    def u32(self,rva): return struct.unpack_from('<I',self.data,self.at(rva,4))[0]
    def text(self,rva):
        p=self.at(rva);end=self.data.find(b'\0',p,min(len(self.data),p+1024))
        check(end>=p,'PE name termination');self.at(rva,end-p+1)
        return self.data[p:end].decode('ascii')
    def exports(self):
        rva,size=self.dirs[0];check(40<=size<=1024*1024,'Export bounds')
        p=self.at(rva,40)
        _a,_b,_c,_d,_name,ordinal,nfunc,nnames,funcs,names,ords=struct.unpack_from('<IIHH7I',self.data,p)
        check(0<nnames<=nfunc<=8192,'Export counts')
        result={}
        self.at(funcs,nfunc*4);self.at(names,nnames*4);self.at(ords,nnames*2)
        for i in range(nnames):
            name=self.text(self.u32(names+4*i));idx=struct.unpack_from('<H',self.data,self.at(ords+2*i,2))[0]
            check(idx<nfunc and name not in result,'Export ordinal/duplicate')
            entry=self.u32(funcs+4*idx)
            result[name]={'ordinal':ordinal+idx,'rva':entry,'forwarder':self.text(entry) if rva<=entry<rva+size else None}
        return result
    def architecture(self):
        rva,size=self.dirs[10];check(size==320,'Pinned load config length')
        p=self.at(rva,size);mrva=struct.unpack_from('<Q',self.data,p+200)[0]-self.base
        f=struct.unpack_from('<20I',self.data,self.at(mrva,80))
        check(f[0]==2 and f[2]==2,'Pinned CHPE version/range count')
        ranges=[]
        for i in range(f[2]):
            val,n=struct.unpack_from('<II',self.data,self.at(f[1]+8*i,8));start=val&~3
            check(n>0 and start+n<=self.image_size,'CHPE range bounds');self.at(start);self.at(start+n-1)
            ranges.append({'kind':val&3,'rva':start,'bytes':n})
        check(any(r['kind']==1 and r['rva']<=RVA and RVA+16<=r['rva']+r['bytes'] for r in ranges),'Patch outside native ARM64EC code')
        return {'coff_machine':'0x8664','effective_architecture':'ARM64EC','chpe_version':2,'metadata_rva':mrva,'fields':list(f),'ranges':ranges}
    def snapshot(self):
        ex=self.exports();arch=self.architecture()
        check(self.dirs[1]==(0,0) and self.dirs[13]==(0,0),'Unexpected import/delay-import table')
        return {'bytes':len(self.data),'timestamp':self.timestamp,'coff_characteristics':self.flags,'image_base':self.base,'image_bytes':self.image_size,'headers_sha256':sha(self.data[:self.header_size]),'architecture':arch,'imports':{},'exports':ex,'export_count':len(ex),'data_directories':self.dirs,
                'sections':[dict(s,sha256=sha(self.data[s['raw_offset']:s['raw_offset']+s['raw_bytes']])) for s in self.sections],
                'directory_hashes':[sha(self.data[self.at(r,n):self.at(r,n)+n]) if r and n else None for r,n in self.dirs]}

def branch_target(insn,pc):
    if insn & 0x9f000000 == 0x10000000: return pc+sx((((insn>>5)&0x7ffff)<<2)|((insn>>29)&3),21) # ADR
    if insn & 0x7c000000 == 0x14000000: return pc+4*sx(insn&0x3ffffff,26)
    if insn & 0xff000010 == 0x54000000 or insn & 0x7e000000 == 0x34000000: return pc+4*sx((insn>>5)&0x7ffff,19)
    if insn & 0x7e000000 == 0x36000000: return pc+4*sx((insn>>5)&0x3fff,14)
    return None

def guards(data,check_hash=True):
    check(len(data)==BASE_BYTES,'Baseline size mismatch')
    if check_hash: check(sha(data)==BASE_SHA,'Baseline hash mismatch')
    p=PE(data);snap=p.snapshot();off=p.at(RVA,len(OLD))
    check(snap['export_count']==1473 and len(snap['sections'])==8,'Latest export/section count differs')
    check(snap['architecture']['ranges']==[{'kind':1,'rva':0x10000,'bytes':0x75a6c},{'kind':2,'rva':0x86000,'bytes':0xdae0}],'Latest native/x64 range contract differs')
    check(off==RVA,'Pinned RVA/file offset differs')
    check(data[p.at(CONTEXT_RVA,len(CONTEXT)):p.at(CONTEXT_RVA,len(CONTEXT))+len(CONTEXT)]==CONTEXT,'Neighbourhood mismatch')
    check(data[off:off+16]==OLD and data.count(OLD)==1,'Original loop mismatch/nonunique')
    check(p.exports()['RtlAllocateHeap']=={'ordinal':414,'rva':0x90970,'forwarder':None},'RtlAllocateHeap export changed')
    thunk=p.at(0x90970,14);check(data[thunk:thunk+14]==bytes.fromhex('488bc448895820555de92e78f9ff'),'Native export thunk changed')
    check(0x90970+14+struct.unpack_from('<i',data,thunk+10)[0]==0x281ac,'Native owner target changed')
    check(branch_target(p.u32(RVA+12),RVA+12)==RVA,'Retry branch target differs')
    interior={RVA+4,RVA+8,RVA+12};refs=[]
    for r in snap['architecture']['ranges']:
        if r['kind']!=1:continue
        for pc in range(r['rva'],r['rva']+r['bytes']-3,4):
            target=branch_target(p.u32(pc),pc)
            if target in interior:refs.append({'from':pc,'to':target})
    check(not refs,'Direct branch/ADR into loop interior')
    check(not any(e['rva'] in interior for e in snap['exports'].values()),'Export into loop interior')
    f=snap['architecture']['fields'];native_starts=[]
    check(f[17]%8==0 and f[17]<=1024*1024,'Native exception table bounds')
    for i in range(f[17]//8):native_starts.append(p.u32(f[16]+8*i))
    check(not interior.intersection(native_starts),'Native exception entry into loop interior')
    r,n=p.dirs[5];cursor=0
    while cursor<n:
        check(cursor+8<=n,'Relocation block header')
        page,size=struct.unpack_from('<II',data,p.at(r+cursor,8))
        check(8<=size<=n-cursor and size%2==0,'Relocation block length')
        for j in range((size-8)//2):
            ent=struct.unpack_from('<H',data,p.at(r+cursor+8+2*j,2))[0];kind=ent>>12;target=page+(ent&0xfff)
            width={0:0,3:4,10:8}.get(kind)
            check(width is not None,'Unreviewed relocation type')
            check(not width or target+width<=RVA or target>=RVA+16,'Relocation overlaps loop')
        cursor+=size
    return p,snap,{'direct_interior_refs':refs,'export_interior_refs':0,'native_exception_entries':len(native_starts),'relocation_overlap':False}

def transform(data):
    p,before,ref=guards(data)
    result=bytearray(data);off=p.at(RVA,16);result[off:off+16]=NEW;result=bytes(result)
    diffs=[i for i,(a,b) in enumerate(zip(data,result)) if a!=b]
    check(diffs==[0x28400,0x28404],'Only prescribed two bytes may differ')
    check(sha(result)==CANDIDATE_SHA,'Candidate full hash mismatch')
    after=PE(result).snapshot()
    for k in ('bytes','timestamp','coff_characteristics','image_base','image_bytes','headers_sha256','architecture','imports','exports','export_count','data_directories','directory_hashes'):check(before[k]==after[k],f'PE invariant changed: {k}')
    for a,b in zip(before['sections'],after['sections']):
        check({k:v for k,v in a.items() if k!='sha256'}=={k:v for k,v in b.items() if k!='sha256'},'Section layout changed')
        if a['name']!='.text':check(a['sha256']==b['sha256'],'Nontext section changed')
    return result,{'baseline_ipa_sha256':IPA_SHA,'baseline_pe_sha256':BASE_SHA,'baseline_pe_bytes':BASE_BYTES,'sha256':sha(result),'bytes':len(result),'candidate_pe_sha256':sha(result),'candidate_pe_bytes':len(result),'changed_file_offsets':diffs,'changed_rvas':diffs,'old_loop_hex':OLD.hex(),'new_loop_hex':NEW.hex(),'owner':'RtlAllocateHeap','owner_export_rva':0x90970,'owner_native_rva':0x281ac,'patch_rva':RVA,'static_reference_guards':ref,'before':before,'after':after,'scope':'Only arm64ec-windows/ntdll.dll. No native/FEX/app/signing changes. Device acceptance pending.'}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('baseline',type=Path);ap.add_argument('output',type=Path)
    ap.add_argument('--report',required=True,type=Path)
    ap.add_argument('--in-place',action='store_true',help='Explicit atomic replacement; baseline/output must be the same regular single-link file')
    args=ap.parse_args()
    check(args.output.parent.is_dir() and args.report.parent.is_dir(),'Output/report parent missing')
    check(shutil.disk_usage(args.output.parent).free>=576*1024*1024,'Scoped scratch floor576MiB')
    st=args.baseline.lstat()
    check(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==BASE_BYTES,'Baseline must be a single-link regular pinned-size file')
    same=args.baseline.absolute()==args.output.absolute()
    check(same==args.in_place,'Same input/output requires exactly --in-place')
    check(not args.report.exists() and not args.report.is_symlink(),'Refusing report overwrite')
    check(args.report.absolute() not in (args.output.absolute(),args.baseline.absolute()),'Report aliases PE path')
    if not same:check(not args.output.exists() and not args.output.is_symlink(),'Refusing output overwrite')
    data=args.baseline.read_bytes()
    result,report=transform(data)
    # No output mutation occurs until full original/candidate hash and all PE checks pass.
    if same:
        fd,tmp=tempfile.mkstemp(prefix='.oni-ntdll-',dir=args.output.parent)
        try:
            with os.fdopen(fd,'wb') as f:
                f.write(result);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),stat.S_IMODE(st.st_mode))
            now=args.baseline.lstat()
            check(all(getattr(now,k)==getattr(st,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_nlink')) and args.baseline.read_bytes()==data,'Input changed during guarded transform')
            os.replace(tmp,args.output)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
    else:
        with args.output.open('xb') as f:f.write(result)
        args.output.chmod(stat.S_IMODE(st.st_mode))
    with args.report.open('x') as f:f.write(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('candidate_pe_sha256','candidate_pe_bytes','changed_file_offsets','owner')}))

if __name__=='__main__':main()

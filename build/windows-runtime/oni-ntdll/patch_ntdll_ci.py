#!/usr/bin/env python3
"""MIT. Exact latest ntdll recipe with only COFF and CodeView timestamp variance for source CI.
No signing, native modification, network or device access.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,stat,struct,subprocess,sys,tempfile
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
PINS_SHA='caa60e5ff122cda1cfe10b541ac8fec92591aba92e26dcc5a468bd856f6a6940'
def sha(b):return hashlib.sha256(b).hexdigest()
def digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  while b:=f.read(1024*1024):h.update(b)
 return h.hexdigest()
class GuardError(RuntimeError):pass
def check(ok,message):
 if not ok:raise GuardError(message)
raw=(ROOT/'provenance-pins.json').read_bytes();check(sha(raw)==PINS_SHA,'Provenance pin file hash mismatch');PINS=json.loads(raw)
check(digest(ROOT/'patch_ntdll.py')==PINS['strict_v1_patcher_sha256'],'Strict v1 recipe changed')
spec=importlib.util.spec_from_file_location('strict_latest_ntdll',ROOT/'patch_ntdll.py');strict=importlib.util.module_from_spec(spec);spec.loader.exec_module(strict)

def _timestamp_fields(data:bytes):
 """Bounded shared parser for exact two-timestamp contract, not acceptance."""
 p=strict.PE(data);check(p.pe==0x78,'Pinned PE-header offset differs')
 r,n=p.dirs[6];check(r and n==28,'Exactly one debug-directory entry required')
 off=p.at(r,n);c,t,major,minor,kind,size,addr,ptr=struct.unpack_from('<IIHHIIII',data,off)
 check(c==0 and major==0 and minor==0 and kind==2 and size==25,'Sole CodeView entry contract differs')
 check(p.at(addr,size)==ptr,'CodeView raw/RVA layout differs')
 payload=data[ptr:ptr+size];check(len(payload)==25,'Bounded CodeView payload differs')
 coff=struct.unpack_from('<I',data,p.pe+8)[0]
 check(coff==t,'COFF and CodeView timestamps must be equal')
 return {'rva':r,'bytes':n,'file_offset':off,'characteristics':c,'major_version':major,'minor_version':minor,'type':kind,'payload_bytes':size,'payload_rva':addr,'payload_file_offset':ptr,'payload_sha256':sha(payload),'timestamp_file_offset':off+4},coff

def _normalize_checked(data:bytes,layout:dict)->bytes:
 out=bytearray(data)
 for off in (0x80,layout['timestamp_file_offset']):struct.pack_into('<I',out,off,PINS['official_timestamp'])
 return bytes(out)

def normalize_timestamp(data:bytes)->bytes:
 """Pure production normalizer: exact official debug layout and equal raw times.
 Only 8 checked metadata bytes change in comparison copy; whole SHA is required.
 """
 check(len(data)==strict.BASE_BYTES,'Pinned latest ntdll size differs')
 layout,_=_timestamp_fields(data)
 check(layout==PINS['official_debug_directory'],'Official sole CodeView directory layout/payload differs')
 return _normalize_checked(data,layout)

def _normalize_fixture_timestamps_for_test(data:bytes)->bytes:
 """Host fixture only. Uses same checked parser, fixture-specific directory RVA.
 Production CLI/transform/candidate verification never use this helper.
 """
 layout,_=_timestamp_fields(data)
 return _normalize_checked(data,layout)

def transform(data:bytes):
 check(len(data)==strict.BASE_BYTES,'Pinned latest ntdll size differs')
 normalized=normalize_timestamp(data)
 check(sha(normalized)==PINS['official_input_sha256'],'Other than exactly two checked timestamp DWORDs, input differs from official PE')
 candidate,base_report=strict.transform(normalized)
 out=bytearray(candidate)
 for off in (0x80,PINS['official_debug_directory']['timestamp_file_offset']):out[off:off+4]=data[off:off+4]
 out=bytes(out)
 check([i for i,(a,b) in enumerate(zip(data,out)) if a!=b]==[0x28400,0x28404],'Raw delta is not exactly two prescribed bytes')
 check(all(out[off:off+4]==data[off:off+4] for off in (0x80,PINS['official_debug_directory']['timestamp_file_offset'])),'Raw timestamps changed')
 check(sha(normalize_timestamp(out))==PINS['official_candidate_sha256'],'Normalized candidate full hash differs')
 before=strict.PE(data).snapshot();after=strict.PE(out).snapshot()
 for key in ('bytes','timestamp','coff_characteristics','image_base','image_bytes','headers_sha256','architecture','imports','exports','export_count','data_directories','directory_hashes'):
  check(before[key]==after[key],'Raw PE metadata changed: '+key)
 for a,b in zip(before['sections'],after['sections']):
  check({k:v for k,v in a.items() if k!='sha256'}=={k:v for k,v in b.items() if k!='sha256'},'Raw section layout changed')
  if a['name']!='.text':check(a['sha256']==b['sha256'],'Raw nontext body changed')
 return out,{'schema':3,'mode':PINS['mode'],'raw_input_sha256':sha(data),'raw_output_sha256':sha(out),'raw_bytes':len(out),'normalized_input_sha256':sha(normalized),'normalized_output_sha256':sha(normalize_timestamp(out)),'normalization':'Only equal COFF timestamp at0x80 and sole CodeView timestamp at0xBA2F4 (4bytes each) replaced with official value for whole-file comparison; both raw timestamps retained in output','raw_timestamp':struct.unpack_from('<I',data,0x80)[0],'raw_debug_timestamp':struct.unpack_from('<I',data,0xBA2F4)[0],'official_timestamp':PINS['official_timestamp'],'changed_file_offsets':[0x28400,0x28404],'raw_timestamp_unchanged':True,'strict_v1_report':base_report,'raw_before':before,'raw_after':after,'scope':'Experimental exact two-byte PE compatibility recipe; no device acceptance or full CI rebuild claim'}

def verify_candidate(data:bytes)->dict:
 """Pure final/cached-IPA check; exact normalized output plus reverse/reapply guards."""
 check(len(data)==strict.BASE_BYTES,'Candidate size differs')
 check(sha(normalize_timestamp(data))==PINS['official_candidate_sha256'],'Whole normalized candidate SHA differs')
 check(data[0x28400:0x28410]==strict.NEW,'Candidate loop differs')
 baseline=bytearray(data);baseline[0x28400:0x28410]=strict.OLD
 out,report=transform(bytes(baseline));check(out==data,'Candidate reverse/reapply differs')
 return {k:report[k] for k in ('raw_input_sha256','raw_output_sha256','raw_bytes','normalized_input_sha256','normalized_output_sha256','raw_timestamp','raw_debug_timestamp','changed_file_offsets','raw_timestamp_unchanged')}

def git(repo,*args):
 r=subprocess.run(['git','-C',str(repo),*args],text=True,capture_output=True)
 check(r.returncode==0,'Git provenance failed: '+' '.join(args))
 return r.stdout.strip()

def validate_toolchain(toolchain:Path)->dict:
 tc=toolchain.resolve();check(tc.name==PINS['toolchain_name'],'Toolchain directory differs')
 result={}
 for rel,record in PINS['toolchain_files'].items():
  path=tc/rel
  check(path.resolve().is_relative_to(tc),'Toolchain file escapes pinned root')
  check(path.is_file() and path.stat().st_size==record['bytes'] and digest(path)==record['sha256'],'Pinned toolchain file differs: '+rel)
  result[rel]=dict(record)
 return {'name':tc.name,'release_archive_sha256':PINS['toolchain_archive_sha256'],'file_hashes_computed':result}

def validate_provenance(repo:Path,toolchain:Path)->dict:
 repo=repo.resolve();wine=repo/'wine'
 head=git(repo,'rev-parse','HEAD')
 git(repo,'merge-base','--is-ancestor',PINS['base_upstream_commit'],'HEAD')
 check(git(repo,'ls-tree','HEAD','wine')=='160000 commit '+PINS['wine_gitlink']+'\twine','Root Wine gitlink differs')
 check(git(wine,'rev-parse','HEAD')==PINS['wine_gitlink'],'Checked-out Wine HEAD differs')
 check(git(wine,'status','--porcelain','--untracked-files=no')=='','Tracked Wine sources modified')
 actual={}
 for rel,expected in PINS['source_files'].items():
  path=repo/rel
  check(path.resolve().is_relative_to(repo) and path.is_file() and digest(path)==expected,'Pinned source/build recipe differs: '+rel)
  actual[rel]=expected
 return {'base_upstream_commit':PINS['base_upstream_commit'],'source_head':head,'wine_gitlink':PINS['wine_gitlink'],'wine_tracked_tree_clean':True,'source_hashes_computed':actual,'toolchain':validate_toolchain(toolchain)}

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('baseline',type=Path);ap.add_argument('output',type=Path)
 ap.add_argument('--report',required=True,type=Path);ap.add_argument('--in-place',action='store_true')
 ap.add_argument('--repo-root',required=True,type=Path);ap.add_argument('--toolchain-root',required=True,type=Path)
 args=ap.parse_args()
 check(args.output.parent.is_dir() and args.report.parent.is_dir(),'Output/report parent missing')
 sv=os.statvfs(args.output.parent);check(sv.f_bavail*sv.f_frsize>=576*1024*1024,'Scoped scratch floor576MiB')
 st=args.baseline.lstat();check(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==strict.BASE_BYTES,'Baseline must be single-link regular pinned-size file')
 same=args.baseline.absolute()==args.output.absolute();check(same==args.in_place,'Same input/output requires exactly --in-place')
 check(not args.report.exists() and not args.report.is_symlink(),'Refusing report overwrite')
 check(args.report.absolute() not in (args.output.absolute(),args.baseline.absolute()),'Report aliases PE path')
 if not same:check(not args.output.exists() and not args.output.is_symlink(),'Refusing output overwrite')
 provenance=validate_provenance(args.repo_root,args.toolchain_root)
 data=args.baseline.read_bytes();result,report=transform(data);report['provenance']=provenance
 # Exact normalized hash, raw two-byte delta and live provenance all precede staging.
 if same:
  fd,tmp=tempfile.mkstemp(prefix='.oni-ntdll-ci-',dir=args.output.parent)
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
 print(json.dumps({k:report[k] for k in ('raw_input_sha256','raw_output_sha256','normalized_input_sha256','normalized_output_sha256','raw_timestamp','raw_debug_timestamp','changed_file_offsets')}))
if __name__=='__main__':main()

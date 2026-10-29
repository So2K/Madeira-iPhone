Madeira ONI ntdll CI recipe v3: pe-build-timestamps-v3

New successor; earlier strict-v1/v2 directories and source packets are unchanged.
Frozen strict-v1 script is included byte-for-byte:
74e11d9759fcb14e98784ddbc1b15004e8ad2c67b93050972ab1b6fa6fbab6a6.

Root-authorized variance is EXACTLY two4-byte fields in source-built input:
COFF TimeDateStamp at file0x80 and sole IMAGE_DEBUG_DIRECTORY.TimeDateStamp at
file0xBA2F4. Both raw timestamps MUST be equal. The production parser requires
the exact official sole28-byte debug entry, CodeView type2/size25, directory
RVA/file0xBA2F0, payloadRVA/file0xBA30C, versions/characteristics and payload SHA.
The official stripped CodeView payload is25zero bytes; no GUID/payload variation
is accepted. A bounded parser validates all mapping before normalization.

Only those8checked metadata bytes are replaced by official1793239674 in a
comparison copy. WHOLE normalized input SHA must be:
3aca1fee7b0c03c56771f809bb7dae7caa1d6bb952d9b17592d6336019eaae4f.
Actual input keeps its timestamps. Raw input -> raw output changes EXACTLY two
allocator-loop bytes at0x28400 and0x28404, retaining both source timestamps.
Whole normalized output SHA must be:
153af52414270ff9a373210c0fcecbfad3f54cffddcc88181ef1ddd2dccb8833.
Every other header/section/code/GUID/export timestamp/resource/padding byte is
covered by these full hashes and all strict-v1 structural/reference checks.
Isolated or mismatched timestamps are refused. No pattern-only fallback exists.

CI command (fresh report must be outside bundle/component farm):
 python3 build/windows-runtime/oni-ntdll/patch_ntdll_ci.py INPUT INPUT \
   --in-place --report NEW_REPORT_JSON --repo-root "$R" \
   --toolchain-root "$R/toolchains/llvm-mingw-20260421-ucrt-macos-universal"
Use after build/wine-pe/build-ntdll.sh final strip/pad and before windows-runtime
targets.py closure and component hash snapshot. Vendoring under existing
build/windows-runtime/oni-ntdll/ source-key glob ensures cache invalidation.
Actual raw hashes remain in component and IPA manifests. Never relabel raw SHA
as normalized SHA or alter manifests after the snapshot. If clean Wine output
differs anywhere else, refuse and request an actual artifact review. This packet
has not executed a complete Wine/CI source build or a device test.

Computed provenance, not caller-supplied claims:
 * source HEAD descends from upstream c2c1b03a9e36ef986c980b9eae3c14d05a372db1;
 * tracked root Wine gitlink and checked-out Wine HEAD equal
   df1c5ea51e194937ac204bc3120922dc56a61bec, tracked Wine tree clean;
 * actual ntdll/Wine/toolchain setup source files match exact c2 hashes;
 * native signal source equals separately approved GPR SHA
   3e0e2ff98aeafe89f0a458613b8182942b95ecfee099ede71dd98ca5828faabe;
 * actual9compiler/linker/strip/config/shared-library files match exact pinned
   hashes/sizes, with exact toolchain basename and release SHA recorded.
Current source_head is logged separately from base_upstream_commit.
Full normalized PE identity is the final gate for all other environment inputs.

Pinned final/cached IPA APIs:
 normalize_timestamp(data:bytes) -> bytes
   Pure production normalizer checks fixedsize/exactdebuglayout/equalrawtimes;
   caller must compare entire normalized SHA. Not acceptance by itself.
 verify_candidate(data:bytes) -> dict
   Stronger acceptance: full normalized output SHA, exact loop, reverse2byte
   transform, strict-v1 input checks/reapply equality; returns actual raw and
   normalized hashes, both timestamps and exact raw byte delta.
Verifier must hash-pin patch_ntdll_ci.py, patch_ntdll.py and provenance-pins.json
before import. Module pins its two companions too. Production transform and
candidate verifier never call the separate flexible fixture-layout helper.

Host proof commands (same Apple arm64 host and pinned toolchain):
 python3 tests/test_timestamp.py EXACT_OFFICIAL_NTDLL PINNED_TOOLCHAIN_ROOT
 python3 tests/test_provenance.py EXACT_OFFICIAL_NTDLL PINNED_TOOLCHAIN_ROOT
Timestamp tests vary both matched timestamp DWORDs, reject individual/mismatched
timestamp bytes and all other representative metadata/code/section/payload/data
mutations. Two real identical same-output compiler links are stripped with the
actual pinned C2 strip command; their normalized WHOLE files must be identical
and raw difference confined to the two timestamps. Fixture parser uses the same
bounded field checks with its own small-file directory layout; production input
requires the fixed official layout. This tiny compiler proof is not a complete
Wine rebuild. Source fixture bytes/toolchain hashes are real; positive git and
CLI provenance units explicitly mock git replies. Actual nonrepository refusal
is tested. Full source CI remains the first real checkout/provenance canary.

PE replacement is atomic, mode-preserving; JSON report is a separate operation,
with no power-loss durability claim. Existing alias CAS/ABA limits and host-only
scope remain. No signing, profiles, accounts, app staging, native edits or phone
access. New wrapper/tests/docs MIT; included frozen v1 notices/source provenance
retain Wine LGPL and Madeira GPL/exception licensing. v1 source archive is a
separate pinned corresponding-source deliverable (v1-proof/source-archive-pin.json).

# SPEC: `NtWow64QueryVirtualMemory64` implementation in Wine

**Status:** v3 — oracle review DONE (v2 = NO-GO, 3 design flaws caught), all corrections independently verified in source
**Target:** Wine master @ f8b1ce3 (fork: `dragon-Elec/wine-fork`, CI pipeline proven green)
**Motivating failure:** VMware ThinApp boot loader (32-bit, `boot_loader.pdb` string proof) resolves this
export via `LdrGetProcedureAddress`, doesn't find it, calls `NtRaiseHardError(STATUS_FATAL_APP_EXIT)`
and exits 1.

---

## 1. Execution-path architecture (the correction that redefined the design)

Modern Wine new-WoW64 — the path our CI build (`--enable-archs=i386,x86_64`) actually executes:

```
32-bit PE ntdll (syscall stub, -arch=win32 export)
  → wow64.dll dispatch (auto-generated from ALL_SYSCALLS32)
    → wow64_NtWow64QueryVirtualMemory64 (dlls/wow64/virtual.c)   ← THE code that runs
      → 64-bit PE NtQueryVirtualMemory
        → unix lib NtQueryVirtualMemory (64-bit; MBI is 48 bytes here = MBI64 layout)
```

Consequences:
- **The wow64 thunk is the piece that must be correct.** It unpacks 32-bit stack args and routes
  to 64-bit `NtQueryVirtualMemory`, which fills a 48-byte `MEMORY_BASIC_INFORMATION` whose layout
  is **identical to `MEMORY_BASIC_INFORMATION64`** — so no repack is needed on this path.
- The unix-side `NtWow64QueryVirtualMemory64` (inside `#ifndef _WIN64`, 7157–7321) only executes
  in old-wine32 mode (32-bit unix lib). Needed for upstream completeness (MR !6666 did both), not
  for our CI artifact — but there the 32-bit clamps (`virtual.c:5820-5822`) mean a naive
  `get_basic_memory_info()` call would truncate/mis-handle >4GB addresses, so it must use the
  `APC_VIRTUAL_QUERY` server request directly.

## 2. Verified file-by-file patchset (6 files, one function)

### 2.1 `dlls/ntdll/ntdll.spec` — export entry
```spec
@ stdcall -syscall -arch=win32 NtWow64QueryVirtualMemory64(long long long long ptr long long ptr)
@ stdcall -private -arch=win32 ZwWow64QueryVirtualMemory64(long long long long ptr long long ptr) NtWow64QueryVirtualMemory64
```
**8 tokens = 32 bytes.** Parameter encoding: `HANDLE`=long(1) + `ULONG64`=long long(2) +
`class`=long(1) + `void*`=ptr(1) + `ULONG64`=long long(2) + `PULONGLONG`=ptr(1).
⚠ `int64` is **forbidden** on `-syscall` functions (`tools/winebuild/parser.c:262`,
"Argument type not allowed for syscall function"). Verified.
Siblings: Read(:466, 28B/7 tokens), Write(:1547 area), QueryInfoProc(:271, 20B).

### 2.2 `dlls/ntdll/ntsyscalls.h` — syscall slot
```c
    SYSCALL_ENTRY( 0x010e, NtWow64QueryVirtualMemory64, 32 ) \
```
Insert after line 273 (`0x010d WriteVirtualMemory64, 28`). Verified: 0x010b/0x010c/0x010d are the
existing Wow64 slots; 32 = 8 dwords × 4. No other registration needed — `dlls/wow64/wow64_private.h`
includes `../ntdll/ntsyscalls.h` with its own `SYSCALL_ENTRY` macro (extern decls) and
`dlls/wow64/syscall.c` consumes `ALL_SYSCALLS32` twice (dispatch table + thunks). Verified.

### 2.3 `dlls/wow64/virtual.c` — the wow64 thunk (what actually runs in new-WoW64)
```c
/**********************************************************************
 *           wow64_NtWow64QueryVirtualMemory64
 */
NTSTATUS WINAPI wow64_NtWow64QueryVirtualMemory64( UINT *args )
{
    HANDLE process = get_handle( &args );
    void *addr = (void *)(ULONG_PTR)get_ulong64( &args );
    MEMORY_INFORMATION_CLASS class = get_ulong( &args );
    void *ptr = get_ptr( &args );
    SIZE_T len = get_ulong64( &args );
    SIZE_T *retlen = get_ptr( &args );

    switch (class)
    {
    case MemoryBasicInformation:
        return NtQueryVirtualMemory( process, addr, class, ptr, len, retlen );
    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}
```
Pattern source: `wow64_NtWow64ReadVirtualMemory64` (:899, verbatim-verified routing to 64-bit PE)
and `wow64_NtWow64QueryInformationProcess64` (`dlls/wow64/process.c:1186`, same switch-default).
On 64-bit PE, `sizeof(MEMORY_BASIC_INFORMATION)==48` = MBI64 layout → direct call, no repack.

### 2.4 `dlls/ntdll/unix/virtual.c` — unix side (old-wine32 mode; insert before `#endif /* _WIN64 */` :7321)
- **Cross-process:** queue `APC_VIRTUAL_QUERY` directly (model: `NtWow64AllocateVirtualMemory64`
  at :7181-7199, verbatim-verified) — `call.virtual_query.addr = addr` (full 64-bit), then unpack
  `result.virtual_query` straight into `MEMORY_BASIC_INFORMATION64`. Do NOT call
  `get_basic_memory_info()` — its `#ifndef _WIN64` clamps (:5820-5822) reject addresses
  `>= ~granularity_mask` and would truncate.
- **Same-process:** `base = (void *)(ULONG_PTR)addr; if ((ULONG_PTR)base != addr) return
  STATUS_INVALID_PARAMETER;` (32-bit process has no >4GB memory), then `get_basic_memory_info()`
  + repack to MBI64.
- Semantics: `len < 48` → `STATUS_INFO_LENGTH_MISMATCH` (write `*ret_len` only on success);
  `BaseAddress==0` is **valid** (memory-walk start — returns first free region, do not error).

### 2.5 `include/winnt.h` — struct (after `MEMORY_BASIC_INFORMATION` :752)
```c
typedef struct _MEMORY_BASIC_INFORMATION64 {
    ULONGLONG BaseAddress;
    ULONGLONG AllocationBase;
    DWORD     AllocationProtect;
    DWORD     __alignment1;
    ULONGLONG RegionSize;
    DWORD     State;
    DWORD     Protect;
    DWORD     Type;
    DWORD     __alignment2;
} MEMORY_BASIC_INFORMATION64, *PMEMORY_BASIC_INFORMATION64;
```
Placement per Windows SDK convention + Wine's own (MBI lives at winnt.h:743, verified;
MBI64 currently absent — only `dbgeng.h:318` fwd-declares the pointer).

### 2.6 `include/winternl.h` — prototype (after :5509, the Wow64 block)
```c
NTSYSAPI NTSTATUS  WINAPI NtWow64QueryVirtualMemory64(HANDLE,ULONG64,MEMORY_INFORMATION_CLASS,void*,ULONG64,ULONG64*);
```

## 3. Scope decision (oracle-enforced)

**SINGLE function only.** Dropped from this patchset: `NtQueryDirectoryFileEx`,
`RtlDosApplyFileIsolationRedirection_Ustr`, `RtlFlushSecureMemoryCache`.
Rationale: one confounding variable per build; if ThinApp still fails we can isolate why.
Bundling 3 extra stubs risks build breakage and masks the actual gate. Deferred list kept in §5.

## 4. v1 class scope

`MemoryBasicInformation` only; others → `STATUS_NOT_IMPLEMENTED` — exactly the shape upstream
accepted in MR !6666 (only `ProcessBasicInformation`, default NOT_IMPLEMENTED).

## 5. Deferred probes (revisit only if trace shows additional gates)

| Probe | Real Win32 ntdll | Wine master | Note |
|---|---|---|---|
| `NtQueryDirectoryFileEx` | YES (Win8.1+) | absent | real impl = hundreds of lines; not a stub candidate |
| `RtlDosApplyFileIsolationRedirection_Ustr` | YES | commented stub (:653) | deep SxS; stubbing risks masking |
| `RtlFlushSecureMemoryCache` | YES | commented stub (:725) | likely not a hard barrier |
| `RtlAddFunctionTable` | NO (x64-only) | `-arch=!i386` (:507) | Windows 32-bit lacks it too — skip |
| `kernel32 GetFileInformationByHandleExW` | NO | kernelbase has undecorated | skip |

## 6. Test plan

1. CI green (warm cache, ~15–25 min).
2. Export gate: 32-bit ntdll.dll in artifact exports both `NtWow64QueryVirtualMemory64` + Zw alias.
3. Behavior gate: ThinApp stub under `WINEDEBUG=+relay,+module` — previous signature:
   `LdrGetProcedureAddress "NtWow64QueryVirtualMemory64" not found` → `NtRaiseHardError 0x40000015`.
   Success = pair gone; loader proceeds into payload extraction.
4. Regression gate: `wine cmd` (32-bit) unaffected; 64-bit `NtQueryVirtualMemory` callers untouched.

## 7. Risks & confidence

| Risk | L | I | Mitigation |
|---|---|---|---|
| Arg marshaling wrong (v2 flaw — caught) | eliminated | High | 8-token layout verified vs parser.c + siblings |
| Thunk missing (v2 flaw — caught) | eliminated | High | 2.3 added; auto-registration verified |
| Build breakage | Low | Med | 6 files mirror merged-upstream MR !6666 exactly |
| ThinApp gates on another API | Medium | Med | single-function isolation; deferred table §5 |
| ThinApp InlineHook rejects Wine internals | Low–Med | High | only empirically resolvable — this build is the probe |

**Confidence build succeeds + export present: ~95%** (template is a merged upstream MR; all
anchors verified line-by-line).
**Confidence ThinApp boot unblocks: ~75%** (residual = InlineHook unknown; test run resolves).

## 8. Review trail

- v1 draft (local-source only) → v2 (+librarian: phnt signature, MBI64, MR !6666)
- v2 → oracle NO-GO: 3 design flaws (arg list dropped the class dword → stack corruption;
  wow64 thunk omitted → link failure; unix code assumed reachable under new-WoW64 → wrong path)
- v3: all oracle claims **independently verified in source** (guards 7157/7321 ✓, thunk :899 ✓,
  parser.c:262 ✓, ntsyscalls 0x010b-d ✓, auto-registration ✓, MR pattern process.c:1186 ✓,
  winnt.h:743 ✓, winternl.h:5505-5509 ✓)

*v3, 2026-09-19. Ready for implementation.*

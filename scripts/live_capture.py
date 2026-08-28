#!/usr/bin/env python3
"""live_capture.py — live/dynamic RICOCHET capture (complements the static pass).

The static reports (docs 05-07) deliberately avoided live interaction. This
script performs the live layer, in privilege tiers, and records what it could
and could NOT do (an access-denied is itself evidence of the AC's protection).

Tiers (run all up to --max-tier):
  0 observe : processes, services, drivers, device objects, pipes (no admin)
  1 probe   : open Randgrid device + IOCTLs, open broker pipe, enumerate game
              modules + memory regions
  2 trap    : read/write game memory regions; detect protection / traps
  3 inject  : CreateRemoteThread probe into the game to read/write (needs
              admin + debug privileges)

Output: a local-only raw JSON file + a human summary on stdout. Raw captures may
contain host-specific identifiers, paths, addresses, handles, command lines,
and small read samples; keep them under the Git-ignored local-analysis folder
and publish only a separately privacy-reduced aggregate.

Usage:
  python live_capture.py --game-pid 44880 --max-tier 2 --out local-analysis/live.json
"""
import argparse, ctypes, json, os, sys, time, struct, datetime
from ctypes import wintypes

# ---------------------------------------------------------------------------
# Win32 constants
# ---------------------------------------------------------------------------
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_FLAG_OVERLAPPED = 0x40000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PROCESS_ALL = 0x001F0FFF
PROCESS_QUERY_INFORMATION = 0x400
PROCESS_VM_READ = 0x10
PROCESS_VM_WRITE = 0x20
PROCESS_VM_OPERATION = 0x8
PROCESS_CREATE_THREAD = 0x2
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MEM_COMMIT = 0x1000
MEM_FREE = 0x10000
PAGE_READWRITE = 0x4
PAGE_READONLY = 0x2
PAGE_EXECUTE_READWRITE = 0x40
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x1
PAGE_WRITECOPY = 0x4
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400
FILE_MAP_ALL_ACCESS = 0xF001F
SEC_IMAGE = 0x1000
SEC_RESERVE = 0x2000
SEC_COMMIT = 0x1000
INFINITE = 0xFFFFFFFF
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
# DeviceIoControl
IOCTL_BASE_DEVICE = 0x00000000
METHOD_BUFFERED = 0
FILE_DEVICE_UNKNOWN = 0x31
# common generic IOCTLs to probe
PROBE_IOCTL = [
    (0x00000000, "IOCTL 0x0"),
    (0x12000000, "IOCTL 0x12000000"),
    (0x12000004, "IOCTL 0x12000004"),
    (0x12000008, "IOCTL 0x12000008"),
    (0x1200000C, "IOCTL 0x1200000C"),
    (0x12000010, "IOCTL 0x12000010"),
    (0x12000014, "IOCTL 0x12000014"),
    (0x12000018, "IOCTL 0x12000018"),
    (0x1200001C, "IOCTL 0x1200001C"),
    (0x12000020, "IOCTL 0x12000020"),
]

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

# --- set prototypes so 64-bit pointer/size handling is correct ---
from ctypes import c_void_p, c_size_t, c_uint, c_bool, c_wchar_p
kernel32.OpenProcess.argtypes = [c_uint, c_bool, c_uint]
kernel32.OpenProcess.restype = c_void_p
kernel32.CloseHandle.argtypes = [c_void_p]
kernel32.CloseHandle.restype = c_bool
kernel32.VirtualQueryEx.argtypes = [c_void_p, c_void_p, c_void_p, c_size_t]
kernel32.VirtualQueryEx.restype = c_size_t
kernel32.ReadProcessMemory.argtypes = [c_void_p, c_void_p, c_void_p, c_size_t, c_void_p]
kernel32.ReadProcessMemory.restype = c_bool
kernel32.WriteProcessMemory.argtypes = [c_void_p, c_void_p, c_void_p, c_size_t, c_void_p]
kernel32.WriteProcessMemory.restype = c_bool
kernel32.VirtualAllocEx.argtypes = [c_void_p, c_void_p, c_size_t, c_uint, c_uint]
kernel32.VirtualAllocEx.restype = c_void_p
kernel32.VirtualFreeEx.argtypes = [c_void_p, c_void_p, c_size_t, c_uint]
kernel32.VirtualFreeEx.restype = c_bool
kernel32.CreateFileW.argtypes = [c_wchar_p, c_uint, c_uint, c_void_p, c_uint, c_uint, c_void_p]
kernel32.CreateFileW.restype = c_void_p
kernel32.DeviceIoControl.argtypes = [c_void_p, c_uint, c_void_p, c_uint, c_void_p, c_uint, c_void_p, c_void_p]
kernel32.DeviceIoControl.restype = c_bool
kernel32.PeekNamedPipe.argtypes = [c_void_p, c_void_p, c_uint, c_void_p, c_void_p, c_void_p]
kernel32.PeekNamedPipe.restype = c_bool
kernel32.CreateToolhelp32Snapshot.argtypes = [c_uint, c_uint]
kernel32.CreateToolhelp32Snapshot.restype = c_void_p
kernel32.Module32FirstW.argtypes = [c_void_p, c_void_p]
kernel32.Module32FirstW.restype = c_bool
kernel32.Module32NextW.argtypes = [c_void_p, c_void_p]
kernel32.Module32NextW.restype = c_bool
kernel32.GetFileType.argtypes = [c_void_p]
kernel32.GetFileType.restype = c_uint
kernel32.CreateRemoteThread.argtypes = [c_void_p, c_void_p, c_size_t, c_void_p, c_void_p, c_uint, c_void_p]
kernel32.CreateRemoteThread.restype = c_void_p
kernel32.WaitForSingleObject.argtypes = [c_void_p, c_uint]
kernel32.WaitForSingleObject.restype = c_uint
kernel32.GetExitCodeThread.argtypes = [c_void_p, c_void_p]
kernel32.GetExitCodeThread.restype = c_bool

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * 260),
    ]

def err():
    return ctypes.get_last_error()

def last_error_str():
    e = err()
    try:
        return f"{e} ({ctypes.FormatError(e)})"
    except Exception:
        return str(e)

def fmt_addr(a):
    return f"0x{a:X}" if a else "0x0"

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Tier 0: observe
# ---------------------------------------------------------------------------
def tier0_observe(evidence, game_pid):
    t0 = {"processes": [], "services": [], "drivers": [], "devices": [], "pipes": []}
    # processes (RICOCHET-specific, exact names)
    try:
        import subprocess
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "$names = 'cod.exe','CODBrokerService.exe','bootstrapper.exe','codCrashHandler.exe','bootstrapperCrashHandler.exe','CODSecureAttestationWizard.exe','telescope.exe'; Get-CimInstance Win32_Process | Where-Object { $names -contains $_.Name } | Select-Object Name,ProcessId,ParentProcessId,CommandLine | ConvertTo-Json"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        if out.stdout.strip():
            t0["processes"] = json.loads(out.stdout)
    except Exception as ex:
        t0["processes_error"] = str(ex)
    # services + drivers
    try:
        import subprocess
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match 'randgrid|ricochet|cod' } | Select-Object Name,State,StartMode,PathName | ConvertTo-Json"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
        if out.stdout.strip():
            t0["drivers"] = json.loads(out.stdout)
    except Exception as ex:
        t0["drivers_error"] = str(ex)
    # device objects
    for dev in (r"\\.\Randgrid", r"\\.\Global\Randgrid", r"\\.\GLOBALROOT\Device\Randgrid"):
        h = kernel32.CreateFileW(dev, GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
        if h != INVALID_HANDLE_VALUE and h is not None:
            t0["devices"].append({"name": dev, "opened": True})
            kernel32.CloseHandle(h)
        else:
            t0["devices"].append({"name": dev, "opened": False, "error": last_error_str()})
    # pipes
    try:
        import subprocess
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-ChildItem '\\\\.\\pipe\\' | Where-Object { $_.Name -match 'cod|broker|randgrid' } | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        t0["pipes"] = [l for l in out.stdout.splitlines() if l.strip()]
    except Exception as ex:
        t0["pipes_error"] = str(ex)
    evidence["tier0_observe"] = t0
    return t0

# ---------------------------------------------------------------------------
# Tier 1: probe (device IOCTLs, broker pipe, game modules + memory)
# ---------------------------------------------------------------------------
def tier1_probe(evidence, game_pid, max_tier):
    t1 = {"device": {}, "broker_pipe": {}, "game": {}}
    # --- Randgrid device IOCTL probe ---
    dev = r"\\.\Randgrid"
    h = kernel32.CreateFileW(dev, GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if h != INVALID_HANDLE_VALUE and h is not None:
        t1["device"]["opened"] = True
        t1["device"]["handle"] = fmt_addr(h)
        # query device type
        dtype = wintypes.DWORD()
        ok = kernel32.GetFileType(h)
        t1["device"]["file_type"] = ok  # 3 = pipe, 2 = char, 1 = disk
        # probe a few IOCTLs
        results = []
        for code, label in PROBE_IOCTL:
            inbuf = ctypes.create_string_buffer(64)
            outbuf = ctypes.create_string_buffer(256)
            ret = wintypes.DWORD()
            ok = kernel32.DeviceIoControl(h, code, inbuf, 64, outbuf, 256,
                                          ctypes.byref(ret), None)
            results.append({"ioctl": label, "ok": bool(ok),
                            "error": None if ok else last_error_str(),
                            "bytes_returned": ret.value})
        t1["device"]["ioctl_probes"] = results
        kernel32.CloseHandle(h)
    else:
        t1["device"]["opened"] = False
        t1["device"]["error"] = last_error_str()
    # --- broker pipe ---
    pipe = r"\\.\pipe\COD.Broker.v1"
    ph = kernel32.CreateFileW(pipe, GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, None,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if ph != INVALID_HANDLE_VALUE and ph is not None:
        t1["broker_pipe"]["opened"] = True
        t1["broker_pipe"]["handle"] = fmt_addr(ph)
        # try a non-blocking peek read of a small header
        buf = ctypes.create_string_buffer(256)
        got = wintypes.DWORD()
        # use PeekNamedPipe to avoid consuming
        avail = wintypes.DWORD()
        total = wintypes.DWORD()
        ok = kernel32.PeekNamedPipe(ph, buf, 256, ctypes.byref(got),
                                   ctypes.byref(avail), ctypes.byref(total))
        t1["broker_pipe"]["peek_ok"] = bool(ok)
        t1["broker_pipe"]["bytes_available"] = avail.value
        t1["broker_pipe"]["bytes_read"] = got.value
        if got.value:
            t1["broker_pipe"]["header_hex"] = buf.raw[:got.value].hex()
        kernel32.CloseHandle(ph)
    else:
        t1["broker_pipe"]["opened"] = False
        t1["broker_pipe"]["error"] = last_error_str()
    # --- game process: modules + memory regions ---
    if max_tier >= 1:
        gh = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                                  False, game_pid)
        if gh != INVALID_HANDLE_VALUE and gh is not None:
            t1["game"]["opened"] = True
            t1["game"]["handle"] = fmt_addr(gh)
            # modules
            mods = []
            TH32CS_SNAPMODULE = 0x00000008
            snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, game_pid)
            if snap != INVALID_HANDLE_VALUE and snap is not None:
                me = MODULEENTRY32W()
                me.dwSize = ctypes.sizeof(MODULEENTRY32W)
                if kernel32.Module32FirstW(snap, ctypes.byref(me)):
                    while True:
                        mods.append({
                            "name": me.szModule.decode("utf-8", "replace"),
                            "base": fmt_addr(me.modBaseAddr),
                            "path": me.szExePath.decode("utf-8", "replace"),
                        })
                        if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                            break
                        if len(mods) > 5000:
                            break
                kernel32.CloseHandle(snap)
            t1["game"]["module_count"] = len(mods)
            t1["game"]["modules"] = mods
            # memory regions (sample)
            regions = []
            addr = 0
            mbi = MEMORY_BASIC_INFORMATION()
            while addr < (1 << 44):
                n = kernel32.VirtualQueryEx(gh, ctypes.c_void_p(addr),
                                            ctypes.byref(mbi),
                                            ctypes.sizeof(mbi))
                if n == 0 or mbi.BaseAddress is None:
                    break
                if mbi.State == MEM_COMMIT:
                    regions.append({
                        "base": fmt_addr(mbi.BaseAddress),
                        "size": mbi.RegionSize,
                        "protect": fmt_addr(mbi.Protect),
                        "type": fmt_addr(mbi.Type),
                    })
                addr = mbi.BaseAddress + mbi.RegionSize
                if len(regions) > 20000:
                    break
            t1["game"]["region_count"] = len(regions)
            # summarize by protection
            from collections import Counter
            prot_counts = Counter(r["protect"] for r in regions)
            t1["game"]["protect_summary"] = dict(prot_counts)
            # keep the largest regions (likely driver-mapped / heap)
            regions.sort(key=lambda r: r["size"], reverse=True)
            t1["game"]["largest_regions"] = regions[:25]
            kernel32.CloseHandle(gh)
        else:
            t1["game"]["opened"] = False
            t1["game"]["error"] = last_error_str()
    evidence["tier1_probe"] = t1
    return t1

# ---------------------------------------------------------------------------
# Tier 2: memory trap (read/write game regions)
# ---------------------------------------------------------------------------
def tier2_trap(evidence, game_pid, max_tier):
    t2 = {"regions": [], "traps": []}
    if max_tier < 2:
        evidence["tier2_trap"] = t2
        return t2
    gh = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE |
                              PROCESS_VM_OPERATION, False, game_pid)
    if gh == INVALID_HANDLE_VALUE or gh is None:
        t2["error"] = last_error_str()
        evidence["tier2_trap"] = t2
        return t2
    t2["opened"] = True
    # find a few committed RW regions to probe
    candidates = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < (1 << 44):
        n = kernel32.VirtualQueryEx(gh, ctypes.c_void_p(addr),
                                    ctypes.byref(mbi), ctypes.sizeof(mbi))
        if n == 0 or mbi.BaseAddress is None:
            break
        if mbi.State == MEM_COMMIT and mbi.Protect in (PAGE_READWRITE, PAGE_WRITECOPY):
            candidates.append((mbi.BaseAddress, mbi.RegionSize, mbi.Protect))
        addr = mbi.BaseAddress + mbi.RegionSize
        if len(candidates) > 200000:
            break
    t2["rw_region_count"] = len(candidates)
    # probe up to 8 regions: read 16 bytes, write a sentinel, read back
    probe_count = 0
    for base, size, prot in candidates:
        if probe_count >= 8:
            break
        if size < 16:
            continue
        # read original
        orig = ctypes.create_string_buffer(16)
        got = wintypes.DWORD()
        ok = kernel32.ReadProcessMemory(gh, ctypes.c_void_p(base),
                                        orig, 16, ctypes.byref(got))
        if not ok:
            continue
        orig_bytes = orig.raw[:got.value]
        # write sentinel
        sentinel = b"RICOCHETTRAP"
        wr = wintypes.DWORD()
        okw = kernel32.WriteProcessMemory(gh, ctypes.c_void_p(base),
                                          sentinel, len(sentinel), ctypes.byref(wr))
        # read back
        back = ctypes.create_string_buffer(16)
        got2 = wintypes.DWORD()
        okr = kernel32.ReadProcessMemory(gh, ctypes.c_void_p(base),
                                         back, 16, ctypes.byref(got2))
        back_bytes = back.raw[:got2.value] if okr else b""
        # restore
        kernel32.WriteProcessMemory(gh, ctypes.c_void_p(base),
                                    orig_bytes, len(orig_bytes), ctypes.byref(wr))
        t2["traps"].append({
            "base": fmt_addr(base),
            "size": size,
            "protect": fmt_addr(prot),
            "read_ok": bool(ok),
            "write_ok": bool(okw),
            "write_error": None if okw else last_error_str(),
            "original_hex": orig_bytes.hex(),
            "after_write_hex": back_bytes.hex(),
            "sentinel_persisted": back_bytes.startswith(sentinel),
        })
        probe_count += 1
    kernel32.CloseHandle(gh)
    evidence["tier2_trap"] = t2
    return t2

# ---------------------------------------------------------------------------
# Tier 3: injection (CreateRemoteThread + LoadLibraryW probe)
# ---------------------------------------------------------------------------
def tier3_inject(evidence, game_pid, max_tier, inject_dll):
    t3 = {}
    if max_tier < 3:
        evidence["tier3_inject"] = t3
        return t3
    # needs PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
    gh = kernel32.OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE |
                              PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                              False, game_pid)
    if gh == INVALID_HANDLE_VALUE or gh is None:
        t3["error"] = last_error_str()
        evidence["tier3_inject"] = t3
        return t3
    t3["opened"] = True
    t3["handle"] = fmt_addr(gh)

    # --- Part A: read/write execution surface (alloc + write + readback) ---
    alloc = kernel32.VirtualAllocEx(gh, None, 64, MEM_COMMIT, PAGE_READWRITE)
    if alloc:
        t3["virtual_alloc_ok"] = True
        t3["alloc_base"] = fmt_addr(alloc)
        data = b"RICOCHETINJ"
        wr = wintypes.DWORD()
        ok = kernel32.WriteProcessMemory(gh, ctypes.c_void_p(alloc),
                                         data, len(data), ctypes.byref(wr))
        t3["write_to_alloc_ok"] = bool(ok)
        rb = ctypes.create_string_buffer(16)
        got = wintypes.DWORD()
        okr = kernel32.ReadProcessMemory(gh, ctypes.c_void_p(alloc),
                                         rb, 16, ctypes.byref(got))
        t3["readback_hex"] = rb.raw[:got.value].hex() if okr else ""
        kernel32.VirtualFreeEx(gh, ctypes.c_void_p(alloc), 0, 0x8000)  # MEM_RELEASE
        t3["freed"] = True
    else:
        t3["virtual_alloc_ok"] = False
        t3["alloc_error"] = last_error_str()

    # --- Part B: real injection — CreateRemoteThread(LoadLibraryW, dll_path) ---
    # This is the event the driver's thread-create callback inspects.
    if inject_dll:
        dll_w = inject_dll.encode("utf-16-le") + b"\x00\x00"
        # allocate the path buffer in the target
        path_buf = kernel32.VirtualAllocEx(gh, None, len(dll_w),
                                           MEM_COMMIT, PAGE_READWRITE)
        if path_buf:
            wr = wintypes.DWORD()
            okw = kernel32.WriteProcessMemory(gh, ctypes.c_void_p(path_buf),
                                              dll_w, len(dll_w),
                                              ctypes.byref(wr))
            t3["inject"] = {"dll": inject_dll, "path_written": bool(okw)}
            # resolve ntdll!LoadLibraryW in the target
            # (use the target's own ntdll base via module snapshot)
            ntdll_base = _find_module_base(gh, game_pid, "ntdll.dll")
            if ntdll_base:
                # LoadLibraryW is exported; resolve via GetProcAddress on our
                # own ntdll (same image, same export offset) as a fallback.
                loadlib = ctypes.windll.kernel32.GetProcAddress(
                    ctypes.windll.kernel32.GetModuleHandleW("ntdll.dll"),
                    b"LoadLibraryW")
                # CreateRemoteThread
                CREATE_SUSPENDED = 0x2
                th = kernel32.CreateRemoteThread(
                    gh, None, 0x1000,
                    ctypes.c_void_p(loadlib),
                    ctypes.c_void_p(path_buf), 0, ctypes.byref(wr))
                t3["inject"]["remote_thread"] = bool(th)
                if th:
                    # wait up to 3s for the thread to finish
                    WAIT_OBJECT_0 = 0
                    res = kernel32.WaitForSingleObject(th, 3000)
                    t3["inject"]["wait_result"] = res
                    code = wintypes.DWORD()
                    kernel32.GetExitCodeThread(th, ctypes.byref(code))
                    t3["inject"]["thread_exit_code"] = code.value
                    # did the DLL land in the target's module table?
                    mods_after = _list_module_names(gh, game_pid)
                    t3["inject"]["dll_in_module_table"] = (
                        inject_dll.lower().split("\\")[-1] in
                        [m.lower() for m in mods_after])
                    kernel32.CloseHandle(th)
            else:
                t3["inject"]["error"] = "ntdll base not found in target"
            kernel32.VirtualFreeEx(gh, ctypes.c_void_p(path_buf), 0, 0x8000)
        else:
            t3["inject"] = {"dll": inject_dll, "path_written": False,
                            "error": "VirtualAllocEx for path failed"}
    kernel32.CloseHandle(gh)
    evidence["tier3_inject"] = t3
    return t3


def _find_module_base(gh, game_pid, name):
    """Return the base address of `name` in the target, or None."""
    TH32CS_SNAPMODULE = 0x00000008
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, game_pid)
    if snap == INVALID_HANDLE_VALUE or snap is None:
        return None
    me = MODULEENTRY32W()
    me.dwSize = ctypes.sizeof(MODULEENTRY32W)
    found = None
    if kernel32.Module32FirstW(snap, ctypes.byref(me)):
        while True:
            if me.szModule.decode("utf-8", "replace").lower() == name.lower():
                found = me.modBaseAddr
                break
            if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                break
    kernel32.CloseHandle(snap)
    return found


def _list_module_names(gh, game_pid):
    TH32CS_SNAPMODULE = 0x00000008
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, game_pid)
    names = []
    if snap != INVALID_HANDLE_VALUE and snap is not None:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if kernel32.Module32FirstW(snap, ctypes.byref(me)):
            while True:
                names.append(me.szModule.decode("utf-8", "replace"))
                if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                    break
                if len(names) > 5000:
                    break
        kernel32.CloseHandle(snap)
    return names

# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--game-pid", type=int, required=True)
    ap.add_argument("--max-tier", type=int, default=2, choices=[0, 1, 2, 3])
    ap.add_argument(
        "--out",
        default="local-analysis/live-capture.json",
        help="local-only raw output; do not commit without privacy reduction",
    )
    ap.add_argument("--inject-dll", default=None,
                    help="absolute path to a DLL to inject at tier 3 "
                         "(CreateRemoteThread + LoadLibraryW)")
    args = ap.parse_args()

    evidence = {
        "schema_version": 1,
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": os.environ.get("COMPUTERNAME", "?"),
        "user": os.environ.get("USERNAME", "?"),
        "admin": is_admin(),
        "game_pid": args.game_pid,
        "max_tier": args.max_tier,
    }
    tier0_observe(evidence, args.game_pid)
    if args.max_tier >= 1:
        tier1_probe(evidence, args.game_pid, args.max_tier)
    if args.max_tier >= 2:
        tier2_trap(evidence, args.game_pid, args.max_tier)
    if args.max_tier >= 3:
        tier3_inject(evidence, args.game_pid, args.max_tier, args.inject_dll)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(evidence, f, indent=2)
    # human summary
    print(f"admin={evidence['admin']}  game_pid={args.game_pid}  max_tier={args.max_tier}")
    t0 = evidence.get("tier0_observe", {})
    print(f"  drivers: {len(t0.get('drivers', []))}  devices_opened: "
          f"{sum(1 for d in t0.get('devices', []) if d.get('opened'))}")
    t1 = evidence.get("tier1_probe", {})
    if t1:
        print(f"  device.opened={t1.get('device', {}).get('opened')}  "
              f"broker.opened={t1.get('broker_pipe', {}).get('opened')}  "
              f"game.opened={t1.get('game', {}).get('opened')}  "
              f"modules={t1.get('game', {}).get('module_count')}  "
              f"regions={t1.get('game', {}).get('region_count')}")
    t2 = evidence.get("tier2_trap", {})
    if t2:
        print(f"  trap.rw_regions={t2.get('rw_region_count')}  "
              f"traps_probed={len(t2.get('traps', []))}")
    t3 = evidence.get("tier3_inject", {})
    if t3:
        print(f"  inject.opened={t3.get('opened')}  alloc_ok={t3.get('virtual_alloc_ok')}")
    print(f"wrote {args.out}")

if __name__ == "__main__":
    main()

"""Focused pass: proper Authenticode check + Randgrid ntoskrnl imports + full strings."""
import os, re, json
import pefile
from pefile import PE

GAME = r"D:\SteamLibrary\steamapps\common\Call of Duty HQ"
BROKER = r"C:\ProgramData\Activision\Call of Duty"
OUT = os.path.dirname(os.path.abspath(__file__))

TARGETS = {
    "bootstrapper.exe": os.path.join(GAME, "bootstrapper.exe"),
    "cod.exe": os.path.join(GAME, "cod.exe"),
    "CODBrokerService.exe": os.path.join(BROKER, "CODBrokerService.exe"),
    "codCrashHandler.exe": os.path.join(BROKER, "codCrashHandler.exe"),
    "CODSecureAttestationWizard.exe": os.path.join(GAME, "CODSecureAttestationWizard.exe"),
    "Randgrid.sys": os.path.join(GAME, "Randgrid.sys"),
    "telescope25.dll": os.path.join(GAME, "telescope25.dll"),
}

def sig_info(path):
    """Return (signed, issuer, subject, time) using pefile's cert parsing."""
    try:
        pe = PE(path)
        pe.parse_data_directories()
        dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        sec = dd[4]  # SECURITY
        if sec.VirtualAddress == 0:
            return {"signed": False, "note": "no security dir"}
        # pefile stores parsed certs in pe.DIRECTORY_ENTRY_SECURITY
        certs = getattr(pe, "DIRECTORY_ENTRY_SECURITY", None)
        if not certs:
            return {"signed": False, "note": "security dir present but no certs parsed"}
        out = []
        for c in certs:
            try:
                out.append({
                    "issuer": c.issuer,
                    "subject": c.subject,
                    "serial": c.serial_number,
                    "valid_from": c.valid_from,
                    "valid_to": c.valid_to,
                })
            except Exception as e:
                out.append({"err": str(e)})
        return {"signed": True, "certs": out}
    except Exception as e:
        return {"signed": None, "note": str(e)}

def randgrid_imports(path):
    pe = PE(path)
    pe.parse_data_directories()
    res = {}
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        name = dll.dll.decode()
        syms = [s.name.decode() if s.name else f"ord#{s.ordinal}" for s in dll.imports]
        res[name] = syms
    return res

def all_strings(data, minlen=6):
    out = set()
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.add(m.group().decode())
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        out.add(m.group().decode("utf-16-le"))
    return out

def main():
    report = {}
    for name, path in TARGETS.items():
        if not os.path.exists(path):
            report[name] = {"sig": {"signed": None, "note": "not found"}}
            continue
        report[name] = {"sig": sig_info(path)}
    # Randgrid deep dive
    rg = TARGETS["Randgrid.sys"]
    pe = PE(rg)
    pe.parse_data_directories()
    imps = randgrid_imports(rg)
    nt = imps.get("ntoskrnl.exe", [])
    # interesting anti-cheat / kernel primitives
    interesting = [s for s in nt if re.search(
        r"ObRegister|ObDeregister|ObOpen|ObReference|ObQuery|ObCapture|ObFast|ObGet|ObSet|"
        r"MmGetPhysical|MmMapIo|MmProbe|MmCopy|MmGetSystem|MmAllocate|MmFree|MmProtect|"
        r"MmGetPhysicalAddress|MmGetPhysicalMemory|MmGetPhysicalPage|MmGetPhysicalPageCount|"
        r"KeQueryPerformance|KeQuerySystem|KeInsert|KeRemove|KeWait|KeSignal|KeDelay|"
        r"KeStack|KeExpand|KeSave|KeRestore|KeAcquire|KeRelease|KeBugCheck|KeRaise|"
        r"ExAllocate|ExFree|ExCreate|ExDelete|ExRegister|ExDeregister|ExAcquire|ExRelease|"
        r"ZwRead|ZwWrite|ZwCreate|ZwClose|ZwQuery|ZwSet|ZwOpen|ZwMapView|ZwUnmap|ZwCreateFile|"
        r"ZwCreateSection|ZwCreateThread|ZwCreateProcess|ZwTerminate|ZwSuspend|ZwResume|"
        r"ZwProtect|ZwFlush|ZwWait|ZwPulse|ZwRelease|ZwAcquire|ZwCancel|ZwImpersonate|"
        r"ZwOpenProcess|ZwOpenThread|ZwOpenKey|ZwOpenFile|ZwOpenSection|ZwOpenSymbolicLink|"
        r"RtlInit|RtlCopy|RtlCompare|RtlFind|RtlHash|RtlImage|RtlNtStatus|RtlPcTo|RtlVirtual|"
        r"RtlSub|RtlAdd|RtlDivide|RtlMod|RtlShift|RtlZero|RtlFill|RtlMove|RtlUpcase|RtlDowncase|"
        r"RtlUnicode|RtlMulti|RtlTime|RtlGet|RtlSet|RtlCheck|RtlVerify|RtlCompute|RtlGenerate|"
        r"RtlRandom|RtlCreate|RtlDelete|RtlDuplicate|RtlEnter|RtlLeave|RtlEnterCriticalSection|"
        r"RtlLeaveCriticalSection|RtlInitialize|RtlAcquire|RtlRelease|RtlTry|RtlUnlock|"
        r"RtlTimeTo|RtlTimeFields|RtlDaysIn|RtlTimeToTimeFields|RtlTimeFieldsToTime|"
        r"RtlImageNtHeader|RtlImageDirectoryEntryToData|RtlImageFileHeader|ExGet|ExFree|"
        r"ExAllocatePool|ExFreePool|ExAllocatePool2|ExFreePool2|ExAllocateFromPagedPool|"
        r"ExAllocateFromNonPagedPool|ExAllocateFromLookaside|ExFreeToLookaside|"
        r"ExAllocateFromCaches|ExFreeToCaches|ExAllocateFromCache|ExFreeToCache|"
        r"ExAllocateFromLookasideList|ExFreeToLookasideList|ExAllocateFromLookaside|"
        r"ExFreeToLookaside|ExAllocateFromLookasideList|ExFreeToLookasideList",
        s, re.I)]
    report["Randgrid.sys"]["ntoskrnl_total"] = len(nt)
    report["Randgrid.sys"]["ntoskrnl_interesting"] = sorted(set(interesting))
    report["Randgrid.sys"]["ntoskrnl_all"] = sorted(nt)
    report["Randgrid.sys"]["other_imports"] = {k: v for k, v in imps.items() if k != "ntoskrnl.exe"}
    # full strings
    data = pe.__data__
    strs = all_strings(data)
    pats = {
        "url": re.compile(r"https?://[^\s\"'<>]+", re.I),
        "registry": re.compile(r"^(HKLM|HKCU|HKEY_[A-Z_]+)[\\\/].+", re.I),
        "service": re.compile(r"atvi-|randgrid|ricochet|COD\.|broker|telescope|wizard|attest", re.I),
        "guid": re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$", re.I),
        "path": re.compile(r"^[A-Z]:\\.+"),
        "endpoint": re.compile(r"(activision|call of duty|callofduty|akamai|azure|telemetry|attest|ricochet|randgrid|broker|crash|upload|ingest|endpoint|api\.|\.dll|\.sys|\.exe)", re.I),
    }
    out = {k: [] for k in pats}
    for s in strs:
        for k, p in pats.items():
            if p.search(s):
                out[k].append(s)
                break
    report["Randgrid.sys"]["strings"] = out
    with open(os.path.join(OUT, "deep_report.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)
    # print
    for name, r in report.items():
        print("="*70)
        print(name)
        sig = r.get("sig", {})
        if sig.get("signed"):
            for c in sig.get("certs", []):
                print(f"  SIGNED: {c.get('subject')}")
                print(f"         issuer: {c.get('issuer')}")
                print(f"         valid: {c.get('valid_from')} -> {c.get('valid_to')}")
        else:
            print(f"  sig: {sig}")
    rg = report["Randgrid.sys"]
    print("="*70)
    print("Randgrid ntoskrnl:", rg["ntoskrnl_total"], "imports")
    print("  interesting:", len(rg["ntoskrnl_interesting"]))
    for s in rg["ntoskrnl_interesting"][:80]:
        print("   ", s)
    print("  other imports:", {k: len(v) for k,v in rg["other_imports"].items()})
    s = rg["strings"]
    for cat in ["url","registry","service","guid","path","endpoint"]:
        items = s.get(cat, [])
        if items:
            print(f"  --- strings:{cat} ({len(items)}) ---")
            for it in items[:40]:
                print(f"    {it}")

if __name__ == "__main__":
    main()

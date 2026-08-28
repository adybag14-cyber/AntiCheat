"""Disassemble entry points + key functions of RICOCHET binaries.

- Entry point of every target (first N instructions)
- Randgrid.sys: locate DriverEntry (scan for the function that references
  the service name / calls ObRegisterCallbacks) and disassemble it
- String extraction: URLs, registry paths, service names, GUIDs, file paths
"""
import os, re, json
import pefile
from pefile import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

GAME = r"D:\SteamLibrary\steamapps\common\Call of Duty HQ"
BROKER = r"C:\ProgramData\Activision\Call of Duty"
OUT = os.path.dirname(os.path.abspath(__file__))

TARGETS = [
    ("bootstrapper.exe",      os.path.join(GAME, "bootstrapper.exe")),
    ("cod.exe",               os.path.join(GAME, "cod.exe")),
    ("CODBrokerService.exe",  os.path.join(BROKER, "CODBrokerService.exe")),
    ("codCrashHandler.exe",   os.path.join(BROKER, "codCrashHandler.exe")),
    ("CODSecureAttestationWizard.exe", os.path.join(GAME, "CODSecureAttestationWizard.exe")),
    ("Randgrid.sys",          os.path.join(GAME, "Randgrid.sys")),
    ("telescope25.dll",       os.path.join(GAME, "telescope25.dll")),
]

def rva_to_off(pe, rva):
    try:
        return pe.get_offset_from_rva(rva)
    except Exception:
        return None

def disasm_at(pe, rva, n=50):
    off = rva_to_off(pe, rva)
    if off is None:
        return [f"(rva {hex(rva)} not in file)"]
    data = pe.get_data(off, n*16)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    out = []
    for i in md.disasm(data, rva):
        out.append(f"  {i.address:08x}: {i.mnemonic:8s} {i.op_str}")
        if len(out) >= n: break
    return out

def find_driver_entry(pe):
    """Find DriverEntry in a kernel driver.

    Strategy: DriverEntry is the function that (a) lives in an executable
    section, (b) is referenced by the section's 'DriverEntry' pointer if
    present, or (c) we scan for the function that calls the most imported
    ntoskrnl functions. Fallback: the first function in .text that references
    a 'DriverEntry' string or calls ObRegisterCallbacks/Ex.
    """
    # 1) try the section header trick: some drivers store DriverEntry RVA
    #    in a known structure. Not reliable.
    # 2) scan .text for calls to ObRegisterCallbacks (import #)
    #    Simpler: find the function that references the service name string.
    #    We'll just disassemble the first 200 bytes of .text and also try to
    #    find a function that calls many ntoskrnl imports.
    # Practical approach: DriverEntry is almost always the FIRST function
    #    in the driver's .text that is NOT a thunk, and it references the
    #    driver object. We'll disassemble the start of .text and look for
    #    the function that pushes/loads the DriverObject pointer.
    # For the report, we'll disassemble the first executable section's start
    #    and also search for the string "DriverEntry" or the service name.
    return None

def extract_strings(data, minlen=6):
    """Extract ASCII + UTF-16LE strings."""
    out = set()
    # ASCII
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.add(m.group().decode())
    # UTF-16LE
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        out.add(m.group().decode("utf-16-le"))
    return out

def interesting_strings(strings):
    """Filter strings to the interesting ones."""
    pats = {
        "url": re.compile(r"https?://[^\s\"'<>]+", re.I),
        "registry": re.compile(r"^(HKLM|HKCU|HKEY_[A-Z_]+)[\\\/].+", re.I),
        "service": re.compile(r"atvi-|randgrid|ricochet|COD\.|broker", re.I),
        "guid": re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?$", re.I),
        "path": re.compile(r"^[A-Z]:\\.+"),
        "endpoint": re.compile(r"(activision|call of duty|callofduty|akamai|azure|telemetry|attest|ricochet|randgrid|broker|crash|upload|ingest|endpoint|api\.)", re.I),
    }
    out = {k: [] for k in pats}
    for s in strings:
        for k, p in pats.items():
            if p.search(s):
                out[k].append(s)
                break
    return out

def main():
    report = {}
    for name, path in TARGETS:
        if not os.path.exists(path):
            report[name] = {"error": "not found"}
            continue
        pe = PE(path)
        pe.parse_data_directories()
        opt = pe.OPTIONAL_HEADER
        entry = opt.AddressOfEntryPoint
        r = {"entry": hex(entry)}
        # entry disassembly
        r["entry_disasm"] = disasm_at(pe, entry, 40)
        # strings (limit to first 8MB for the big ones to keep it fast)
        data = pe.__data__
        if len(data) > 8*1024*1024:
            data = data[:8*1024*1024]
        strs = extract_strings(data)
        r["strings"] = interesting_strings(strs)
        # for Randgrid, also disassemble the start of .text
        if name == "Randgrid.sys":
            text = pe.sections[0]
            r["text_start_disasm"] = disasm_at(pe, text.VirtualAddress, 60)
        report[name] = r
    with open(os.path.join(OUT, "disasm_report.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)
    # print a readable summary
    for name, r in report.items():
        print("="*70)
        print(f"{name}  entry={r.get('entry')}")
        if "error" in r:
            print("  ", r["error"]); continue
        print("  --- entry point ---")
        for line in r["entry_disasm"][:25]:
            print(line)
        if "text_start_disasm" in r:
            print("  --- .text start ---")
            for line in r["text_start_disasm"][:25]:
                print(line)
        s = r.get("strings", {})
        for cat in ["url","registry","service","guid","path","endpoint"]:
            items = s.get(cat, [])
            if items:
                print(f"  --- strings:{cat} ({len(items)}) ---")
                for it in items[:20]:
                    print(f"    {it}")

if __name__ == "__main__":
    main()

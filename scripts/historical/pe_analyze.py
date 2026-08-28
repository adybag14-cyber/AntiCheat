"""PE structure + disassembly analyzer for RICOCHET binaries.

For each target: machine, subsystem, entry point, sections, imports, exports,
Authenticode signature, version info, and a disassembly of the entry point
plus any exported functions. Strings are dumped separately.
"""
import os, sys, json, struct
import pefile
from pefile import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

GAME = r"D:\SteamLibrary\steamapps\common\Call of Duty HQ"
BROKER = r"C:\ProgramData\Activision\Call of Duty"

TARGETS = [
    ("bootstrapper.exe",      os.path.join(GAME, "bootstrapper.exe")),
    ("cod.exe",               os.path.join(GAME, "cod.exe")),
    ("CODBrokerService.exe",  os.path.join(BROKER, "CODBrokerService.exe")),
    ("codCrashHandler.exe",   os.path.join(BROKER, "codCrashHandler.exe")),
    ("CODSecureAttestationWizard.exe", os.path.join(GAME, "CODSecureAttestationWizard.exe")),
    ("Randgrid.sys",          os.path.join(GAME, "Randgrid.sys")),
    ("telescope25.dll",       os.path.join(GAME, "telescope25.dll")),
    ("telescope24.dll",       os.path.join(GAME, "telescope24.dll")),
]

def fmt_size(n):
    for u in ["B","KB","MB","GB"]:
        if n < 1024 or u=="GB":
            return f"{n:.1f}{u}" if u!="B" else f"{n}B"
        n/=1024.0

def get_authenticode(pe):
    try:
        certs = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # SECURITY / AUTHDATA
        if certs.VirtualAddress == 0:
            return None
        # parse the WIN_CERTIFICATE
        data = pe.get_data(certs.VirtualAddress, certs.Size)
        out = []
        off = 0
        while off + 8 <= len(data):
            dw_len, w_rev, w_type = struct.unpack_from("<IHH", data, off)
            if dw_len == 0: break
            # find subject/issuer via a quick scan for 'CN=' strings
            chunk = data[off:off+dw_len]
            # try to decode as UTF-16 to find CN=
            try:
                txt = chunk.decode('utf-16-le', errors='ignore')
            except Exception:
                txt = ''
            import re
            cns = re.findall(r'CN=([^,\\]+)', txt)
            out.append({"type": w_type, "len": dw_len, "cn": cns[:3]})
            off += dw_len
            if off > len(data): break
        return out
    except Exception as e:
        return {"error": str(e)}

def get_version_info(pe):
    try:
        vs = pe.VS_VERSIONINFO
        if not vs: return None
        out = {}
        for f in vs["StringFileInfo"]:
            for k,v in f["Strings"].items():
                out[k] = v
        return out
    except Exception:
        return None

def disasm_around(data, va, size, is64, n=40):
    md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
    md.detail = False
    # find file offset for va
    # we need section mapping; caller passes a function
    return md

def analyze(path, name):
    r = {"name": name, "path": path}
    if not os.path.exists(path):
        r["error"] = "NOT FOUND"
        return r
    r["size"] = os.path.getsize(path)
    pe = PE(path)
    pe.parse_data_directories()
    opt = pe.OPTIONAL_HEADER
    mach = pe.FILE_HEADER.Machine
    r["machine"] = mach
    r["machine_name"] = {0x8664:"x86-64",0x14c:"i386",0xaa64:"ARM64"}.get(mach, hex(mach))
    r["is64"] = mach == 0x8664
    r["subsystem"] = {1:"native",2:"windows-gui",3:"windows-cui",7:"native-driver",8:"windows-ce"}.get(opt.Subsystem, opt.Subsystem)
    r["entry_rva"] = hex(opt.AddressOfEntryPoint)
    r["image_base"] = hex(opt.ImageBase)
    r["num_sections"] = len(pe.sections)
    r["sections"] = []
    for s in pe.sections:
        r["sections"].append({
            "name": s.Name.rstrip(b"\x00").decode(errors="ignore"),
            "vsize": s.Misc_VirtualSize,
            "vaddr": hex(s.VirtualAddress),
            "rawsize": s.SizeOfRawData,
            "chars": s.Characteristics,
            "exec": bool(s.Characteristics & 0x20000000),
            "read": bool(s.Characteristics & 0x40000000),
            "write": bool(s.Characteristics & 0x80000000),
        })
    # imports
    r["imports"] = {}
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore")
            r["imports"][dll] = [imp.name.decode(errors="ignore") if imp.name else hex(imp.ordinal) for imp in entry.imports]
    except Exception as e:
        r["imports_error"] = str(e)
    # exports
    r["exports"] = []
    try:
        if pe.DIRECTORY_ENTRY_EXPORT:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                nm = exp.name.decode(errors="ignore") if exp.name else None
                r["exports"].append({"name": nm, "rva": hex(exp.address)})
    except Exception as e:
        r["exports_error"] = str(e)
    r["authenticode"] = get_authenticode(pe)
    r["version"] = get_version_info(pe)
    # resources count
    try:
        r["num_resources"] = len(pe.DIRECTORY_ENTRY_RESOURCE.entries) if pe.DIRECTORY_ENTRY_RESOURCE else 0
    except Exception:
        r["num_resources"] = 0
    # TLS
    try:
        r["has_tls"] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress != 0
    except Exception:
        r["has_tls"] = False
    # delay imports
    try:
        r["delay_imports"] = [e.dll.decode(errors="ignore") for e in pe.DIRECTORY_ENTRY_DELAY_IMPORT] if pe.DIRECTORY_ENTRY_DELAY_IMPORT else []
    except Exception:
        r["delay_imports"] = []
    return r

def main():
    out = {}
    for name, path in TARGETS:
        try:
            out[name] = analyze(path, name)
        except Exception as e:
            out[name] = {"name": name, "path": path, "error": repr(e)}
    with open(os.path.join(os.path.dirname(__file__), "pe_analysis.json"), "w") as f:
        json.dump(out, f, indent=2, default=str)
    # print a compact summary
    for name, r in out.items():
        print("="*70)
        print(f"{name}  ({r.get('size','?')} bytes)")
        if "error" in r:
            print("  ERROR:", r["error"]); continue
        print(f"  machine={r['machine_name']}  subsystem={r['subsystem']}  entry={r['entry_rva']}  base={r['image_base']}")
        print(f"  sections: " + ", ".join(f"{s['name']}({'X' if s['exec'] else '-'}{'W' if s['write'] else '-'})" for s in r["sections"]))
        imps = r.get("imports", {})
        print(f"  imports: {len(imps)} DLLs")
        for dll, syms in imps.items():
            print(f"    {dll}: {len(syms)}  e.g. {', '.join(syms[:6])}")
        if r.get("exports"):
            print(f"  exports: {len(r['exports'])}  e.g. {', '.join(e['name'] or hex(e['rva']) for e in r['exports'][:10])}")
        ac = r.get("authenticode")
        if ac:
            for c in ac:
                print(f"  sig: type={c.get('type')} CN={c.get('cn')}")
        v = r.get("version") or {}
        if v:
            print(f"  version: {v.get('ProductName','?')} {v.get('ProductVersion','?')}  file={v.get('FileVersion','?')}  co={v.get('CompanyName','?')}")
        print(f"  resources={r.get('num_resources',0)}  tls={r.get('has_tls')}  delay={r.get('delay_imports')}")

if __name__ == "__main__":
    main()

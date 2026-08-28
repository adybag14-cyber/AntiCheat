// Read-only Ghidra post-analysis evidence exporter for Randgrid.sys.
// @category Analysis

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class GhidraStaticEvidence extends GhidraScript {
    private static final List<String> TARGETS = Arrays.asList(
        "ObRegisterCallbacks",
        "MmGetPhysicalAddress",
        "MmMapIoSpace",
        "MmProbeAndLockPages",
        "MmProbeAndLockSelectedPages",
        "MmCopyMemory",
        "MmGetSystemRoutineAddress",
        "ExGetFirmwareEnvironmentVariable",
        "RtlImageNtHeader",
        "RtlImageDirectoryEntryToData",
        "CiCheckSignatureMandatory"
    );

    private String markdownSafe(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("```", "` ` `");
    }

    private List<Symbol> matchingSymbols(String target) {
        List<Symbol> result = new ArrayList<>();
        SymbolIterator iterator = currentProgram.getSymbolTable().getAllSymbols(true);
        while (iterator.hasNext() && !monitor.isCancelled()) {
            Symbol symbol = iterator.next();
            String name = symbol.getName();
            if (name.equals(target) || name.equals("__imp_" + target) || name.contains(target)) {
                result.add(symbol);
            }
        }
        return result;
    }

    private Set<Function> callersForSymbol(Symbol symbol) {
        Set<Function> callers = new LinkedHashSet<>();
        FunctionManager functions = currentProgram.getFunctionManager();
        ReferenceIterator references = currentProgram.getReferenceManager().getReferencesTo(symbol.getAddress());
        while (references.hasNext() && !monitor.isCancelled()) {
            Reference reference = references.next();
            Function function = functions.getFunctionContaining(reference.getFromAddress());
            if (function != null) {
                callers.add(function);
            }
        }
        Function imported = functions.getFunctionAt(symbol.getAddress());
        if (imported != null) {
            ReferenceIterator thunkReferences = currentProgram.getReferenceManager().getReferencesTo(imported.getEntryPoint());
            while (thunkReferences.hasNext() && !monitor.isCancelled()) {
                Reference reference = thunkReferences.next();
                Function function = functions.getFunctionContaining(reference.getFromAddress());
                if (function != null && !function.equals(imported)) {
                    callers.add(function);
                }
            }
        }
        return callers;
    }

    private void collectNeighborhood(Function seed, int depth, Set<Function> result) {
        if (seed == null || seed.isExternal() || !result.add(seed) || depth <= 0) {
            return;
        }
        for (Function caller : seed.getCallingFunctions(monitor)) {
            collectNeighborhood(caller, depth - 1, result);
        }
        for (Function callee : seed.getCalledFunctions(monitor)) {
            collectNeighborhood(callee, depth - 1, result);
        }
    }

    private String decompile(DecompInterface decompiler, Function function) {
        DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
        if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
            return result.getDecompiledFunction().getC();
        }
        return "/* decompilation unavailable: " + (result == null ? "no result" : result.getErrorMessage()) + " */";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("usage: GhidraStaticEvidence.java <output.md> <entry-rva-hex>");
        }
        File output = new File(args[0]);
        long entryRva = Long.parseUnsignedLong(args[1].replace("0x", ""), 16);
        Address entry = currentProgram.getImageBase().add(entryRva);
        FunctionManager functions = currentProgram.getFunctionManager();
        Function entryFunction = functions.getFunctionContaining(entry);
        if (entryFunction == null) {
            entryFunction = functions.createFunction("DriverEntry_candidate", entry, null, null);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);

        Map<String, Set<Function>> callersByTarget = new LinkedHashMap<>();
        Set<Function> allEvidenceFunctions = new LinkedHashSet<>();
        if (entryFunction != null) {
            allEvidenceFunctions.add(entryFunction);
        }
        // Explicit seeds surfaced by the entry thunk and the flattened
        // ObRegisterCallbacks registration path. Ghidra's call graph does not
        // always retain edges across the driver's jump-based dispatcher.
        long[] seedRvas = new long[] { 0x15cf58L, 0xab2df3L, 0xa27286L, 0xab309dL };
        for (long seedRva : seedRvas) {
            Function seed = functions.getFunctionContaining(currentProgram.getImageBase().add(seedRva));
            if (seed != null) {
                allEvidenceFunctions.add(seed);
            }
        }
        for (String target : TARGETS) {
            Set<Function> callers = new LinkedHashSet<>();
            for (Symbol symbol : matchingSymbols(target)) {
                callers.addAll(callersForSymbol(symbol));
            }
            callersByTarget.put(target, callers);
            allEvidenceFunctions.addAll(callers);
        }

        try (PrintWriter writer = new PrintWriter(output, "UTF-8")) {
            writer.println("# Randgrid.sys — Ghidra static evidence");
            writer.println();
            writer.println("- Program: `" + currentProgram.getName() + "`");
            writer.println("- Image base: `" + currentProgram.getImageBase() + "`");
            writer.println("- PE entry RVA: `0x" + Long.toHexString(entryRva) + "`");
            writer.println("- Entry address: `" + entry + "`");
            writer.println("- Entry function: `" + (entryFunction == null ? "unresolved" : entryFunction.getName()) + "`");
            writer.println("- Ghidra-defined functions: " + functions.getFunctionCount());
            writer.println();
            writer.println("## Imported-API reference map");
            writer.println();
            for (Map.Entry<String, Set<Function>> item : callersByTarget.entrySet()) {
                writer.println("### `" + item.getKey() + "`");
                for (Symbol symbol : matchingSymbols(item.getKey())) {
                    writer.println("- Symbol `" + symbol.getName() + "` at `" + symbol.getAddress() + "`");
                    ReferenceIterator rawReferences = currentProgram.getReferenceManager().getReferencesTo(symbol.getAddress());
                    while (rawReferences.hasNext()) {
                        Reference reference = rawReferences.next();
                        writer.println("  - raw reference from `" + reference.getFromAddress() + "` (`" + reference.getReferenceType() + "`)");
                    }
                }
                if (item.getValue().isEmpty()) {
                    writer.println("- No direct statically resolved caller found.");
                } else {
                    for (Function function : item.getValue()) {
                        writer.println("- `" + function.getName() + "` at `" + function.getEntryPoint() + "`");
                    }
                }
                writer.println();
            }

            writer.println("## Kernel-routine-looking defined strings and xrefs");
            writer.println();
            DataIterator definedData = currentProgram.getListing().getDefinedData(true);
            while (definedData.hasNext()) {
                Data data = definedData.next();
                if (!data.hasStringValue()) {
                    continue;
                }
                Object value = data.getValue();
                if (value == null) {
                    continue;
                }
                String text = value.toString();
                if (!text.matches(".*(Mm|Ob|Ps|Zw|Nt|Ke|Ex|Rtl)[A-Z][A-Za-z0-9_]{4,}.*")) {
                    continue;
                }
                writer.println("- `" + markdownSafe(text) + "` at `" + data.getAddress() + "`");
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Function owner = functions.getFunctionContaining(ref.getFromAddress());
                    writer.println("  - referenced from `" + ref.getFromAddress() + "` in `" + (owner == null ? "<no function>" : owner.getName()) + "`");
                }
            }
            writer.println();

            writer.println("## Evidence-function decompilations");
            writer.println();
            Set<Function> expandedEvidenceFunctions = new LinkedHashSet<>();
            for (Function seed : allEvidenceFunctions) {
                collectNeighborhood(seed, 2, expandedEvidenceFunctions);
            }
            writer.println("Expanded two-hop call-graph functions: " + expandedEvidenceFunctions.size());
            writer.println();
            writer.println("### Call-graph edges");
            writer.println();
            for (Function function : expandedEvidenceFunctions) {
                for (Function callee : function.getCalledFunctions(monitor)) {
                    if (!callee.isExternal()) {
                        writer.println("- `" + function.getName() + "` (`" + function.getEntryPoint() + "`) -> `" + callee.getName() + "` (`" + callee.getEntryPoint() + "`)");
                    }
                }
            }
            writer.println();
            for (Function function : expandedEvidenceFunctions) {
                writer.println("### `" + function.getName() + "` at `" + function.getEntryPoint() + "`");
                writer.println();
                writer.println("```c");
                writer.println(markdownSafe(decompile(decompiler, function)));
                writer.println("```");
                writer.println();
            }
        } finally {
            decompiler.dispose();
        }
        println("Wrote " + output.getAbsolutePath());
    }
}

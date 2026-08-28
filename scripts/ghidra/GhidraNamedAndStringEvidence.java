// Generic read-only named-symbol/string-xref evidence exporter.
// @category Analysis

import java.io.File;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class GhidraNamedAndStringEvidence extends GhidraScript {
    private List<String> split(String value) {
        List<String> result = new ArrayList<>();
        for (String item : value.split(";")) {
            if (!item.trim().isEmpty()) {
                result.add(item.trim());
            }
        }
        return result;
    }

    private void collect(Function function, int depth, Set<Function> result) {
        if (function == null || function.isExternal() || !result.add(function) || depth <= 0) {
            return;
        }
        for (Function caller : function.getCallingFunctions(monitor)) {
            collect(caller, depth - 1, result);
        }
        for (Function callee : function.getCalledFunctions(monitor)) {
            collect(callee, depth - 1, result);
        }
    }

    private String decompile(DecompInterface decompiler, Function function) {
        DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
        if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
            return result.getDecompiledFunction().getC().replace("```", "` ` `");
        }
        return "/* decompilation unavailable */";
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: GhidraNamedAndStringEvidence.java <output.md> <symbols...> --strings <strings...>"
            );
        }
        File output = new File(args[0]);
        List<String> symbolTerms = new ArrayList<>();
        List<String> stringTerms = new ArrayList<>();
        boolean parsingStrings = false;
        for (int index = 1; index < args.length; index++) {
            if (args[index].equals("--strings")) {
                parsingStrings = true;
            } else if (parsingStrings) {
                stringTerms.add(args[index]);
            } else {
                symbolTerms.add(args[index]);
            }
        }
        FunctionManager functions = currentProgram.getFunctionManager();
        Set<Function> seeds = new LinkedHashSet<>();

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);

        try (PrintWriter writer = new PrintWriter(output, "UTF-8")) {
            writer.println("# " + currentProgram.getName() + " — named/static-string evidence");
            writer.println();
            writer.println("- Image base: `" + currentProgram.getImageBase() + "`");
            writer.println("- Ghidra-defined functions: " + functions.getFunctionCount());
            writer.println();
            writer.println("## Named symbols");
            writer.println();
            SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(true);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                for (String term : symbolTerms) {
                    if (!symbol.getName().contains(term)) {
                        continue;
                    }
                    writer.println("- `" + symbol.getName() + "` at `" + symbol.getAddress() + "`");
                    Function owner = functions.getFunctionAt(symbol.getAddress());
                    if (owner == null) {
                        owner = functions.getFunctionContaining(symbol.getAddress());
                    }
                    if (owner != null && !owner.isExternal()) {
                        seeds.add(owner);
                    }
                    ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(symbol.getAddress());
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        Function caller = functions.getFunctionContaining(ref.getFromAddress());
                        writer.println("  - `" + ref.getReferenceType() + "` from `" + ref.getFromAddress() + "` in `" + (caller == null ? "<no function>" : caller.getName()) + "`");
                        if (caller != null) {
                            seeds.add(caller);
                        }
                    }
                }
            }
            writer.println();
            writer.println("## Matching defined strings and code xrefs");
            writer.println();
            DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
            while (dataIterator.hasNext()) {
                Data data = dataIterator.next();
                if (!data.hasStringValue() || data.getValue() == null) {
                    continue;
                }
                String value = data.getValue().toString();
                boolean matched = false;
                for (String term : stringTerms) {
                    if (value.toLowerCase().contains(term.toLowerCase())) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    continue;
                }
                writer.println("- `" + value.replace("`", "'") + "` at `" + data.getAddress() + "`");
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Function owner = functions.getFunctionContaining(ref.getFromAddress());
                    writer.println("  - `" + ref.getReferenceType() + "` from `" + ref.getFromAddress() + "` in `" + (owner == null ? "<no function>" : owner.getName()) + "`");
                    if (owner != null) {
                        seeds.add(owner);
                    }
                }
            }
            Set<Function> evidence = new LinkedHashSet<>();
            for (Function seed : seeds) {
                collect(seed, 2, evidence);
            }
            writer.println();
            writer.println("## Evidence call graph");
            writer.println();
            for (Function function : evidence) {
                for (Function callee : function.getCalledFunctions(monitor)) {
                    if (!callee.isExternal()) {
                        writer.println("- `" + function.getName() + "` (`" + function.getEntryPoint() + "`) -> `" + callee.getName() + "` (`" + callee.getEntryPoint() + "`)");
                    }
                }
            }
            writer.println();
            writer.println("## Decompilations");
            writer.println();
            for (Function function : evidence) {
                writer.println("### `" + function.getName() + "` at `" + function.getEntryPoint() + "`");
                writer.println();
                writer.println("```c");
                writer.println(decompile(decompiler, function));
                writer.println("```");
                writer.println();
            }
        } finally {
            decompiler.dispose();
        }
        println("Wrote " + output.getAbsolutePath());
    }
}

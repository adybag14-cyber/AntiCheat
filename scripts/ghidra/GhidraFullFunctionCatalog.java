// Read-only export of every Ghidra-defined function in Randgrid.sys.
// Does not decompile flattened bodies. Writes compact JSONL.
// @category Analysis

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;


public class GhidraFullFunctionCatalog extends GhidraScript {
    private String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder(value.length() + 8);
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            switch (ch) {
                case '\\':
                    builder.append("\\\\");
                    break;
                case '"':
                    builder.append("\\\"");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    if (ch < 0x20) {
                        builder.append(String.format("\\u%04x", (int) ch));
                    } else {
                        builder.append(ch);
                    }
            }
        }
        return builder.toString();
    }

    private String jsonStringList(List<String> values) {
        StringBuilder builder = new StringBuilder();
        builder.append("[");
        for (int index = 0; index < values.size(); index++) {
            if (index > 0) {
                builder.append(",");
            }
            builder.append("\"").append(jsonEscape(values.get(index))).append("\"");
        }
        builder.append("]");
        return builder.toString();
    }

    private String jsonAddressRanges(Function function) {
        StringBuilder builder = new StringBuilder();
        builder.append("[");
        AddressRangeIterator ranges = function.getBody().getAddressRanges();
        boolean first = true;
        while (ranges.hasNext()) {
            AddressRange range = ranges.next();
            if (!first) {
                builder.append(",");
            }
            first = false;
            builder.append("{\"min\":\"")
                .append(range.getMinAddress())
                .append("\",\"max\":\"")
                .append(range.getMaxAddress())
                .append("\"}");
        }
        builder.append("]");
        return builder.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("usage: GhidraFullFunctionCatalog.java <output.jsonl>");
        }
        File output = new File(args[0]);
        File parent = output.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }

        FunctionManager manager = currentProgram.getFunctionManager();
        long imageBase = currentProgram.getImageBase().getOffset();
        int functionCount = manager.getFunctionCount();
        int written = 0;

        try (PrintWriter writer = new PrintWriter(output, "UTF-8")) {
            writer.println(
                "{\"type\":\"header\",\"program\":\""
                    + jsonEscape(currentProgram.getName())
                    + "\",\"image_base\":\""
                    + currentProgram.getImageBase()
                    + "\",\"program_sha256\":\""
                    + jsonEscape(String.valueOf(currentProgram.getExecutableSHA256()))
                    + "\",\"ghidra_version\":\""
                    + jsonEscape(Application.getApplicationVersion())
                    + "\",\"language_id\":\""
                    + jsonEscape(String.valueOf(currentProgram.getLanguageID()))
                    + "\",\"compiler_spec_id\":\""
                    + jsonEscape(String.valueOf(currentProgram.getCompilerSpec().getCompilerSpecID()))
                    + "\",\"ghidra_function_count\":"
                    + functionCount
                    + "}"
            );

            FunctionIterator functions = manager.getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function function = functions.next();
                Address entry = function.getEntryPoint();
                long entryOff = entry.getOffset();
                long bodyMin = function.getBody().getMinAddress().getOffset();
                long bodyMax = function.getBody().getMaxAddress().getOffset();
                long bodyCount = function.getBody().getNumAddresses();

                List<String> callees = new ArrayList<>();
                Iterator<Function> called = function.getCalledFunctions(monitor).iterator();
                while (called.hasNext()) {
                    Function callee = called.next();
                    callees.add(callee.getName() + "@" + callee.getEntryPoint());
                }
                Collections.sort(callees);
                int calleeCount = callees.size();
                if (calleeCount > 64) {
                    callees = new ArrayList<>(callees.subList(0, 64));
                }

                List<String> callers = new ArrayList<>();
                Iterator<Function> calling = function.getCallingFunctions(monitor).iterator();
                while (calling.hasNext()) {
                    Function caller = calling.next();
                    callers.add(caller.getName() + "@" + caller.getEntryPoint());
                }
                Collections.sort(callers);
                int callerCount = callers.size();
                if (callerCount > 64) {
                    callers = new ArrayList<>(callers.subList(0, 64));
                }

                List<String> head = new ArrayList<>();
                int insnCount = 0;
                InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                while (instructions.hasNext() && !monitor.isCancelled()) {
                    Instruction instruction = instructions.next();
                    insnCount++;
                    if (head.size() < 12) {
                        head.add(instruction.getAddress() + " " + instruction.toString());
                    }
                }

                Address thunkTarget = null;
                if (function.isThunk()) {
                    Function thunked = function.getThunkedFunction(true);
                    if (thunked != null) {
                        thunkTarget = thunked.getEntryPoint();
                    }
                }

                writer.print("{");
                writer.print("\"type\":\"function\"");
                writer.print(",\"name\":\"" + jsonEscape(function.getName()) + "\"");
                writer.print(",\"entry\":\"" + entry + "\"");
                writer.print(",\"entry_rva\":" + (entryOff - imageBase));
                writer.print(",\"body_min\":\"" + function.getBody().getMinAddress() + "\"");
                writer.print(",\"body_max\":\"" + function.getBody().getMaxAddress() + "\"");
                writer.print(",\"body_span_bytes\":" + (bodyMax - bodyMin + 1));
                writer.print(",\"body_addresses\":" + bodyCount);
                writer.print(",\"body_ranges\":" + jsonAddressRanges(function));
                writer.print(",\"instruction_count\":" + insnCount);
                writer.print(",\"thunk\":" + function.isThunk());
                writer.print(",\"external\":" + function.isExternal());
                writer.print(",\"noreturn\":" + function.hasNoReturn());
                writer.print(",\"calling_convention\":\"" + jsonEscape(String.valueOf(function.getCallingConventionName())) + "\"");
                writer.print(",\"signature\":\"" + jsonEscape(function.getSignature().getPrototypeString()) + "\"");
                if (thunkTarget != null) {
                    writer.print(",\"thunk_target\":\"" + thunkTarget + "\"");
                }
                writer.print(",\"callee_count\":" + calleeCount);
                writer.print(",\"caller_count\":" + callerCount);
                writer.print(",\"callees\":" + jsonStringList(callees));
                writer.print(",\"callers\":" + jsonStringList(callers));
                writer.print(",\"head\":" + jsonStringList(head));
                writer.println("}");
                written++;
                if (written % 500 == 0) {
                    monitor.setMessage("exported " + written + " / " + functionCount);
                }
            }

            writer.println(
                "{\"type\":\"footer\",\"written_functions\":"
                    + written
                    + ",\"cancelled\":"
                    + monitor.isCancelled()
                    + "}"
            );
            writer.flush();
            if (writer.checkError()) {
                throw new IOException("failed while writing Ghidra function catalog");
            }
        }
        println("Wrote " + written + " functions to " + output.getAbsolutePath());
    }
}

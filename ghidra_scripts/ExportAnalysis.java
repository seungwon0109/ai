// Defensive static-analysis export script for Ghidra headless.
// The imported program is never executed.
//@category MCP

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;

public class ExportAnalysis extends GhidraScript {

    private Map<String, Object> functionRef(Function function) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("name", function.getName());
        result.put("entry", function.getEntryPoint().toString());
        result.put("external", function.isExternal());
        return result;
    }

    private List<Map<String, Object>> functionRefs(Set<Function> functions) {
        List<Map<String, Object>> results = new ArrayList<>();
        for (Function function : functions) {
            results.add(functionRef(function));
        }
        return results;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException(
                "Usage: ExportAnalysis.java <output.json> [maxFunctions] [maxDecompile]");
        }
        Path output = Paths.get(args[0]).toAbsolutePath();
        int maxFunctions = args.length > 1 ? Integer.parseInt(args[1]) : 1200;
        int maxDecompile = args.length > 2 ? Integer.parseInt(args[2]) : 120;

        Map<String, Object> root = new LinkedHashMap<>();
        Map<String, Object> program = new LinkedHashMap<>();
        program.put("name", currentProgram.getName());
        program.put("executable_path", currentProgram.getExecutablePath());
        program.put("executable_format", currentProgram.getExecutableFormat());
        program.put("language_id", currentProgram.getLanguageID().toString());
        program.put("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        program.put("image_base", currentProgram.getImageBase().toString());
        program.put("min_address", currentProgram.getMinAddress().toString());
        program.put("max_address", currentProgram.getMaxAddress().toString());
        root.put("program", program);

        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);

        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionIterator iterator = functionManager.getFunctions(true);
        List<Map<String, Object>> functions = new ArrayList<>();
        int functionCount = 0;
        int decompiledCount = 0;
        int externalCount = 0;

        while (iterator.hasNext() && functionCount < maxFunctions) {
            monitor.checkCancelled();
            Function function = iterator.next();
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("name", function.getName());
            item.put("entry", function.getEntryPoint().toString());
            item.put("signature", function.getSignature().toString());
            item.put("size", function.getBody().getNumAddresses());
            item.put("external", function.isExternal());
            item.put("thunk", function.isThunk());
            item.put("calling_convention", function.getCallingConventionName());
            item.put("callers", functionRefs(function.getCallingFunctions(monitor)));
            item.put("callees", functionRefs(function.getCalledFunctions(monitor)));

            if (function.isExternal()) {
                externalCount++;
            }
            else if (decompiledCount < maxDecompile) {
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (result != null && result.decompileCompleted() &&
                    result.getDecompiledFunction() != null) {
                    item.put("decompiled", result.getDecompiledFunction().getC());
                    decompiledCount++;
                }
                else if (result != null) {
                    item.put("decompile_error", result.getErrorMessage());
                }
            }
            functions.add(item);
            functionCount++;
        }
        decompiler.dispose();
        root.put("functions", functions);

        Listing listing = currentProgram.getListing();
        DataIterator dataIterator = listing.getDefinedData(true);
        List<Map<String, Object>> strings = new ArrayList<>();
        while (dataIterator.hasNext() && strings.size() < 2000) {
            monitor.checkCancelled();
            Data data = dataIterator.next();
            Object value = data.getValue();
            if (value instanceof String) {
                String text = (String) value;
                if (text.length() >= 4) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("address", data.getAddress().toString());
                    item.put("value", text);
                    DataType type = data.getDataType();
                    item.put("data_type", type == null ? null : type.getName());
                    strings.add(item);
                }
            }
        }
        root.put("strings", strings);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("function_count_exported", functionCount);
        summary.put("decompiled_count", decompiledCount);
        summary.put("external_function_count", externalCount);
        summary.put("defined_string_count_exported", strings.size());
        root.put("summary", summary);

        Files.createDirectories(output.getParent());
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        Files.writeString(output, gson.toJson(root), StandardCharsets.UTF_8);
        println("MCP_EXPORT_JSON=" + output.toString());
    }
}

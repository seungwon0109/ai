// Defensive static-analysis export for explicitly requested function addresses.
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
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class FocusedFunctions extends GhidraScript {

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
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "Usage: FocusedFunctions.java <output.json> <address> [address...]");
        }
        Path output = Paths.get(args[0]).toAbsolutePath();
        FunctionManager manager = currentProgram.getFunctionManager();
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");
        decompiler.openProgram(currentProgram);

        List<Map<String, Object>> functions = new ArrayList<>();
        for (int index = 1; index < args.length; index++) {
            monitor.checkCancelled();
            Address address = toAddr(args[index]);
            Function function = manager.getFunctionAt(address);
            if (function == null) {
                function = manager.getFunctionContaining(address);
            }
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("requested_address", args[index]);
            if (function == null) {
                item.put("error", "No function at or containing address");
                functions.add(item);
                continue;
            }
            item.put("name", function.getName());
            item.put("entry", function.getEntryPoint().toString());
            item.put("signature", function.getSignature().toString());
            item.put("size", function.getBody().getNumAddresses());
            item.put("thunk", function.isThunk());
            item.put("callers", functionRefs(function.getCallingFunctions(monitor)));
            item.put("callees", functionRefs(function.getCalledFunctions(monitor)));
            DecompileResults result = decompiler.decompileFunction(function, 120, monitor);
            if (result != null && result.decompileCompleted() &&
                result.getDecompiledFunction() != null) {
                item.put("decompiled", result.getDecompiledFunction().getC());
            }
            else if (result != null) {
                item.put("decompile_error", result.getErrorMessage());
            }
            functions.add(item);
        }
        decompiler.dispose();

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("program", currentProgram.getName());
        root.put("functions", functions);
        Files.createDirectories(output.getParent());
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        Files.writeString(output, gson.toJson(root), StandardCharsets.UTF_8);
        println("MCP_FOCUSED_JSON=" + output.toString());
    }
}

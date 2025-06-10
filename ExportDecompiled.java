//Exports all decompiled functions to a single text file
// @author Brian Reardon 
// @category Decompiler
// @keybinding
// @menupath
// @toolbar

import java.io.*;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.ConsoleTaskMonitor;

public class ExportDecompiled extends ghidra.app.script.GhidraScript {

    @Override
    public void run() throws Exception {
        String outputPath = askFile("Choose output file", "Save").getAbsolutePath();
        FileWriter writer = new FileWriter(outputPath);

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionManager fm = currentProgram.getFunctionManager();
        int count = 0;

        for (Function func : fm.getFunctions(true)) {
            monitor.setMessage("Decompiling: " + func.getName());

            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (results != null && results.decompileCompleted()) {
                writer.write("\n// ---------- " + func.getName() + " @ " + func.getEntryPoint() + " ----------\n");
                writer.write(results.getDecompiledFunction().getC());
                writer.write("\n");
                count++;
            }
        }

        writer.close();
        println("✅ Exported " + count + " functions to:\n" + outputPath);
    }
}

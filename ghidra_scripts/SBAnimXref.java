import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

public class SBAnimXref extends GhidraScript {
    private static final String[] NEEDLES = {
        "GetCurrentCustomAnimAlpha",
        "GetCurrentCustomAnimAddtiveAlpha",
        "GetCurrentCustomAnimByMeshSlotAlpha",
        "SBAnimInstance",
        "SBAnimNode_SequenceBlendedPlayer",
        "PlaySequences",
        "PlaySubSequences",
        "CustomAnimNode",
        "SBCustomAnimNode01"
    };

    private PrintWriter out;
    private final Set<Function> functions = new LinkedHashSet<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File report = new File(args.length > 0 ? args[0] : "SBAnimXref_report.txt");
        out = new PrintWriter(new FileWriter(report, false));
        try {
            out.println("SBAnimInstance / CustomAnim native xref report");
            out.println("Program=" + currentProgram.getName());
            out.println("ImageBase=" + currentProgram.getImageBase());
            out.println();

            Memory memory = currentProgram.getMemory();
            for (String needle : NEEDLES) {
                out.println("============================================================");
                out.println("NEEDLE: " + needle);
                scan(memory, needle.getBytes(StandardCharsets.US_ASCII), "ASCII");
                scan(memory, utf16le(needle), "UTF16LE");
                out.println();
            }

            out.println("============================================================");
            out.println("UNIQUE CONTAINING FUNCTIONS: " + functions.size());
            out.println("============================================================");

            DecompInterface decomp = new DecompInterface();
            decomp.toggleCCode(true);
            decomp.toggleSyntaxTree(true);
            if (!decomp.openProgram(currentProgram)) {
                out.println("DECOMPILER_OPEN_FAILED: " + decomp.getLastMessage());
                return;
            }

            for (Function f : functions) {
                if (monitor.isCancelled()) break;
                out.println();
                out.println("------------------------------------------------------------");
                out.println("FUNCTION " + f.getName(true) + " @ " + f.getEntryPoint());
                DecompileResults r = decomp.decompileFunction(f, 60, monitor);
                if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                    out.println(r.getDecompiledFunction().getC());
                } else {
                    out.println("DECOMPILE_FAILED: " + (r == null ? "null" : r.getErrorMessage()));
                }
            }
            decomp.dispose();
        } finally {
            if (out != null) out.close();
        }
        println("SBAnimXref wrote " + report.getAbsolutePath());
    }

    private void scan(Memory memory, byte[] pattern, String encoding) throws Exception {
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized()) continue;
            Address start = block.getStart();
            Address end = block.getEnd();
            Address cursor = start;
            int hits = 0;
            while (cursor != null && cursor.compareTo(end) <= 0 && hits < 256) {
                Address hit = memory.findBytes(cursor, end, pattern, null, true, monitor);
                if (hit == null) break;
                hits++;
                out.println(encoding + " hit " + hit + " block=" + block.getName());
                collectRefs(hit, 0, new LinkedHashSet<Address>());
                try {
                    cursor = hit.add(1);
                } catch (Exception e) {
                    break;
                }
            }
            if (hits >= 256) out.println("  HIT_LIMIT_REACHED in block " + block.getName());
        }
    }

    private void collectRefs(Address target, int depth, Set<Address> visited) {
        if (depth > 2 || target == null || !visited.add(target)) return;
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(target);
        int count = 0;
        while (it.hasNext() && count < 256) {
            Reference ref = it.next();
            count++;
            Address from = ref.getFromAddress();
            Function f = getFunctionContaining(from);
            out.println(indent(depth + 1) + "xref " + from + " -> " + target +
                " type=" + ref.getReferenceType() +
                (f == null ? "" : " func=" + f.getName(true) + " entry=" + f.getEntryPoint()));
            if (f != null) functions.add(f);
            collectRefs(from, depth + 1, visited);
        }
    }

    private static byte[] utf16le(String s) {
        byte[] a = s.getBytes(StandardCharsets.US_ASCII);
        byte[] b = new byte[a.length * 2];
        for (int i = 0; i < a.length; i++) b[i * 2] = a[i];
        return b;
    }

    private static String indent(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append("  ");
        return sb.toString();
    }
}

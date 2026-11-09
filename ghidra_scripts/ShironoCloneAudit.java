// Ghidra headless post-script. Read-only clone-related function/xref inventory.
// @category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.io.*;
import java.util.*;

public class ShironoCloneAudit extends GhidraScript {
    private static final String NEEDLE =
        "(?iu).*?(clone|copy|duplic|summon|shadow|player|objectcreate|createobject|instance|actionobject|分身|複製|コピー|残像|召喚).*";
    private static boolean interested(String x) {
        return x != null && x.length() < 20000 && x.matches(NEEDLE);
    }
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        Path dest = Paths.get(args.length > 0 ? args[0] : "/tmp");
        Files.createDirectories(dest);
        FunctionManager fm = currentProgram.getFunctionManager();
        LinkedHashMap<String,Function> candidates = new LinkedHashMap<>();
        int total=0;
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(
                dest.resolve("ghidra_clone_candidates.txt")))) {
            out.printf("PROGRAM %s%nLANGUAGE %s%n", currentProgram.getName(), currentProgram.getLanguageID());
            for (Function f : fm.getFunctions(true)) {
                total++;
                if(interested(f.getName()) || interested(f.getParentNamespace().getName())) {
                    if(candidates.size() < 600) candidates.put(f.getEntryPoint().toString(),f);
                    out.printf("FN %s %s %s%n",f.getEntryPoint(),f.getName(),f.getSignature());
                }
                if (monitor.isCancelled()) break;
            }
            out.printf("TOTAL_FUNCTIONS %d%n", total);
            int strings=0, stringHits=0;
            for (Data d : currentProgram.getListing().getDefinedData(true)) {
                if (++strings > 2500000 || monitor.isCancelled()) break;
                Object val = d.getValue();
                if(val == null) continue;
                String str = val.toString();
                if(!interested(str)) continue;
                stringHits++;
                if(stringHits<=1200)
                    out.printf("DATA %s %s%n",d.getAddress(),str.replace("\n"," ").substring(0,Math.min(str.length(),250)));
                for (Reference r : currentProgram.getReferenceManager().getReferencesTo(d.getAddress())) {
                    Function caller = fm.getFunctionContaining(r.getFromAddress());
                    if(caller != null) {
                        if(candidates.size() < 800)
                            candidates.put(caller.getEntryPoint().toString(), caller);
                        if(stringHits<=1200) out.printf("  XREF %s %s %s%n",r.getFromAddress(),caller.getEntryPoint(),caller.getName());
                    }
                }
            }
            out.printf("DATA_SCANNED %d MATCHES %d CANDIDATES %d%n",strings,stringHits,candidates.size());
        }
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        int done=0;
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(
                dest.resolve("ghidra_clone_decompile.txt")))) {
            for (Function f : candidates.values()) {
                if (++done > 45 || monitor.isCancelled()) break;
                out.printf("%n=========== %s %s ===========%n",f.getEntryPoint(),f.getName());
                try {
                    DecompileResults r=dec.decompileFunction(f,40,monitor);
                    if(r.decompileCompleted() && r.getDecompiledFunction()!=null) {
                        String code = r.getDecompiledFunction().getC();
                        out.println(code.substring(0, Math.min(code.length(),18000)));
                    } else out.println("DECOMPILATION_NOT_AVAILABLE "+r.getErrorMessage());
                } catch(Exception e) {
                    out.println("ERROR "+e);
                }
            }
            out.printf("%nDECOMPILED %d OF %d%n",Math.min(done,45),candidates.size());
        }
        dec.dispose();
        println("SHIRONO_GHIDRA_AUDIT_DONE functions="+total+" candidates="+candidates.size());
    }
}
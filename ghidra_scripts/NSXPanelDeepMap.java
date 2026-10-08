// Ghidra 12.1.4 headless post-script for NS XPanel 1.4.2
// Maps native handlers around the Ninja Saga-only login/session bridge.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class NSXPanelDeepMap extends GhidraScript {

    private static final String[] NEEDLES = new String[] {
        "start_game_login_cmd",
        "stop_game_login_cmd",
        "game_browser_request_cmd",
        "http_request",
        "get_hwid_cmd",
        "https://ninjasaga.cc/",
        "https://amf.ninjasaga.cc/",
        "/login",
        "player_id",
        "access_token",
        "signature",
        "hash_time",
        "game-login-success",
        "WebView2",
        "facebooklatest85224034668",
        "SystemService.requireLogin",
        "SystemService.snsLogin",
        "CharacterDAO.getCharactersList",
        "CharacterDAO.getCharacterById"
    };

    private PrintWriter out;
    private final Set<Address> dumpedFunctions = new LinkedHashSet<>();

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException("Output report path required");
        }

        File report = new File(args[0]);
        File parent = report.getParentFile();
        if (parent != null) parent.mkdirs();
        out = new PrintWriter(report, StandardCharsets.UTF_8);

        try {
            out.println("NSXPANEL_GHIDRA_DEEP_MAP");
            out.println("PROGRAM=" + currentProgram.getName());
            out.println("IMAGE_BASE=" + currentProgram.getImageBase());
            out.println("LANGUAGE=" + currentProgram.getLanguageID());
            out.println("COMPILER=" + currentProgram.getCompilerSpec().getCompilerSpecID());
            out.println();

            Map<String, Address> hits = new LinkedHashMap<>();
            Memory mem = currentProgram.getMemory();

            for (String needle : NEEDLES) {
                monitor.checkCancelled();
                byte[] bytes = needle.getBytes(StandardCharsets.UTF_8);
                Address start = currentProgram.getMinAddress();
                Address hit = mem.findBytes(start, bytes, null, true, monitor);
                if (hit != null) {
                    hits.put(needle, hit);
                    out.println("STRING_HIT\t" + needle + "\t" + hit);
                } else {
                    out.println("STRING_MISS\t" + needle);
                }
            }

            out.println();
            out.println("==== STRING XREFS ====");
            for (Map.Entry<String, Address> e : hits.entrySet()) {
                monitor.checkCancelled();
                String needle = e.getKey();
                Address addr = e.getValue();
                out.println();
                out.println("[STRING] " + needle + " @ " + addr);

                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
                int count = 0;
                while (refs.hasNext()) {
                    Reference r = refs.next();
                    count++;
                    Address from = r.getFromAddress();
                    Function f = getFunctionContaining(from);
                    out.println("XREF\t" + from + "\t" + r.getReferenceType() + "\tFUNC=" + (f == null ? "<none>" : f.getName() + "@" + f.getEntryPoint()));
                    if (f != null) dumpFunction(f, "xref:" + needle);
                }
                out.println("XREF_COUNT=" + count);
            }

            out.println();
            out.println("==== INTERESTING FUNCTION NAMES ====");
            FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
            while (fit.hasNext()) {
                monitor.checkCancelled();
                Function f = fit.next();
                String n = f.getName().toLowerCase();
                if (n.contains("webview") || n.contains("login") || n.contains("http") || n.contains("request") || n.contains("cookie") || n.contains("tauri")) {
                    out.println("FUNC_NAME\t" + f.getEntryPoint() + "\t" + f.getName());
                }
            }

            out.println();
            out.println("==== EXTERNAL FUNCTIONS ====");
            FunctionIterator eit = currentProgram.getFunctionManager().getExternalFunctions();
            while (eit.hasNext()) {
                monitor.checkCancelled();
                Function f = eit.next();
                String n = f.getName().toLowerCase();
                if (n.contains("http") || n.contains("internet") || n.contains("url") || n.contains("process") || n.contains("thread") || n.contains("token") || n.contains("library") || n.contains("webview")) {
                    out.println("EXTERNAL\t" + f.getName() + "\t" + f.getExternalLocation());
                }
            }

            out.println();
            out.println("DUMPED_FUNCTIONS=" + dumpedFunctions.size());
            out.println("NSXPANEL_GHIDRA_DEEP_MAP_END");
        } finally {
            out.flush();
            out.close();
        }
    }

    private void dumpFunction(Function f, String reason) {
        Address ep = f.getEntryPoint();
        if (!dumpedFunctions.add(ep)) return;

        out.println();
        out.println("---- FUNCTION " + f.getName() + " @ " + ep + " REASON=" + reason + " ----");
        out.println("SIGNATURE=" + f.getSignature());
        out.println("BODY=" + f.getBody());

        try {
            DecompInterface ifc = new DecompInterface();
            ifc.toggleCCode(true);
            ifc.toggleSyntaxTree(true);
            ifc.openProgram(currentProgram);
            DecompileResults res = ifc.decompileFunction(f, 90, monitor);
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                out.println("[DECOMPILE]");
                out.println(res.getDecompiledFunction().getC());
            } else {
                out.println("[DECOMPILE_FAILED] " + (res == null ? "null" : res.getErrorMessage()));
            }
            ifc.dispose();
        } catch (Throwable t) {
            out.println("[DECOMPILE_EXCEPTION] " + t.getClass().getName() + ": " + t.getMessage());
        }

        out.println("[CALL/REFERENCE SUMMARY]");
        try {
            AddressSetView body = f.getBody();
            InstructionIterator ii = currentProgram.getListing().getInstructions(body, true);
            int emitted = 0;
            while (ii.hasNext() && emitted < 300) {
                Instruction ins = ii.next();
                Reference[] refs = ins.getReferencesFrom();
                for (Reference r : refs) {
                    if (r.getReferenceType().isCall() || r.getReferenceType().isData()) {
                        out.println(ins.getAddress() + "\t" + ins + "\t->\t" + r.getToAddress() + "\t" + r.getReferenceType());
                        emitted++;
                        if (emitted >= 300) break;
                    }
                }
            }
        } catch (Throwable t) {
            out.println("[REF_SUMMARY_EXCEPTION] " + t.getMessage());
        }
        out.println("---- END FUNCTION ----");
    }
}

// Ghidra 12.1.4 headless post-script for NS XPanel 1.4.2
// Deep map of the native Ninja Saga login/session bridge. No Discord/HWID
// functionality is required by the replacement panel; those strings are kept
// only as negative-control boundaries when present in the original binary.

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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.File;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class NSXPanelDeepMap extends GhidraScript {

    private static final String[] NEEDLES = new String[] {
        // Tauri command boundary
        "start_game_login_cmd",
        "stop_game_login_cmd",
        "game_browser_request_cmd",
        "http_request",
        "get_hwid_cmd",

        // Ninja Saga browser/session boundary
        "https://ninjasaga.cc/",
        "https://ninjasaga.cc",
        "https://amf.ninjasaga.cc/",
        "amf.ninjasaga.cc",
        "/login",
        "game-login-success",
        "game-login",
        "player_id",
        "access_token",
        "signature",
        "hash_time",
        "username",
        "password",

        // Browser/cookie/header clues
        "WebView2",
        "webview2",
        "Cookie",
        "cookie",
        "Set-Cookie",
        "User-Agent",
        "Origin",
        "Referer",
        "execute_script",
        "initialization_script",
        "with_webview",

        // AMF bootstrap / known application strings
        "facebooklatest85224034668",
        "SystemService.requireLogin",
        "SystemService.snsLogin",
        "SystemService.checkAmf",
        "CharacterDAO.getCharactersList",
        "CharacterDAO.getCharacterById",
        "CharacterDAO.getExtraData",

        // Networking/runtime implementation clues
        "reqwest",
        "hyper",
        "tauri",
        "wry",

        // Original-panel-only negative controls
        "discord",
        "64.235.45.180:3090"
    };

    private static final int MAX_OCCURRENCES_PER_NEEDLE = 64;
    private static final int MAX_DUMPED_FUNCTIONS = 120;
    private static final int CALLER_DEPTH = 2;

    private PrintWriter out;
    private DecompInterface decompiler;
    private final Set<Address> dumpedFunctions = new LinkedHashSet<>();
    private final Set<Address> callerWalkSeen = new LinkedHashSet<>();

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

        decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.openProgram(currentProgram);

        try {
            emitProgramInfo();
            Map<String, List<Hit>> hits = collectAllStringHits();
            emitStringXrefs(hits);
            emitInterestingFunctionNames();
            emitExternalFunctions();

            out.println();
            out.println("==== SUMMARY ====");
            out.println("DUMPED_FUNCTIONS=" + dumpedFunctions.size());
            out.println("NSXPANEL_GHIDRA_DEEP_MAP_END");
        } finally {
            if (decompiler != null) decompiler.dispose();
            out.flush();
            out.close();
        }
    }

    private void emitProgramInfo() {
        out.println("NSXPANEL_GHIDRA_DEEP_MAP_V2");
        out.println("PROGRAM=" + currentProgram.getName());
        out.println("IMAGE_BASE=" + currentProgram.getImageBase());
        out.println("MIN_ADDRESS=" + currentProgram.getMinAddress());
        out.println("MAX_ADDRESS=" + currentProgram.getMaxAddress());
        out.println("LANGUAGE=" + currentProgram.getLanguageID());
        out.println("COMPILER=" + currentProgram.getCompilerSpec().getCompilerSpecID());
        out.println("POINTER_SIZE=" + currentProgram.getDefaultPointerSize());
        out.println();

        out.println("==== MEMORY BLOCKS ====");
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            out.println("BLOCK\t" + b.getName() + "\t" + b.getStart() + "-" + b.getEnd() +
                "\tR=" + b.isRead() + " W=" + b.isWrite() + " X=" + b.isExecute() +
                "\tSIZE=" + b.getSize());
        }
        out.println();
    }

    private Map<String, List<Hit>> collectAllStringHits() throws Exception {
        Map<String, List<Hit>> all = new LinkedHashMap<>();
        Memory mem = currentProgram.getMemory();

        out.println("==== STRING OCCURRENCES ====");
        for (String needle : NEEDLES) {
            monitor.checkCancelled();
            List<Hit> hits = new ArrayList<>();
            findAll(mem, needle, needle.getBytes(StandardCharsets.UTF_8), "UTF8", hits);
            findAll(mem, needle, needle.getBytes(StandardCharsets.UTF_16LE), "UTF16LE", hits);
            all.put(needle, hits);

            if (hits.isEmpty()) {
                out.println("STRING_MISS\t" + needle);
            } else {
                for (Hit h : hits) {
                    out.println("STRING_HIT\t" + needle + "\t" + h.encoding + "\t" + h.address);
                }
                out.println("STRING_HIT_COUNT\t" + needle + "\t" + hits.size());
            }
        }
        out.println();
        return all;
    }

    private void findAll(Memory mem, String needle, byte[] bytes, String encoding, List<Hit> outHits) throws Exception {
        if (bytes.length == 0) return;
        Address cursor = currentProgram.getMinAddress();
        Address max = currentProgram.getMaxAddress();
        int localCount = 0;

        while (cursor != null && cursor.compareTo(max) <= 0 && localCount < MAX_OCCURRENCES_PER_NEEDLE) {
            monitor.checkCancelled();
            Address hit = mem.findBytes(cursor, bytes, null, true, monitor);
            if (hit == null) break;
            outHits.add(new Hit(hit, encoding));
            localCount++;
            try {
                cursor = hit.add(1);
            } catch (Exception e) {
                break;
            }
        }
    }

    private void emitStringXrefs(Map<String, List<Hit>> hits) throws Exception {
        out.println("==== STRING XREFS / FUNCTION OWNERS ====");
        for (Map.Entry<String, List<Hit>> e : hits.entrySet()) {
            String needle = e.getKey();
            for (Hit hit : e.getValue()) {
                monitor.checkCancelled();
                out.println();
                out.println("[STRING] " + needle + " [" + hit.encoding + "] @ " + hit.address);

                Set<Address> ownerEntries = new LinkedHashSet<>();
                int refsCount = 0;

                // Rust often references a string start directly. Also inspect the first
                // few bytes because Ghidra can place a reference on an interior address.
                int span = Math.min(16, Math.max(1, needle.length()));
                for (int off = 0; off < span; off++) {
                    Address target;
                    try { target = hit.address.add(off); }
                    catch (Exception ex) { break; }
                    ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
                    while (refs.hasNext()) {
                        Reference r = refs.next();
                        refsCount++;
                        Address from = r.getFromAddress();
                        Function f = getFunctionContaining(from);
                        out.println("XREF\tTARGET=" + target + "\tFROM=" + from + "\t" + r.getReferenceType() +
                            "\tFUNC=" + functionLabel(f));
                        if (f != null) ownerEntries.add(f.getEntryPoint());
                    }
                }
                out.println("XREF_COUNT=" + refsCount);

                for (Address ep : ownerEntries) {
                    Function f = currentProgram.getFunctionManager().getFunctionAt(ep);
                    if (f == null) continue;
                    dumpFunction(f, "string-xref:" + needle);
                    walkCallers(f, CALLER_DEPTH, "caller-of:" + needle);
                }
            }
        }
    }

    private void walkCallers(Function target, int depth, String reason) throws Exception {
        if (depth <= 0 || target == null) return;
        Address ep = target.getEntryPoint();
        if (!callerWalkSeen.add(ep)) return;

        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(ep);
        int count = 0;
        while (refs.hasNext() && count < 80) {
            monitor.checkCancelled();
            Reference r = refs.next();
            if (!r.getReferenceType().isCall()) continue;
            count++;
            Function caller = getFunctionContaining(r.getFromAddress());
            out.println("CALLER\t" + functionLabel(target) + "\t<-\t" + functionLabel(caller) +
                "\tAT=" + r.getFromAddress());
            if (caller != null) {
                dumpFunction(caller, reason + ":depth" + depth);
                walkCallers(caller, depth - 1, reason);
            }
        }
    }

    private void emitInterestingFunctionNames() throws Exception {
        out.println();
        out.println("==== INTERESTING FUNCTION NAMES ====");
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        int dumpedNamed = 0;
        while (fit.hasNext()) {
            monitor.checkCancelled();
            Function f = fit.next();
            String n = f.getName().toLowerCase();
            if (containsAny(n, "webview", "login", "browser_request", "http_request", "cookie", "tauri", "reqwest", "wry")) {
                out.println("FUNC_NAME\t" + f.getEntryPoint() + "\t" + f.getName());
                // Named application functions are especially useful when symbols survive.
                if (dumpedNamed < 24 && (n.contains("game_login") || n.contains("browser_request") || n.contains("start_game") || n.contains("stop_game"))) {
                    dumpFunction(f, "interesting-name");
                    dumpedNamed++;
                }
            }
        }
    }

    private void emitExternalFunctions() throws Exception {
        out.println();
        out.println("==== EXTERNAL FUNCTIONS ====");
        FunctionIterator eit = currentProgram.getFunctionManager().getExternalFunctions();
        while (eit.hasNext()) {
            monitor.checkCancelled();
            Function f = eit.next();
            String n = f.getName().toLowerCase();
            if (containsAny(n, "http", "internet", "url", "process", "thread", "token", "library", "webview", "winhttp", "wininet", "crypt", "socket")) {
                out.println("EXTERNAL\t" + f.getName() + "\t" + f.getExternalLocation());
            }
        }
    }

    private void dumpFunction(Function f, String reason) throws Exception {
        if (f == null) return;
        Address ep = f.getEntryPoint();
        if (dumpedFunctions.contains(ep)) return;
        if (dumpedFunctions.size() >= MAX_DUMPED_FUNCTIONS) {
            out.println("FUNCTION_DUMP_LIMIT_REACHED=" + MAX_DUMPED_FUNCTIONS);
            return;
        }
        dumpedFunctions.add(ep);

        out.println();
        out.println("---- FUNCTION " + f.getName() + " @ " + ep + " REASON=" + reason + " ----");
        out.println("SIGNATURE=" + f.getSignature());
        out.println("BODY=" + f.getBody());

        try {
            DecompileResults res = decompiler.decompileFunction(f, 120, monitor);
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                out.println("[DECOMPILE]");
                out.println(res.getDecompiledFunction().getC());
            } else {
                out.println("[DECOMPILE_FAILED] " + (res == null ? "null" : res.getErrorMessage()));
            }
        } catch (Throwable t) {
            out.println("[DECOMPILE_EXCEPTION] " + t.getClass().getName() + ": " + t.getMessage());
        }

        out.println("[CALL/DATA REFERENCE SUMMARY]");
        try {
            AddressSetView body = f.getBody();
            InstructionIterator ii = currentProgram.getListing().getInstructions(body, true);
            int emitted = 0;
            while (ii.hasNext() && emitted < 500) {
                monitor.checkCancelled();
                Instruction ins = ii.next();
                Reference[] refs = ins.getReferencesFrom();
                for (Reference r : refs) {
                    if (r.getReferenceType().isCall() || r.getReferenceType().isData()) {
                        Function callee = null;
                        if (r.getReferenceType().isCall()) {
                            callee = currentProgram.getFunctionManager().getFunctionAt(r.getToAddress());
                            if (callee == null) callee = getFunctionContaining(r.getToAddress());
                        }
                        out.println(ins.getAddress() + "\t" + ins + "\t->\t" + r.getToAddress() +
                            "\t" + r.getReferenceType() + (callee == null ? "" : "\tCALLEE=" + functionLabel(callee)));
                        emitted++;
                        if (emitted >= 500) break;
                    }
                }
            }
        } catch (Throwable t) {
            out.println("[REF_SUMMARY_EXCEPTION] " + t.getClass().getName() + ": " + t.getMessage());
        }
        out.println("---- END FUNCTION ----");
    }

    private boolean containsAny(String s, String... parts) {
        for (String p : parts) if (s.contains(p)) return true;
        return false;
    }

    private String functionLabel(Function f) {
        return f == null ? "<none>" : f.getName() + "@" + f.getEntryPoint();
    }

    private static class Hit {
        final Address address;
        final String encoding;
        Hit(Address address, String encoding) {
            this.address = address;
            this.encoding = encoding;
        }
    }
}

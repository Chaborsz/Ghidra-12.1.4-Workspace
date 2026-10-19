// APK2SaveCryptoTrace.java
// Targeted static analysis for Demon Slayer Hinokami Chronicles 2 save crypto.
//@category APK2

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class APK2SaveCryptoTrace extends GhidraScript {
    private PrintWriter out;
    private DecompInterface decomp;

    private static final String[] TARGETS = {
        "EncryptKey", "DefaultData", "UAPKSaveGameManager", "UAPKGameSaveDataHandler",
        "UAPKSaveGame", "SaveData", "SaveGame", "LoadSave", "OldVersion", "NewVersion",
        "Corrupt", "OutOfLocalStorage", "Serialize", "Deserialize", "Encrypt", "Decrypt", "FAES"
    };

    @Override
    protected void run() throws Exception {
        File f = new File(System.getProperty("java.io.tmpdir"), "APK2_GHIDRA_SAVE_CRYPTO.txt");
        out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(f), StandardCharsets.UTF_8));
        decomp = new DecompInterface();
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(false);
        decomp.openProgram(currentProgram);

        emit("PROGRAM=" + currentProgram.getName());
        emit("IMAGE_BASE=" + currentProgram.getImageBase());
        emit("LANGUAGE=" + currentProgram.getLanguageID());
        emit("COMPILER=" + currentProgram.getCompilerSpec().getCompilerSpecID());

        Memory mem = currentProgram.getMemory();
        Set<Address> allHits = new TreeSet<>();

        for (String target : TARGETS) {
            emit("\n===== TARGET " + target + " =====");
            List<Address> hits = new ArrayList<>();
            hits.addAll(findBytes(mem, target.getBytes(StandardCharsets.US_ASCII)));
            hits.addAll(findBytes(mem, utf16le(target)));
            Collections.sort(hits);
            for (Address a : hits) {
                if (!allHits.add(a)) continue;
                emit("STRING_HIT " + a + " block=" + blockName(a));
                dumpReferences(a, 0);
                scanRawPointersTo(a);
            }
        }

        emit("\n===== SYMBOL NAME MATCHES =====");
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator si = st.getAllSymbols(true);
        while (si.hasNext() && !monitor.isCancelled()) {
            Symbol s = si.next();
            String n = s.getName();
            for (String t : TARGETS) {
                if (n.toLowerCase(Locale.ROOT).contains(t.toLowerCase(Locale.ROOT))) {
                    emit("SYMBOL " + s.getAddress() + " " + s.getSymbolType() + " " + s.getName(true));
                    break;
                }
            }
        }

        emit("\n===== FUNCTION NAME MATCHES =====");
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext() && !monitor.isCancelled()) {
            Function fn = fi.next();
            String n = fn.getName();
            String sig = fn.getSignature().getPrototypeString();
            boolean match = false;
            for (String t : TARGETS) {
                if (n.toLowerCase(Locale.ROOT).contains(t.toLowerCase(Locale.ROOT)) ||
                    sig.toLowerCase(Locale.ROOT).contains(t.toLowerCase(Locale.ROOT))) { match = true; break; }
            }
            if (match) {
                emit("FUNCTION " + fn.getEntryPoint() + " " + sig);
                decompile(fn);
            }
        }

        out.flush(); out.close(); decomp.dispose();
        println("APK2 trace written to " + f.getAbsolutePath());
    }

    private List<Address> findBytes(Memory mem, byte[] pat) throws Exception {
        List<Address> r = new ArrayList<>();
        Address start = currentProgram.getMinAddress();
        while (start != null && !monitor.isCancelled()) {
            Address a = mem.findBytes(start, pat, null, true, monitor);
            if (a == null) break;
            r.add(a);
            try { start = a.add(1); } catch (Exception e) { break; }
        }
        return r;
    }

    private byte[] utf16le(String s) {
        return s.getBytes(StandardCharsets.UTF_16LE);
    }

    private String blockName(Address a) {
        try { return currentProgram.getMemory().getBlock(a).getName(); } catch (Exception e) { return "?"; }
    }

    private void dumpReferences(Address target, int depth) {
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(target);
        int count = 0;
        while (it.hasNext() && count < 200 && !monitor.isCancelled()) {
            Reference r = it.next(); count++;
            Address from = r.getFromAddress();
            emit(indent(depth) + "XREF " + from + " type=" + r.getReferenceType() + " op=" + r.getOperandIndex());
            Function fn = currentProgram.getFunctionManager().getFunctionContaining(from);
            if (fn != null) {
                emit(indent(depth) + "  IN_FUNCTION " + fn.getEntryPoint() + " " + fn.getName(true));
                decompile(fn);
                dumpCallers(fn, depth + 1);
            } else {
                emit(indent(depth) + "  DATA_OR_NOFUNC block=" + blockName(from));
            }
        }
        if (count == 0) emit(indent(depth) + "NO_GHIDRA_XREFS");
    }

    private void dumpCallers(Function fn, int depth) {
        if (depth > 2) return;
        Set<Function> seen = new LinkedHashSet<>();
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(fn.getEntryPoint());
        int n = 0;
        while (refs.hasNext() && n < 40 && !monitor.isCancelled()) {
            Reference r = refs.next();
            Function caller = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
            if (caller != null && seen.add(caller)) {
                n++;
                emit(indent(depth) + "CALLER " + caller.getEntryPoint() + " " + caller.getName(true));
                if (depth <= 1) decompile(caller);
            }
        }
    }

    private void scanRawPointersTo(Address target) throws Exception {
        long v = target.getOffset();
        byte[] pat = new byte[8];
        for (int i=0;i<8;i++) pat[i]=(byte)((v >>> (8*i)) & 0xff);
        Memory mem=currentProgram.getMemory();
        Address start=currentProgram.getMinAddress();
        int n=0;
        while (start != null && n < 200 && !monitor.isCancelled()) {
            Address a=mem.findBytes(start,pat,null,true,monitor);
            if (a==null) break;
            n++;
            emit("RAW_PTR_TO_STRING at="+a+" block="+blockName(a)+" -> "+target);
            dumpReferences(a,1);
            try { start=a.add(1); } catch(Exception e){break;}
        }
        if(n==0) emit("NO_RAW_64BIT_POINTERS_TO_STRING");
    }

    private void decompile(Function fn) {
        try {
            DecompileResults res=decomp.decompileFunction(fn,30,monitor);
            if(res!=null && res.decompileCompleted() && res.getDecompiledFunction()!=null){
                String c=res.getDecompiledFunction().getC();
                if(c.length()>30000) c=c.substring(0,30000)+"\n/* TRUNCATED */";
                emit("----- DECOMPILE "+fn.getEntryPoint()+" "+fn.getName(true)+" -----\n"+c+"----- END DECOMPILE -----");
            } else emit("DECOMPILE_FAILED "+fn.getEntryPoint()+" "+fn.getName(true));
        } catch(Exception e){emit("DECOMPILE_EXCEPTION "+fn.getEntryPoint()+" "+e);}
    }

    private String indent(int d){ return "  ".repeat(Math.max(0,d)); }
    private void emit(String s){ out.println(s); }
}

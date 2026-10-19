// APK2QuickEncryptKeyInit.java
//@category APK2

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class APK2QuickEncryptKeyInit extends GhidraScript {
    private PrintWriter out;
    private DecompInterface decomp;
    private final long[] targets={
        0x1450d58c0L,0x144cd2430L,0x14154bc70L,0x141433f00L,
        0x1450ce860L,0x1450ceb50L
    };
    @Override protected void run() throws Exception {
        File f=new File(System.getProperty("java.io.tmpdir"),"APK2_GHIDRA_ENCRYPTKEY_INIT.txt");
        out=new PrintWriter(new OutputStreamWriter(new FileOutputStream(f),StandardCharsets.UTF_8));
        decomp=new DecompInterface();decomp.toggleCCode(true);decomp.openProgram(currentProgram);
        for(long v:targets){
            Address a=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
            emit("\n===== TARGET "+a+" =====");
            try{disassemble(a);}catch(Exception e){emit("DISASM_EX "+e);}
            Function fn=getFunctionAt(a); if(fn==null)try{fn=createFunction(a,"APK2_init_"+Long.toHexString(v));}catch(Exception e){emit("CREATE_EX "+e);}
            if(fn==null){emit("NO_FUNCTION");continue;}
            emit("FUNCTION "+fn.getEntryPoint()+" "+fn.getName(true)+" BODY="+fn.getBody());
            DecompileResults r=decomp.decompileFunction(fn,30,monitor);
            if(r!=null&&r.decompileCompleted()&&r.getDecompiledFunction()!=null){String c=r.getDecompiledFunction().getC();emit(c);scanCalls(fn);}
            else emit("DECOMPILE_FAILED");
        }
        out.flush();out.close();decomp.dispose();println("Wrote "+f);
    }
    private void scanCalls(Function fn){
        Listing l=currentProgram.getListing();InstructionIterator it=l.getInstructions(fn.getBody(),true);Set<Address> callees=new LinkedHashSet<>();
        int n=0;while(it.hasNext()&&n++<3000){Instruction i=it.next();String s=i.toString();if(s.contains("0x30")||s.contains("+0x30")||s.contains("30h"))emit("PLUS30 "+i.getAddress()+" "+s);for(Reference r:i.getReferencesFrom()){if(r.getReferenceType().isCall())callees.add(r.getToAddress());}}
        int k=0;for(Address ca:callees){if(k++>=80)break;emit("CALLEE "+ca);try{disassemble(ca);}catch(Exception e){}Function cf=getFunctionAt(ca);if(cf==null)try{cf=createFunction(ca,"APK2_callee_"+ca.toString());}catch(Exception e){}if(cf!=null){DecompileResults rr=decomp.decompileFunction(cf,15,monitor);if(rr!=null&&rr.decompileCompleted()&&rr.getDecompiledFunction()!=null){String c=rr.getDecompiledFunction().getC();if(c.contains("0x30")||c.contains("+ 0x30")||c.contains("+0x30")||c.contains("param_1[6]")||c.contains("param_1 + 6")){emit("--- INTERESTING CALLEE "+ca+" ---\n"+c+"--- END ---");}}}}
    }
    private void emit(String s){out.println(s);}
}

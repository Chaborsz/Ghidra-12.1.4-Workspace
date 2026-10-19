// APK2QuickSaveManager.java
//@category APK2

import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class APK2QuickSaveManager extends GhidraScript {
    private PrintWriter out;
    private DecompInterface decomp;
    private final long[] targets = {
        0x1450ce860L,0x1450ceb20L,0x1450ceb50L,0x1450cec30L,0x1450cec60L,
        0x1450ced10L,0x1450cedf0L,0x1450ceea0L,0x1450cf290L
    };

    @Override protected void run() throws Exception {
        File f=new File(System.getProperty("java.io.tmpdir"),"APK2_GHIDRA_QUICK_SAVE_MANAGER.txt");
        out=new PrintWriter(new OutputStreamWriter(new FileOutputStream(f),StandardCharsets.UTF_8));
        decomp=new DecompInterface(); decomp.toggleCCode(true); decomp.openProgram(currentProgram);
        emit("PROGRAM="+currentProgram.getName()+" BASE="+currentProgram.getImageBase());
        for(long v:targets){
            Address a=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
            emit("\n===== TARGET "+a+" =====");
            try{ disassemble(a); }catch(Exception e){emit("DISASSEMBLE_EXCEPTION "+e);}
            Function fn=getFunctionAt(a);
            if(fn==null){
                try{ fn=createFunction(a,"APK2_target_"+Long.toHexString(v)); }catch(Exception e){emit("CREATE_FUNCTION_EXCEPTION "+e);}
            }
            if(fn!=null){
                emit("FUNCTION="+fn.getName(true)+" ENTRY="+fn.getEntryPoint()+" BODY="+fn.getBody());
                dumpFunctionInstructions(fn);
                dumpRefs(fn);
                decompile(fn);
            }else{
                dumpLinear(a,300);
            }
        }
        // Known UHT EncryptKey structures/pointers.
        long[] meta={0x14a1d45f8L,0x14a1dead0L,0x14a1dea78L,0x14a1dee08L,0x14b1edee0L};
        emit("\n===== KNOWN ENCRYPTKEY METADATA REFS =====");
        for(long v:meta){
            Address a=currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
            emit("META "+a);
            ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(a);
            int n=0; while(ri.hasNext()&&n<100){ Reference r=ri.next(); n++; emit(" XREF "+r.getFromAddress()+" "+r.getReferenceType()); }
            if(n==0)emit(" NO_XREF");
        }
        out.flush();out.close();decomp.dispose();println("Wrote "+f);
    }
    private void dumpFunctionInstructions(Function fn){
        Listing l=currentProgram.getListing(); InstructionIterator it=l.getInstructions(fn.getBody(),true);int n=0;
        while(it.hasNext()&&n++<800){Instruction i=it.next();String s=i.toString();String mark=s.contains("0x30")||s.contains("+0x30")||s.contains("30h")?" ***PLUS30***":"";emit(i.getAddress()+"  "+s+mark);}
    }
    private void dumpLinear(Address a,int max){
        Listing l=currentProgram.getListing(); Address cur=a; for(int n=0;n<max;n++){Instruction i=l.getInstructionAt(cur);if(i==null){try{disassemble(cur);i=l.getInstructionAt(cur);}catch(Exception e){}}if(i==null)break;String s=i.toString();emit(i.getAddress()+"  "+s+(s.contains("0x30")?" ***PLUS30***":""));cur=i.getAddress().add(i.getLength());}
    }
    private void dumpRefs(Function fn){
        ReferenceIterator rr=currentProgram.getReferenceManager().getReferencesTo(fn.getEntryPoint());int n=0;while(rr.hasNext()&&n++<80){Reference r=rr.next();emit("CALLER_REF "+r.getFromAddress()+" "+r.getReferenceType());}
    }
    private void decompile(Function fn){try{DecompileResults r=decomp.decompileFunction(fn,20,monitor);if(r!=null&&r.decompileCompleted()&&r.getDecompiledFunction()!=null){String c=r.getDecompiledFunction().getC();if(c.length()>30000)c=c.substring(0,30000);emit("----- DECOMPILE -----\n"+c+"----- END -----");}else emit("DECOMPILE_FAILED");}catch(Exception e){emit("DECOMPILE_EXCEPTION "+e);}}
    private void emit(String s){out.println(s);}
}

// Read-only targeted Ghidra review of the native AGTK object creation path.
// @category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.Address;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class ShironoTargeted extends GhidraScript {
  private static final String[] TARGETS={
    "00537bd0","00537b00","005284a0","005189f0","00588e70",
    "005d8af0","00520df0","00520ed0","00543df0",
    "0046af40","0046b370","0046b470","00522d80"
  };
  @Override protected void run() throws Exception {
    Path dir=Paths.get(getScriptArgs()[0]);Files.createDirectories(dir);
    FunctionManager fm=currentProgram.getFunctionManager();
    LinkedHashMap<String,Function> found=new LinkedHashMap<>();
    for(String v:TARGETS){
      Address at=currentProgram.getAddressFactory().getAddress(v);
      Function f=fm.getFunctionAt(at);
      if(f==null) f=fm.getFunctionContaining(at);
      if(f!=null)found.put(f.getEntryPoint().toString(),f);
    }
    for(Function f:fm.getFunctions(true)){
      String sig=f.getPrototypeString(true,false);
      String name=f.getName().toLowerCase();
      if((sig.contains("SceneLayer") && 
          (name.contains("addobject")||name.contains("removeobject")||name.contains("createobject"))) ||
         (sig.contains("GameManager")&&(name.contains("getinstance")||name.contains("gettarget"))) ||
         (name.contains("execactionobjectcreate") && sig.contains("agtk"))) {
        if(found.size()<75)found.put(f.getEntryPoint().toString(),f);
      }
    }
    DecompInterface dec=new DecompInterface();
    dec.openProgram(currentProgram);
    try(PrintWriter w=new PrintWriter(Files.newBufferedWriter(dir.resolve("targeted_native_paths.txt")))){
      w.printf("PROGRAM %s ImageBase %s%n",currentProgram.getName(),currentProgram.getImageBase());
      for(Function f:found.values()){
        w.printf("%n============ %s %s ============%n",f.getEntryPoint(),f.getName());
        w.println(f.getPrototypeString(true,true));
        byte[] b=new byte[24];
        try{
          int n=currentProgram.getMemory().getBytes(f.getEntryPoint(),b);
          StringBuilder hex=new StringBuilder();
          for(int j=0;j<n;j++)hex.append(String.format("%02x ",b[j]&255));
          w.println("BYTES "+hex);
        }catch(Exception e){w.println("BYTES_ERR "+e);}
        int nref=0;
        for(Reference r:currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint())){
          if(nref++<100){
            Function caller=fm.getFunctionContaining(r.getFromAddress());
            w.printf("CALLER %s %s %s%n",r.getFromAddress(),caller==null?"none":caller.getEntryPoint(),caller==null?"":caller.getName());
          }
        }
        w.printf("TOTAL_XREFS %d%n",nref);
        try{
          DecompileResults r=dec.decompileFunction(f,75,monitor);
          if(r.decompileCompleted()&&r.getDecompiledFunction()!=null){
            String c=r.getDecompiledFunction().getC();
            w.println(c.substring(0,Math.min(c.length(),42000)));
          }else w.println("DECOMP_FAIL "+r.getErrorMessage());
        }catch(Exception e){w.println("DECOMP_EXCEPTION "+e);}
      }
      w.println("FUNCTIONS_WRITTEN "+found.size());
    }
    dec.dispose();
    println("SHIRONO_TARGETED_GHIDRA_DONE "+found.size());
  }
}

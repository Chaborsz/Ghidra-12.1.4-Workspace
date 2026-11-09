#!/usr/bin/env python3
"""Focused game-data evidence for one-clone restriction and its lifecycle (read-only)."""
import json,sys,collections,re
from pathlib import Path
data=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
out=Path(sys.argv[2]);out.parent.mkdir(parents=True,exist_ok=True)
objById={}
def gather(node):
 if isinstance(node,dict):
  if isinstance(node.get("id"),int) and "actionList" in node and "name" in node:objById.setdefault(node["id"],node)
  for v in node.values():gather(v)
 elif isinstance(node,list):
  for v in node:gather(v)
gather(data.get("objectList",[]))
def compact(obj, depth=0):
 if depth>3:return "<nested>"
 if isinstance(obj,dict):
  return {str(k):compact(v,depth+1) for k,v in obj.items() if k not in {"javaScript","assignScript","keyframeList","particleList","animationList","imageList","scenePartList"} and (not isinstance(v,(list,dict)) or len(v)<15)}
 if isinstance(obj,list):return [compact(v,depth+1) for v in obj[:20]]
 return obj if not isinstance(obj,str) or len(obj)<150 else obj[:150]
def summarize(ref):
 if isinstance(ref,dict):return {k:v for k,v in ref.items() if k in ("id","name","objectId","actionId","objectCreate","switchId","variableId","switchObjectId","switchQualifierId","variableObjectId","variableQualifierId","assignVariableId","assignValue","variableValue","switchValue","commandType","commandTypeName","conditionType","conditionId","condition","isOn","actionLinkId","type","targetType","objectType","objectId","objectVariableId","variableQualifier","useRotation","useConnect","connectId","actionDataId","disappear","deleteObject","objectDisappear")}
 return ref
lines=[]
def printline(*args):lines.append(" ".join(str(x) for x in args))
printline("ROOT", {k:data.get(k) for k in ["version","gameType","playerCount","projectId"]})
printline("OBJECT_IDS",[(x.get("id"),x.get("name")) for x in objById.values()])
for oid in [1,19]:
 o=objById.get(oid)
 if not o:printline("MISSING_OBJECT",oid);continue
 printline("\n===== OBJECT",oid,o.get("name"),"keys=",list(o)[:100])
 printline("OBJECT_HEADER",compact({k:v for k,v in o.items() if not isinstance(v,(list,dict))}))
 printline("VARIABLES", [(x.get("id"),x.get("name"),x.get("initialValue")) for x in o.get("variableList",[])])
 printline("SWITCHES",[(x.get("id"),x.get("name"),x.get("initialValue")) for x in o.get("switchList",[])])
 acts=o.get("actionList",[])
 printline("ACTIONS_COUNT",len(acts))
 for idx,act in enumerate(acts):
  if not isinstance(act,dict):continue
  cmds=act.get("objCommandList",[])
  create=[c for c in cmds if isinstance(c,dict) and isinstance(c.get("objectCreate"),dict)]
  clonecreate=[c for c in create if c["objectCreate"].get("objectId")==19]
  destroy=[c for c in cmds if isinstance(c,dict) and any(k in c for k in ("objectDestroy","objectDisappear","objectDelete","objectChange","objectMove","switchVariableChange"))]
  tag = bool(re.search(r"分身|召喚|死亡|消去|消滅|消す|戻|終了|離|制限|クローン|コピー|残像|解除|状態",act.get("name","")))
  if oid==19 or clonecreate or (tag and oid==1):
   printline("ACTION idx=",idx,"id=",act.get("id"),"name=",act.get("name"),"keys=",list(act.keys())[:25],"commands=",len(cmds))
   if clonecreate:printline("  CLONE_CREATE", [compact(c) for c in clonecreate][:6])
   if oid==19:
    printline("  COMMANDS",[(c.get("id"),c.get("commandType"),list(c.keys()), compact({k:v for k,v in c.items() if k not in ("id","commandType","ignored","instanceConfigurable")})) for c in cmds[:16]])
   elif tag:printline("  SPECIAL_COMMANDS",[(c.get("id"),c.get("commandType"),compact({k:v for k,v in c.items() if k not in ("id","commandType","ignored","instanceConfigurable")})) for c in cmds[:12]])
 for k,v in o.items():
  if "link" in k.lower():
   printline("LINK_KEY",k,"TYPE",type(v).__name__, "LENGTH",len(v) if isinstance(v,(dict,list)) else "")
   if isinstance(v,list):
    for i,x in enumerate(v):
     if not isinstance(x,dict):continue
     acs=set()
     def findids(n,level=0):
      if level>5:return
      if isinstance(n,dict):
       for k,z in n.items():
        if isinstance(z,(int,str)) and (k.lower() in ("actionid","actionid1","actionid2","fromactionid","toactionid","startactionid","endactionid","nextactionid","objectid")):acs.add(f"{k}={z}")
        if isinstance(z,(dict,list)):findids(z,level+1)
      elif isinstance(n,list):
       for z in n:findids(z,level+1)
     findids(x)
     if oid==19 or any(t in " ".join(acs) for t in ("=118","=135")):printline("  LINK",i,"id",x.get("id"),"refs",sorted(acs),"details",compact(x))
for key in ["switchList","variableList"]:
 printline("\nGLOBAL",key,[(x.get("id"),x.get("name"),x.get("initialValue")) for x in data.get(key,[]) if isinstance(x,dict)])
rx=re.compile(r"分身|召喚|clone|copy|clon|companion|コピー|複製|残像|数|体|終了|消滅|解除",re.I)
for oid in (1,19):
 o=objById.get(oid)
 if not o:continue
 printline("\nRELEVANT_NAMED",oid)
 def relevant(v,path):
  if isinstance(v,dict):
   for k,z in v.items():
    if k in ("name","memo","text","description") and isinstance(z,str) and rx.search(z):printline("  ",path+"."+k,z[:220])
    if isinstance(z,(dict,list)):relevant(z,path+"."+str(k))
  elif isinstance(v,list):
   for i,z in enumerate(v):relevant(z,path+f"[{i}]")
 relevant(o,f"object{oid}")
out.write_text("\n".join(lines),encoding="utf-8")
print("SHIRONO_RULES_REPORT",len(lines),len(objById),out)

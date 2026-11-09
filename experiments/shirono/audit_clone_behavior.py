#!/usr/bin/env python3
"""Evidence-oriented AGTK game rules audit for native multiclone; read only."""
import json, re, sys
from pathlib import Path
from collections import Counter
base=Path(sys.argv[1])
out=Path(sys.argv[2]); out.mkdir(parents=True,exist_ok=True)
jpath=next(base.rglob("project_decrypted.json"))
game=json.loads(jpath.read_text(encoding="utf-8-sig"))
rx=re.compile(r'clone|clon|replica|double|shadow|分身|コピー|複製|残像|影|幻影|幽体|身代わり|召喚|コピー|増殖|ドッペル|複体',re.I)
def simple(x):
    return {str(k):str(v)[:300] for k,v in x.items() if not isinstance(v,(list,dict))} if isinstance(x,dict) else {}
def rows_for(key):
    node=game.get(key,[])
    if isinstance(node,list):return [x for x in node if isinstance(x,dict)]
    if isinstance(node,dict):return [x for x in node.values() if isinstance(x,dict)]
    return []
objects=rows_for('objectList')
switches=rows_for('switchList')
variables=rows_for('variableList')
scenes=rows_for('sceneList')
report={
    "root_metadata":{k:v for k,v in game.items() if k in ["version","gameType","playerCount","playerCharacter","loadingSceneId"]},
    "counts":{"objects":len(objects),"scenes":len(scenes),"switches":len(switches),"variables":len(variables)},
    "objects":[simple(o) for o in objects],
    "switches":[simple(o) for o in switches],
    "variables":[simple(o) for o in variables],
    "scenes":[simple(o) for o in scenes],
    "named_clone_matches":[],
    "command_types":{},
    "create_commands":[],
    "matched_object_commands":[],
    "behavior_samples":[],
}
counter=Counter()
def walk(node, path="$", level=0, owner=None):
    if level>24:return
    if isinstance(node,dict):
        if "commandType" in node:
            counter[str(node["commandType"])]+=1
            keys=set(node)
            if any("create" in x.lower() or "copy" in x.lower() or "clone" in x.lower() for x in keys):
                if len(report["create_commands"])<1500:
                    report["create_commands"].append({"path":path[:250],"source_object":owner,"data":{k:v for k,v in node.items() if k!="javaScript" and len(str(v))<1800}})
            if owner is not None and (rx.search(str(node.get("name",""))) or rx.search(str(node.get("objectCreate","")))):
                if len(report["matched_object_commands"])<300:
                    report["matched_object_commands"].append({"path":path[:250],"source_object":owner,"data":simple(node)})
        for k,v in node.items():
            if k in ("name","description","text","notes") and isinstance(v,str) and rx.search(v):
                if len(report["named_clone_matches"])<500:
                    report["named_clone_matches"].append({"path":path+"."+k,"source_object":owner,"text":v[:350]})
            if isinstance(v,(dict,list)):
                walk(v,path+"."+str(k)[:70],level+1,owner)
    elif isinstance(node,list):
        for i,v in enumerate(node):
            if isinstance(v,(dict,list)):walk(v,f"{path}[{i}]",level+1,owner)
for i,obj in enumerate(objects):
    walk(obj,f"$.objectList[{i}]",0,{"id":obj.get("id"),"name":obj.get("name")})
for group in ("switchList","variableList","sceneList","textList"):
    walk(game.get(group,[]),"$$."+group,0)
report["command_types"]=dict(counter.most_common())
(out/"behavior.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
with (out/"behavior_summary.txt").open("w",encoding="utf-8") as f:
    print("COUNTS",report["counts"],"ROOT",report["root_metadata"],file=f)
    print("\nOBJECT NAMES (all)\n",file=f)
    for x in report["objects"]: print(x,file=f)
    print("\nMATCHED NAMES AND TEXT\n",file=f)
    for x in report["named_clone_matches"]:print(x,file=f)
    print("\nCOMMAND TYPE COUNTS\n",report["command_types"],file=f)
    print("\nOBJECT CREATE COMMANDS\n",file=f)
    for x in report["create_commands"][:300]:print(str(x)[:900],file=f)
print("BEHAVIOR_AUDIT_DONE objects",len(objects),"commands",sum(counter.values()),"create_cmds",len(report["create_commands"]),"named_hits",len(report["named_clone_matches"]))

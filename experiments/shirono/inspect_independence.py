#!/usr/bin/env python3
import json,sys
from pathlib import Path
j=json.loads(Path(sys.argv[1]).read_text("utf-8-sig"))
out=Path(sys.argv[2]);out.parent.mkdir(parents=True,exist_ok=True)
o={x.get("id"):x for x in j["objectList"] if isinstance(x,dict) and isinstance(x.get("id"),int)}
def flatten(o):
  if isinstance(o,dict):
    yield o
    for v in o.values():yield from flatten(v)
  elif isinstance(o,list):
    for v in o:yield from flatten(v)
rows=[]
def row(**kw):rows.append(kw)
for oid in (1,19):
  p=o[oid]
  row(kind="OBJ",object=oid,name=p.get("name"),initialAction=p.get("initialActionId"),
    meta={k:p.get(k) for k in ("followType","hp","unattackableToParent","disappearWhenHp0",
         "disappearWhenOutOfCamera","takeoverStatesAtSceneEnd")})
  for a in p.get("actionList",[]):
    c=a.get("objCommandList",[])
    for cmd in c:
      typ=cmd.get("commandType")
      if oid==19 or a.get("id") in (117,119,136,127,128) or any(
          isinstance(c.get(x),dict) and c[x].get("objectId")==19
          for x in ("objectCreate","objectChange","objectMove")
      ):
        row(kind="CMD",owner=oid,action=a.get("id"),name=a.get("name"),command=cmd)
  for link in p.get("actionLinkList",[]):
    pair=link.get("typeIdPair",[])
    allid=[a[1] for a in pair if isinstance(a,list) and len(a)>1]
    if oid==19 or any(i in (117,119,136,127,128) for i in allid):
      row(kind="LINK",owner=oid,fromTo=allid,link=link)
for target in (2033,19,2022):
  count=0
  for owner,project_object in o.items():
    if owner in (1,19):continue
    for a in project_object.get("actionList",[]):
      for cmd in a.get("objCommandList",[]):
        for node in flatten(cmd):
          if isinstance(node,dict) and (node.get("objectId")==target or
             node.get("switchId")==target or node.get("variableId")==target or
             node.get("switchObjectId")==target or node.get("variableObjectId")==target):
            if count<70:row(kind="XREF",target=target,owner=owner,action=a.get("id"),name=a.get("name"),command=cmd)
            count+=1
  row(kind="XREF_COUNT",target=target,count=count)
out.write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding="utf8")
print("SHIRONO_CLONE_RULES_DETAILED",len(rows),out)

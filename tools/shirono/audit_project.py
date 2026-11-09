#!/usr/bin/env python3
"""Read-only inventory of ShironoYakata assets; no game modifications."""
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
out.mkdir(parents=True, exist_ok=True)
wanted = re.compile(r"clon|clone|copy|duplicate|replica|summon|shadow|分身|複製|コピー|残像|召喚|プレイヤー|player|objectcreate|object_create|instance", re.I)
jsons = sorted((p for p in root.rglob("*") if p.is_file() and p.suffix.lower() == ".json"), key=lambda p: p.stat().st_size, reverse=True)
exes = sorted((p for p in root.rglob("*") if p.is_file() and p.suffix.lower() == ".exe"), key=lambda p: p.stat().st_size, reverse=True)
others = Counter(p.suffix.lower() for p in root.rglob("*") if p.is_file())

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

with (out / "input_inventory.txt").open("w", encoding="utf-8") as fp:
    print("file_types", others.most_common(25), file=fp)
    for p in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.stat().st_size, reverse=True)[:120]:
        print(p.relative_to(root), "size", p.stat().st_size, file=fp)
    for p in exes + jsons[:8]:
        print("HASH", p.relative_to(root), sha(p), file=fp)
    print("EXE_COUNT", len(exes), "JSON_COUNT", len(jsons), file=fp)

report = {"input_count":len(jsons), "executables":[str(p.relative_to(root)) for p in exes], "jsons":[]}
for jfile in jsons[:20]:
    entry = {"path":str(jfile.relative_to(root)), "size":jfile.stat().st_size}
    try:
        data = json.loads(jfile.read_text(encoding="utf-8-sig"))
    except (Exception) as exc:
        entry["parse_error"] = str(exc)
        report["jsons"].append(entry)
        continue
    entry["root_type"] = type(data).__name__
    entry["root_keys"] = list(data)[:100] if isinstance(data, dict) else []
    entry["hits"] = []
    entry["object_summaries"] = []
    entry["key_frequency"] = Counter()
    stack = [("$", data, 0)]
    seen = 0
    while stack and seen < 1200000:
        path, node, level = stack.pop()
        seen += 1
        if level > 24:
            continue
        if isinstance(node, dict):
            if len(entry["object_summaries"]) < 300 and any(wanted.search(str(k)) for k in node.keys()):
                entry["object_summaries"].append({"at":path[:180], "fields":{str(k):str(v)[:180] for k, v in node.items() if not isinstance(v,(dict,list))} })
            for k,v in list(node.items())[::-1]:
                name = str(k)
                entry["key_frequency"][name] += 1
                p2 = path + "." + name[:90]
                if wanted.search(name) and len(entry["hits"]) < 650:
                    entry["hits"].append({"at":p2[:250],"value":str(v)[:350] if not isinstance(v, (dict,list)) else f"<{type(v).__name__} size={len(v)}>"})
                if isinstance(v, (dict,list)):
                    stack.append((p2,v,level+1))
                elif isinstance(v, str) and wanted.search(v) and len(entry["hits"]) < 650:
                    entry["hits"].append({"at":p2[:250],"value":v[:350]})
        elif isinstance(node,list):
            for idx,v in reversed(list(enumerate(node))):
                if isinstance(v, (dict,list)):
                    stack.append((f"{path}[{idx}]",v,level+1))
                elif isinstance(v,str) and wanted.search(v) and len(entry["hits"]) < 650:
                    entry["hits"].append({"at":f"{path}[{idx}]"[:250],"value":v[:350]})
    entry["visited"] = seen
    entry["key_frequency"] = entry["key_frequency"].most_common(70)
    report["jsons"].append(entry)

(out/"json_clone_audit.json").write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding="utf-8")
with (out/"json_clone_summary.txt").open("w",encoding="utf-8") as fp:
    for e in report["jsons"]:
        print("JSON",e["path"],"bytes",e["size"],"root_keys",e.get("root_keys",[])[:50],"visited",e.get("visited"),"hits",len(e.get("hits",[])),file=fp)
        for x in e.get("hits",[])[:160]:
            print("  ",x["at"],"=",x["value"][:200],file=fp)
print("AUDIT_COMPLETE", "EXE", len(exes), "JSON",len(jsons))
for e in report["jsons"]:
    print("JSON_SUMMARY",e["path"],"hits",len(e.get("hits",[])),"keys",e.get("root_keys",[])[:12])

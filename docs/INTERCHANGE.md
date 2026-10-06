# dede analysis interchange

dede does not parse a proprietary `.idb` / `.bndb` database. Instead it reads and
writes the **analysis facts** an analyst accumulates — symbols, comments,
functions, and recovered structs — as a small, documented JSON schema, so those
facts move freely between dede, IDA, Binary Ninja, and Ghidra.

- In the shell: `export-db <path>` writes the current session's symbols and
  discovered functions; `import-db <path>` loads names from a JSON file (yours or
  one another tool produced).
- In code: `dede::interchange::to_json(AnalysisDoc)` /
  `parse_json(std::string)` (see `include/dede/interchange/interchange.hpp`).

## Schema

```json
{
  "symbols":   [ {"addr": "0x401000", "name": "main"} ],
  "comments":  [ {"addr": "0x401004", "text": "loop head"} ],
  "functions": [ {"addr": "0x401000", "name": "main", "size": 64} ],
  "structs":   [ {"tag": "s_rdi", "fields": [ {"offset": 0, "width": 8} ]} ]
}
```

`addr`, `offset`, `width`, and `size` accept either a JSON number or a string
(`"0x401000"` or `"4198400"`). Unknown top-level or per-entry keys are ignored,
so a richer export from another tool imports without error.

## Exporter snippets

### IDAPython (export names + comments dede can `import-db`)

```python
import json, idautils, idc, ida_funcs
doc = {"symbols": [], "comments": [], "functions": [], "structs": []}
for ea, name in idautils.Names():
    doc["symbols"].append({"addr": "0x%x" % ea, "name": name})
for f in idautils.Functions():
    fn = ida_funcs.get_func(f)
    doc["functions"].append({"addr": "0x%x" % f, "name": idc.get_func_name(f),
                             "size": (fn.end_ea - fn.start_ea) if fn else 0})
    c = idc.get_func_cmt(f, 0)
    if c:
        doc["comments"].append({"addr": "0x%x" % f, "text": c})
open("analysis.json", "w").write(json.dumps(doc, indent=2))
```

### Binary Ninja

```python
import json
doc = {"symbols": [], "comments": [], "functions": [], "structs": []}
for f in bv.functions:
    doc["functions"].append({"addr": "0x%x" % f.start, "name": f.name,
                             "size": f.total_bytes})
    doc["symbols"].append({"addr": "0x%x" % f.start, "name": f.name})
for addr, text in bv.address_comments.items():
    doc["comments"].append({"addr": "0x%x" % addr, "text": text})
open("analysis.json", "w").write(json.dumps(doc, indent=2))
```

Then, in dede: `import-db analysis.json`. To go the other way, `export-db
analysis.json` and read it back with the mirror of the snippet above.

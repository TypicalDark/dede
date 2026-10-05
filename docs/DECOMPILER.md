<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Grounded design input for dede's native decompiler + type-system backend,
     synthesized from research into Ghidra, Hex-Rays, Binary Ninja, the type-
     recovery literature (TIE/Retypd/VSA), and the structuring literature
     (Cifuentes/Phoenix/DREAM/SAILR). Drives milestones M0-M8. -->

# dede Decompiler + Type-System Backend — Grounded Design Input

**Scope:** a native C++20 decompiler + type-recovery backend for a documented, flat (no segmentation) x86-64 subset. Capstone is the only hard dependency. The Ghidra native decompiler stays an *optional differential oracle* behind `DEDE_WITH_GHIDRA`; the native pipeline is the plan. This document consolidates findings on Ghidra, Hex-Rays, Binary Ninja, the type-recovery literature (TIE / Retypd / BinSub / VSA / REWARDS), and the structuring literature (Cifuentes / Phoenix / DREAM / SAILR), reduced to what fits dede's scope and existing building blocks.

**Existing building blocks this design reuses (verified in-repo):**
- `include/dede/disasm/instruction.hpp` — `DecodedInsn{addr,size,bytes,mnemonic,op_str,id,operands,cf}`, `Operand{kind,reg,width,seg,imm,mem,size,supported}`, `MemOperand{has_base,base,has_index,index,scale,disp,size}`, `CfInfo{is_branch,is_cond_branch,is_call,is_ret}`, `OpKind{None,Reg,Imm,Mem,SegReg}`.
- `include/dede/common/cpu_state.hpp` — `enum class Width : u8 { B1=1, B2=2, B4=4, B8=8 }`.
- `include/dede/common/types.hpp` — `enum class Reg : u8 { Rax..R15, Rip, Rflags, Count }` (16 GPRs), `flags::{CF,PF,AF,ZF,SF,OF}` bit masks.
- `include/dede/analysis/cfg.hpp` — `BasicBlock{start,end,insns,terminates}`, `CfgEdge{from,to,kind}`, `Cfg{entry,blocks,edges,calls,block_at,to_dot,layout}`, `EdgeKind{Fallthrough,Taken,NotTaken,Jump,Call}`, `build_cfg(disasm, ByteReader, entry)`. **Calls are already kept out of flow edges** (`Cfg::calls`), which is exactly right for structuring.
- `include/dede/decompiler/decompiler.hpp` — `IDecompiler{name,decompile}`, `IInsnVisitor` (GoF visitor), `accept()`, `make_decompiler()`. Current fallback: `src/decompiler/linear_pseudocode.cpp` (linear per-insn emitter, `goto loc_X`). Oracle: `src/decompiler/ghidra_adapter.cpp`.
- A live interpreter with exact semantics for the supported subset, a call-graph builder, and a `ByteReader` over the live (possibly self-modified) image — a **time-travel advantage no static decompiler has**.

---

## 1. The common pipeline — stages essentially all real decompilers share

Ghidra, Hex-Rays, and Binary Ninja differ in surface architecture but run the same macro-pipeline. In order:

1. **Decode / disassemble.** Bytes → architecture-neutral decoded instructions with typed operands. *dede already has this* (Capstone → `DecodedInsn`/`Operand`). No new work.
2. **Lift to a uniform IR.** Each machine instruction → one-or-more IR ops over a flat `(space, offset, size)` storage model. Normalizes away sub-register aliasing, addressing modes, and **flags** so every later pass is uniform data-flow. (Ghidra: P-code/Varnodes; Hex-Rays: microcode/`mop_t`; BN: LLIL expression trees.)
3. **Build the CFG + type edges.** Split the IR stream into basic blocks, resolve direct branches. **Switch/jump-table recovery happens here**, not in structuring — a missed table becomes goto-soup later. *dede has the CFG; add switch recovery.*
4. **SSA construction.** Dominator tree + dominance frontiers → phi placement → rename. Gives every value definition its own name — the precondition for sound data-flow and per-definition typing.
5. **Data-flow simplification (to a fixed point).** Constant/copy propagation, dead-code elimination, algebraic identities/strength reduction, CSE, **and flag re-fusion** (collapse explicit CF/ZF/SF/OF computations back into high-level signed/unsigned comparisons). This is where lazy flags, spill/reload pairs, and compiler boilerplate vanish and expression trees get rebuilt.
6. **Stack & call analysis.** Track the stack pointer so `[rsp±k]`/`[rbp±k]` become references to a single stack frame; attach prototypes; model what a call clobbers.
7. **Variable recovery.** Coalesce SSA values that share storage + live range into named locals (register locals + stack slots). Detect params/returns.
8. **Type inference.** Propagate/solve types over the def-use graph; recover struct/array layout from access patterns; insert casts where inferred type disagrees with what an op expects.
9. **Control-flow structuring.** CFG → nested `if/else`, `while/do-while/for`, `switch`, `break/continue`. Minimize (ideally eliminate) `goto`.
10. **C emission.** Walk the structured AST + expression trees, applying precedence, casts, recovered names and types.

The takeaway: **the "named IL levels" are really pass groupings over one reusable IR.** dede should implement one IR advanced through staged "maturity" checkpoints, not several class hierarchies.

---

## 2. Where the tools differ, and why

### 2a. IR: single IR vs layered ILs

| Tool | IR shape | Philosophy |
|---|---|---|
| **Ghidra** | *One* P-code IR (Varnodes = `(AddrSpace, offset, size)`), refined **in place** by ~100 ordered Actions/Rules. SSA via "heritage". | One IR, many rewrite rules, ordering is load-bearing. Open, clean, copyable. |
| **Hex-Rays** | *One* microcode IR (`minsn_t`/`mop_t` in `mba_t`) advanced through ~9 **maturity levels** (MMAT_GENERATED→…→MMAT_LVARS). Operands nest (`mop_d`) → expression trees. Separate `ctree` AST for output. | Middle path: one IR, staged maturities, rule catalog is the proprietary moat. |
| **Binary Ninja** | *Several* named ILs (LLIL→MLIL→HLIL), each with an SSA variant, each one flat `ExprId`-indexed expression-tree array. | Level boundaries = genuine representational shifts (registers→variables, graph→AST). Conceptually clean, large engineering surface. |

**Tradeoff:** BN's LLIL/MLIL split earns its keep — SSA/data-flow is far simpler on registers-then-variables, and types attach to variables not registers. But BN's MLIL/HLIL split mostly separates "statement graph" from "structured AST." **The honest industry choice is "one IR through maturity stages" (Ghidra/Hex-Rays) vs "several typed IRs" (BN).** For a small native project, implement **one expression IR** that carries a `maturity` flag and a `register-vs-variable` operand kind — you get BN's conceptual benefits at Ghidra/Hex-Rays implementation cost.

### 2b. Structuring: schema-matching vs condition-based

- **Schema-matching / structural analysis** (Cifuentes dcc, Ghidra `CollapseStructure`, Hex-Rays): iteratively collapse sub-graphs matching a fixed catalog (if/if-else/while/do-while/switch/sequence) into single nodes; residue that matches nothing → `goto`. Incremental and testable, but **stalls on irreducible graphs** and emits goto on any unmatched shape.
- **Phoenix (USENIX'13):** schema-matching made **semantics-preserving** + **iterative refinement** — when stuck, virtualize one edge to a `goto` and resume. Always terminates, always correct, bounded gotos.
- **DREAM "No More Gotos" (NDSS'15):** *pattern-independent* — compute a boolean **reaching condition** per node, emit code from the conditions, simplify the boolean algebra. **Guarantees zero gotos.** Needs a real boolean simplifier (BDD/algebraic) and can over-produce deeply nested compound predicates.
- **SAILR (USENIX'24):** argues DREAM-style over-structuring hurts readability; recover structure that matches the *original source* by reverting known compiler idioms, add goto only when genuinely necessary.

**Tradeoff:** schema-matching is the fastest path to *correct, demonstrable* output; condition-based is the path to *goto-free* output but front-loads the boolean machinery and a readability-tuning problem.

### 2c. Type inference: heuristic propagation vs constraint solving

- **Shipping tools (Ghidra, Hex-Rays, BN) do NOT run a sound global solver.** Ghidra propagates types op-by-op over a `Datatype` **specificity lattice** (more-specific wins) to a fixed point, inserting casts on disagreement. BN uses **confidence-weighted** propagation (0–255, higher confidence wins). Both lean heavily on **known prototypes** (type libraries / FLIRT) propagated across calls — which is where most real-world accuracy actually comes from. All are context-insensitive and lossy (frequent `__int64`/`undefined4`/`void*`).
- **Academic frontier:** **TIE** (NDSS'11) — finite lattice, each type variable an interval `[lower,upper]`, subtype constraints meet/join to a monotone fixpoint. **Retypd** (PLDI'16) — derived type variables with variance labels (`.load`/`.store`/`.in`/`.out`/offsets), recursive + polymorphic types, solved as pushdown/CFL-reachability (powerful, *hard* to build). **BinSub** (SAS'24) — re-derives Retypd's power in ordinary algebraic subtyping (polar types, meet/join, bisubstitution) — the recommended polymorphism path *if ever needed*.

**Tradeoff:** heuristic propagation is cheap and produces useful C early but is unsound and over-general; a TIE-style bounded-lattice solver is a few hundred lines, always terminates, and is far more honest about signedness/pointerness. Retypd is the "done right" ceiling but is the part most likely to blow the budget.

---

## 3. Shortcomings to avoid (from the research), and how

1. **Over-aggressive simplification hiding behavior.** Textbook structural analysis and aggressive rewrite rules can duplicate/reorder code unsoundly (Phoenix's central critique; "Dangers of the Decompiler"). *Avoid:* every rewrite rule is a pure `IrFunction→bool(changed)` with a **differential-execution test** (re-run the block in the interpreter vs the lifted/optimized IR; assert identical register/memory effects). Only semantics-preserving structuring transforms.
2. **Wrong type guesses printed as fact.** Unconstrained 64-bit values are pointer/int-ambiguous; signedness is genuinely erased by the compiler. *Avoid:* type on **SSA values, not storage locations** (the single decision that defeats "slot reused as int then pointer"); carry `Unknown`/confidence explicitly; emit honest casts/`__undef` rather than inventing a type; default unresolved signedness to signed `int` but *mark* it.
3. **Goto-spaghetti.** Schema-matching emits goto on any unmatched/irreducible region; indirect branches not resolved → truncated CFG → goto. *Avoid:* recover switches at CFG-build time (use the live image + observed trace targets); Phoenix iterative refinement with a **goto-count metric** tracked in `dede-eval`; DREAM condition-refinement as phase 2.
4. **Irreducible-CFG handling.** Classic node-splitting is exponential and duplicates code. *Avoid:* virtualize an edge to a goto (Phoenix) in v1; structure-by-conditions (DREAM) in v2. Add a **virtual unique-exit node** so post-dominators are total.
5. **Fragile variable recovery.** BN's auto-split mis-splits on overlapping slots/unions; aliased (address-taken) storage breaks SSA. *Avoid:* split only when live ranges provably don't interfere; mark address-taken stack slots as **aliased** and keep them as explicit `LOAD`/`STORE` memory, not SSA variables.
6. **Brittle switch recovery.** Sparse/multi-level/PIC-offset tables and signed indices defeat static recognizers. *Avoid:* dede can **read the real table bytes from the live image and observe actually-taken targets across the trace** — strictly more robust than any static pattern-match.
7. **Calling-convention failures.** Varargs, struct-by-value in multiple regs, `sret`, tail calls, custom ABIs corrupt prototype constraints. *Avoid:* encode SysV + Win64 as **data tables**, recover the maximal hole-free prefix (ParamActive/ParamTrial method), and mark non-standard conventions honestly rather than guessing.
8. **Flag mishandling.** *Avoid:* model flags explicitly as 1-bit IR values written by arithmetic and read by `jcc`; "lazy flags" then disappear via ordinary DCE — no bespoke flag analysis.
9. **The unbounded rule list.** Ghidra's ~100 Actions have emergent, load-bearing ordering that is hard to reason about. *Avoid:* keep ~15–25 rules, expose the order explicitly, add rules test-first as sample binaries demand.
10. **Float/SIMD.** Poorly recovered even by the big tools. *Avoid:* out of scope day one — represent as opaque `INTRINSIC`-style pass-through ops.
11. **No soundness guarantee.** *Avoid overclaiming:* ship each pass with tests and an explicit capability statement; the output is a best-effort reconstruction, stated as such.

---

## 4. Recommended architecture for dede

### 4a. IR design

**One expression-tree IR**, flat and index-addressable, carrying a `maturity` flag. Uniform `(AddrSpace, offset, size)` storage — the single most important simplifier.

```cpp
// include/dede/ir/ir.hpp  (new)
enum class Space : u8 { Register, Stack, Ram, Const, Unique };  // flat; no segments
struct Varnode { Space space; u64 offset; u8 size; };            // size in bytes
```
- **Registers:** reuse `dede::Reg` as `Register`-space offsets. Model `AL/AX/EAX/RAX` as overlapping `(Register, rax_off, {1,2,4,8})` — sub-register aliasing becomes overlap, not a special case. `Width{B1,B2,B4,B8}` maps directly to `size`.
- **Flags:** CF/ZF/SF/OF/PF/AF are **1-byte Varnodes in `Register` space** (reuse the `flags::` layout). Lift every flag-setting op to explicit writes; `jcc` reads them. Lazy flags fall out of DCE for free.
- **Immediates:** `Const` space. **Temporaries:** per-function `Unique` space. **Stack:** a `Stack` spacebase after the stack-pointer pass.

**Operation set** (trim of P-code; derive each op's semantics from the interpreter):
```
COPY, LOAD, STORE,
INT_ADD INT_SUB INT_MUL INT_UDIV INT_SDIV INT_UMOD INT_SMOD
INT_AND INT_OR INT_XOR INT_NEG INT_NOT INT_LSHL INT_LSHR INT_ASHR
INT_EQUAL INT_NOTEQUAL INT_SLESS INT_LESS INT_SLESSEQUAL INT_LESSEQUAL
INT_CARRY INT_SCARRY INT_SBORROW INT_ZEXT INT_SEXT SUBPIECE PIECE
BRANCH CBRANCH BRANCHIND CALL CALLIND RETURN
// SSA/analysis pseudo-ops:
PHI(=MULTIEQUAL) INDIRECT PTRADD PTRSUB CAST
// escape hatch for unmodeled (float/SIMD): INTRINSIC
```
- Distinguish **signed vs unsigned** flavors (`INT_SLESS` vs `INT_LESS`, `INT_ASHR` vs `INT_LSHR`, `INT_SEXT` vs `INT_ZEXT`) — these directly imply sign constraints for the type solver.
- `PTRADD(base, index, stride)` ⇒ base is array/pointer with element size `stride`. `PTRSUB(base, k)` ⇒ base points to a struct with a field at offset `k`. These are the struct/array oracle.
- **Operands nest** (an input can be a sub-expression id) — the `mop_d` trick that turns optimized IR directly into C expressions and makes the emitter trivial.

```cpp
struct IrInsn {
    IrOp op;
    std::optional<ValueId> out;   // SSA value id (cleaner than in-place Varnode rewrite)
    small_vector<ValueId> in;     // ids of input values/sub-expressions
    Addr origin;                  // machine address this came from
    u32 seq;                      // SeqNum = (origin,seq): stable unique identity
};
struct IrBlock { Addr start; std::vector<IrInsn> insns; /*preds/succs mirror Cfg*/ };
struct IrFunction { std::vector<IrBlock> blocks; VarTable vars; StackFrame frame; int maturity; };
```

**Derive the lifter from the interpreter.** Write `DecodedInsn → IrInsn[]` as a parallel "emit IR instead of execute" pass over the *same semantic tables the interpreter uses*, so lift and execution cannot drift. This is a correctness lever Hex-Rays/Ghidra lack.

### 4b. SSA construction (textbook)

- Dominator tree via **Cooper-Harvey-Kennedy** iterative algorithm (~40 lines, no deps; functions are small). Dominance frontiers (Cytron et al.) → PHI placement → stack-rename DFS.
- **Scope-saving simplification unique to the flat subset:** skip Ghidra's hardest machinery (multi-pass heritage over address ranges, LoadGuard/StoreGuard value-set guarding, segment ops). **Start SSA over registers + recognized stack slots only** (`[rsp±k]`/`[rbp±k]` after a stack-pointer pass). Model heap/global memory as explicit `LOAD`/`STORE`; a call or unknown store clobbers memory via a conservative `INDIRECT` rule. Defer full memory-SSA / `MEM_PHI`.
- Keep def-use chains: per-`ValueId` a definer `IrInsn*` and a `vector<IrInsn*> uses`.

### 4c. Data-flow passes, in order

A **small, explicitly-ordered** list of pure `IrFunction→bool(changed)` rules, run to a fixed point. ~15–25 rules, not Ghidra's ~100. Suggested order:

1. Constant folding.
2. Copy propagation (COPY/PHI pass-through).
3. Constant-pointer propagation (track `sp`/`bp` offsets → `Stack` spacebase).
4. Algebraic identities / strength reduction (`+0`, `*1`, `x^x=0`, `<<`→`*`).
5. **Flag-comparison re-fusion** — collapse explicit `SF!=OF`-style flag chains back into `INT_SLESS` etc. (turns `jcc` into readable signed/unsigned comparisons).
6. Common-subexpression elimination.
7. Dead-code elimination (over SSA — this is what deletes unused flag writes).

Each rule ships with golden-output tests; re-run the group to fixpoint. Expose the order as data, not buried control flow.

### 4d. Variable recovery (stack + register)

- **Stack:** after the stack-pointer pass, turn `[rsp±k]`/`[rbp±k]` into named slots `var_<hexoffset>`. Detect saved regs, return address, and outgoing-arg region. Use value-set/stack-offset facts for layout.
- **Register locals:** coalesce PHI-connected SSA versions of a storage location (union-find over `ValueId` — "webs") into one named local.
- **Params/returns:** registers live-in at entry (read before written) → parameters in ABI order; register(s) consumed after a call (`RAX`) → return.
- **Aliasing:** mark address-taken slots as aliased → keep as memory `LOAD`/`STORE`, not SSA variables. Split a storage location into multiple variables **only when live ranges provably don't interfere** (conservative; avoids BN's mis-split).
- `Location = variant<Register, StackOffset, Scattered>` (the `vdloc_t` analog).

### 4e. Constraint-based type inference (modest but real)

**Type on SSA values.** Ship **TIE-style bounded-lattice first**; defer Retypd/BinSub.

**Lattice — three orthogonal axes, a POD, not a lattice library:**
```cpp
enum class Class : u8 { Top, Integer, Pointer, Code, Bool, Bottom };  // Int & Ptr both below Top
struct LatticeType { Class cls; u8 width; /*1,2,4,8,0=unknown*/ Sign sign; }; // Sign{Signed,Unsigned,Unknown}
struct TypeVar { UnionFind uf; LatticeType lower; LatticeType upper; };       // interval per SSA value
```
`width` maps 1:1 to dede's `Width`. Join = LUB, meet = GLB; cheap because each axis is tiny. Monotone fixpoint over finite height ⇒ **always terminates**. Conflict = `lower ⋢ upper` ⇒ fall back to `Top`/union.

**Constraint kinds:**
```
Equality(a,b)         // copies, PHI (union-find)
Subtype(a,b)          // assignment/flow, actual <: formal (bound propagation)
PinClass/Width/Sign   // from instruction flavor & operand size
Deref(ptr,off,w,pointee) // LOAD/STORE base+offset ⇒ pointer + field
ArrayStride(ptr,stride)  // PTRADD / index*scale
CallArg(site,i,tv)       // actual <: param from a prototype table
```

**Constraint generation — straight from structures dede already has:**
- `MemOperand`: `has_base` ⇒ base is `Pointer`; `disp` ⇒ field offset; `size` ⇒ pointee width; `has_index` + `scale` ⇒ array stride = `scale`.
- `Operand.size`/`Width` ⇒ width.
- **Signedness from a mnemonic table** over `DecodedInsn.mnemonic`: `movsx/movzx/cbw/cwde/cdqe/cdq/cqo`, `idiv`vs`div`, `imul`vs`mul`, `sar`vs`shr`; `jcc` family via `CfInfo`/condition code (`jg/jge/jl/jle`⇒signed, `ja/jae/jb/jbe`⇒unsigned).
- **Prototype table + ABI binding** (high value, low effort): a `unordered_map<string,FuncProto>` of libc/Win32 signatures keyed by imported symbol (wire to the existing ELF/PE loader + symbols); bind SysV `RDI,RSI,RDX,RCX,R8,R9`/`RAX` (and Win64 `RCX,RDX,R8,R9`); propagate inter-procedurally. This is where IDA/Ghidra get most real accuracy.
- **Time-travel oracle (dede's edge, REWARDS-style):** a slot that always holds a mapped in-range address ⇒ pointer; observed value-sets per slot ⇒ cheap dynamic VSA for variable recovery; runtime call arguments ⇒ strong type sinks. Fuse as additional lower-bound constraints in the *same* solver.

**Solver:** union-find for equalities, then worklist bound-propagation (`lower(b)⊔=lower(a)`, `upper(a)⊓=upper(b)`) to fixpoint.

**Struct/array recovery (phase 2, ASI-lite):** per pointer-typed variable accumulate `{offset,width}` observations across deref sites; union-find-partition the offset range into fields at access boundaries; strided indices ⇒ arrays; memoize pointer cycles for recursive structs.

**Shared output currency between solver and emitter:**
```cpp
using DType = variant<Scalar{width,sign,is_bool,is_char}, Pointer{DType}, Array{DType,count},
                      Struct{name,vector<Field{offset,DType}>}, Code, Unknown>;  // interned, memoized
```

**Upgrade path (documented, not built first):** BinSub (algebraic subtyping) if polymorphism is ever needed — *not* Retypd's pushdown engine.

### 4f. Control-flow structuring — what to implement first, and why

**Two phases.** Do **not** start with pure DREAM (needs a boolean simplifier + reaching-condition machinery before any output, plus readability tuning).

**Phase 1 — Phoenix-style semantics-preserving structural analysis + iterative refinement.** Correct, terminating, incrementally testable, emits a few honest gotos. Matches dede's "honest, incremental, tested" value and beats the current linear `goto loc_X` emitter fastest.

Build order (each unit-tested):
1. Virtual unique-exit node (join all `ret`/`hlt`/tail blocks) → total post-dominators.
2. RPO numbering; dominator tree (CHK); post-dominator tree (same algo on reversed CFG).
3. Back-edge detection (`u→h` with `h dom u`); natural-loop bodies (reverse BFS latch→header); loop forest (merge shared headers).
4. Schema collapse over the region tree: Sequence, IfThen, IfThenElse, While (pre-tested), DoWhile (post-tested), EndlessLoop+break, Switch. Classify loop type by where the exiting conditional sits.
5. **Compound-condition (&&/||) recovery via Cifuentes' local pattern** (consecutive 2-way nodes, second single-entry, shared successor) — cheap, no boolean solver, removes most nesting.
6. Residue/irreducible regions: virtualize one edge → `goto` (heuristic: cut the edge into the region with the most incoming region-edges / a loop's secondary entry). **Track goto-count as a regression metric in `dede-eval`.**

**Phase 2 (later) — DREAM condition-based refinement** to drive residual gotos toward zero, tempered by SAILR's "add goto only when genuinely necessary." Needs reaching-condition formulas + a boolean simplifier (BDD/hash-consed algebra).

**Conditions seam:** start with a placeholder from Capstone's condition code (`jz`→`ZF==0`, or symbolic `cond_<addr>`); upgrade each 2-way block's condition to a real expression tree once data-flow (4c) lands. Structuring logic (which edge is taken) never changes — only the printed predicate improves. So structuring can proceed **in parallel** with the IR/SSA work.

**Output = a region/AST tree**, not inline text:
```cpp
using Region = variant<Seq, If, IfElse, While, DoWhile, EndlessLoop,
                       Switch{idx,cases,default}, Break, Continue, Return,
                       Goto{label}, Label{id}, Leaf{BasicBlock}>;
```

### 4g. C emitter

Because operands nest (`SubExpr`) and the structurer yields an explicit `Region` tree, the emitter is a **recursive pretty-printer**: walk the AST, print `Expr` nodes with operator precedence and the recovered `DType`, print `Stmt` nodes as C. Carry type + confidence through. Where confidence is low or structuring failed, emit **honest casts / `__undef` / `goto`** rather than overclaiming. Keep it a separate module behind `IDecompiler` so it replaces the linear fallback incrementally and both coexist.

---

## 5. Phased implementation plan

Each milestone is independently testable with dede's dependency-free harness, and each **honestly flips specific effectiveness tests**. Effectiveness FAILs in scope: constant folding **#11**, variable naming **#12**, type inference/struct recovery **#17**, switch/case **#20**, pointer-arith simplification **#21**, function-signature inference **#23**, variable scope/lifetime **#24**, implicit cast **#25**, bitfield **#29**, type database **#84**.

> General test levers: **differential execution** (interpret a block, then interpret its lifted/optimized IR; assert equal reg+mem effects) is the correctness backbone for M1–M3. **Golden AST/text** tests for structuring. The **Ghidra adapter stays a differential oracle** in `dede-eval`, never the primary path.

**M0 — Switch/jump-table recovery in the CFG builder.** ✅ **Delivered.** *(Landed first; nearly independent.)*
- Delivers: `cmp idx,N; ja default; jmp [table + idx*scale]` recognized; per-case edges materialized; the bound `cmp` is found in the preceding block (walking contiguous predecessors), the table is read from the **live image** (`m.scale ∈ {4,8}`, index-only `MemOperand`), and entries are truncated on a zero slot past the table end. The native decompiler consumes those edges and emits a real `switch (idx) { case k: … }` with the case bodies as a structured tail; `AnalysisSession::decompile` now hands the decompiler a whole-image reader (new `IDecompiler::decompile(code, addr, image)` overload) so a table in `.rodata` outside the `len` window is still recovered.
- Files: `src/analysis/cfg.cpp` (`switch_targets`, `read_val`, predecessor walk), `src/decompiler/native.cpp` (n-way `BInfo::cases`, switch emission + residue tail, image-reader overload), `include/dede/decompiler/decompiler.hpp`, `src/session/analysis_session.cpp`.
- Test: hand-built switch sample in `tests/test_cfg.cpp` (4 case edges) and `tests/test_decompiler.cpp` (`switch`/`case`/body constants). **Flips #20 (switch/case)** and prevents goto-soup downstream.

**M1 — IR + lifter (maturity: generated).**
- Delivers: `Varnode`/`IrInsn`/`IrBlock`/`IrFunction`; `DecodedInsn→IR` derived from the interpreter; flags as explicit 1-byte Varnodes; nested operands.
- Files: `include/dede/ir/ir.hpp`, `src/ir/lifter.cpp`; a second `IDecompiler`.
- Test: **differential execution round-trip** per supported instruction.

**M2 — SSA.**
- Delivers: dominators (CHK), dominance frontiers, PHI placement, rename; SSA over registers + recognized stack slots.
- Files: `src/ir/ssa.cpp`, `src/ir/dominators.cpp` (dominator code **shared with M5 structuring**).
- Test: single-definition invariant; interpret-SSA == interpret-original.

**M3 — Data-flow simplification (maturity: optimized).**
- Delivers: the ordered rule set (4c) to fixpoint: const fold, copy prop, const-ptr prop, algebraic/strength reduction, flag re-fusion, CSE, DCE.
- Files: `src/ir/opt/*.cpp` (one rule per file), `src/ir/pipeline.cpp`.
- Test: golden-output per rule. **Flips #11 (constant folding)** and **#21 (pointer-arith simplification)** (const-ptr prop + `PTRADD`/`PTRSUB` folding).

**M4 — Variable recovery.**
- Delivers: stack-slot naming, saved-reg/retaddr detection, PHI-web coalescing to register locals, aliasing marks; param/return detection.
- Files: `src/ir/variables.cpp`, `VarTable`/`StackFrame`.
- Test: known stack layouts from debug-info samples. **Flips #12 (variable naming)** and **#24 (variable scope/lifetime)**.

**M5 — Structuring phase 1 (Phoenix) + C emitter v1.**
- Delivers: unique-exit, dominators/post-dominators (reuse M2), loops, schema collapse, Cifuentes &&/|| recovery, iterative-refinement goto fallback with **goto-count metric**; `Region` AST; recursive C emitter.
- Files: `src/decompiler/structure.cpp`, `src/decompiler/emit_c.cpp`.
- Test: golden AST on hand-built CFGs (if, if-else, while, do-while, switch, nested loop+break/continue, short-circuit &&, one **irreducible diamond** that must legitimately produce a goto). Consumes M0's switch edges → **confirms #20** end-to-end; replaces `goto loc_X` fallback.
- *Can start in parallel against placeholder conditions; upgrade predicates after M3.*

**M6 — Type inference phase 1 (TIE-style lattice) + prototype DB.**
- Delivers: the three-axis lattice + union-find + bound-propagation solver; constraint generation from `MemOperand`/widths/mnemonic sign table; `DType`; libc/Win32 **prototype table** wired to the ELF/PE loader + ABI binding; time-travel value oracle fused as constraints.
- Files: `include/dede/types/{lattice,dtype}.hpp`, `src/types/{constraints,solver,proto_db}.cpp`.
- Test: recovery vs known-good types from debug-info samples; measure scalar width/sign/pointerness. **Flips #23 (function-signature inference)**, **#25 (implicit cast)** (casts inserted where lattice disagrees), **#84 (type database)**, and the scalar part of **#17**.

**M7 — Struct/array + bitfield recovery (TIE phase 2, ASI-lite).** ✅ **Delivered** (bitfield + struct/array; nested/recursive types remain).
- Delivers: per-pointer `{offset,width}` clustering → `Struct` fields; strided → `Array`; bitfield detection from masked sub-word loads/stores.
- Files: aggregate recovery in `src/types/infer.cpp` (`Aggregate`, `FuncTypes::aggregate_defs`); field-access + bitfield rendering in `src/decompiler/native.cpp`.
- **Delivered (bitfield):** the `(x >> lo) & ((1<<w)-1)` read idiom (multi-bit, nonzero position) is recognized across statements via a parallel symbolic-value track and collapsed into a `BITFIELD(x, lo, width)` intrinsic, with the dead shift/mask feeder statements removed. Collapse is sound — only when the source register is unclobbered to that point and no memory operand is involved; single-bit extracts stay as `& 1` bit-tests. **Flips #29.**
- **Delivered (struct/array):** a pointer dereferenced at several offsets `[p+off]` is clustered into a `struct s_<reg>` (fields sorted by offset, rendered `p->field_<off>` for both loads and stores, with the layout emitted above the function); indexed `[p+idx*scale]` access is recovered as an array (`T *`). A lone `[p+0]` stays a plain pointer. Intra-function only; **strengthens #17** (nested/recursive + cross-function aggregates remain future work).
- Test: `tests/test_decompiler.cpp` (BITFIELD + struct field access), `tests/test_types.cpp` (struct/array recovery + the single-`*p` and single-bit negative cases).

**M8 (optional, later) — DREAM condition-refinement + BinSub polymorphism.**
- Delivers: reaching conditions + boolean simplifier to minimize gotos (SAILR-tempered); optional algebraic-subtyping upgrade for per-function polymorphic schemes.
- Test: goto-count drops toward zero on the corpus without correctness regressions.

**Ordering rationale:** M0 unblocks switches and prevents goto-soup; M1–M3 are the IR substrate (differential-testable); M4 depends on M2/M3; **M5 is type-free and can land before M6** (its only real upstream dep is good edges + expression trees); M6/M7 are the type backend. Every layer ships with tests and an explicit capability statement.

---

## 6. Risks & what to keep honest

- **Types will be weaker than Hex-Rays'.** Hex-Rays wins via huge `.til` type libraries + FLIRT + 15 years of tuning. dede's TIE-lattice + a modest prototype DB will often leave `int`/`void*`/`Unknown`, especially for unconstrained 64-bit values and signedness. *Honest stance:* report confidence; prefer `Unknown` + cast over a confident wrong type; state that struct recovery is intra-function only and best-effort.
- **No soundness guarantee.** Like all decompilers, output is a plausible reconstruction, not a verified-equivalent program (overflow/aliasing/flag corner cases). *Honest stance:* say so in the capability statement; lean on differential-execution tests to bound the risk on the supported subset.
- **Structuring will emit some gotos in phase 1.** Irreducible/obfuscated control flow legitimately needs them. *Honest stance:* label v1 output "minimized goto," not "goto-free"; publish the per-function goto count in `dede-eval`; DREAM (M8) is the documented path toward zero.
- **Float/SIMD/x87 are out of scope.** Both big tools recover these poorly anyway. *Honest stance:* represent as opaque `INTRINSIC` pass-throughs; do not pretend to decompile them.
- **Calling-convention recovery breaks on varargs / struct-by-value / `sret` / custom ABIs.** *Honest stance:* recover the hole-free prefix of a known ProtoModel and flag anything non-standard rather than inventing a signature.
- **Coverage-limited dynamic evidence.** The time-travel oracle only types/resolves what a given run exercises. *Honest stance:* it is *sound for what it observes* and *fused as additional constraints*, never the sole source — the static lattice still runs.
- **The rule-ordering trap.** Even a 15–25 rule engine can miss simplifications or (rarely) fail to converge if ordering is wrong. *Honest stance:* keep the order explicit and data-driven, add rules test-first, and cap fixpoint iterations with a logged bail-out.
- **Scope discipline is the project's credibility.** Target the documented flat x86-64 subset: no segmentation, no exceptions/C++ objects, no SIMD day one. Every milestone ships behind tests (IR invariants, differential execution, golden pseudocode/AST) so capability is *demonstrated*, not claimed — and the Ghidra adapter remains a differential oracle to catch regressions, never the headline backend.
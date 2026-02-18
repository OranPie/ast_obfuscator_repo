# AST Obfuscator Documentation (ZH / EN)

> File: `ast_obfuscator.py`
> 
> This tool is for code obfuscation only, not cryptographic protection.

---

## 1) 简介 (Overview)

### 中文
`ast_obfuscator.py` 是一个单文件 Python AST 混淆器，支持：
- 多级别/多配置混淆（`--level` + `--profile`）
- 多类型字面量混淆（字符串、整数、浮点、bytes、None、bool）
- 属性/调用/内建引用改写（`attrs/setattrs/calls/builtins`）
- 导入语句混淆（`imports` / `importlib` 风格）
- 条件与分支扩展（`conditions` + `branch-rate`）
- 循环编码（`loops`）
- 动态方法池（tier + allow/deny）
- 元数据导出 `obfumeta` 与反混淆（`--deobfuscate`）

### English
`ast_obfuscator.py` is a single-file Python AST obfuscator with:
- Multi-level/preset configuration (`--level` + `--profile`)
- Type-specific literal obfuscation (string/int/float/bytes/None/bool)
- Attribute/call/builtin rewriting (`attrs/setattrs/calls/builtins`)
- Import obfuscation (`imports` / importlib-style runtime loading)
- Condition encoding and branch extension (`conditions` + `branch-rate`)
- Loop encoding (`loops`)
- Dynamic method pools (tier + allow/deny)
- Metadata export (`obfumeta`) and deobfuscation (`--deobfuscate`)

---

## 2) 快速开始 (Quick Start)

```bash
# Obfuscate
python3 ast_obfuscator.py input.py -o output.py --profile balanced --check --explain

# Emit metadata + rename map
python3 ast_obfuscator.py input.py -o output.py \
  --emit-map output.map.json \
  --emit-meta output.obfumeta.json

# Deobfuscate using metadata
python3 ast_obfuscator.py output.py -o restored.py \
  --deobfuscate --meta output.obfumeta.json --deobf-mode best-effort
```

---

## 3) 配置优先级 (Configuration Priority)

### 中文
解析顺序：
1. `--level` 基础默认
2. `--profile` 覆盖默认（balanced/stealth/max）
3. `--dynamic-level` 方法池级别（safe/medium/heavy）
4. `--dynamic-allow` / `--dynamic-deny` 精细覆盖
5. 显式布尔开关与参数最终覆盖（如 `--no-calls`、`--attr-rate`）

### English
Resolution order:
1. `--level` base defaults
2. `--profile` preset defaults
3. `--dynamic-level` method pool tier
4. `--dynamic-allow` / `--dynamic-deny` fine-grained method override
5. Explicit flags/rates win last (`--no-calls`, `--attr-rate`, etc.)

---

## 4) 主要参数 (Key CLI Options)

### Presets / Core
- `--level {1,2,3,4,5}`
- `--profile {balanced,stealth,max}`
- `--passes N`
- `--mt-workers N` (parallel workers for string-obf stage, default `1`)
- `--order imports,attrs,setattrs,calls,conds,loops,bools,ints,floats,bytes,none,flow`

### Dynamic method control
- `--dynamic-level {safe,medium,heavy}`
- `--dynamic-allow attr:globals_getattr,call:builtins_eval_call`
- `--dynamic-deny call:builtins_eval_call`

### Feature toggles
- `--[no-]rename`
- `--[no-]strings`
- `--[no-]ints`
- `--[no-]floats`
- `--[no-]bytes`
- `--[no-]none`
- `--[no-]bools`
- `--[no-]imports`
- `--[no-]conditions`
- `--[no-]loops`
- `--[no-]flow`
- `--[no-]attrs`
- `--[no-]setattrs`
- `--[no-]calls`
- `--[no-]builtins`
- `--[no-]wrap`

### Method modes
- `--string-mode {mixed,xor,b85,reverse,split}`
- `--int-mode {mixed,xor,arith,split}`
- `--float-mode {mixed,hex,struct}`
- `--bytes-mode {mixed,xor,list,split}`
- `--bool-mode {mixed,compare,xor}`
- `--none-mode {mixed,lambda,ifexpr}`
- `--attr-mode {mixed,getattr,builtins,attrgetter,lambda}`
- `--setattr-mode {mixed,setattr,builtins,lambda}`
- `--call-mode {mixed,wrap,lambda,factory,thunk,eval}`
- `--builtin-mode {mixed,alias,getattr,globals}`
- `--import-mode {mixed,importlib,builtins,dunder}`
- `--condition-mode {mixed,double_not,ifexp,bool_call,lambda_call,tuple_pick}`
- `--loop-mode {mixed,guard,iterator}`
- `--value-salt INT` (mix user salt into xor-like literal encoding)
- `--[no-]auto-value-salt` (derive extra source-coupled salt)

### Rates / density
- `--import-rate 0.0..1.0`
- `--condition-rate 0.0..1.0`
- `--branch-rate 0.0..1.0`
- `--loop-rate 0.0..1.0`
- `--attr-rate 0.0..1.0`
- `--setattr-rate 0.0..1.0`
- `--call-rate 0.0..1.0`
- `--builtin-rate 0.0..1.0`
- `--flow-rate 0.0..1.0`
- `--flow-count N`
- `--string-helpers N` (number of emitted string decode helpers)
- `--call-helpers N` (number of emitted call wrapper helpers)
- `--[no-]frontline-redirects` (redirect top-level class/function/variable loads via generated resolvers)
- `--[no-]redirect-all` (force redirect of all eligible frontline symbols)
- `--redirect-rate 0.0..1.0`
- `--redirect-max N`
- `--redirect-kinds class,function,variable`
- `--redirect-class-mode {mixed,lambda,globals_get,dict_get,itemgetter}`
- `--redirect-function-mode {mixed,lambda,globals_get,dict_get,itemgetter}`
- `--redirect-variable-mode {mixed,lambda,globals_get,dict_get,itemgetter}`

### Metadata / deobfuscation
- `--emit-map path.json`
- `--emit-meta path.json`
- `--[no-]meta-include-source` (default: **no-meta-include-source**)
- `--[no-]meta-minimal` (omit source/rename_map/helper_hints)
- `--[no-]meta-omit-rename-map` (default: include rename map)
- `--[no-]meta-omit-helper-hints` (default: include helper hints)
- `--deobfuscate --meta meta.json`
- `--deobf-mode {best-effort,strict}`
- `--force`

---

## 5) Dynamic 方法池 (Dynamic Method Pools)

### Method families
- `attr`: `getattr`, `builtins_getattr`, `operator_attrgetter`, `lambda_getattr`, `globals_getattr`, `locals_getattr`
- `setattr`: `setattr`, `delattr`, `builtins_setattr`, `builtins_delattr`, `lambda_setattr`, `lambda_delattr`
- `call`: `helper_wrap`, `lambda_wrap`, `factory_lambda_call`, `thunk_wrap`, `builtins_eval_call`
- `builtin`: `alias`, `builtins_getattr_alias`, `globals_lookup`
- `import`: `importlib_import_module`, `builtins_import`, `dunder_import_module`

### Risk policy
- `builtins_eval_call` is treated as risky and requires explicit opt-in via `--dynamic-allow`.
- 示例 / Example:
```bash
python3 ast_obfuscator.py in.py -o out.py \
  --dynamic-level heavy \
  --dynamic-allow call:builtins_eval_call
```

---

## 6) obfumeta 与反混淆 (Metadata & Deobfuscation)

### 中文
- 当前输出格式：`obfumeta-v2`
- 兼容读取：`obfumeta-v1` + `obfumeta-v2`
- 默认不嵌入源码（`--no-meta-include-source`），因此 strict 模式可能失败。
- `--meta-minimal` 会同时省略 source payload、rename_map、helper_hints，降低元数据泄露面。
- 可选不导出 rename_map（`--meta-omit-rename-map`），降低元数据泄露面，但会削弱 best-effort 还原能力。
- 可选不导出 helper hints（`--meta-omit-helper-hints`），进一步降低对 deobf 的提示信息。
- `obfumeta` 会附带 helper hints（字符串 helper 模式标签 / 调用 helper 名称），用于在 helper 随机化后提升反混淆兼容性。
- `best-effort`：在无源码时尝试基于 rename_map 做部分恢复并给出 warning。

### English
- Current emit format: `obfumeta-v2`
- Reader supports both: `obfumeta-v1` and `obfumeta-v2`
- Source payload is not embedded by default (`--no-meta-include-source`)
- `--meta-minimal` drops source payload, rename_map, and helper_hints together to reduce metadata leakage.
- You can omit `rename_map` from metadata (`--meta-omit-rename-map`) to reduce metadata leakage, but this weakens best-effort restoration.
- You can also omit helper hints (`--meta-omit-helper-hints`) to further reduce deobf guidance in metadata.
- `obfumeta` now stores helper hints (string helper mode tags/salt + call helper names) so deobfuscation can track randomized helper signatures.
- `best-effort`: attempts partial restoration (rename-map based) and prints warnings.

### Named args / 具名参数
- EN: Rename pass auto-preserves keyword argument names used in call sites to avoid breaking `fn(seed=...)` patterns.
- 中文：重命名阶段会自动保留调用点中的具名参数名，避免 `fn(seed=...)` 这类调用被破坏。

---

## 7) 常用命令模板 (Common Recipes)

### A. 平衡强度（推荐）/ Balanced
```bash
python3 ast_obfuscator.py app.py -o app.obf.py \
  --profile balanced --seed 1337 --check --explain
```

### B. 隐蔽低侵入 / Stealth
```bash
python3 ast_obfuscator.py app.py -o app.obf.py \
  --profile stealth --flow-rate 0.2 --call-rate 0.25 --check
```

### C. 极限强度 / Max
```bash
python3 ast_obfuscator.py app.py -o app.obf.py \
  --profile max --dynamic-level heavy --check --explain
```

### D. 指定 transform 顺序 / Custom order
```bash
python3 ast_obfuscator.py app.py -o app.obf.py \
  --order attrs,calls,ints,floats,bytes,none,bools,setattrs,flow
```

### E. 元数据 + strict 还原 / strict restore
```bash
python3 ast_obfuscator.py app.py -o app.obf.py \
  --emit-meta app.meta.json --meta-include-source

python3 ast_obfuscator.py app.obf.py -o app.restore.py \
  --deobfuscate --meta app.meta.json --deobf-mode strict
```

### F. 全量前线重定向 + 分类型模式 / Full frontline redirects + per-type modes
```bash
python3 ast_obfuscator.py app.py -o app.obf.py \
  --no-wrap --frontline-redirects --redirect-all \
  --redirect-class-mode itemgetter \
  --redirect-function-mode lambda \
  --redirect-variable-mode dict_get \
  --check --explain
```

---

## 8) 注意事项 (Notes)

- 混淆可能影响调试可读性与运行性能。
- 高强度 profile + 高 rate 会显著增加代码体积。
- 对反射/动态元编程重度代码，请先小范围验证。
- `--check` 只做 compile 检查，不等于完整行为测试。
- `--wrap` 会做额外包装（多段 payload、随机解包步骤、轻量 anti-hook 检查），主要提升静态阅读成本，不等于加密壳。
- 在 `--no-wrap` 场景下，可提高 `--string-helpers` / `--call-helpers` 并使用 `--string-mode split`，增加 helper 分散度与片段重组复杂度。
- `--mt-workers` 主要加速字符串混淆阶段；建议在较大脚本上实测 2/4/8 后选择最优值（默认 `1`）。

---

## 9) 版本建议 (Versioning Advice)

- 推荐固定 `--seed` 以便构建可复现。
- 在 CI 中保存 `emit-map` 与 `emit-meta` 以便追踪与恢复。
- 生产场景建议至少跑：
  1. 原始脚本功能测试
  2. 混淆后功能测试
  3. deobf 回退流程测试

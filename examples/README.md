# Examples / 示例

This folder contains multiple source scripts, their obfuscated outputs, and deobfuscated outputs generated with different configs.

本目录包含多个示例：原始源码、混淆后版本、以及反混淆版本（deobf），并且每个示例使用不同配置。

## Structure

- `case01_balanced/`
  - `src.py`: original source
  - `obf.py`: obfuscated output (balanced profile)
  - `deobf.py`: best-effort deobfuscated output (metadata is minimal)
  - `map.json`: rename map
  - `meta.json`: obfumeta
  - `config.txt`: exact command used

- `case02_stealth/`
  - `src.py`, `obf.py`, `deobf.py`, `map.json`, `meta.json`, `config.txt`
  - best-effort deobf mode with metadata leak controls (omit rename_map + helper_hints)

- `case03_max_dynamic/`
  - `src.py`, `obf.py`, `deobf.py`, `map.json`, `meta.json`, `config.txt`
  - max profile + heavy dynamic methods + risky call method opt-in

- `case04_import_cond_loop/`
  - `src.py`, `obf.py`, `deobf.py`, `map.json`, `meta.json`, `config.txt`
  - import obfuscation + condition/branch encoding + loop encoding demo

- `case05_long_redirect_all/`
  - `src.py`, `obf.py`, `deobf.py`, `map.json`, `meta.json`, `config.txt`
  - long source + no-wrap + redirect-all with per-type redirect modes + value-salt mixing

- `case06_self_obfuscate/`
  - `config.txt`
  - recipe to obfuscate `ast_obfuscator.py` itself (outputs go to `/tmp` to avoid huge repo artifacts, includes `--mt-workers`)

- `case07_full_self_obf/`
  - `src.py`, `obf.py`, `meta.json`, `config.txt`
  - full self-obfuscation artifact stored in repo

## Re-generate all examples

```bash
# Run in repo root
python3 ast_obfuscator.py examples/case01_balanced/src.py -o examples/case01_balanced/obf.py --profile balanced --level 4 --seed 101 --dynamic-level heavy --passes 3 --no-wrap --string-mode split --string-helpers 4 --call-helpers 4 --value-salt 23 --frontline-redirects --redirect-rate 0.85 --redirect-max 20 --redirect-kinds class,function,variable --attr-rate 0.95 --setattr-rate 0.95 --call-rate 0.90 --builtin-rate 0.95 --condition-rate 0.95 --branch-rate 0.85 --flow-rate 0.90 --loop-rate 0.85 --flow-count 2 --emit-map examples/case01_balanced/map.json --emit-meta examples/case01_balanced/meta.json --meta-minimal --check
python3 ast_obfuscator.py examples/case01_balanced/obf.py -o examples/case01_balanced/deobf.py --deobfuscate --meta examples/case01_balanced/meta.json --deobf-mode best-effort

python3 ast_obfuscator.py examples/case02_stealth/src.py -o examples/case02_stealth/obf.py --profile stealth --level 4 --seed 202 --passes 2 --no-wrap --string-mode split --string-helpers 3 --call-helpers 3 --frontline-redirects --redirect-rate 0.60 --redirect-max 12 --redirect-kinds class,function,variable --attr-mode mixed --attr-rate 0.80 --setattr-rate 0.75 --call-rate 0.70 --builtin-rate 0.80 --flow-rate 0.55 --condition-rate 0.70 --branch-rate 0.40 --loop-rate 0.55 --emit-map examples/case02_stealth/map.json --emit-meta examples/case02_stealth/meta.json --meta-omit-rename-map --meta-omit-helper-hints --check
python3 ast_obfuscator.py examples/case02_stealth/obf.py -o examples/case02_stealth/deobf.py --deobfuscate --meta examples/case02_stealth/meta.json --deobf-mode best-effort

python3 ast_obfuscator.py examples/case03_max_dynamic/src.py -o examples/case03_max_dynamic/obf.py --profile max --level 5 --dynamic-level heavy --seed 303 --dynamic-allow call:builtins_eval_call,attr:locals_getattr --emit-map examples/case03_max_dynamic/map.json --emit-meta examples/case03_max_dynamic/meta.json --check
python3 ast_obfuscator.py examples/case03_max_dynamic/obf.py -o examples/case03_max_dynamic/deobf.py --deobfuscate --meta examples/case03_max_dynamic/meta.json --deobf-mode best-effort

python3 ast_obfuscator.py examples/case04_import_cond_loop/src.py -o examples/case04_import_cond_loop/obf.py --profile balanced --level 3 --seed 404 --imports --conditions --loops --import-mode mixed --condition-mode mixed --loop-mode iterator --import-rate 1.0 --condition-rate 0.9 --branch-rate 0.8 --loop-rate 1.0 --emit-map examples/case04_import_cond_loop/map.json --emit-meta examples/case04_import_cond_loop/meta.json --no-wrap --check
python3 ast_obfuscator.py examples/case04_import_cond_loop/obf.py -o examples/case04_import_cond_loop/deobf.py --deobfuscate --meta examples/case04_import_cond_loop/meta.json --deobf-mode best-effort

python3 ast_obfuscator.py examples/case05_long_redirect_all/src.py -o examples/case05_long_redirect_all/obf.py --profile max --level 5 --seed 505 --no-wrap --dynamic-level heavy --passes 3 --string-mode split --string-helpers 5 --call-helpers 5 --value-salt 77 --auto-value-salt --frontline-redirects --redirect-all --redirect-class-mode itemgetter --redirect-function-mode lambda --redirect-variable-mode dict_get --attr-rate 1.0 --setattr-rate 1.0 --call-rate 1.0 --builtin-rate 1.0 --condition-rate 1.0 --branch-rate 0.9 --flow-rate 1.0 --loop-rate 1.0 --flow-count 2 --emit-map examples/case05_long_redirect_all/map.json --emit-meta examples/case05_long_redirect_all/meta.json --meta-omit-rename-map --meta-omit-helper-hints --check
python3 ast_obfuscator.py examples/case05_long_redirect_all/obf.py -o examples/case05_long_redirect_all/deobf.py --deobfuscate --meta examples/case05_long_redirect_all/meta.json --deobf-mode best-effort

# self-obfuscation recipe
bash examples/case06_self_obfuscate/config.txt

# full self-obfuscation artifact (in-repo)
bash examples/case07_full_self_obf/config.txt

# optional tuning (self-obf): try 1/4/8 and keep the fastest for your machine
# --mt-workers 4
```

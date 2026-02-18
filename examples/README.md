# Examples / 示例

This folder contains multiple source scripts, their obfuscated outputs, and deobfuscated outputs generated with different configs.

本目录包含多个示例：原始源码、混淆后版本、以及反混淆版本（deobf），并且每个示例使用不同配置。

## Structure

- `case01_balanced/`
  - `src.py`: original source
  - `obf.py`: obfuscated output (balanced profile)
  - `deobf.py`: strict deobfuscated output (with source embedded in metadata)
  - `map.json`: rename map
  - `meta.json`: obfumeta
  - `config.txt`: exact command used

- `case02_stealth/`
  - `src.py`, `obf.py`, `deobf.py`, `map.json`, `meta.json`, `config.txt`
  - best-effort deobf mode (metadata does not embed source)

- `case03_max_dynamic/`
  - `src.py`, `obf.py`, `deobf.py`, `map.json`, `meta.json`, `config.txt`
  - max profile + heavy dynamic methods + risky call method opt-in

## Re-generate all examples

```bash
# Run in repo root
python3 ast_obfuscator.py examples/case01_balanced/src.py -o examples/case01_balanced/obf.py --profile balanced --level 3 --seed 101 --emit-map examples/case01_balanced/map.json --emit-meta examples/case01_balanced/meta.json --meta-include-source --check
python3 ast_obfuscator.py examples/case01_balanced/obf.py -o examples/case01_balanced/deobf.py --deobfuscate --meta examples/case01_balanced/meta.json --deobf-mode strict

python3 ast_obfuscator.py examples/case02_stealth/src.py -o examples/case02_stealth/obf.py --profile stealth --level 4 --seed 202 --attr-mode attrgetter --attr-rate 0.55 --setattr-rate 0.45 --call-rate 0.35 --builtin-rate 0.60 --flow-rate 0.30 --emit-map examples/case02_stealth/map.json --emit-meta examples/case02_stealth/meta.json --check
python3 ast_obfuscator.py examples/case02_stealth/obf.py -o examples/case02_stealth/deobf.py --deobfuscate --meta examples/case02_stealth/meta.json --deobf-mode best-effort

python3 ast_obfuscator.py examples/case03_max_dynamic/src.py -o examples/case03_max_dynamic/obf.py --profile max --level 5 --dynamic-level heavy --seed 303 --dynamic-allow call:builtins_eval_call,attr:locals_getattr --emit-map examples/case03_max_dynamic/map.json --emit-meta examples/case03_max_dynamic/meta.json --check
python3 ast_obfuscator.py examples/case03_max_dynamic/obf.py -o examples/case03_max_dynamic/deobf.py --deobfuscate --meta examples/case03_max_dynamic/meta.json --deobf-mode best-effort
```

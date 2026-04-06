# ROParser

Code repo of "ROParser: A high-efficient framework for return-oriented programming deobfuscation"

## Introduction

ROParser recovers the original control flow from ROP-obfuscated binaries. It supports multiple loader modes, performs symbolic execution to trace ROP chains, and provides an optional multi-pass optimization pipeline to clean up recovered CFGs.

**Key features:**
- CFG recovery via localized symbolic execution and reduced value-set analysis
- LLM-assisted custom stack operation recovery (`--stack-recovery`)
- Dead code elimination through liveness analysis (`--liveness`)
- Constant propagation (`--constant-propagation`)
- Semantic block elimination (`--block-elimination`)

## Usage

Install requirements by pip

```
pip install -r requirements.txt
```

Run deobfuscator with cmd, the [README.md in ./testcase](testcase/README.md) store the execution command of each testcases

```
python main.py -i testcase/programs/raindrop/simple.rop -o testcase/output/raindrop/simple -m raindrop
```

To enable the LLM-assisted custom stack operation recovery (`--stack-recovery`), set the environment variable DEEPSEEK_API_KEY, DEEPSEEK_URL and ROPARSER_MODEL_ID.

### Arguments

| Argument | Required | Description                                                                 |
|---|---|-----------------------------------------------------------------------------|
| `-i`, `--input` | Yes | Input file path (binary or JSON config)                                     |
| `-o`, `--output` | Yes | Output directory for results                                                |
| `-m`, `--mode` | Yes | Loader mode: `raindrop` or `PE`                                             |
| `-f`, `--function` | No | Analyze specific function(s) by name (default: all)                         |
| `--stack-recovery` | No | Enable LLM-based custom stack operation recovery                            |
| `--liveness` | No | Enable liveness analysis and dead code elimination                          |
| `--constant-propagation` | No | Enable constant propagation                                                 |
| `--block-elimination` | No | Enable semantic block-level elimination                                     |
| `--cfg-graph` | No | Generate Graphviz CFG output (default: enabled)                             |
| `--log-level` | No | Logging verbosity: `DEBUG` / `INFO` / `WARNING` / `ERROR` (default: `INFO`) |

### Examples

```bash
# Analyze Raindrop obfuscated binary
python main.py -i binary.rop -o output/ -m raindrop -f main

# Analyze specific functions from a PE config
python main.py -i config.json -o output/ -m PE

# Full optimization pipeline
python main.py -i binary.rop -o output/ -m raindrop \
  --stack-recovery --liveness --constant-propagation --block-elimination
```


## Site

```
@article{liu2026roparser,
  title={ROParser: A High-Efficient Framework for Return-Oriented Programming Deobfuscation},
  author={Liu, Haoran and Liu, Tieming and Chang, Rui and Lin, Jian and Zhou, Zuozheng and Jing, Jing},
  journal={Computers \& Security},
  pages={104884},
  year={2026},
  publisher={Elsevier}
}
```
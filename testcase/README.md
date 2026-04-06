# Testcases

## Raindrop

### simple

```
python main.py -i testcase/programs/raindrop/simple.rop -o testcase/output/raindrop/simple -m raindrop --stack-recovery
```

### recursion

```
python main.py -i testcase/programs/raindrop/recursion.rop -o testcase/output/raindrop/recursion -m raindrop --stack-recovery
```

### hash

```
python main.py -i testcase/programs/raindrop/hash.rop -o testcase/output/raindrop/hash -m raindrop --stack-recovery
```

### jump_tables

```
python main.py -i testcase/programs/raindrop/jump_tables.rop -o testcase/output/raindrop/jump_tables -m raindrop --stack-recovery
```

### ls

```
python main.py -f main -i testcase/programs/raindrop/ls.rop -o testcase/output/raindrop/ls -m raindrop --stack-recovery
```

## Aggressive

### anti-ROP-disasm

```
python main.py -i testcase/programs/aggressive/simple.anti-rop-disasm.rop -o testcase/output/aggressive/anti-rop-disasm -m raindrop --stack-recovery
```

### state explosion

```
python main.py -i testcase/programs/aggressive/simple.state-explosion.rop -o testcase/output/aggressive/state-explosion -m raindrop --block-elimination --stack-recovery
```

### anti-bruteforce

```
python main.py -i testcase/programs/aggressive/simple.anti-bruteforce.rop -o testcase/output/aggressive/anti-bruteforce -m raindrop --stack-recovery
```

### gadget confusion

```
python main.py -i testcase/programs/aggressive/simple.confusion.rop -o testcase/output/aggressive/confusion -m raindrop --stack-recovery
```

## PE

### bubblesort

```
python main.py -i testcase/programs/pe/demo-payloads/json/bubblesort.json -o testcase/output/pe/bubblesort/ -m pe --liveness --constant-propagation   
```

### factorial

```
python main.py -i testcase/programs/pe/demo-payloads/json/factorial.json -o testcase/output/pe/factorial/ -m pe --liveness --constant-propagation 
```

### fib

```
python main.py -i testcase/programs/pe/demo-payloads/json/fib.json -o testcase/output/pe/fib/ -m pe --liveness --constant-propagation 
```

### mmul

```
python main.py -i test/input/pe/demo-payloads/json/mmul.json -o testcase/output/pe/mmul/ -m pe --liveness --constant-propagation 
```
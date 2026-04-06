"""
Localized Symbolic Execution (LSE) Executor
Localized symbolic execution engine

Integrates control flow guided pruning and opaque encoding recovery to implement complete LSE framework
"""

import logging
from collections import deque, defaultdict
from copy import deepcopy
from typing import Any

from capstone import *
from keystone import *
from capstone.x86 import *
from miasm.expression.expression import ExprCond, ExprId, ExprInt, ExprMem, ExprOp
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.analysis.binary import Container
from miasm.expression.simplifications import ExpressionSimplifier, expr_simp

from .memory import MemoryCallbackHandler
from .rvsa import ReducedValueSetAnalyzer
from utils.constants import *
from utils.helpers import *

logger = logging.getLogger(__name__)


class LocalizedSymbolicExecutor:
    def __init__(
            self,
            loader: cle.Loader,
            machine: Machine,
            loc_db: LocationDB,
            rsp: str,
            rip: str,
            base: int,
            chain_begin: int,
            chain_end: int,
            stack_address: int
    ):
        """
        Initialize the Localized Symbolic Executor.

        Args:
            loader: CLE binary loader
            machine: Miasm machine instance
            loc_db: Miasm location database
            rsp: RSP register name string (e.g., 'RSP' or 'ESP')
            rip: RIP register name string (e.g., 'RIP' or 'EIP')
            base: Architecture bit width (32 or 64)
            chain_begin: Start address of the ROP chain in memory
            chain_end: End address of the ROP chain in memory
            stack_address: The known custom stack anchor address
        """
        self.loader = loader
        self.machine = machine
        self.loc_db = loc_db
        self.rsp = rsp
        self.rip = rip
        self.base = base
        self.stack_address = stack_address

        self.gadgets = self._preload_gadgets(chain_begin, chain_end)
        self.rop_chain = self._load_rop_chain(chain_begin, chain_end)

        # Get start address
        if not self.rop_chain:
            raise ValueError("ROP chain is empty")

        start_rip = self.rop_chain.pop(0)
        self.start_address: AddressPair = (start_rip, 0)

        # Initialize reduced value set analyzer
        self.vsa = ReducedValueSetAnalyzer(loader, rsp, rip, base, self.rop_chain)
        # Initialize memory callback handler (replaces global variables)
        self.mem_callback = MemoryCallbackHandler(self.loader, self.rop_chain, self.vsa)

        self.initial_symbols: Set[ExprId] = set()

        # Record external function call addresses
        self.external_functions: Set[int] = set()

        # Record POP instruction conversion results
        self.preload_instr = {}

        # Default condition symbol for ExprCond placeholder
        # Only mark this as a conditional branch result, no specific condition needed
        self.default_cond_symbol = ExprId('cond', 1)

        if self.base == 32:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        else:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

        self.cs.detail = True

    def _load_rop_chain(
            self,
            chain_begin: Optional[int],
            chain_end: Optional[int]
    ) -> List[int]:
        """
        Load the ROP chain, with support for detecting and skipping unaligned zero-byte padding.

        Uses self.gadgets (populated by _preload_gadgets) as ground truth:
        if a read value is not a known gadget, probe 1~word_size-1 byte offsets ahead
        to check whether a known gadget exists there. If found, the current position
        is treated as padding and skipped.
        """
        if chain_begin is None:
            return []

        memory = self.loader.memory
        chain: List[int] = []
        word_size = self.base // 8  # 8 for 64-bit, 4 for 32-bit

        # Determine scan range
        if chain_end:
            scan_end = chain_end
            use_terminator = False
        else:
            scan_end = chain_begin + 0x10000
            use_terminator = True

        pos = chain_begin

        while pos + word_size <= scan_end:
            data = unpack(memory.load(pos, word_size), self.base)

            # Double-zero termination check (used when chain_end is not specified)
            if use_terminator:
                if pos + 2 * word_size <= scan_end:
                    next_data = unpack(memory.load(pos + word_size, word_size), self.base)
                    if not data and not next_data:
                        break
                elif not data:
                    break

            # Known gadget address — no padding, append directly
            if data in self.gadgets:
                chain.append(data)
                pos += word_size
                continue

            # Not a known gadget — probe for alignment padding
            padding_found = False
            for skip in range(1, word_size):
                probe_pos = pos + skip
                if probe_pos + word_size > scan_end:
                    break
                probe_value = unpack(memory.load(probe_pos, word_size), self.base)
                if probe_value in self.gadgets:
                    # Gadget found at pos+skip — skip bytes are padding
                    logger.debug(
                        f"Detected {skip}-byte padding at {hex(pos)}, "
                        f"corrected to gadget {hex(probe_value)} at {hex(probe_pos)}"
                    )
                    pos = probe_pos
                    chain.append(probe_value)
                    pos += word_size
                    padding_found = True
                    break

            if not padding_found:
                # Not a gadget and no padding found — treat as a data value (e.g., POP argument)
                chain.append(data)
                pos += word_size

        return chain if chain else []

    def _preload_gadgets(
            self,
            chain_begin: Optional[int],
            chain_end: Optional[int]
    ) -> Dict[int, bytes]:
        gadgets: Dict[int, bytes] = {}
        memory = self.loader.memory

        if chain_begin is None:
            return gadgets

        if chain_end is None:
            chain_end = chain_begin + 0x10000

        for addr in range(chain_begin, chain_end):
            gadget_addr = unpack(
                memory.load(addr, self.base // 8),
                self.base
            )

            if is_valid_rop_address(gadget_addr, memory, self.stack_address):
                gadget_bytes = self.split_gadget(gadget_addr)
                if gadget_bytes:
                    gadgets[gadget_addr] = gadget_bytes

        # Module-aware clustering: group gadgets by memory backer
        if gadgets:
            module_groups: Dict[Optional[int], list] = defaultdict(list)
            for addr in gadgets:
                module_groups[get_backer_id(memory, addr)].append(addr)

            # Adaptive cluster selection based on dominance ratio
            # - Dominant scenario (e.g., Raindrop): one backer has most gadgets,
            #   others are noise from data/external-function segments
            # - Distributed scenario (e.g., PE+DLLs): multiple backers contribute
            #   legitimate gadgets, keep all significant ones
            total = len(gadgets)
            largest_bid = max(module_groups, key=lambda bid: len(module_groups[bid]))
            dominance_ratio = len(module_groups[largest_bid]) / total

            if dominance_ratio > DOMINANCE_THRESHOLD:
                # Dominant: keep only the largest cluster
                significant_modules = {largest_bid}
            else:
                # Distributed: keep all clusters with minimum size
                min_cluster_size = 2
                significant_modules = {
                    bid for bid, addrs in module_groups.items()
                    if len(addrs) >= min_cluster_size
                }

            gadgets = {
                addr: g for addr, g in gadgets.items()
                if get_backer_id(memory, addr) in significant_modules
            }

        return gadgets

    def split_gadget(self, address: int) -> Optional[bytes]:
        """
        Extract gadget bytes starting at the given address, up to and including RET.

        Disassembles memory starting at `address` and collects instruction bytes
        until a RET is found. Returns None if the gadget contains a CALL, exceeds
        the maximum length, or cannot be disassembled.

        Args:
            address: Start address of the gadget

        Returns:
            Raw gadget bytes (including RET), or None if extraction failed
        """
        memory = self.loader.memory
        code = memory.load(address, GADGETS_MAX_LEN) + b'\xF4'

        try:
            cont = Container.from_string(code, loc_db=self.loc_db)
            mdis = self.machine.dis_engine(cont.bin_stream, loc_db=self.loc_db)
            mblock = mdis.dis_block(0)

            gadget_bytes = b''
            for line in mblock.lines:
                gadget_bytes += line.b
                if 'CALL' in line.name:
                    return None
                if 'RET' in line.name:
                    break

            if len(gadget_bytes) == GADGETS_MAX_LEN + 1:
                return None

            return gadget_bytes
        except Exception as e:
            logger.debug(f"Error splitting gadget at {hex(address)}: {e}")
            return None

    def get_init_state(self, init_rsp: int = 0) -> SymbolMngr:
        """
        Build the initial symbolic state for the executor.

        Initializes all architecture registers to symbolic identifiers (e.g., 'RAX_init')
        and sets RSP to the given concrete value.

        Args:
            init_rsp: Initial RSP value (concrete integer, typically 0 for the first gadget)

        Returns:
            Initialized SymbolMngr with symbolic register values and a concrete RSP
        """
        init_state: SymbolMngr = SymbolMngr(addrsize=self.base)

        # Create initial symbols for all registers
        registers = X86_64_REGS if self.base == 64 else X86_32_REGS

        for reg_name in registers:
            reg_expr = ExprId(reg_name, self.base)
            init_state[reg_expr] = ExprId(f'{reg_name}_init', self.base)
            self.initial_symbols.add(ExprId(f'{reg_name}_init', self.base))

        # Set initial RSP value to concrete value
        rsp_expr = ExprId(self.rsp, self.base)
        init_state[rsp_expr] = ExprInt(init_rsp, self.base)

        return init_state

    def _modify_pop_to_mov(self, addr, symbol, asmcfg):
        """
        Replace POP instructions with equivalent MOV instructions using resolved concrete values.

        When a POP destination register has a known concrete value in the symbolic state,
        convert `POP reg` to `MOV reg, <value>` for cleaner CFG representation.
        The modified block is stored in self.preload_instr keyed by addr.

        Args:
            addr: Address pair (RIP, RSP) identifying the gadget
            symbol: Current symbolic state containing resolved register values
            asmcfg: Assembly CFG of the gadget
        """
        first_block = next(iter(asmcfg.blocks))
        modified_block = deepcopy(first_block)
        modified_block.lines = list(modified_block.lines)

        for i, line in enumerate(modified_block.lines):
            if line.name != 'POP':
                continue

            dst_reg = line.args[0]
            if dst_reg not in symbol:
                logger.debug(f"Register {dst_reg} not in symbol after POP")
                continue

            value = symbol[dst_reg]
            if isinstance(value, ExprInt):
                asm_str = f"MOV {dst_reg.name}, {hex(value.arg)}"
                logger.debug(f"Converted POP {dst_reg} to MOV {dst_reg}, {value}")
            elif isinstance(value, ExprId):
                asm_str = f"MOV {dst_reg.name}, {hex(value.name)}"
                logger.debug(f"Converted POP {dst_reg} to MOV {dst_reg}, {value}")
            else:
                logger.debug(f"Converted POP {dst_reg} error")
                continue

            instr = self.machine.mn.fromstring(asm_str, self.loc_db, self.base)
            instr.b = bytes(self.ks.asm(asm_str)[0])
            modified_block.lines[i] = instr

        self.preload_instr[addr] = modified_block

    def symbolic_execute(
            self,
            addr: AddressPair | bytes,
            state: SymbolMngr
    ) -> List[SymbolMngr]:
        """
        Symbolically execute a single gadget and return the resulting states.

        Handles multi-branch gadgets (delayed branches, CMOV, ADC/SBB), indirect
        branches via RVSA, and single-successor gadgets. POP-to-MOV conversions and
        VSA constraint updates are applied as side effects.

        Args:
            addr: Either an AddressPair (RIP, RSP) identifying a gadget in the chain,
                  or raw bytes for direct execution (e.g., a RET stub b'\\xC3')
            state: Current symbolic register/memory state

        Returns:
            List of successor symbolic states (1 for linear gadgets, 2+ for branches)

        Raises:
            TypeError: If addr type is not AddressPair or bytes
            TypeError: If RSP or RIP cannot be resolved after execution
        """
        gadget: bytes = b''
        if isinstance(addr, tuple):
            if not state:
                state = self.get_init_state(addr[1])

            if addr[0] in self.gadgets:
                gadget = self.gadgets[addr[0]]
            else:
                gadget = self.split_gadget(addr[0])

        elif isinstance(addr, bytes):
            gadget = addr

        else:
            TypeError('Error in addr of sym_exec')
        if not gadget:
            raise ValueError(f"Failed to retrieve gadget bytes for address: {addr}")

        code = Container.from_string(gadget, self.loc_db)
        mdis = self.machine.dis_engine(code.bin_stream, loc_db=self.loc_db)
        asmcfg = mdis.dis_multiblock(0)

        state = self.vsa.constraints.update(state, asmcfg)

        if 'REP' in str(asmcfg):
            code = Container.from_string(b'\xC3', self.loc_db)
            mdis = self.machine.dis_engine(code.bin_stream, loc_db=self.loc_db)
            asmcfg = mdis.dis_multiblock(0)

        logger.debug('-----------ASMCFG-----------')
        for b in asmcfg.blocks:
            logger.debug(str(b))

        lifter = self.machine.lifter_model_call(self.loc_db)
        ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)

        my_expr_simp_explicit = ExpressionSimplifier()
        my_expr_simp_explicit.enable_passes(ExpressionSimplifier.PASS_COMMONS)
        my_expr_simp_explicit.enable_passes(ExpressionSimplifier.PASS_HIGH_TO_EXPLICIT)

        my_expr_simp_explicit.expr_simp_cb[ExprMem].insert(0, self.mem_callback)

        # Multi Branches (Merge delayed branches)
        if len(ircfg.nodes()) > 1:
            logger.debug('-----------IRCFG-----------')
            for lbl, irblock in ircfg.blocks.items():
                logger.debug('[lbl]:' + str(lbl))
                logger.debug(irblock)

            if len(ircfg.heads()) != 1:
                raise ValueError(f"Invalid IRCFG structure: expected 1 head node, got {len(ircfg.heads())}")

            head = ircfg.heads()[0]
            paths = ircfg_dfs_traversal(ircfg, head)
            symbols = []

            for path in paths:
                see = SymbolicExecutionEngine(lifter, state=state, sb_expr_simp=my_expr_simp_explicit)
                self.mem_callback.set_engine(see)
                for node in path:
                    see.run_block_at(ircfg=ircfg, addr=node)
                symbols.append(see.state.symbols)

            if 'POP' in str(asmcfg) or 'CMP' in str(asmcfg):
                raise ValueError("Invalid multi branch with POP instructions")

            logger.debug('-----------BRANCH-----------')
            logger.debug(str(ircfg.nodes()))
            logger.debug(str(ircfg.edges()))

            for symbol in symbols:
                if not isinstance(symbol[ExprId(self.rsp, self.base)], ExprInt):
                    raise TypeError("sp type error")

                for i, v in symbol.items():
                    logger.debug(str(i) + ":" + str(v))

            condition = is_conditional_branch(asmcfg)

            # Merge condition symbols for delayed branch
            if condition:
                if not self.vsa.constraints.prefork(condition, symbols):
                    logger.error('constraint fork error')
                    raise ValueError("constraint fork error")
                merged_state = self._merge_branches(symbols)
                return [merged_state] if merged_state else symbols[:1]
            else:
                return symbols[:1]

        # Single successor
        else:
            see = SymbolicExecutionEngine(lifter, state=state, sb_expr_simp=my_expr_simp_explicit)

            self.mem_callback.set_engine(see)

            see.run_block_at(ircfg=ircfg, addr=0)
            symbol = see.state.symbols
            symbol_sp = ExprId(self.rsp, self.base)
            symbol_ip = ExprId(self.rip, self.base)
            symbols = []

            if 'POP' in str(asmcfg):
                self._modify_pop_to_mov(addr, symbol, asmcfg)

            if 'CMP' in str(asmcfg) or 'TEST' in str(asmcfg):
                self.vsa.constraints.preload(asmcfg)

            sp_value = symbol[symbol_sp]
            ip_value = symbol[symbol_ip]

            # ADC/SBB delayed branch: CF is symbolic in some register, must check before VSA
            if self._is_adc_delayed_branch(asmcfg):
                forked = self._fork_on_adc(symbol, asmcfg)
                merged_state = self._merge_branches(forked)
                target_state = merged_state if merged_state else symbols[0]
                symbols.append(target_state)

            elif self.vsa.check_vsa_symbol(sp_value):
                successors = self.vsa.execute(sp_value, symbol)
                for succ in successors:
                    new_symbol = deepcopy(symbol)
                    new_symbol[symbol_ip] = succ[0]
                    new_symbol[symbol_sp] = succ[1]
                    symbols.append(new_symbol)

            # Resolve indirect branch of __libc_csu_init
            elif self.vsa.check_vsa_symbol(ip_value):
                successor = self.vsa.execute(ip_value, symbol)[0]
                new_symbol = deepcopy(symbol)
                new_symbol[symbol_ip] = successor[0]
                new_symbol[symbol_sp] = successor[1]
                symbols.append(new_symbol)

            elif isinstance(sp_value, ExprInt):
                symbols.append(symbol)

            # Resolve exprcond (delayed branches)
            elif isinstance(sp_value, ExprCond):
                ip_value = symbol[symbol_ip]

                if isinstance(ip_value, ExprCond):
                    new_ip1, new_ip2 = ip_value.src1, ip_value.src2
                elif isinstance(ip_value, ExprInt):
                    new_ip1 = new_ip2 = ip_value
                else:
                    raise TypeError(f"Unsupported RIP type after conditional branch: {type(ip_value)}")

                symbol1 = symbol.copy()
                symbol1[symbol_ip] = new_ip1
                symbol1[symbol_sp] = sp_value.src1

                symbol2 = symbol.copy()
                symbol2[symbol_ip] = new_ip2
                symbol2[symbol_sp] = sp_value.src2

                con_sym = self.vsa.constraints.constraint_symbol
                cons = self.vsa.constraints.get_fork_constraint()
                symbol1[con_sym] = cons[0]
                symbol2[con_sym] = cons[1]

                # First explore fall through path
                if abs(addr[1] - sp_value.src1.arg) < abs(addr[1] - sp_value.src2.arg):
                    symbols.append(symbol1)
                    symbols.append(symbol2)
                else:
                    symbols.append(symbol2)
                    symbols.append(symbol1)

            elif isinstance(sp_value, ExprOp):
                ids = get_all_expr_ids(sp_value)
                env = {}
                for id in ids:
                    if '_init' not in id.name:
                        continue
                    reg_name = id.name.replace('_init', '')
                    con = self.vsa.constraints.constraints[X86_CAP_REGS_MAP[reg_name]]
                    if not con:
                        continue
                    value = self.vsa.analysis(state, con)
                    if not value:
                        value = [0]

                    if not value:
                        continue

                    assert len(value) == 1
                    env[id] = ExprInt(value[0], id.size)
                sp_value = sp_value.replace_expr(env)
                sp_value = expr_simp(sp_value)
                symbol[symbol_sp] = sp_value
                symbol[symbol_ip] = ExprInt(self.rop_chain[(sp_value.arg // (self.base // 8)) - 1], self.base)
                symbols.append(symbol)
            else:
                raise TypeError(f"Unsupported SP type in symbolic execution: {type(sp_value)}")

        return symbols

    def _is_adc_delayed_branch(self, asmcfg):
        """
        Detect whether the current gadget is an ADC/SBB delayed branch.

        Returns True when both conditions hold:
        1. The gadget contains an ADC or SBB instruction.
        2. No flag-setting instruction precedes ADC/SBB (CF is inherited from the previous gadget).

        Note: Miasm symbolic execution assumes CF=0 for ADC by default and does not
        preserve CF as a symbolic value. Therefore, we no longer check whether the state
        contains a 'cf' symbol — we simply trigger a fork whenever ADC/SBB is detected
        and CF has not been determined locally.

        Args:
            asmcfg: Assembly CFG

        Returns:
            True if this is an ADC/SBB delayed branch
        """
        condition = is_conditional_branch(asmcfg)
        if not condition:
            return False

        instr_name = condition.name
        if 'ADC' not in instr_name and 'SBB' not in instr_name:
            return False

        # CF is locally determined in this gadget — no fork needed
        trigger = 'ADC' if 'ADC' in instr_name else 'SBB'
        if has_preset_flags(asmcfg, trigger_instr=trigger):
            return False

        # ADC/SBB present with CF from an external gadget — fork required
        return True

    def _fork_on_adc(self, symbol, asmcfg):
        """
        Core logic for ADC delayed branch forking.

        Miasm executes ADC/SBB with CF=0 by default, so `symbol` already represents
        the CF=0 outcome. This method manually constructs the CF=1 outcome:
        for ADC, dst += 1; for SBB, dst -= 1.

        Args:
            symbol: Symbolic state after execution (Miasm default: CF=0)
            asmcfg: Assembly CFG

        Returns:
            List of two branch states [state_cf0, state_cf1], or [symbol] on failure
        """
        rsp_expr_id = ExprId(self.rsp, self.base)
        rip_expr_id = ExprId(self.rip, self.base)

        # state_cf0 = Miasm result (CF=0), deep copy directly
        state_cf0 = deepcopy(symbol)

        # state_cf1 = manually adjusted ADC destination register (CF=1)
        state_cf1 = deepcopy(symbol)

        # Extract the ADC/SBB destination register
        asm_block = list(asmcfg.blocks)[0]
        adc_dst_reg = None
        is_adc = True
        for line in asm_block.lines:
            if 'ADC' in line.name:
                is_adc = True
                dst = line.args[0]
                if isinstance(dst, ExprId):
                    adc_dst_reg = dst
                break
            elif 'SBB' in line.name:
                is_adc = False
                dst = line.args[0]
                if isinstance(dst, ExprId):
                    adc_dst_reg = dst
                break

        if adc_dst_reg is None or adc_dst_reg not in state_cf1:
            logger.warning(f"[ADC Fork] Cannot extract ADC destination register")
            return [symbol]

        # When CF=1: ADC result = CF=0 result + 1; SBB result = CF=0 result - 1
        cf0_val = state_cf1[adc_dst_reg]
        if not isinstance(cf0_val, ExprInt):
            logger.warning(f"[ADC Fork] ADC dst {adc_dst_reg} is not ExprInt: {cf0_val}")
            return [symbol]

        delta = 1 if is_adc else -1
        cf1_val = ExprInt(cf0_val.arg + delta, self.base)
        state_cf1[adc_dst_reg] = cf1_val

        logger.debug(f"[ADC Fork] CF=0: {adc_dst_reg}={hex(cf0_val.arg)}, ESP={state_cf0[rsp_expr_id]}")
        logger.debug(f"[ADC Fork] CF=1: {adc_dst_reg}={hex(cf1_val.arg)}, ESP={state_cf1[rsp_expr_id]}")

        # Verify RSP/RIP in both states are concrete ExprInt
        for state, label in [(state_cf0, 'CF=0'), (state_cf1, 'CF=1')]:
            sp = state.get(rsp_expr_id)
            ip = state.get(rip_expr_id)
            if not isinstance(sp, ExprInt) or not isinstance(ip, ExprInt):
                logger.warning(f"[ADC Fork] {label} branch has non-concrete RSP/RIP: RSP={sp}, RIP={ip}")
                return [symbol]

        # Attach fork constraints to each state
        if adc_dst_reg and adc_dst_reg.name in X86_CAP_REGS_MAP:
            self.vsa.constraints.create_adc_fork_constraints(adc_dst_reg.name, [0, 1])

        return [state_cf0, state_cf1]

    def _merge_branches(
            self,
            symbols: List[SymbolMngr],
    ) -> Optional[SymbolMngr]:
        """
        Merge two symbolic branch states into one using ExprCond placeholders.

        Values that are identical in both states are kept as-is. Differing values
        are wrapped in ExprCond(default_cond_symbol, val1, val2) to represent the
        conditional outcome. Used for delayed branches (ADC/SBB, CMOV).

        Args:
            symbols: List of exactly two SymbolMngr branch states

        Returns:
            Merged SymbolMngr, or None if input is empty
        """
        if len(symbols) < 2:
            return symbols[0] if symbols else None

        if len(symbols) > 2:
            logger.warning(f"_merge_branches: Expected 2 branches, got {len(symbols)}, using first 2")
            symbols = symbols[:2]

        state1, state2 = symbols[0], symbols[1]
        merged_state = SymbolMngr(addrsize=self.base)

        # Use default condition symbol as placeholder
        # No need to extract concrete condition, only mark this as a conditional branch result
        condition_expr = self.default_cond_symbol

        # Merge all register states
        all_keys = set(state1.keys()) | set(state2.keys())

        for key in all_keys:
            val1 = state1.get(key)
            val2 = state2.get(key)

            # If values are identical in both states, use directly
            if val1 == val2:
                merged_state[key] = val1
            else:
                # Values differ, merge using ExprCond
                # ExprCond(condition, if_true, if_false)
                # Use default condition symbol placeholder, later optimization will handle branch logic

                merged_state[key] = ExprCond(
                    condition_expr,
                    val1 if val1 is not None else ExprInt(0, key.size),
                    val2 if val2 is not None else ExprInt(0, key.size)
                )
                logger.debug(f"Merged {key}: {val1} ? {val2} with default condition symbol")

        return merged_state

    def _is_symbolic_rsp_branch(
            self,
            rsp_expr: Any,
            rip_expr: Any
    ) -> bool:
        """
        Check whether the RSP or RIP expression contains an ExprCond (delayed slot result).

        Args:
            rsp_expr: Current RSP symbolic expression
            rip_expr: Current RIP symbolic expression

        Returns:
            True if either expression contains an ExprCond node
        """
        # If RSP or RIP contains ExprCond, indicates delayed slot result
        def contains_exprcond(expr: Any) -> bool:
            """Recursively check if expression contains ExprCond"""
            if isinstance(expr, ExprCond):
                return True
            if isinstance(expr, ExprOp):
                return any(contains_exprcond(arg) for arg in expr.args)
            return False

        return contains_exprcond(rsp_expr) or contains_exprcond(rip_expr)

    def _fork_on_rsp_branch(
            self,
            state: SymbolMngr,
            rsp_expr: Any,
            rip_expr: Any
    ) -> List[SymbolMngr]:
        """
        Fork the symbolic state on an RSP/RIP ExprCond branch.

        Extracts all possible concrete RSP and RIP values from the conditional
        expression and creates one new state per (RSP, RIP) combination.

        Args:
            state: Current symbolic state containing conditional RSP/RIP
            rsp_expr: RSP expression (may be ExprCond)
            rip_expr: RIP expression (may be ExprCond)

        Returns:
            List of forked symbolic states with concrete RSP/RIP values
        """
        # Extract all possible RSP/RIP values
        rsp_values = self._extract_values_from_exprcond(rsp_expr)
        rip_values = self._extract_values_from_exprcond(rip_expr)

        if not rsp_values or not rip_values:
            logger.warning("Cannot extract values from ExprCond, returning original state")
            return [state]

        # Generate all possible RSP/RIP combinations
        forked_states = []
        rsp_expr_id = ExprId(self.rsp, self.base)
        rip_expr_id = ExprId(self.rip, self.base)

        for rsp_val, rip_val in zip(rsp_values, rip_values):
            # Create new state
            new_state = SymbolMngr(addrsize=self.base)
            new_state.update(state)

            # Set concrete RSP and RIP values
            if isinstance(rsp_val, int):
                new_state[rsp_expr_id] = ExprInt(rsp_val, self.base)
            else:
                new_state[rsp_expr_id] = rsp_val

            if isinstance(rip_val, int):
                new_state[rip_expr_id] = ExprInt(rip_val, self.base)
            else:
                new_state[rip_expr_id] = rip_val

            forked_states.append(new_state)

        logger.debug(f"Forked {len(forked_states)} states from RSP branch")
        return forked_states

    def _extract_values_from_exprcond(self, expr: Any) -> List[Any]:
        """
        Recursively extract all possible concrete values from an ExprCond expression.

        Args:
            expr: Expression to extract values from (ExprInt, ExprCond, or ExprOp)

        Returns:
            List of extracted values (integers or sub-expressions)
        """
        if isinstance(expr, ExprInt):
            return [expr.arg]

        if isinstance(expr, ExprCond):
            # ExprCond structure: typically has cond, src1, src2 attributes
            # src1 is value when condition is true, src2 is value when false
            try:
                # Try to access ExprCond attributes
                if hasattr(expr, 'src1') and hasattr(expr, 'src2'):
                    true_vals = self._extract_values_from_exprcond(expr.src1)
                    false_vals = self._extract_values_from_exprcond(expr.src2)
                    return true_vals + false_vals
                elif hasattr(expr, 'args') and len(expr.args) >= 3:
                    # If using args: args[0] is condition, args[1] is true, args[2] is false
                    true_vals = self._extract_values_from_exprcond(expr.args[1])
                    false_vals = self._extract_values_from_exprcond(expr.args[2])
                    return true_vals + false_vals
                else:
                    logger.warning(f"Cannot extract values from ExprCond: {expr}")
                    return []
            except Exception as e:
                logger.warning(f"Error extracting values from ExprCond: {e}")
                return []

        if isinstance(expr, ExprOp):
            # For operation expressions, attempt evaluation
            # Simplified, may need more complex logic
            return []

        # For other types, try to use directly
        return [expr]

    def identify_call_ret(
            self,
            curr_addr: AddressPair,
            next_addr: AddressPair,
            curr_state: SymbolMngr,
            next_state: SymbolMngr,
    ):
        """
        Classify the edge from curr_addr to next_addr as NORMAL, RET, or CALL.

        - NORMAL: next_addr RIP is a known gadget — continue execution normally.
        - RET: next_addr RIP is 0 or the stack_address — terminate this path.
        - CALL: next_addr RIP is an external function — simulate CALL/RET and continue.

        Args:
            curr_addr: Current (RIP, RSP) address pair
            next_addr: Successor (RIP, RSP) address pair from symbolic execution
            curr_state: Symbolic state at curr_addr
            next_state: Symbolic state after executing curr_addr

        Returns:
            (call_node, edges, successor) where:
              - call_node: Address pair of external call target (or None)
              - edges: List of (from, to) address pair edges to record
              - successor: (addr, state) tuple to push onto worklist, or None to stop
        """
        # Normal gadget: continue execution
        if next_addr[0] in self.gadgets:
            return None, [(curr_addr, next_addr)], (next_addr, next_state)

        # RET: terminate execution, add edge to stack bottom
        if not next_addr[0] or next_addr[0] == self.stack_address:
            logger.debug(f'[RET] {hex(curr_addr[0])} -> stack_bottom')
            new_address = (self.stack_address, curr_addr[1])
            return new_address, [(curr_addr, new_address)], None

        # CALL: simulate RET execution to get state after function return
        rsp = curr_addr[1] // (self.base // 8)
        for rsp in range(curr_addr[1] // (self.base // 8), len(self.rop_chain)):
            if self.rop_chain[rsp] in self.gadgets:
                break
            else:
                continue

        rsp_sym = ExprId(self.rsp, self.base)
        if curr_state[rsp_sym].arg % (self.base // 8) == 0:
            curr_state[rsp_sym] = ExprInt(rsp * (self.base // 8), self.base)

        ret_state = self.symbolic_execute(b'\xC3', curr_state)[0]
        ret_rsp = ret_state[ExprId(self.rsp, self.base)].arg
        ret_rip = ret_state[ExprId(self.rip, self.base)].arg
        ret_addr = (ret_rip, ret_rsp)

        # Handle all external calls uniformly (including invalid addresses)
        function_addr = next_addr[0]

        logger.debug(f'[CALL] {hex(curr_addr[0])} -> {hex(function_addr)} (returns to {hex(ret_rip)})')
        self.external_functions.add(function_addr)

        # Add two edges:
        # 1. Call edge: curr -> function_addr (indicates external function call or invalid address)
        # 2. Return edge: curr -> ret_addr (indicates target after function return)
        new_address = (function_addr, curr_addr[1])
        edges = [
            (curr_addr, new_address),  # Call edge
            (new_address, ret_addr),  # Return edge
        ]

        # Continue exploration with state after return
        if rsp >= len(self.rop_chain) - 1:
            return new_address, edges, None
        else:
            return new_address, edges, (ret_addr, ret_state)

    def _chain_out_of_range(self, sp):
        """Return True if the RSP index exceeds the ROP chain length."""
        return sp // 8 > len(self.rop_chain)

    def _is_pop_rsp_inst(self, rip):
        """
        Check whether the first instruction at the given RIP is a POP RSP/ESP.

        Args:
            rip: Gadget start address

        Returns:
            True if the first instruction is POP RSP (or ESP in 32-bit mode)
        """
        if rip in self.gadgets:
            gadget = self.gadgets[rip]
        else:
            gadget = self.split_gadget(rip)

        inst = next(self.cs.disasm(gadget, 0), None)
        if 'pop' == inst.mnemonic and self.rsp.lower() == inst.op_str:
            return True
        else:
            return False

    # ==================== Sensitive Gadget Detection ====================

    def _identify_sensitive_gadgets(
            self,
            curr_addr: AddressPair,
            next_addr: AddressPair
    ) -> Set[AddressPair]:
        """
        Heuristically identify gadgets that are sensitive to RSP propagation.

        Pattern: ADD RSP, regX where the preceding instruction is ADD/SUB/MOV reg, reg
        (i.e., regX depends on another external register, not a constant assignment).

        Returns:
            Set of address pairs for gadgets identified as RSP-propagation sensitive
        """
        sensitive = set()
        if not curr_addr or not next_addr:
            return sensitive

        if curr_addr[0] in self.gadgets:
            curr_gadget = self.gadgets[curr_addr[0]]
        else:
            curr_gadget = self.split_gadget(curr_addr[0])

        if next_addr[0] in self.gadgets:
            next_gadget = self.gadgets[next_addr[0]]
        else:
            next_gadget = self.split_gadget(next_addr[0])

        if not curr_gadget or not next_gadget:
            return sensitive

        code = Container.from_string(curr_gadget, self.loc_db)
        mdis = self.machine.dis_engine(code.bin_stream, loc_db=self.loc_db)
        curr_instr = mdis.dis_instr(0)

        code = Container.from_string(next_gadget, self.loc_db)
        mdis = self.machine.dis_engine(code.bin_stream, loc_db=self.loc_db)
        next_instr = mdis.dis_instr(0)

        if next_instr.name == 'ADD' and \
                isinstance(next_instr.args[0], ExprId) and \
                isinstance(next_instr.args[1], ExprId) and \
                next_instr.args[0].name == self.rsp:
            if curr_instr.name in ('SUB', 'ADD', 'MOV') and \
                    isinstance(curr_instr.args[1], ExprId) and \
                    isinstance(curr_instr.args[1], ExprId) and \
                    curr_instr.args[0] == next_instr.args[1]:
                sensitive.add(curr_addr)
                sensitive.add(next_addr)

        return sensitive

    # ==================== LSE Stage 2 Methods ====================

    def _is_valid_rsp(self, rsp: int) -> bool:
        """
        Check whether an RSP value is within the valid ROP chain index range.

        Also accepts RSP values that are within 0x100 bytes below stack_address,
        to tolerate minor overflows at the end of the chain.

        Args:
            rsp: RSP value (byte offset into the ROP chain)

        Returns:
            True if the RSP index is within bounds or near the stack anchor
        """
        chain_len = len(self.rop_chain)
        if chain_len == 0:
            return False

        rsp_index = rsp // (self.base // 8)
        if 0 <= rsp_index <= chain_len:
            return True

        if 0 <= self.stack_address - rsp <= 0x100:
            return True

        return False

    def _stage2_recover(
            self,
            curr_addr: AddressPair,
            curr_state: SymbolMngr,
            visited_nodes: List[AddressPair],
            visited_edges: List[Tuple[AddressPair, AddressPair]],
    ) -> Optional[SymbolMngr]:
        """
        Attempt Stage-2 recovery for a gadget with an invalid RSP.

        Performs backward slicing to identify RSP-irrelevant instructions,
        then re-executes the path with those instructions replaced by RET stubs.

        Args:
            curr_addr: Address pair where invalid RSP was detected
            curr_state: Symbolic state at curr_addr
            visited_nodes: Nodes explored so far (for backward slice)
            visited_edges: Edges explored so far (for backward slice)

        Returns:
            Recovered SymbolMngr with valid RSP, or None if recovery failed
        """

        logger.info(f"[Stage2] Triggered at ({hex(curr_addr[0])}, {hex(curr_addr[1])})")

        # Step 1: Dependency Analysis - Backward Slicing
        irrelated_insts = self._backward_slice(curr_addr, curr_state, visited_nodes, visited_edges)

        # Step 2: Path-Sensitive Re-Execution with Semantic Pruning
        recovered_state = self._path_sensitive_reexec(curr_addr, irrelated_insts)
        if recovered_state:
            rsp_expr = recovered_state[ExprId(self.rsp, self.base)]
            logger.info(f"[Stage2] Recovery successful: RSP={hex(rsp_expr.arg)}")
            return recovered_state

        logger.warning("[Stage2] Recovery failed")
        return None

    def _backward_slice(
            self,
            start_addr: AddressPair,
            start_state: SymbolMngr,
            visited_nodes: List[AddressPair],
            visited_edges: List[Tuple[AddressPair, AddressPair]],
    ):
        """
        Perform backward slicing from start_addr to find RSP-irrelevant instructions.

        Traverses the reverse CFG from start_addr, classifying each gadget as either
        RSP-relevant (uses/defines registers contributing to RSP) or irrelevant.

        Args:
            start_addr: Starting address pair for backward traversal
            start_state: Symbolic state at start_addr (unused, kept for API symmetry)
            visited_nodes: Previously visited address pairs
            visited_edges: Previously visited edges

        Returns:
            Set of address pairs whose instructions are irrelevant to RSP computation
        """
        reverse_graph = defaultdict(list)
        for src, dst in visited_edges:
            reverse_graph[dst].append(src)

        visited = set()
        stack = [start_addr]
        alias_map = dict.fromkeys(X86_CAP_REGS_MAP.values(), None)
        irrelated_insts = set()

        while stack:
            curr = stack.pop()
            if curr in visited:
                continue
            visited.add(curr)

            for pred in reverse_graph.get(curr, []):
                if pred not in visited and pred in visited_nodes:
                    stack.append(pred)

            # Instruction classification
            if curr in self.preload_instr:
                gadget = b''.join([i.b for i in self.preload_instr[curr].lines])
            elif curr[0] in self.gadgets:
                gadget = self.gadgets[curr[0]]
            else:
                gadget = self.split_gadget(curr[0])

            inst = next(self.cs.disasm(gadget, 0), None)
            _use, _def = inst.regs_access()

            if X86_REG_EFLAGS in _def and 'test' != inst.mnemonic and 'cmp' != inst.mnemonic:
                _def.remove(X86_REG_EFLAGS)

            if X86_REG_RSP in _def or X86_REG_ESP in _def:
                for reg in _def:
                    alias_map[reg] = True

            is_rsp_related = any(alias_map.get(r) for r in _def)
            if is_rsp_related or curr in self.preload_instr:
                for dst in _use:
                    alias_map[dst] = True
            else:
                irrelated_insts.add(curr)

            if inst.mnemonic in ['mov', 'lea'] and not _use:
                for reg in _def:
                    alias_map[reg] = False

        return irrelated_insts

    def _path_sensitive_reexec(
            self,
            target_addr: AddressPair,
            irr_insts: List[AddressPair],
    ) -> Optional[SymbolMngr]:
        """
        Re-execute the ROP chain from the start with RSP-irrelevant instructions replaced by RET stubs.

        Explores paths from self.start_address toward target_addr. At each step,
        gadgets in irr_insts are replaced with a RET stub (0xC3) so that their
        RSP-perturbing effects are skipped. Fork constraints from prior branches
        are used to select the correct path when branching occurs.

        Args:
            target_addr: The address pair where recovery is needed
            irr_insts: Set of address pairs identified as RSP-irrelevant

        Returns:
            Symbolic state at target_addr with a valid RSP, or None if recovery failed
        """
        init_state = self.get_init_state()
        worklist: deque[tuple[AddressPair, SymbolMngr]] = deque()
        worklist.append((self.start_address, init_state))

        rsp_expr_id = ExprId(self.rsp, self.base)
        rip_expr_id = ExprId(self.rip, self.base)
        canonical_regs = X86_64_REGS if self.base == 64 else X86_32_REGS
        normalized_reg_to_expr = {
            X86_CAP_REGS_MAP[reg_name]: ExprId(reg_name, self.base)
            for reg_name in canonical_regs
            if reg_name in X86_CAP_REGS_MAP
        }
        irr_inst_set = set(irr_insts)
        max_steps = max(1, len(self.rop_chain)) * STAGE2_MAX_REEXEC_ITERATIONS
        steps = 0

        while worklist and steps < max_steps:
            curr_addr, curr_state = worklist.pop()
            steps += 1

            if self._chain_out_of_range(curr_addr[1]):
                continue

            if curr_addr in irr_inst_set:
                exec_target = b'\xC3'
            else:
                exec_target = curr_addr

            states = self.symbolic_execute(exec_target, curr_state)

            if len(states) == 1:
                next_state = states[0]
            elif len(states) == 2:
                correspond_state = None
                for state in states:
                    constraint = state.get(self.vsa.constraints.constraint_symbol)
                    correspond_cons = True

                    if not constraint:
                        logger.debug("[Stage2] Missing fork constraint on candidate state")
                        continue

                    for reg, cons in constraint.items():
                        if cons is None:
                            continue

                        normalized_reg = X86_CAP_ALIGN_MAP.get(reg, reg)
                        left_expr = normalized_reg_to_expr.get(normalized_reg)
                        if left_expr is None or left_expr not in state:
                            correspond_cons = False
                            break

                        left = state[left_expr]
                        check_result = cons.check(left)
                        if not check_result:
                            correspond_cons = False
                            break

                    if correspond_cons:
                        correspond_state = state
                        break

                if not correspond_state:
                    return None

                next_state = correspond_state
            else:
                return None

            rsp_expr = next_state[rsp_expr_id]
            rip_expr = next_state[rip_expr_id]

            if self._is_symbolic_rsp_branch(rsp_expr, rip_expr):
                logger.debug(f"[Stage2] Symbolic RSP/RIP branch encountered during re-execution at {curr_addr}")
                return None

            if not isinstance(rsp_expr, ExprInt) or not isinstance(rip_expr, ExprInt):
                return None

            if curr_addr == target_addr:
                if isinstance(rsp_expr, ExprInt) and self._is_valid_rsp(rsp_expr.arg):
                    return next_state
                else:
                    return None

            next_addr = (rip_expr.arg, rsp_expr.arg)
            _node, _edges, successor = self.identify_call_ret(curr_addr, next_addr, curr_state, next_state)

            if successor:
                succ_addr, succ_state = successor
                if not self._chain_out_of_range(succ_addr[1]):
                    worklist.append((succ_addr, succ_state))
            else:
                return None

            if steps >= max_steps:
                logger.warning(f"[Stage2] Re-execution exceeded step budget before reaching {target_addr}")
                return None

        return None

    # =================== LSE Stage 2 Methods End ===================

    def execute(self) -> Tuple[List[AddressPair], List[Tuple[AddressPair, AddressPair]]]:
        """
        Run the full LSE (Localized Symbolic Execution) over the ROP chain.

        Starting from self.start_address, symbolically executes each gadget in BFS/DFS order,
        resolves branches (conditional, delayed, indirect), handles CALL/RET detection,
        and triggers Stage-2 recovery when an invalid RSP is encountered.

        Returns:
            (visited_nodes, visited_edges) where:
              - visited_nodes: Ordered list of (RIP, RSP) address pairs explored
              - visited_edges: List of (from_addr, to_addr) directed edges between address pairs
        """
        init_state = self.get_init_state()
        worklist: deque[tuple[AddressPair, SymbolMngr]] = deque()
        worklist.append((self.start_address, init_state))

        # Use list to preserve exploration order
        visited_nodes: List[AddressPair] = []
        # Use set for O(1) duplicate checking
        visited_nodes_set: Set[AddressPair] = set()
        visited_edges: List[Tuple[AddressPair, AddressPair]] = []

        # Sensitive gadgets: allow re-execution when external reg state differs
        sensitive_gadgets: Set[AddressPair] = set()

        while worklist:
            curr_addr, curr_state = worklist.pop()

            # Check if already visited using set for efficiency
            if curr_addr in visited_nodes_set:
                if curr_addr not in sensitive_gadgets:
                    continue
            if self._chain_out_of_range(curr_addr[1]):
                continue

            # Add to both list (for order) and set (for fast lookup)
            visited_nodes.append(curr_addr)
            visited_nodes_set.add(curr_addr)

            states = self.symbolic_execute(curr_addr, curr_state)

            for next_state in states:
                rsp_expr = next_state[ExprId(self.rsp, self.base)]
                rip_expr = next_state[ExprId(self.rip, self.base)]

                # Detect RSP branch: if RSP or RIP is symbolic (contains ExprCond), need to fork
                is_rsp_branch = self._is_symbolic_rsp_branch(rsp_expr, rip_expr)

                if is_rsp_branch:
                    # RSP branch: fork into multiple states
                    forked_states = self._fork_on_rsp_branch(next_state, rsp_expr, rip_expr)
                    for forked_state in forked_states:
                        rsp = forked_state[ExprId(self.rsp, self.base)].arg
                        rip = forked_state[ExprId(self.rip, self.base)].arg
                        next_addr = (rip, rsp)

                        node, edges, successor = self.identify_call_ret(curr_addr, next_addr, curr_state, forked_state)
                        if node: visited_nodes.append(node)
                        visited_edges.extend(edges)

                        if successor:
                            worklist.append(successor)
                else:
                    # Non-RSP branch: normal processing
                    if isinstance(rsp_expr, ExprInt) and isinstance(rip_expr, ExprInt):
                        rsp = rsp_expr.arg
                        rip = rip_expr.arg

                        if not self._is_valid_rsp(rsp) and not self._is_pop_rsp_inst(curr_addr[0]):
                            # print('!!!', hex(rsp), hex(rip), hex(self.stack_address))
                            logger.warning(f"[Stage1] Invalid RSP detected: {hex(rsp)} at {hex(curr_addr[0])}")

                            recovered_state = self._stage2_recover(curr_addr, curr_state, visited_nodes, visited_edges)

                            if recovered_state:
                                next_state = recovered_state
                                rsp_expr = next_state[ExprId(self.rsp, self.base)]
                                rip_expr = next_state[ExprId(self.rip, self.base)]

                                if isinstance(rsp_expr, ExprInt) and isinstance(rip_expr, ExprInt):
                                    rsp = rsp_expr.arg
                                    rip = rip_expr.arg
                                    logger.info(f"[Stage2] Using recovered state: RSP={hex(rsp)}, RIP={hex(rip)}")
                                else:
                                    logger.warning("[Stage2] Recovered state has non-concrete RSP/RIP, skipping")
                                    continue
                            else:
                                logger.warning("[Stage2] Recovery failed, skipping this path")
                                continue

                        next_addr = (rip, rsp)

                        sensitive_gadgets |= self._identify_sensitive_gadgets(curr_addr, next_addr)

                        node, edges, successor = self.identify_call_ret(curr_addr, next_addr, curr_state, next_state)
                        if node:
                            visited_nodes.append(node)

                        if edges:
                            visited_edges.extend(edges)

                        if successor:
                            worklist.append(successor)
                    else:
                        logger.warning(f"Unexpected symbolic RSP/RIP: RSP={rsp_expr}, RIP={rip_expr}")

        return visited_nodes, visited_edges

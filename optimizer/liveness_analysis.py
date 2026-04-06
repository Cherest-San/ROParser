"""
Liveness Analysis Module
Liveness analysis module

Implements instruction-level liveness analysis described in the paper for dead code elimination
"""

import logging
from typing import Dict, Set, List, Tuple
from miasm.core.asmblock import LocKey
from miasm.arch.x86.arch import instruction_x86
from miasm.core.asmblock import AsmCFG
from miasm.expression.expression import ExprId, ExprMem

from utils.constants import X86_CAP_REGS_MAP, X86_CAP_ALIGN_MAP
from utils.helpers import trace_identifiers_from_memory

logger = logging.getLogger(__name__)

# Synthetic register ID for EFLAGS liveness tracking (must not conflict with capstone IDs)
_X86_EFLAGS_ID = 0xFE

# Instructions that modify EFLAGS (capstone regs_access does NOT report EFLAGS)
_FLAG_SETTING_INSTRS = frozenset({
    'ADD', 'SUB', 'ADC', 'SBB', 'INC', 'DEC', 'NEG',
    'AND', 'OR', 'XOR', 'NOT',
    'SHL', 'SHR', 'SAR', 'SAL', 'ROL', 'ROR', 'RCL', 'RCR',
    'MUL', 'DIV', 'IMUL', 'IDIV',
    'BT', 'BTS', 'BTR', 'BTC', 'BSF', 'BSR',
    'XADD', 'CMPXCHG',
})

# Instructions whose name starts with these prefixes consume EFLAGS
_FLAG_CONSUMING_PREFIXES = ('CMOV', 'SET', 'ADC', 'SBB', 'LOOP')


class InstructionNode:
    """
    Instruction node

    Stores DEF, USE, IN, OUT sets of an instruction
    """

    def __init__(self, instruction: instruction_x86, base: int):
        """
        Initialize instruction node

        Args:
            instruction: Instruction object
            base: Architecture bit width
        """
        self.instruction = instruction
        self.base = base
        self.alive = True

        # Set definitions
        self._in: Set[int] = set()      # IN[I]
        self._out: Set[int] = set()     # OUT[I]
        self._def: Set[int] = set()     # DEF[I]
        self._use: Set[int] = set()     # USE[I]

        # Initialize DEF and USE sets
        self._init_def_use()

    def _init_def_use(self):
        """Initialize DEF and USE sets"""
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
            from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64

            if self.base == 32:
                cs = Cs(CS_ARCH_X86, CS_MODE_32)
                ks = Ks(KS_ARCH_X86, KS_MODE_32)
            else:
                cs = Cs(CS_ARCH_X86, CS_MODE_64)
                ks = Ks(KS_ARCH_X86, KS_MODE_64)

            cs.detail = True

            # Get register access information of instruction
            if self.instruction.b:
                inst = next(cs.disasm(self.instruction.b, 0), None)
            else:
                asm_bytes = bytes(ks.asm(str(self.instruction))[0])
                inst = next(cs.disasm(asm_bytes, 0), None)

            # Handle CMP and TEST instructions (special handling)
            if self.instruction.name in ['CMP', 'TEST']:
                if len(self.instruction.args) >= 1:
                    if isinstance(self.instruction.args[0], ExprId):
                        reg_id = X86_CAP_REGS_MAP.get(self.instruction.args[0].name)
                        if reg_id:
                            self._use.add(X86_CAP_ALIGN_MAP.get(reg_id, reg_id))
                if len(self.instruction.args) >= 2:
                    if isinstance(self.instruction.args[1], ExprId):
                        reg_id = X86_CAP_REGS_MAP.get(self.instruction.args[1].name)
                        if reg_id:
                            self._use.add(X86_CAP_ALIGN_MAP.get(reg_id, reg_id))
                inst = None

            if inst:
                read_regs, write_regs = inst.regs_access()

                # Handle write registers (DEF)
                for reg_id in write_regs:
                    if reg_id is None:
                        continue
                    aligned_id = X86_CAP_ALIGN_MAP.get(reg_id, reg_id)
                    self._def.add(aligned_id)

                # Handle read registers (USE)
                for reg_id in read_regs:
                    if reg_id is None:
                        continue
                    aligned_id = X86_CAP_ALIGN_MAP.get(reg_id, reg_id)
                    self._use.add(aligned_id)

                # Special instruction handling
                if self.instruction.name == 'CALL':
                    self.alive = False
                    # x64 calling convention: parameter registers
                    if self.base == 64:
                        self._use.update([19, 22, 24, 23, 29, 106, 107])

                if self.instruction.name == 'RET':
                    self.alive = False

                if len(read_regs) == 0 and len(write_regs) == 0:
                    self.alive = False

            # Handle memory operations
            if len(self.instruction.args) > 0:
                for index, arg in enumerate(self.instruction.args):
                    if isinstance(arg, ExprMem):
                        # Track memory pointer registers
                        identifiers = trace_identifiers_from_memory(arg, [])
                        for reg_expr in identifiers:
                            if reg_expr.name in X86_CAP_REGS_MAP:
                                reg_id = X86_CAP_REGS_MAP[reg_expr.name]
                                aligned_id = X86_CAP_ALIGN_MAP.get(reg_id, reg_id)
                                self._use.add(aligned_id)

                        # Memory write is side-effecting
                        if index == 0:
                            self.alive = False

            # Track EFLAGS dependencies for correct liveness analysis
            # capstone regs_access() does not report EFLAGS for most instructions,
            # so we manually add it to DEF/USE to prevent incorrect dead code elimination
            inst_name = self.instruction.name
            if inst_name in _FLAG_SETTING_INSTRS:
                self._def.add(_X86_EFLAGS_ID)
            for prefix in _FLAG_CONSUMING_PREFIXES:
                if inst_name.startswith(prefix):
                    self._use.add(_X86_EFLAGS_ID)
                    break

        except Exception as e:
            logger.debug(f"Error initializing DEF/USE for instruction: {e}")
            self.alive = False

    def is_side_effecting(self) -> bool:
        """
        Determine if instruction is side-effecting

        Returns:
            True if it's side-effecting
        """
        # Side-effecting instructions include:
        # 1. CALL instructions
        # 2. Memory read/write instructions

        if self.instruction.name == 'CALL':
            return True

        # Check memory read or write (any operand)
        for arg in self.instruction.args:
            if isinstance(arg, ExprMem):
                return True

        return False

    def is_dead_code(self) -> bool:
        """
        Determine if instruction is dead code

        Based on paper algorithm: if DEF[I] ∩ OUT[I] = ∅, it's dead code

        Returns:
            True if it's dead code
        """
        if not self.is_side_effecting():
            # Non-side-effecting instruction, check DEF and OUT intersection
            return len(self._def & self._out) == 0

        return False


class LivenessAnalyzer:
    """
    Liveness analyzer

    Implements Algorithm 1 and Algorithm 2 from the paper
    """

    def __init__(self, base: int):
        """
        Initialize liveness analyzer

        Args:
            base: Architecture bit width
        """
        self.base = base
        self.node_map: Dict[Tuple[LocKey, int], InstructionNode] = {}

    def analyze_cfg(self, cfg: AsmCFG) -> Dict[Tuple[LocKey, int], InstructionNode]:
        """
        Analyze CFG, calculate IN and OUT sets for all instructions

        Implements Algorithm 1 from the paper

        Args:
            cfg: Control flow graph

        Returns:
            Instruction node mapping
        """
        # Initialize all nodes
        self.node_map.clear()

        for block in cfg.blocks:
            for index, instruction in enumerate(block.lines):
                node = InstructionNode(instruction, self.base)
                self.node_map[(block.loc_key, index)] = node

        # Iteratively calculate IN and OUT sets
        changed = True
        iteration = 0
        max_iterations = 100  # Prevent infinite loop

        while changed and iteration < max_iterations:
            changed = False
            iteration += 1

            # Traverse all basic blocks in reverse order
            blocks = list(cfg.blocks)
            blocks.reverse()

            for block in blocks:
                # Traverse instructions in block in reverse order
                for index in range(len(block.lines) - 1, -1, -1):
                    node = self.node_map[(block.loc_key, index)]

                    # Save old values
                    in_prev = node._in.copy()
                    out_prev = node._out.copy()

                    # Calculate IN[I] = USE[I] ∪ (OUT[I] \ DEF[I])
                    node._in = node._use | (node._out - node._def)

                    # Calculate OUT[I]
                    if index + 1 < len(block.lines):
                        # Not the last instruction in block, OUT[I] = IN[next(I)]
                        next_node = self.node_map[(block.loc_key, index + 1)]
                        node._out = next_node._in.copy()
                    else:
                        # Is the last instruction in block, OUT[I] = ∪ IN[first(S)] for S in succ(B)
                        successor_in = set()
                        for successor_block_key in cfg.successors(block.loc_key):
                            # Get first instruction node of successor block
                            if (successor_block_key, 0) in self.node_map:
                                successor_node = self.node_map[(successor_block_key, 0)]
                                successor_in.update(successor_node._in)
                        node._out = successor_in

                    # Check if changed
                    if node._in != in_prev or node._out != out_prev:
                        changed = True

        logger.debug(f"Liveness analysis completed in {iteration} iterations")
        return self.node_map

    def identify_dead_code(
        self,
        cfg: AsmCFG
    ) -> List[Tuple[LocKey, int]]:
        """
        Identify dead code

        Implements Algorithm 2 from the paper

        Args:
            cfg: Control flow graph

        Returns:
            Dead code instruction list [(block_loc_key, instruction_index)]
        """
        if not self.node_map:
            self.analyze_cfg(cfg)

        dead_code_list: List[Tuple[LocKey, int]] = []

        for block in cfg.blocks:
            for index in range(len(block.lines)):
                node = self.node_map[(block.loc_key, index)]

                # Check if it's dead code
                # is_dead_code() already handles side-effecting protection internally
                if node.is_dead_code():
                    dead_code_list.append((block.loc_key, index))

        logger.info(f"Identified {len(dead_code_list)} dead code instructions")
        return dead_code_list

    def remove_dead_code(
        self,
        cfg: AsmCFG
    ) -> AsmCFG:
        """
        Remove dead code and eliminate residual NOP instructions

        Args:
            cfg: Control flow graph

        Returns:
            Optimized control flow graph
        """
        dead_code_list = self.identify_dead_code(cfg)

        if not dead_code_list:
            # Even if no dead code, still sweep existing NOPs
            self._remove_nops(cfg)
            return cfg

        # Group by block
        dead_by_block: Dict[LocKey, Set[int]] = {}
        for block_key, index in dead_code_list:
            if block_key not in dead_by_block:
                dead_by_block[block_key] = set()
            dead_by_block[block_key].add(index)

        # Remove dead code (remove from back to front to avoid index changes)
        for block in cfg.blocks:
            if block.loc_key in dead_by_block:
                indices_to_remove = sorted(dead_by_block[block.loc_key], reverse=True)

                for index in indices_to_remove:
                    if 0 <= index < len(block.lines):
                        del block.lines[index]
                        logger.debug(f"Removed dead code at {block.loc_key}:{index}")

        return cfg

    def _remove_nops(self, cfg: AsmCFG) -> None:
        """
        Remove all NOP instructions from every block in the CFG

        This handles NOPs that may originate from prior optimization passes
        or from external sources.

        Args:
            cfg: Control flow graph
        """
        for block in cfg.blocks:
            if not block.lines:
                continue
            original_len = len(block.lines)
            block.lines = [
                line for line in block.lines
                if line.name != 'NOP'
            ]
            removed = original_len - len(block.lines)
            if removed > 0:
                logger.debug(f"Removed {removed} NOP(s) from block {block.loc_key}")

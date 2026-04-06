"""
Code Slicing Module
Code slicing module

Implements δ-correlated instruction sequence extraction described in the paper
For identifying custom stack operation instruction sequences
"""

import logging
from typing import Dict, List, Optional, Set, Tuple

from miasm.arch.x86.arch import instruction_x86
from miasm.core.asmblock import AsmBlock
from miasm.expression.expression import ExprId, ExprInt, ExprMem

from utils.constants import X86_CAP_ALIGN_MAP, X86_CAP_REGS_MAP
from utils.helpers import trace_identifiers_from_memory

logger = logging.getLogger(__name__)


class CodeSlicer:
    """
    Code slicer

    Extracts δ-correlated instruction sequences based on DEF-USE chain analysis
    """

    def __init__(
        self,
        delta: int = 1,
        max_sequence_length: int = 50
    ):
        """
        Initialize code slicer

        Args:
            delta: Correlation window size (δ in the paper)
            max_sequence_length: Maximum sequence length threshold
        """
        self.delta = delta
        self.max_sequence_length = max_sequence_length

    def get_def_set(self, instruction: instruction_x86, base: int) -> Set[int]:
        """
        Get DEF set of instruction (defined registers)

        Args:
            instruction: Instruction object
            base: Architecture bit width

        Returns:
            Set of defined register IDs
        """
        def_set: Set[int] = set()

        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
            from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64

            if base == 32:
                cs = Cs(CS_ARCH_X86, CS_MODE_32)
                ks = Ks(KS_ARCH_X86, KS_MODE_32)
            else:
                cs = Cs(CS_ARCH_X86, CS_MODE_64)
                ks = Ks(KS_ARCH_X86, KS_MODE_64)

            cs.detail = True

            if instruction.b:
                inst = next(cs.disasm(instruction.b, 0), None)
            else:
                asm_bytes = bytes(ks.asm(str(instruction))[0])
                inst = next(cs.disasm(asm_bytes, 0), None)

            if inst:
                _, write_regs = inst.regs_access()
                for reg_id in write_regs:
                    def_set.add(X86_CAP_ALIGN_MAP.get(reg_id, reg_id))

            if instruction.args and isinstance(instruction.args[0], ExprMem):
                identifiers = trace_identifiers_from_memory(instruction.args[0])
                for reg_expr in identifiers:
                    reg_id = X86_CAP_REGS_MAP.get(reg_expr.name.upper())
                    if reg_id is not None:
                        def_set.add(reg_id)

        except Exception as e:
            logger.debug(f"Error getting DEF set: {e}")

        return def_set

    def get_use_set(self, instruction: instruction_x86, base: int) -> Set[int]:
        """
        Get USE set of instruction (used registers)

        Args:
            instruction: Instruction object
            base: Architecture bit width

        Returns:
            Set of used register IDs
        """
        use_set: Set[int] = set()

        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
            from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64

            if base == 32:
                cs = Cs(CS_ARCH_X86, CS_MODE_32)
                ks = Ks(KS_ARCH_X86, KS_MODE_32)
            else:
                cs = Cs(CS_ARCH_X86, CS_MODE_64)
                ks = Ks(KS_ARCH_X86, KS_MODE_64)

            cs.detail = True

            if instruction.b:
                inst = next(cs.disasm(instruction.b, 0), None)
            else:
                asm_bytes = bytes(ks.asm(str(instruction))[0])
                inst = next(cs.disasm(asm_bytes, 0), None)

            if inst:
                read_regs, _ = inst.regs_access()
                for reg_id in read_regs:
                    use_set.add(X86_CAP_ALIGN_MAP.get(reg_id, reg_id))

            for arg in instruction.args:
                if isinstance(arg, ExprMem):
                    identifiers = trace_identifiers_from_memory(arg)
                    for reg_expr in identifiers:
                        reg_id = X86_CAP_REGS_MAP.get(reg_expr.name.upper())
                        if reg_id is not None:
                            use_set.add(reg_id)
                elif isinstance(arg, ExprId):
                    reg_id = X86_CAP_REGS_MAP.get(arg.name.upper())
                    if reg_id is not None:
                        use_set.add(reg_id)

        except Exception as e:
            logger.debug(f"Error getting USE set: {e}")

        return use_set

    def _get_register_name(self, expression) -> Optional[str]:
        """Return the uppercase register name if expression is ExprId, else None."""
        if isinstance(expression, ExprId):
            return expression.name.upper()
        return None

    def _get_immediate_value(self, expression) -> Optional[int]:
        """Return the integer value if expression is ExprInt, else None."""
        if isinstance(expression, ExprInt):
            return int(expression.arg)
        return None

    def _get_defined_register_names(self, instruction: instruction_x86) -> Set[str]:
        """
        Return the set of register names defined (written) by an instruction.

        For XCHG both operands are treated as defined. For all other instructions
        only the first operand (destination) is considered.
        """
        names: Set[str] = set()

        if instruction.name.upper() == 'XCHG':
            for arg in instruction.args:
                reg_name = self._get_register_name(arg)
                if reg_name:
                    names.add(reg_name)
            return names

        if instruction.args:
            reg_name = self._get_register_name(instruction.args[0])
            if reg_name:
                names.add(reg_name)

        return names

    def _register_names_to_ids(self, register_names: Set[str]) -> Set[int]:
        """Convert a set of register name strings to their Capstone register IDs."""
        register_ids: Set[int] = set()
        for name in register_names:
            reg_id = X86_CAP_REGS_MAP.get(name.upper())
            if reg_id is not None:
                register_ids.add(reg_id)
        return register_ids

    def _instruction_references_register_names(
        self,
        instruction: instruction_x86,
        register_names: Set[str]
    ) -> bool:
        """
        Return True if the instruction references any register in register_names.

        Checks direct register operands and registers used inside ExprMem pointers.
        """
        if not register_names:
            return False

        for arg in instruction.args:
            reg_name = self._get_register_name(arg)
            if reg_name and reg_name in register_names:
                return True

            if isinstance(arg, ExprMem):
                identifiers = trace_identifiers_from_memory(arg)
                for reg_expr in identifiers:
                    if reg_expr.name.upper() in register_names:
                        return True

        return False

    def _is_control_flow_boundary(self, instruction: instruction_x86) -> bool:
        """Return True if instruction is a control-flow boundary (RET, CALL, or any Jcc/JMP)."""
        name = instruction.name.upper()
        return name == 'RET' or name == 'CALL' or name.startswith('J')

    def is_stack_array_access(
        self,
        instruction: instruction_x86,
        stack_address: Optional[int] = None
    ) -> bool:
        """
        Determine if instruction is a stack array access anchor.

        Args:
            instruction: Instruction object
            stack_address: Known stack array anchor address

        Returns:
            True if it is an anchor instruction
        """
        if stack_address is None:
            return False

        if instruction.name.upper() != 'MOV' or len(instruction.args) != 2:
            return False

        reg_name = self._get_register_name(instruction.args[0])
        immediate = self._get_immediate_value(instruction.args[1])
        if not reg_name or immediate is None:
            return False

        return immediate == stack_address

    def extract_delta_correlated_sequence(
        self,
        block: AsmBlock,
        start_index: int,
        base: int
    ) -> List[instruction_x86]:
        """
        Extract δ-correlated instruction sequence

        Args:
            block: Basic block
            start_index: Start instruction index
            base: Architecture bit width

        Returns:
            δ-correlated instruction sequence
        """
        if start_index >= len(block.lines):
            return []

        sequence: List[instruction_x86] = []
        instructions = block.lines[start_index:]

        for i, instruction in enumerate(instructions):
            if len(sequence) >= self.max_sequence_length:
                break

            if i == 0:
                sequence.append(instruction)
                continue

            prev_instruction = sequence[-1]
            prev_def = self.get_def_set(prev_instruction, base)
            curr_use = self.get_use_set(instruction, base)

            if prev_def & curr_use:
                sequence.append(instruction)
            else:
                break

        return sequence

    def extract_stack_related_sequence(
        self,
        block: AsmBlock,
        start_index: int,
        base: int,
        stack_address: Optional[int] = None,
        excluded_indices: Optional[Set[int]] = None
    ) -> List[instruction_x86]:
        """
        Extract one stack-related sequence using a stack_address anchor and DEF/USE expansion.

        Args:
            block: Basic block
            start_index: Anchor instruction index
            base: Architecture bit width
            stack_address: Known stack array anchor address
            excluded_indices: Indices already reserved by deterministic replacements

        Returns:
            Stack-related instruction sequence
        """
        if start_index >= len(block.lines):
            return []

        excluded_indices = excluded_indices or set()
        if start_index in excluded_indices:
            return []

        anchor_instruction = block.lines[start_index]
        if not self.is_stack_array_access(anchor_instruction, stack_address):
            return []

        anchor_reg = self._get_register_name(anchor_instruction.args[0])
        if not anchor_reg:
            return []

        sequence: List[instruction_x86] = [anchor_instruction]
        tracked_names: Set[str] = {anchor_reg}
        tracked_ids: Set[int] = self._register_names_to_ids(tracked_names)

        for index in range(start_index + 1, len(block.lines)):
            if index in excluded_indices:
                break

            instruction = block.lines[index]
            if self._is_control_flow_boundary(instruction):
                break

            use_set = self.get_use_set(instruction, base)
            def_set = self.get_def_set(instruction, base)
            prev_def = self.get_def_set(sequence[-1], base)

            shares_tracked_register = bool((use_set | def_set) & tracked_ids)
            shares_tracked_memory = self._instruction_references_register_names(instruction, tracked_names)
            is_delta_correlated = bool(prev_def & use_set)

            if not shares_tracked_register and not shares_tracked_memory and not is_delta_correlated:
                break

            sequence.append(instruction)

            if shares_tracked_register or shares_tracked_memory:
                tracked_names.update(self._get_defined_register_names(instruction))
                tracked_ids = self._register_names_to_ids(tracked_names)

            if len(sequence) >= self.max_sequence_length:
                break

        return sequence

    def find_stack_operation_sequences(
        self,
        block: AsmBlock,
        base: int,
        stack_address: Optional[int] = None,
        excluded_indices: Optional[Set[int]] = None
    ) -> List[Tuple[int, List[instruction_x86]]]:
        """
        Find all custom stack operation instruction sequences.

        Args:
            block: Basic block
            base: Architecture bit width
            stack_address: Known stack array anchor address
            excluded_indices: Indices already reserved by deterministic replacements

        Returns:
            List of (start_index, instruction_sequence)
        """
        sequences: List[Tuple[int, List[instruction_x86]]] = []
        occupied: Set[int] = set(excluded_indices or set())

        index = 0
        while index < len(block.lines):
            if index in occupied:
                index += 1
                continue

            instruction = block.lines[index]
            if not self.is_stack_array_access(instruction, stack_address):
                index += 1
                continue

            sequence = self.extract_stack_related_sequence(
                block,
                index,
                base,
                stack_address=stack_address,
                excluded_indices=occupied
            )
            if len(sequence) > 1:
                sequences.append((index, sequence))
                occupied.update(range(index, index + len(sequence)))
                index += len(sequence)
                continue

            index += 1

        return sequences

    def extract_all_sequences(
        self,
        blocks: List[AsmBlock],
        base: int,
        stack_address: Optional[int] = None,
        excluded_indices: Optional[Dict[AsmBlock, Set[int]]] = None
    ) -> Dict[AsmBlock, List[Tuple[int, List[instruction_x86]]]]:
        """
        Extract instruction sequences from all basic blocks.

        Args:
            blocks: Basic block list
            base: Architecture bit width
            stack_address: Known stack array anchor address
            excluded_indices: Optional reserved instruction index map per block

        Returns:
            Sequence list for each basic block
        """
        all_sequences: Dict[AsmBlock, List[Tuple[int, List[instruction_x86]]]] = {}

        for block in blocks:
            block_excluded = None
            if excluded_indices:
                block_excluded = excluded_indices.get(block)

            sequences = self.find_stack_operation_sequences(
                block,
                base,
                stack_address=stack_address,
                excluded_indices=block_excluded
            )
            if sequences:
                all_sequences[block] = sequences

        return all_sequences

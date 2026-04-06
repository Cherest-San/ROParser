"""
Constant Propagation Module
Constant propagation module

Implements partial forward constant propagation algorithm described in the paper
"""

import logging
from typing import List, Tuple, Optional, Set, Any
from miasm.core.asmblock import AsmBlock, AsmCFG
from miasm.arch.x86.arch import instruction_x86
from miasm.expression.expression import ExprId, ExprInt, ExprOp
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

logger = logging.getLogger(__name__)


class ConstantPropagator:
    """
    Constant propagator

    Implements Algorithm 3 from the paper - partial forward constant propagation
    """

    def __init__(
        self,
        machine: Machine,
        loc_db: LocationDB,
        base: int
    ):
        """
        Initialize constant propagator

        Args:
            machine: Machine object
            loc_db: Location database
            base: Architecture bit width
        """
        self.machine = machine
        self.loc_db = loc_db
        self.base = base

    def is_propagatable_constant(self, value: Any) -> bool:
        """
        Determine if value is propagatable

        Based on paper definition: immediates, registers, sum/difference of register and immediate

        Args:
            value: Value to check

        Returns:
            True if propagatable
        """
        # Immediate
        if isinstance(value, ExprInt):
            return True

        # Register
        if isinstance(value, ExprId):
            return True

        # Operation of register and immediate
        if isinstance(value, ExprOp):
            if value.op in ['+', '-']:
                # Check if contains immediate and register
                has_int = any(isinstance(arg, ExprInt) for arg in value.args)
                has_reg = any(isinstance(arg, ExprId) for arg in value.args)
                return has_int and has_reg

        return False

    def simulate_instruction(
        self,
        instruction: instruction_x86,
        worklist: Optional[List[Tuple[ExprId, Any, Any]]] = None
    ) -> Tuple[Optional[ExprId], Optional[Any]]:
        """
        Simulate instruction execution, get output register and output constant state

        Implements function F_I(I) from the paper

        Args:
            instruction: Instruction object
            worklist: Current constant propagation worklist for folding

        Returns:
            (output_register, output_constant_state) tuple
        """
        output_register: Optional[ExprId] = None

        if len(instruction.args) > 0:
            if isinstance(instruction.args[0], ExprId):
                output_register = instruction.args[0]

        output_constant: Optional[Any] = None

        if instruction.name == 'MOV':
            if len(instruction.args) >= 2:
                source = instruction.args[1]
                # If source is a register, try to resolve from worklist
                if isinstance(source, ExprId) and worklist:
                    resolved = self._resolve_from_worklist(source, worklist)
                    if resolved is not None:
                        output_constant = resolved
                    elif self.is_propagatable_constant(source):
                        output_constant = source
                elif self.is_propagatable_constant(source):
                    output_constant = source

        elif instruction.name in ['ADD', 'SUB']:
            if len(instruction.args) >= 2:
                dest = instruction.args[0]
                if isinstance(dest, ExprId):
                    output_register = dest
                    imm_arg = instruction.args[1]

                    # Only fold when second operand is an immediate
                    if isinstance(imm_arg, ExprInt):
                        imm_val = imm_arg.arg

                        # Try to resolve destination register from worklist
                        if worklist:
                            existing = self._resolve_from_worklist(dest, worklist)
                            if existing is not None:
                                if isinstance(existing, ExprInt):
                                    # Concrete fold: e.g. RAX=0x100 + 0x10 -> 0x110
                                    if instruction.name == 'ADD':
                                        result = existing.arg + imm_val
                                    else:
                                        result = existing.arg - imm_val
                                    output_constant = ExprInt(result, existing.size)
                                elif isinstance(existing, ExprOp) and existing.op in ['+', '-']:
                                    # Propagated fold: (RSP + 0x8) + 0x10 -> RSP + 0x18
                                    if instruction.name == 'ADD':
                                        output_constant = ExprOp('+', existing.args[0],
                                                                 ExprInt(existing.args[1].arg + imm_val, existing.args[1].size))
                                    else:
                                        output_constant = ExprOp('+', existing.args[0],
                                                                 ExprInt(existing.args[1].arg - imm_val, existing.args[1].size))

        return (output_register, output_constant)

    def _resolve_from_worklist(
        self,
        reg: ExprId,
        worklist: List[Tuple[ExprId, Any, Any]]
    ) -> Optional[Any]:
        """
        Look up register's constant value from worklist

        Args:
            reg: Register expression to look up
            worklist: Current worklist

        Returns:
            Constant value if found, None otherwise
        """
        for entry_reg, entry_const, _ in worklist:
            if entry_reg.name == reg.name:
                return entry_const
        return None

    def check_instruction_syntax(
        self,
        instruction_str: str
    ) -> bool:
        """
        Check if instruction conforms to x86 assembly syntax

        Args:
            instruction_str: Instruction string

        Returns:
            True if syntax is valid
        """
        try:
            self.machine.mn.fromstring(instruction_str, self.loc_db, mode=self.base)
            return True
        except Exception:
            return False

    def update_instruction_argument(
        self,
        instruction: instruction_x86,
        old_arg: Any,
        new_arg: Any
    ) -> Optional[instruction_x86]:
        """
        Update instruction operand by index, avoiding fragile substring replacement

        Args:
            instruction: Original instruction
            old_arg: Old operand (used to locate the position in args)
            new_arg: New operand value

        Returns:
            Updated instruction, None if failed
        """
        try:
            # Locate old_arg position in instruction args
            target_index = None
            for i, arg in enumerate(instruction.args):
                if arg is old_arg:
                    target_index = i
                    break
                elif isinstance(arg, ExprId) and isinstance(old_arg, ExprId) and arg.name == old_arg.name:
                    target_index = i
                    break

            if target_index is None:
                return None

            # Build new args list with replaced operand
            new_args = list(instruction.args)
            new_args[target_index] = new_arg

            # Reconstruct instruction string and re-parse
            # Format: "OPNAME arg0, arg1, ..."
            arg_strs = []
            for a in new_args:
                if isinstance(a, ExprInt):
                    arg_strs.append(f"0x{a.arg:x}")
                elif isinstance(a, ExprId):
                    arg_strs.append(a.name)
                elif isinstance(a, ExprOp):
                    arg_strs.append(self._expr_op_to_str(a))
                else:
                    arg_strs.append(str(a))

            new_inst_str = f"{instruction.name} {', '.join(arg_strs)}"
            new_instruction = self.machine.mn.fromstring(
                new_inst_str, self.loc_db, mode=self.base
            )

            return new_instruction
        except Exception as e:
            logger.debug(f"Failed to update instruction argument: {e}")
            return None

    def _expr_op_to_str(self, expr: ExprOp) -> str:
        """
        Convert ExprOp to x86 assembly operand string

        Args:
            expr: ExprOp expression (expected '+' or '-' with ExprId + ExprInt)

        Returns:
            Assembly operand string, e.g. "RSP + 0x10"
        """
        if expr.op == '+':
            base, offset = expr.args[0], expr.args[1]
            base_str = base.name if isinstance(base, ExprId) else str(base)
            offset_str = f"0x{offset.arg:x}" if isinstance(offset, ExprInt) else str(offset)
            return f"{base_str} + {offset_str}"
        elif expr.op == '-':
            base, offset = expr.args[0], expr.args[1]
            base_str = base.name if isinstance(base, ExprId) else str(base)
            offset_str = f"0x{offset.arg:x}" if isinstance(offset, ExprInt) else str(offset)
            return f"{base_str} - {offset_str}"
        return str(expr)

    def propagate_block(
        self,
        block: AsmBlock
    ) -> AsmBlock:
        """
        Perform constant propagation within basic block

        Implements Algorithm 3 from the paper

        Args:
            block: Basic block

        Returns:
            Optimized basic block
        """
        # Worklist: (OUT_R, OUT_I, I)
        worklist: List[Tuple[ExprId, Any, instruction_x86]] = []

        new_instructions: List[instruction_x86] = []
        instructions_to_remove: Set[int] = set()

        for index, instruction in enumerate(block.lines):
            # Phase 1: Check if operands can be replaced
            updated = False

            for arg_index, arg in enumerate(instruction.args):
                # Check worklist for matching constants
                for out_reg, out_const, source_inst in worklist:
                    if isinstance(arg, ExprId) and arg.name == out_reg.name:
                        # Found match, try to replace
                        new_instruction = self.update_instruction_argument(
                            instruction,
                            arg,
                            out_const
                        )

                        if new_instruction:
                            # Check new instruction syntax
                            if self.check_instruction_syntax(str(new_instruction)):
                                instruction = new_instruction
                                updated = True
                                logger.debug(
                                    f"Propagated constant {out_const} to instruction {index}"
                                )

            # Phase 2: Simulate execution, get output (pass worklist for folding)
            output_reg, output_const = self.simulate_instruction(instruction, worklist)

            # Phase 3: Update worklist
            if output_reg:
                # Remove old propagation state
                worklist = [
                    (r, c, i) for r, c, i in worklist
                    if r.name != output_reg.name
                ]

                # Add new propagation state
                if output_const and self.is_propagatable_constant(output_const):
                    worklist.append((output_reg, output_const, instruction))

            new_instructions.append(instruction)

        # Update instructions in block
        block.lines = new_instructions

        return block

    def propagate_cfg(self, cfg: AsmCFG) -> AsmCFG:
        """
        Perform constant propagation on entire CFG

        Args:
            cfg: Control flow graph

        Returns:
            Optimized control flow graph
        """
        for block in cfg.blocks:
            try:
                self.propagate_block(block)
            except Exception as e:
                logger.error(f"Error propagating constants in block {block.loc_key}: {e}")

        return cfg

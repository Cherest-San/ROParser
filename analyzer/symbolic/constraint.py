import logging
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from typing import Optional,Dict, Tuple, Any

from miasm.core.asmblock import AsmCFG
from miasm.expression.expression import Expr, ExprId, ExprMem, ExprInt, ExprOp
from miasm.ir.symbexec import SymbolMngr

from utils.helpers import get_all_expr_ids
from utils.constants import X86_64_REGS, X86_32_REGS, X86_CAP_REGS_MAP

logger = logging.getLogger(__name__)


class ConstraintOp(Enum):
    EQ = "=="
    NE = "!="
    LT = "<"
    LE = "<="
    GT = ">"
    GE = ">="


@dataclass
class Constraint:
    op: ConstraintOp
    right: Expr
    signed: bool

    def __invert__(self):
        """Return the logically negated constraint (flips the comparison operator)."""
        negations = {
            ConstraintOp.EQ: ConstraintOp.NE,
            ConstraintOp.NE: ConstraintOp.EQ,
            ConstraintOp.LT: ConstraintOp.GE,
            ConstraintOp.LE: ConstraintOp.GT,
            ConstraintOp.GT: ConstraintOp.LE,
            ConstraintOp.GE: ConstraintOp.LT,
        }
        return Constraint(negations[self.op], self.right, self.signed)

    @staticmethod
    def transform(line, right):
        CMOV_MAP: Dict[str, Tuple] = {
            # Unsigned comparisons (based on CF and ZF)
            "CMOVA": (ConstraintOp.GT, False),    # Above (CF=0 && ZF=0)
            "CMOVAE": (ConstraintOp.GE, False),   # Above or Equal (CF=0)
            "CMOVB": (ConstraintOp.LT, False),    # Below (CF=1)
            "CMOVBE": (ConstraintOp.LE, False),   # Below or equal (CF=1 || ZF=1)
            "CMOVC": (ConstraintOp.LT, False),    # Carry (CF=1) - same as CMOVB
            "CMOVNC": (ConstraintOp.GE, False),   # No carry (CF=0) - same as CMOVAE

            # Equality (based on ZF)
            "CMOVE": (ConstraintOp.EQ, False),    # Equal (ZF=1)
            "CMOVNE": (ConstraintOp.NE, False),   # Not equal (ZF=0)
            "CMOVZ": (ConstraintOp.EQ, False),    # Zero (ZF=1) - same as CMOVE
            "CMOVNZ": (ConstraintOp.NE, False),   # Not zero (ZF=0) - same as CMOVNE

            # Signed comparisons (based on SF, OF, ZF)
            "CMOVG": (ConstraintOp.GT, True),     # Greater (SF=OF && ZF=0)
            "CMOVGE": (ConstraintOp.GE, True),    # Greater or equal (SF=OF)
            "CMOVL": (ConstraintOp.LT, True),     # Less (SF!=OF)
            "CMOVLE": (ConstraintOp.LE, True),    # Less or equal (SF!=OF || ZF=1)

            # Sign flag based
            "CMOVS": (ConstraintOp.LT, True),     # Sign (SF=1) - negative result
            "CMOVNS": (ConstraintOp.GE, True),    # No sign (SF=0) - non-negative result

            # Overflow and parity (less common, approximate mapping)
            "CMOVO": (ConstraintOp.LT, True),     # Overflow (OF=1)
            "CMOVNO": (ConstraintOp.GE, True),    # No overflow (OF=0)
            "CMOVP": (ConstraintOp.EQ, False),    # Parity (PF=1)
            "CMOVNP": (ConstraintOp.NE, False),   # No parity (PF=0)
            "CMOVPE": (ConstraintOp.EQ, False),   # Parity even (PF=1) - same as CMOVP
            "CMOVPO": (ConstraintOp.NE, False),   # Parity odd (PF=0) - same as CMOVNP
        }

        if line.name not in CMOV_MAP:
            logger.warning(f"Unknown CMOV instruction: {line.name}")
            raise KeyError(f"CMOV instruction '{line.name}' not supported")

        res = CMOV_MAP[line.name]
        return Constraint(res[0], right, res[1])

    def check(self, left):
        """Check whether left satisfies the current constraint."""
        def _to_concrete(value):
            if isinstance(value, ExprInt):
                return value.arg, value.size
            if isinstance(value, int):
                return value, None
            return None, getattr(value, 'size', None)

        def _to_signed(value: int, bit_size: int) -> int:
            mask = (1 << bit_size) - 1
            value &= mask
            sign_bit = 1 << (bit_size - 1)
            return value - (1 << bit_size) if value & sign_bit else value

        left_value, left_size = _to_concrete(left)
        right_value, right_size = _to_concrete(self.right)

        # For non-concrete expressions, only equality/inequality can be checked structurally.
        if left_value is None or right_value is None:
            if self.op == ConstraintOp.EQ:
                return left == self.right
            if self.op == ConstraintOp.NE:
                return left != self.right
            logger.warning(f"Cannot evaluate non-concrete constraint: {left} {self.op.value} {self.right}")
            return False

        bit_size = left_size or right_size
        if self.signed and bit_size:
            left_value = _to_signed(left_value, bit_size)
            right_value = _to_signed(right_value, bit_size)
        elif bit_size:
            mask = (1 << bit_size) - 1
            left_value &= mask
            right_value &= mask

        if self.op == ConstraintOp.EQ:
            return left_value == right_value
        if self.op == ConstraintOp.NE:
            return left_value != right_value
        if self.op == ConstraintOp.LT:
            return left_value < right_value
        if self.op == ConstraintOp.LE:
            return left_value <= right_value
        if self.op == ConstraintOp.GT:
            return left_value > right_value
        if self.op == ConstraintOp.GE:
            return left_value >= right_value

        raise ValueError(f"Unsupported constraint op: {self.op}")

    def __str__(self):
        return f"{self.op.value} {self.right}"


class ConstraintManager:
    def __init__(self, base):
        """
        Initialize constraint manager.

        Args:
            base: Architecture bit width (32 or 64)
        """
        self.base = base
        if base == 64:
            self.rip = ExprId(X86_64_REGS[0], self.base)
            self.rsp = ExprId(X86_64_REGS[2], self.base)
        else:
            self.rip = X86_32_REGS[0]
            self.rsp = X86_32_REGS[2]

        self.constraints = dict.fromkeys(X86_CAP_REGS_MAP.values(), None)
        self._preload = None
        self._fork_constraint = None
        self.constraint_symbol = ExprId('constraint', self.base)

    def preload(self, asmcfg: AsmCFG):
        """Collect CMP/TEST instructions for constraint analysis"""
        for block in asmcfg.blocks:
            for line in block.lines:
                if 'CMP' == line.name or 'TEST' == line.name:
                    self._preload = line
                    return

    def _extract_left_register(self, arg: Any) -> Optional[int]:
        """
        Extract left register key from CMP/TEST first argument

        Handles both ExprId (register) and ExprMem (memory operand) types.
        For memory operands, extracts the first non-RSP register from the address.

        Args:
            arg: CMP/TEST first argument (ExprId or ExprMem)

        Returns:
            Register key for X86_CAP_REGS_MAP, or None if extraction fails
        """
        try:
            # Case 1: ExprId - direct register access (e.g., CMP RAX, 0x0)
            if isinstance(arg, ExprId):
                reg_name = arg.name
                if reg_name in X86_CAP_REGS_MAP:
                    return X86_CAP_REGS_MAP[reg_name]
                else:
                    logger.warning(f"Register {reg_name} not in X86_CAP_REGS_MAP")
                    return None

            # Case 2: ExprMem - memory access (e.g., CMP [R10], 0x0)
            elif isinstance(arg, ExprMem):
                # Extract registers from memory pointer expression
                ptr_ids = get_all_expr_ids(arg.ptr)

                for expr_id in ptr_ids:
                    if isinstance(expr_id, ExprId):
                        reg_name = expr_id.name
                        # Skip RSP - we don't constrain stack pointer
                        if reg_name == self.rsp if isinstance(self.rsp, str) else reg_name == self.rsp.name:
                            continue
                        if reg_name in X86_CAP_REGS_MAP:
                            logger.debug(f"Extracted register {reg_name} from memory operand")
                            return X86_CAP_REGS_MAP[reg_name]

                logger.warning(f"No valid register found in memory operand: {arg}")
                return None

            # Case 3: Unknown type
            else:
                logger.warning(f"Unsupported CMP/TEST operand type: {type(arg)}")
                return None

        except Exception as e:
            logger.error(f"Exception in _extract_left_register: {e}")
            return None

    def prefork(self, line, states):
        """
        Generate constraints for CMOV conditional branches

        Args:
            line: CMOV instruction
            states: List of symbolic states from symbolic execution

        Returns:
            True if constraints were generated, False otherwise
        """
        if not self._preload:
            return False

        # Extract left register key from CMP/TEST first argument
        left = self._extract_left_register(self._preload.args[0])
        if left is None:
            logger.warning(f"Cannot extract left register from CMP/TEST: skipping constraint processing")
            return False

        # Get right operand
        if 'CMP' == self._preload.name:
            right = self._preload.args[1]
        elif 'TEST' == self._preload.name:
            right = ExprInt(0, self.base)
        else:
            logger.warning(f"Unknown preload instruction: {self._preload.name}")
            return False

        # Check if this is a CMOV instruction
        if 'CMOV' not in str(line):
            return False

        # Validate states
        if len(states) != 2:
            logger.warning(f"[prefork] Expected 2 states, got {len(states)}")
            return False

        dst = line.args[0]
        src = line.args[1]

        cons = []
        for state in states:
            # Create a copy of current constraints
            con = deepcopy(self.constraints)

            # If dst equals src in the forked state, CMOV has taken effect.
            if state[dst] == state[src]:
                # CMOV executed - condition was true
                con[left] = Constraint.transform(line, right)
            else:
                # CMOV not executed - condition was false
                con[left] = ~Constraint.transform(line, right)

            cons.append(con)

        self._fork_constraint = cons
        return True

    def create_adc_fork_constraints(self, adc_dst_reg, cf_values):
        """
        Create fork constraints for ADC instruction based on CF values.

        Args:
            adc_dst_reg: Destination register name of the ADC instruction
            cf_values: List of CF flag values (e.g., [0, 1]) to fork on

        Returns:
            List of constraint dicts, one per CF value
        """
        if adc_dst_reg not in X86_CAP_REGS_MAP:
            logger.warning(f"ADC dst register {adc_dst_reg} not in X86_CAP_REGS_MAP")
            return [deepcopy(self.constraints)] * 2

        reg_key = X86_CAP_REGS_MAP[adc_dst_reg]
        cons = []
        for cf_val in cf_values:
            con = deepcopy(self.constraints)
            con[reg_key] = Constraint(ConstraintOp.EQ, ExprInt(cf_val, self.base), signed=False)
            cons.append(con)

        self._fork_constraint = cons
        return cons

    def get_fork_constraint(self):
        """Return the most recently generated fork constraint list."""
        return self._fork_constraint

    def __getitem__(self, key):
        """Get constraint for a register key."""
        return self.constraints[key]

    def __setitem__(self, key, value):
        """Set constraint for a register key."""
        self.constraints[key] = value

    def update(self, state: SymbolMngr, asmcfg: AsmCFG):
        """Update constraints based on MOV instructions"""
        if self.constraint_symbol in state:
            self.constraints = deepcopy(state[self.constraint_symbol])
            del state[self.constraint_symbol]

        for block in asmcfg.blocks:
            for line in block.lines:
                if line.name == 'MOV' and isinstance(line.args[0], ExprId):
                    left = X86_CAP_REGS_MAP[line.args[0].name]
                    if isinstance(line.args[1], ExprId):
                        right = self[X86_CAP_REGS_MAP[line.args[1].name]]
                    else:
                        right = None
                    self[left] = right

        return state

    def remove(self, src):
        """Clear constraint for a single register key."""
        self.constraints[src] = None

    def clear(self):
        """Reset all constraints to None."""
        for i in X86_CAP_REGS_MAP.values():
            self.constraints[i] = None

"""
Reduced Value Set Analysis (RVSA) Module

Provides value set analysis for ROP chain execution.
Reduces the search space of possible register and memory values
during symbolic execution by tracking concrete and symbolic values.
"""

import logging
from copy import deepcopy
from typing import List, Optional, Tuple, Any

import cle
from miasm.expression.expression import ExprId, ExprInt, ExprOp, ExprMem
from miasm.expression.simplifications import expr_simp
from miasm.arch.x86.arch import instruction_x86
from miasm.ir.symbexec import SymbolMngr

from analyzer.symbolic.constraint import ConstraintManager, Constraint, ConstraintOp
from utils import X86_CAP_REGS_MAP
from utils.helpers import unpack, get_all_expr_ids, pack, evaluate_expression

logger = logging.getLogger(__name__)


class ReducedValueSetAnalyzer:
    """
    Reduced Value Set Analyzer for ROP chain analysis
    """

    def __init__(
            self,
            loader: cle.Loader,
            rsp,
            rip,
            base: int,
            chain: List[int],
    ):
        self.loader = loader
        self.base = base
        self.rop_chain = chain
        self.rsp = rsp
        self.rip = rip

        self.symbol_str = 'value_set'
        self.symbol_num = 0
        self.value_set_symbols: List[ExprId] = []

        self.symbol2instr = {}
        self.instr2symbol = {}
        self.symbol2state = {}

        self.symbol2expr = {}

        self.constraints = ConstraintManager(self.base)

    def get_add_terms(self, expr):
        if isinstance(expr, ExprOp) and expr.op == '+':
            terms = []
            for arg in expr.args:
                terms.extend(self.get_add_terms(arg))
            return terms
        return [expr]

    def identify_tabel_query(self, expr: ExprOp):
        terms = self.get_add_terms(expr)

        base_reg: Optional[ExprId] = None
        index_reg: Optional[ExprId] = None
        scale_val: int = 1
        disp_val: int = 0

        for term in terms:
            if isinstance(term, ExprOp) and term.op == '*':
                args = term.args
                if len(args) == 2:
                    op1, op2 = args[0], args[1]

                    if isinstance(op1, ExprInt) and isinstance(op2, ExprId):
                        scale_val = int(op1)
                        index_reg = op2
                    elif isinstance(op2, ExprInt) and isinstance(op1, ExprId):
                        scale_val = int(op2)
                        index_reg = op1

            elif isinstance(term, ExprId):
                if base_reg is None:
                    base_reg = term

            elif isinstance(term, ExprInt):
                disp_val += int(term)

        if index_reg and base_reg and scale_val:
            return {
                'base': base_reg,
                'index': index_reg,
                'scale': scale_val,
                'disp': disp_val
            }
        return False

    def check_vsa_symbol(self, expr: Any) -> bool:
        """Check if expression contains a VSA symbol"""
        # Convert to string is a quick check, but visiting is safer.
        # Using string as per original snippet for performance.
        return self.symbol_str in str(expr)

    def get_new_symbol(self, expr, size, state):
        symbol = ExprId(f'{self.symbol_str}_{self.symbol_num}', size)
        self.symbol_num += 1
        self.value_set_symbols.append(symbol)
        self.symbol2expr[symbol] = expr
        self.symbol2state[symbol] = state
        return symbol

    def get_symbol(self, expr):
        for i in get_all_expr_ids(expr):
            if isinstance(i, ExprId) and self.symbol_str in str(i):
                return i
        return None

    def _get_rip_from_chain(self, rsp, size):
        # Unaligned access
        if rsp % (size // 8) != 0:
            unpack_chain = b''
            for b in self.rop_chain:
                unpack_chain += pack(b, size)
            data = unpack(unpack_chain[rsp:rsp + size // 8], size)

        # Within ROP chain bounds
        elif rsp // (size // 8) < len(self.rop_chain):
            data = self.rop_chain[rsp // (size // 8) - 1]

        # Switch case overflow - return last address
        else:
            data = self.rop_chain[-1]

        return data

    def analysis(self, state: SymbolMngr, constraint: Constraint) -> Optional[List[int]]:
        right = constraint.right
        if isinstance(right, ExprInt):
            bound = int(right)
        elif isinstance(right, ExprId):
            resolved = evaluate_expression(right, state)
            if resolved is not None:
                bound = resolved
            else:
                logger.warning(f"Cannot resolve constraint RHS to concrete value: {right}")
                return None
        else:
            logger.warning(f"Unsupported constraint RHS type: {type(right)}")
            return None

        values: Optional[List[int]] = None

        if constraint.signed:
            # Signed comparison: interpret bound as signed value
            half = 1 << (self.base - 1)
            if bound >= half:
                bound = bound - (1 << self.base)

            if constraint.op == ConstraintOp.EQ:
                # index == bound
                values = [bound]

            elif constraint.op == ConstraintOp.NE:
                # index != bound — not useful for enumeration
                logger.warning("NE constraint cannot produce bounded value set")
                return None

            elif constraint.op == ConstraintOp.LT:
                # index < bound (signed), assume index >= 0
                if bound <= 0:
                    return None
                values = list(range(0, bound))

            elif constraint.op == ConstraintOp.LE:
                # index <= bound (signed), assume index >= 0
                if bound < 0:
                    return None
                values = list(range(0, bound + 1))

            elif constraint.op == ConstraintOp.GE:
                logger.warning("GE constraint cannot produce bounded value set")
                return None

            elif constraint.op == ConstraintOp.GT:
                logger.warning("GT constraint cannot produce bounded value set")
                return None

        else:
            # Unsigned comparison
            if constraint.op == ConstraintOp.EQ:
                # index == bound
                values = [bound]

            elif constraint.op == ConstraintOp.NE:
                logger.warning("NE constraint cannot produce bounded value set")
                return None

            elif constraint.op == ConstraintOp.LT:
                # index < bound (unsigned)
                if bound == 0:
                    return None
                values = list(range(0, bound))

            elif constraint.op == ConstraintOp.LE:
                # index <= bound (unsigned)
                values = list(range(0, bound + 1))

            elif constraint.op == ConstraintOp.GE:
                logger.warning("GE constraint cannot produce bounded value set")
                return None

            elif constraint.op == ConstraintOp.GT:
                logger.warning("GT constraint cannot produce bounded value set")
                return None

        if values is None:
            return None

        logger.debug(f"RVSA analysis result: {constraint} -> {len(values)} values")
        return values if values else None

    def execute(self, expr: Any, curr_state: SymbolMngr):
        symbol_sp = ExprId(self.rsp, self.base)
        symbol_ip = ExprId(self.rip, self.base)

        symbol = self.get_symbol(expr)
        vsa_expr = self.symbol2expr[symbol]
        state = self.symbol2state[symbol]

        query = self.identify_tabel_query(vsa_expr)
        # Indirect branch handler
        # Query: base + index * scale + disp(0)
        #        RCX  + RDX   * 0x4   + 0
        #  e.g.  MOVSXD RAX, DWORD PTR [RCX + RDX * 0x4]
        if query:
            # No proper constraint
            constraint = self.constraints[X86_CAP_REGS_MAP[query['index'].name]]
            if not constraint:
                if isinstance(state[query['base']], ExprInt) and isinstance(state[query['index']], ExprInt):
                    address = state[query['base']].arg + query['scale'] * state[query['index']].arg + query['disp']
                    data = unpack(self.loader.memory.load(address, query['scale']), query['scale'] * 8)
                    return [(ExprInt(data, self.base), curr_state[symbol_sp])]
                else:
                    raise ValueError("Failed to context parser.")

            # Get proper constraint
            value_set = self.analysis(state, constraint)
            if not value_set:
                raise ValueError("Failed to value set analysis.")

            result = []
            for i in value_set:
                address = state[query['base']].arg + query['scale'] * i + query['disp']
                data = unpack(self.loader.memory.load(address, query['scale']), query['scale'] * 8)
                result.append(data)

            result_expr = []
            for res in result:
                new_expr = deepcopy(expr)

                env = {symbol: ExprInt(res, symbol.size)}

                for i in new_expr.get_r():
                    if isinstance(i, ExprMem):
                        ptr = i.ptr.replace_expr(env)
                        ptr = expr_simp(ptr)
                        value = unpack(self.loader.memory.load(ptr.arg & 0xffffffff, i.size // 8), i.size)
                        env1 = {i: ExprInt(value, i.size)}
                        new_expr = new_expr.replace_expr(env1)

                expr_sp = expr_simp(new_expr)
                expr_ip = ExprInt(self._get_rip_from_chain(expr_sp.arg, self.base), self.base)
                result_expr.append((expr_ip, expr_sp))

            return result_expr
        return None

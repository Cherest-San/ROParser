"""
Utility functions module
Provides various auxiliary functions required by the framework
"""

import struct
import itertools
from typing import Tuple, Optional, List, Dict, Set, Any
import cle
from miasm.expression.expression import (
    ExprId, ExprMem, ExprInt, ExprOp, ExprCompose, ExprSlice
)
from miasm.ir.symbexec import SymbolMngr
from miasm.core.asmblock import LocKey, AsmCFG
from miasm.ir.ir import IRCFG

from .constants import X86_32_REGS, X86_64_REGS


# ==================== Data packing/unpacking ====================

def pack(value: int, size: int) -> bytes:
    """
    Pack integer value into byte sequence

    Args:
        value: Integer value to pack
        size: Bit width (8, 16, 32, 64)

    Returns:
        Packed byte sequence
    """
    if size == 8:
        return struct.pack('<B', value)
    elif size == 16:
        return struct.pack('<H', value)
    elif size == 32:
        return struct.pack('<I', value)
    elif size == 64:
        return struct.pack('<Q', value)
    else:
        raise ValueError(f"Unsupported size: {size}")


def unpack(data: bytes, size: int) -> int:
    """
    Unpack integer value from byte sequence

    Args:
        data: Byte sequence
        size: Bit width (8, 16, 32, 64)

    Returns:
        Unpacked integer value
    """
    if size == 8:
        return struct.unpack('<B', data)[0]
    elif size == 16:
        return struct.unpack('<H', data)[0]
    elif size == 32:
        return struct.unpack('<I', data)[0]
    elif size == 64:
        return struct.unpack('<Q', data)[0]
    else:
        raise ValueError(f"Unsupported size: {size}")


# ==================== Address and memory operations ====================

def describe_address(memory: cle.memory.Clemory, address: int) -> bool:
    """
    Check if address is in memory mapping

    Args:
        memory: CLE memory object
        address: Address to check

    Returns:
        True if address is valid, False otherwise
    """
    for begin, value in memory.backers():
        if isinstance(value, (bytearray, list)):
            if begin <= address < begin + len(value):
                return True
        elif isinstance(value, cle.memory.Clemory):
            if describe_address(value, address):
                return True
    return False


def get_backer_id(memory: cle.memory.Clemory, address: int) -> Optional[int]:
    """
    Return the top-level memory backer start address for a given address.

    Used for module-level grouping of gadgets by their memory region.

    Args:
        memory: CLE memory object
        address: Address to locate

    Returns:
        Backer start address if found, None otherwise
    """
    for begin, value in memory.backers():
        if isinstance(value, (bytearray, list)):
            if begin <= address < begin + len(value):
                return begin
        elif isinstance(value, cle.memory.Clemory):
            if begin <= address < begin + sum(
                len(v) if isinstance(v, (bytearray, list)) else 0
                for _, v in value.backers()
            ):
                return begin
    return None


def is_valid_rop_address(
        address: int,
        memory: cle.memory.Clemory,
        stack_address: int
) -> bool:
    """
    Check if address is a valid ROP gadget address

    Args:
        address: Address to check
        memory: CLE memory object
        stack_address: Stack address (for exclusion)

    Returns:
        True if address is valid
    """
    if address == stack_address:
        return False
    return describe_address(memory, address)


# ==================== Register operations ====================

def get_register_value(
        state: Dict[ExprId, Any],
        register_name: str,
        base: int = 64
) -> int:
    """
    Get register value from state

    Args:
        state: Symbolic execution state dictionary
        register_name: Register name
        base: Architecture bit width (32 or 64)

    Returns:
        Integer value of register

    Raises:
        ValueError: If register not found or value is invalid
    """
    register_expr = ExprId(register_name, base)

    if register_expr not in state:
        raise ValueError(f"Register {register_name} not found in state")

    value = state[register_expr]

    if isinstance(value, ExprInt):
        return value.arg
    elif isinstance(value, ExprId):
        return value  # Return symbolic expression itself
    else:
        raise ValueError(f"Invalid register value type: {type(value)}")


def compute_rsp_offset(
        current_rsp: int,
        target_rsp: int,
        base: int
) -> int:
    """
    Calculate RSP offset

    Args:
        current_rsp: Current RSP value
        target_rsp: Target RSP value
        base: Architecture bit width

    Returns:
        RSP offset (in bytes)
    """
    return target_rsp - current_rsp


# ==================== Expression evaluation ====================

def evaluate_expression_operation(operation: ExprOp, state: SymbolMngr) -> Optional[int]:
    """
    Recursively evaluate expression operation value

    Args:
        operation: Expression operation object
        state: Symbolic execution state

    Returns:
        Calculation result, None if unable to calculate
    """
    evaluated_args: List[int] = []

    for arg in operation.args:
        result = evaluate_expression(arg, state)
        if result is None or result == 'None':
            return None
        evaluated_args.append(result)

    if None in evaluated_args:
        return None

    op_type = operation.op

    if op_type == '+':
        return sum(evaluated_args)
    elif op_type == '-':
        if len(evaluated_args) == 1:
            return -evaluated_args[0]
        return evaluated_args[0] - evaluated_args[1]
    elif op_type == '*':
        product = 1
        for num in evaluated_args:
            product *= num
        return product
    elif op_type == '<<':
        return evaluated_args[0] << evaluated_args[1]
    elif op_type == '>>':
        return evaluated_args[0] >> evaluated_args[1]
    elif op_type == '&':
        return evaluated_args[0] & evaluated_args[1]
    elif op_type == '|':
        return evaluated_args[0] | evaluated_args[1]
    elif op_type == '^':
        return evaluated_args[0] ^ evaluated_args[1]
    else:
        raise ValueError(f"Unsupported operation: {op_type}")


def evaluate_expression_compose(compose: ExprCompose, state: SymbolMngr) -> int:
    """
    Evaluate compose expression value

    Args:
        compose: Compose expression
        state: Symbolic execution state

    Returns:
        Composed integer value
    """
    value = 0
    bit_offset = 0

    for arg in compose.args:
        if isinstance(arg, ExprInt):
            arg_value = arg.arg
        elif isinstance(arg, ExprId):
            if arg not in state or not isinstance(state[arg], ExprInt):
                raise ValueError("Cannot compose non-integer expression")
            arg_value = state[arg].arg
        elif isinstance(arg, ExprOp):
            arg_value = evaluate_expression_operation(arg, state)
            if arg_value is None:
                raise ValueError("Cannot evaluate operation in compose")
        else:
            raise ValueError(f"Unsupported compose argument type: {type(arg)}")

        value |= arg_value << bit_offset
        bit_offset += arg.size

    return value


def evaluate_expression_slice(slice_expr: ExprSlice, state: SymbolMngr) -> int:
    """
    Evaluate slice expression value

    Args:
        slice_expr: Slice expression
        state: Symbolic execution state

    Returns:
        Sliced integer value
    """
    expr = slice_expr.arg
    start = slice_expr.start
    stop = slice_expr.stop

    if expr in state:
        value = state[expr]
    elif isinstance(expr, ExprOp):
        value = evaluate_expression_operation(expr, state)
        if value is None:
            raise ValueError("Cannot evaluate operation in slice")
    else:
        raise ValueError(f"Expression not found: {expr}")

    if isinstance(value, ExprInt):
        full_value = value.arg
    elif isinstance(value, int):
        full_value = value
    else:
        raise ValueError(f"Invalid value type for slice: {type(value)}")

    mask = (1 << (stop - start)) - 1
    sliced_value = (full_value >> start) & mask
    return sliced_value


def evaluate_expression(expression: Any, state: SymbolMngr) -> Optional[int]:
    """
    Evaluate expression value

    Args:
        expression: Expression to evaluate
        state: Symbolic execution state

    Returns:
        Integer value of expression, None if unable to calculate
    """
    if isinstance(expression, ExprInt):
        return expression.arg

    if isinstance(expression, ExprId):
        if expression not in state:
            return None

        value = state[expression]
        if isinstance(value, ExprInt):
            return value.arg
        return None

    if isinstance(expression, ExprCompose):
        try:
            return evaluate_expression_compose(expression, state)
        except (ValueError, KeyError):
            return None

    if isinstance(expression, ExprOp):
        return evaluate_expression_operation(expression, state)

    if isinstance(expression, ExprSlice):
        try:
            return evaluate_expression_slice(expression, state)
        except (ValueError, KeyError):
            return None

    return None


def evaluate_branch_expression(
        expression: Any,
        state: SymbolMngr
) -> Set[int]:
    """
    Evaluate branch expression, return set of all possible values

    Args:
        expression: Branch expression
        state: Symbolic execution state

    Returns:
        Set of all possible values
    """
    # Extract symbolic flags (e.g., CF)
    symbols = {
        ExprId('cf', 1): [
            ExprInt(0, 1),
            ExprInt(1, 1)
        ]
    }

    symbol_keys = list(symbols.keys())
    symbol_values = [symbols[key] for key in symbol_keys]
    symbol_product = itertools.product(*symbol_values)

    results: Set[int] = set()

    for combo in symbol_product:
        # Create temporary state
        temp_state = dict(state)
        symbol_dict = {symbol_keys[i]: combo[i] for i in range(len(symbol_keys))}
        temp_state.update(symbol_dict)

        result = evaluate_expression(expression, temp_state)
        if result is not None:
            results.add(result)

    return results


# ==================== IRCFG traversal ====================

def ircfg_dfs_traversal(ircfg: IRCFG, head: LocKey) -> List[List[LocKey]]:
    """
    Perform depth-first search traversal on IRCFG

    Args:
        ircfg: Intermediate representation control flow graph
        head: Starting node

    Returns:
        List of all paths, each path is a list of LocKeys
    """
    paths: List[List[LocKey]] = []
    edges = list(ircfg.edges())
    stack: List[Tuple[LocKey, List[LocKey]]] = [(head, [head])]

    # Find all predecessor nodes
    fronts = {edge[0] for edge in edges}

    # Find all tail nodes (nodes without successors)
    tails = [node for node in ircfg.nodes() if node not in fronts]

    while stack:
        vertex, path = stack.pop()

        if vertex in tails:
            paths.append(path)

        for edge in edges:
            if edge[0] == vertex:
                stack.append((edge[1], path + [edge[1]]))

    return paths


# ==================== Expression tracing ====================

def trace_identifiers_from_memory(
        expression: Any,
        result: Optional[List[ExprId]] = None
) -> List[ExprId]:
    """
    Trace all identifiers from memory expression

    Args:
        expression: Expression to trace
        result: Result list (for recursive use)

    Returns:
        List of all found identifiers
    """
    if result is None:
        result = []

    if isinstance(expression, ExprMem):
        trace_identifiers_from_memory(expression.ptr, result)

    if isinstance(expression, ExprOp):
        for arg in expression.args:
            trace_identifiers_from_memory(arg, result)

    if isinstance(expression, ExprId):
        result.append(expression)

    return result


# ==================== Sequence difference analysis ====================

def diff_sequence(
        sequence1: List[Any],
        sequence2: List[Any]
) -> Dict[Any, List[Any]]:
    """
    Calculate difference between two sequences

    Args:
        sequence1: First sequence
        sequence2: Second sequence

    Returns:
        Difference dictionary, key is address, value is index pair
    """
    similarities: List[Tuple[int, int]] = []

    for i, item1 in enumerate(sequence1):
        for j, item2 in enumerate(sequence2):
            if item1 == item2:
                similarities.append((i, j))

    result: Dict[Any, List[Any]] = {}

    for idx in range(len(similarities) - 1):
        if (similarities[idx + 1][0] == similarities[idx][0] + 1 and
                similarities[idx + 1][1] == similarities[idx][1] + 1):
            continue

        address = sequence1[similarities[idx][0]]
        result[address] = [similarities[idx][0], similarities[idx][1]]

    if similarities:
        last_idx = len(similarities) - 1
        if (similarities[last_idx][0] + 1 < len(sequence1) and
                similarities[last_idx][1] + 1 < len(sequence2)):
            address = sequence1[similarities[last_idx][0]]
            result[address] = [
                similarities[last_idx][0],
                similarities[last_idx][1]
            ]

    # Convert indices to actual values
    for address in result:
        indices = result[address]
        result[address] = [sequence1[indices[0]], sequence2[indices[1]]]

    return result


def get_all_expr_ids(expr) -> Set[ExprId]:
    """
    Recursively extract all ExprId instances from a Miasm expression.

    Handles deeply nested structures including ExprMem, ExprCond, ExprOp,
    and ExprSlice. For ExprMem (e.g., @32[RDI + 0x4]), the function
    penetrates the memory read and recurses into the pointer (.ptr) to
    extract registers or symbols involved in the address calculation.

    Args:
        expr: Miasm expression object (ExprOp, ExprId, ExprMem, etc.)

    Returns:
        Set[ExprId]: Set of all ExprId instances found in the expression
    """
    ids: Set[ExprId] = set()

    def visitor(e):
        if isinstance(e, ExprId):
            ids.add(e)

        return e

    if isinstance(expr, ExprId):
        ids.add(expr)
        return ids

    if hasattr(expr, 'visit'):
        expr.visit(visitor)

    return ids


# ==================== ADC delayed branch helpers ====================

def has_preset_flags(asmcfg, trigger_instr='ADC'):
    """
    Detect whether a flag-setting instruction precedes ADC/SBB in a gadget.

    If a flag setter is found before the trigger instruction, CF is determined
    within this gadget and no branch fork is needed. If not, CF comes from a
    previous gadget and a fork is required.

    Args:
        asmcfg: Assembly CFG
        trigger_instr: The instruction name to check against ('ADC' or 'SBB')

    Returns:
        True if a flag setter precedes the trigger instruction (CF is locally determined)
        False if no flag setter precedes it (CF comes from a prior gadget, fork needed)
    """
    flag_setters = {
        'CMP', 'TEST', 'ADD', 'SUB', 'SBB', 'ADC',
        'OR', 'AND', 'XOR', 'INC', 'DEC', 'NEG',
        'SHL', 'SHR', 'SAR', 'ROL', 'ROR', 'RCL', 'RCR'
    }
    asm_block = list(asmcfg.blocks)[0]
    for line in asm_block.lines:
        if trigger_instr in line.name:
            return False  # Trigger instruction found with no prior flag setter
        if line.name in flag_setters:
            return True   # Flag setter found before the trigger instruction
    return False


def is_conditional_branch(
        asmcfg: AsmCFG,
):
    """
    Detect if gadget contains conditional instructions

    Args:
        asmcfg: Assembly CFG to analyze

    Returns:
        True if conditional instructions (CMOV, SET, ADC) are present
    """
    asm = list(asmcfg.blocks)[0]
    conditional_instrs = ['CMOV', 'SET', 'ADC']

    for line in asm.lines:
        for instr in conditional_instrs:
            if instr in str(line):
                return line

    return None

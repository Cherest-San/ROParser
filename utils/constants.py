"""
Constants definition module
Defines all constants used in the framework
"""

import os

# ==================== Architecture-related constants ====================
GADGETS_MAX_LEN = 0x20
CLUSTER_THRESHOLD = 0x10000
DEFAULT_CHAIN_END_OFFSET = 0x3000
DOMINANCE_THRESHOLD = 0.8  # Adaptive cluster selection: if largest cluster exceeds this ratio, keep only it

# ==================== Register definitions ====================
X86_32_REGS = ['EIP', 'EBP', 'ESP', 'EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI']
X86_64_REGS = [
    'RIP', 'RBP', 'RSP', 'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI',
    'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15'
]

# ==================== LSE (Localized Symbolic Execution) constants ====================
# Maximum symbolic execution depth
LSE_MAX_SYMBOLIC_DEPTH = 10

# RSP relevance threshold (for judging if symbolic value is related to RSP update)
LSE_RSP_RELEVANT_THRESHOLD = 0.8

# Opaque encoding candidate value set size
LSE_OPAQUE_CANDIDATE_SET_SIZE = 10

# Maximum iterations for stage 1 execution
LSE_STAGE1_MAX_ITERATIONS = 1000

# RSP value consistency check threshold
LSE_RSP_CONSISTENCY_THRESHOLD = 0.95

# ==================== LSE Stage 2 constants ====================
# Maximum backward slice depth
STAGE2_MAX_SLICE_DEPTH = 10

# Maximum re-execution iterations
STAGE2_MAX_REEXEC_ITERATIONS = 100

# ==================== RVSA (Reduced Value-Set Analysis) constants ====================
# Maximum number of candidate values
RVSA_MAX_CANDIDATE_VALUES = 100

# Constraint solving timeout (seconds)
RVSA_CONSTRAINT_TIMEOUT = 5.0

# Interval analysis precision (bits)
RVSA_INTERVAL_PRECISION = 8

# Branch exploration maximum depth
RVSA_BRANCH_EXPLORATION_DEPTH = 5

# ==================== Control flow constraints ====================
CONSTRAINT_NEXT = 'c_next'  # Sequential execution
CONSTRAINT_TO = 'c_to'  # Jump execution


# ==================== State type enumeration ====================
class StateType:
    """Symbolic execution state types"""
    CONCRETE = 'concrete'  # Concrete value
    SYMBOLIC = 'symbolic'  # Symbolic value
    MIXED = 'mixed'  # Mixed state
    INVALID = 'invalid'  # Invalid state


# ==================== Threat type enumeration ====================
class ThreatType:
    """ROP obfuscation threat types (corresponding to T1-T5 in the paper)"""
    T1_OPAQUE_BRANCH_HIDING = 'T1'  # Opaque branch hiding
    T2_STATE_EXPLOSION = 'T2'  # State explosion
    T3_ANTI_BRUTEFORCE = 'T3'  # Anti-bruteforce
    T4_GADGET_CONFUSION = 'T4'  # Gadget confusion
    T5_INDIRECT_BRANCH = 'T5'  # Indirect branch


# ==================== Execution stage enumeration ====================
class ExecutionStage:
    """LSE two-stage execution strategy"""
    STAGE1_NO_PRUNING = 'stage1'  # Stage 1: No-pruning execution
    STAGE2_RSP_PRUNING = 'stage2'  # Stage 2: RSP-relevant pruning


# ==================== Address pair types ====================
# ROP address pair: <RSP, RIP>
AddressPair = tuple[int, int]  # (RIP address, RSP offset)


# ==================== LLM API configuration ====================


def _get_env_value(*names, default=None):
    """Return the first non-empty environment variable value."""
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


# LLM API configuration from environment variables
API_KEY = _get_env_value('DEEPSEEK_API_KEY', 'ROPARSER_API_KEY')
BASE_URL = _get_env_value('DEEPSEEK_URL', 'ROPARSER_BASE_URL', default="https://api.deepseek.com/v1")
MODEL_ID = _get_env_value('ROPARSER_MODEL_ID', default="deepseek-chat")
PROMPT_PATH = _get_env_value('ROPARSER_PROMPT_PATH')

# Global LLM configuration dictionary
LLM_CONFIG = {
    'api_key': API_KEY,
    'base_url': BASE_URL,
    'model_id': MODEL_ID,
    'prompt_path': PROMPT_PATH,
}

# ==================== Capstone register mapping ====================
X86_CAP_REGS_MAP = {
    'RAX': 19, 'EAX': 19, 'AX': 19, 'AL': 19, 'AH': 19,
    'RBX': 21, 'EBX': 21, 'BX': 21, 'BL': 21, 'BH': 21,
    'RCX': 22, 'ECX': 22, 'CX': 22, 'CL': 22, 'CH': 22,
    'RDX': 24, 'EDX': 24, 'DX': 24, 'DL': 24, 'DH': 24,
    'RDI': 23, 'EDI': 23, 'DI': 23, 'DIL': 23,
    'RSI': 29, 'ESI': 29, 'SI': 29, 'SIL': 29,
    'RIP': 26, 'EIP': 26, 'RBP': 20, 'EBP': 20, 'RSP': 30, 'ESP': 30,
    'R8': 106, 'R9': 107, 'R10': 108, 'R11': 109,
    'R12': 110, 'R13': 111, 'R14': 112, 'R15': 113,
    'R8B': 106, 'R9B': 107, 'R10B': 108, 'R11B': 109,
    'R12B': 110, 'R13B': 111, 'R14B': 112, 'R15B': 113,
    'R8D': 106, 'R9D': 107, 'R10D': 108, 'R11D': 109,
    'R12D': 110, 'R13D': 111, 'R14D': 112, 'R15D': 113,
    'FS': 32, 'CS': 11
}
X86_CAP_ALIGN_MAP = {
    35: 19, 19: 19, 3: 19, 2: 19, 1: 19,  # EAX
    37: 21, 21: 21, 8: 21, 5: 21, 4: 21,  # EBX
    38: 22, 22: 22, 12: 22, 10: 22, 9: 22,  # ECX
    40: 24, 24: 24, 18: 24, 16: 24, 13: 24,  # EDX
    39: 23, 23: 23, 14: 23, 15: 23,  # EDI
    43: 29, 29: 29, 45: 29, 46: 29,  # ESI
    41: 26, 26: 26, 36: 20, 20: 20, 44: 30, 30: 30,  # EIP EBP ESP
    106: 106, 218: 106, 226: 106,  # R8
    107: 107, 219: 107, 227: 107,  # R9
    108: 108, 220: 108, 228: 108,  # R10
    109: 109, 221: 109, 229: 109,  # R11
    110: 110, 222: 110, 230: 110,  # R12
    111: 111, 223: 111, 231: 111,  # R13
    112: 112, 224: 112, 232: 112,  # R14
    113: 113, 225: 113, 233: 113,  # R15
    32: 32, 11: 11  # FS
}

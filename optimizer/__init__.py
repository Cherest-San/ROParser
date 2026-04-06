"""Optimizer module"""

from .stack_recovery import StackOperationRecovery
from .liveness_analysis import LivenessAnalyzer
from .constant_propagation import ConstantPropagator
from .block_elimination import SemanticBlockEliminator
from .optimizer import Optimizer

__all__ = [
    'StackOperationRecovery',
    'LivenessAnalyzer',
    'ConstantPropagator',
    'SemanticBlockEliminator',
    'Optimizer',
]

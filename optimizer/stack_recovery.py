"""
Custom Stack Operation Instruction Recovery
Custom stack operation instruction recovery module

Uses deterministic preprocessing and LLM batching to recover custom stack operations
"""

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from miasm.analysis.binary import Container
from capstone import *
from keystone import *
from openai import OpenAI
from miasm.analysis.machine import Machine
from miasm.arch.x86.arch import instruction_x86
from miasm.core.asmblock import AsmBlock, AsmCFG
from miasm.core.locationdb import LocationDB
from miasm.expression.expression import ExprId, ExprInt, ExprMem

from .code_slicing import CodeSlicer
from utils.constants import (
    API_KEY,
    BASE_URL,
    CONSTRAINT_NEXT,
    CONSTRAINT_TO,
    MODEL_ID,
    PROMPT_PATH, X86_CAP_REGS_MAP, X86_64_REGS, X86_32_REGS,
)

logger = logging.getLogger(__name__)


@dataclass
class ReplacementSpan:
    block: AsmBlock
    start_index: int
    end_index: int
    instructions: List[instruction_x86] | None
    description: str


@dataclass
class SequenceCandidate:
    candidate_id: str
    block: AsmBlock
    start_index: int
    end_index: int
    instructions: List[instruction_x86]


class StackOperationRecovery:
    """
    Stack operation instruction recovery

    Uses deterministic preprocessing first, then batches the remaining candidates for LLM recovery.
    """

    _JCC_INVERSE_MAP = {"AE": "B", "A": "BE", "BE": "A", "B": "AE", "E": "NE", "Z": "NE", "GE": "L", "G": "LE",
                        "LE": "G", "L": "GE", "NE": "E", "NZ": "E", "NO": "O", "NP": "P", "NS": "S", "O": "NO",
                        "P": "NP", "S": "NS"}

    def __init__(
            self,
            loc_db: LocationDB,
            machine: Machine,
            api_key: Optional[str] = None,
            base_url: Optional[str] = None,
            model_id: Optional[str] = None,
            prompt_path: Optional[str] = None,
            stack_address: Optional[int] = None,
            max_retries: int = 3,
            parallel_workers: int = 4,
            llm_batch_char_limit: int = 6000,
            base: int = 32
    ):
        """
        Initialize stack operation recovery

        Args:
            api_key: LLM API key
            base_url: API base URL
            model_id: Model ID
            prompt_path: Prompt file path
            stack_address: Known custom stack anchor address
            max_retries: Maximum retry count
            parallel_workers: Reserved for future use
            llm_batch_char_limit: Maximum user prompt size per LLM batch
        """
        self.api_key = api_key or API_KEY
        self.base_url = base_url or BASE_URL
        self.model_id = model_id or MODEL_ID
        self.prompt_path = prompt_path or PROMPT_PATH
        self.stack_address = stack_address
        self.max_retries = max_retries
        self.parallel_workers = parallel_workers
        self.llm_batch_char_limit = llm_batch_char_limit
        self.client: Optional[OpenAI] = None

        self.system_prompt = self._load_prompt(self.prompt_path)
        self.code_slicer = CodeSlicer(delta=1, max_sequence_length=50)

        self.machine = machine
        self.loc_db = loc_db

        if base == 32:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
            self.ip = X86_32_REGS[0]
            self.sp = X86_32_REGS[2]
        else:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
            self.ip = X86_64_REGS[0]
            self.sp = X86_64_REGS[2]

        self.cs.detail = True

    def _get_client(self) -> OpenAI:
        """Get or create the OpenAI-compatible client lazily."""
        if self.client is None:
            self.client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
            )
        return self.client

    def _create_completion(
            self,
            messages: List[Dict[str, str]],
            temperature: float = 0.0
    ):
        """
        Send a chat completion request to the LLM.

        Args:
            messages: Chat message list (system + user roles)
            temperature: Sampling temperature (0.0 = deterministic)

        Returns:
            OpenAI-compatible completion response object
        """
        client = self._get_client()
        return client.chat.completions.create(
            model=self.model_id,
            messages=messages,
            temperature=temperature,
        )

    def _load_prompt(self, prompt_path: Optional[str]) -> str:
        """
        Load system prompt

        Args:
            prompt_path: Prompt file path

        Returns:
            Prompt content
        """
        if prompt_path:
            try:
                with open(prompt_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"Failed to load prompt from {prompt_path}: {e}")

        return """### Assembly Deobfuscation Expert

**Task**: Convert ROP-obfuscated stack instructions to standard x86 instructions

**Core Rules**:

1. Each obfuscated blocks (multiple instructions) → Output deobfuscated instructions
2. Must use `RSP`, eliminate intermediate registers
3. Preserve immediate values in original format
4. Output non-obfuscated instructions unchanged
5. Unrecognized patterns → `UNKNOWN`
6. Output the results directly without any explanation

**Obfuscation Patterns**:

- Starts with fixed address: `MOV REG, 0x...`
- Memory dereference: `SUB REG, [REG]`
- Stack operation: `[REG]` or `[REG+OFFSET]`

**Examples**:

```assembly
# RSP adjustment
Input: MOV R11,0x21E1FF0; SUB R11,[R11]; SUB [R11],0x20
Output: SUB RSP, 0x20

# PUSH operation
Input: MOV R8,0x55AAFF0; SUB R8,[R8]; SUB [R8],8; MOV R8,[R8]; MOV [R8],R15
Output: PUSH R15

# PUSH IMM operation
Input: MOV R8,0x55AAFF0; SUB R8,[R8]; SUB [R8],8; MOV R8,[R8]; MOV [R8], 0x8
Output: PUSH 0x8

# POP operation
Input: MOV R8,0x55AAFF0; SUB R8,[R8]; ADD [R8],8; MOV R8,[R8]; SUB R8,8; MOV R15,[R8]
Output: POP R15

# RET operation
Input: MOV R8,0x55AAFF0; SUB [R8],8; SUB R8,[R8]; SUB R8,8; MOV RSP,[R8]
Output: RET

# Memory store
Input: MOV R13,0x2277FF0; SUB R13,[R13]; MOV R13,[R13]; MOV [R13+0x48],RAX
Output: MOV [RSP+0x48], RAX

# Non-obfuscated
Input: LEA RSI,[RIP+0x200]
Output: LEA RSI,[RIP+0x200]
```

**Begin deobfuscation**:
Input:

```
{User instructions}
-----
{User instructions}
```

Output:

```
{Deobfuscated instructions}
-----
{Deobfuscated instructions}
```
"""

    def test_connection(self) -> Dict[str, Optional[str]]:
        """
        Validate normalized LLM configuration and perform one minimal request.

        Returns:
            A dictionary with success flag and diagnostic information.
        """
        if not self.api_key:
            return {
                'success': False,
                'message': 'Missing API key. Please set DEEPSEEK_API_KEY or ROPARSER_API_KEY.',
                'base_url': self.base_url,
                'model_id': self.model_id,
                'response': None,
            }

        if not self.base_url:
            return {
                'success': False,
                'message': 'Missing base URL. Please set DEEPSEEK_URL or ROPARSER_BASE_URL.',
                'base_url': self.base_url,
                'model_id': self.model_id,
                'response': None,
            }

        if not self.model_id:
            return {
                'success': False,
                'message': 'Missing model ID. Please set ROPARSER_MODEL_ID.',
                'base_url': self.base_url,
                'model_id': self.model_id,
                'response': None,
            }

        logger.info(
            f"Testing LLM connectivity with base_url={self.base_url}, model_id={self.model_id}"
        )

        try:
            completion = self._create_completion(
                messages=[
                    {
                        'role': 'system',
                        'content': 'You are a connectivity test assistant. Reply with exactly: OK'
                    },
                    {
                        'role': 'user',
                        'content': 'Return OK.'
                    },
                ]
            )
        except Exception as e:
            error_message = str(e)
            lowered = error_message.lower()

            if '401' in lowered or 'unauthorized' in lowered or 'authentication' in lowered:
                diagnosis = f'Authentication failed: {error_message}'
            elif '403' in lowered or 'forbidden' in lowered:
                diagnosis = f'Access forbidden: {error_message}'
            elif '404' in lowered:
                diagnosis = f'Endpoint not found, please verify base URL: {error_message}'
            elif 'connection' in lowered or 'timeout' in lowered or 'network' in lowered:
                diagnosis = f'Network error: {error_message}'
            else:
                diagnosis = f'LLM request failed: {error_message}'

            return {
                'success': False,
                'message': diagnosis,
                'base_url': self.base_url,
                'model_id': self.model_id,
                'response': None,
            }

        response = None
        if completion.choices:
            response = completion.choices[0].message.content
            if response is not None:
                response = response.strip()

        if not response:
            return {
                'success': False,
                'message': 'LLM response is empty.',
                'base_url': self.base_url,
                'model_id': self.model_id,
                'response': None,
            }

        return {
            'success': True,
            'message': 'LLM connectivity test succeeded.',
            'base_url': self.base_url,
            'model_id': self.model_id,
            'response': response,
        }

    def _collect_block_replacements(
            self,
            block: AsmBlock,
    ) -> List[ReplacementSpan]:
        """
        Scan one basic block and collect candidate replacement spans.

        Identifies custom stack operations (anchored by stack_address immediates),
        CALL/RET patterns, and JCC/JMP patterns from CMOV+ADD sequences.

        Args:
            block: Basic block to scan

        Returns:
            List of ReplacementSpan objects (start_index, end_index, description)
        """
        replacements: List[ReplacementSpan] = []
        occupied: Set[int] = set()

        for index in range(len(block.lines)):
            line = block.lines[index]
            # custom stack operation instructions
            if len(line.args) == 2 and isinstance(line.args[1], ExprInt) and self.stack_address == line.args[1].arg:
                ind = index
                for ind in range(index, index + 10):
                    if ind + 1 >= len(block.lines):
                        break

                    line_prev = block.lines[ind]
                    line_next = block.lines[ind + 1]
                    if not line_prev.b or not line_next.b:
                        break

                    inst_prev = next(self.cs.disasm(line_prev.b, 0), None)
                    _, _def_prev = inst_prev.regs_access()
                    inst_next = next(self.cs.disasm(line_next.b, 0), None)
                    _use_next, _ = inst_next.regs_access()

                    if len(line_prev.args) >= 1 and \
                            isinstance(line_prev.args[0], ExprMem) and \
                            isinstance(line_prev.args[0].arg, ExprId):
                        _def_prev.append(X86_CAP_REGS_MAP[line_prev.args[0].arg.name])
                    if len(line_next.args) >= 1 and \
                            isinstance(line_next.args[1], ExprMem) and \
                            isinstance(line_next.args[1].arg, ExprId):
                        _use_next.append(X86_CAP_REGS_MAP[line_next.args[1].arg.name])

                    if not list(set(_def_prev) & set(_use_next)):
                        break

                replacements.append(ReplacementSpan(
                    block=block,
                    start_index=index,
                    end_index=ind + 1,
                    description='CUSTOM',
                    instructions=None
                ))

            if 'CALL' in line.name:
                line = block.lines[index - 9]
                if not len(line.args) == 2 \
                        and isinstance(line.args[1], ExprInt) \
                        and self.stack_address == line.args[1].arg:
                    continue

                flag = 1
                for replace in replacements:
                    if replace.start_index >= index - 9 and replace.end_index <= index:
                        replace.start_index = index - 9
                        replace.end_index = index + 1
                        replace.description = 'CALL'
                        flag = 0

                if flag:
                    replacements.append(ReplacementSpan(
                        block=block,
                        start_index=index - 9,
                        end_index=index + 1,
                        description='CALL',
                        instructions=None
                    ))

            if 'RET' in line.name:
                line = block.lines[index - 5]
                if not len(line.args) == 2 and isinstance(line.args[1], ExprInt) and self.stack_address == line.args[
                    1].arg:
                    continue
                flag = 1
                for replace in replacements:
                    if replace.start_index >= index - 5 and replace.end_index <= index:
                        replace.start_index = index - 5
                        replace.end_index = index + 1
                        replace.description = 'RET'
                        flag = 0

                if flag:
                    replacements.append(ReplacementSpan(
                        block=block,
                        start_index=index - 5,
                        end_index=index + 1,
                        description='RET',
                        instructions=None
                    ))

            if 'ADD' in line.name and isinstance(line.args[0], ExprId) and line.args[0].name == self.sp:
                line_prev = block.lines[index - 1]
                if 'CMOV' in line_prev.name:
                    replacements.append(ReplacementSpan(
                        block=block,
                        start_index=index - 3,
                        end_index=index + 1,
                        description='JCC',
                        instructions=None
                    ))
                elif line_prev.name == 'MOV' and line_prev.args[0] == line.args[1]:
                    replacements.append(ReplacementSpan(
                        block=block,
                        start_index=index - 1,
                        end_index=index + 1,
                        description='JMP',
                        instructions=None
                    ))

        return replacements

    def _collect_deterministic_replacements(
            self,
            cfg: AsmCFG,
    ) -> Dict[AsmBlock, List[ReplacementSpan]]:
        """
        Collect replacement spans across all blocks in the CFG.

        Args:
            cfg: Control flow graph to scan

        Returns:
            Mapping of block -> list of replacement spans
        """
        replacements_by_block: Dict[AsmBlock, List[ReplacementSpan]] = {}

        for block in list(cfg.blocks):
            replacements = self._collect_block_replacements(block)
            if replacements:
                replacements_by_block[block] = replacements

        return replacements_by_block

    def _apply_replacements(
            self,
            cfg: AsmCFG,
            replacements_by_block: Dict[AsmBlock, List[ReplacementSpan]]
    ) -> AsmCFG:
        """
        Apply all replacement spans to their corresponding blocks.

        For each block, rebuild its instruction list by replacing
        [start_index, end_index) ranges with recovered instructions.
        Processes spans in reverse order to avoid index shifting.

        Args:
            cfg: The control flow graph to modify
            replacements_by_block: Block -> replacement spans mapping

        Returns:
            Modified CFG with deobfuscated instructions
        """
        for block, replacements in replacements_by_block.items():
            replacements.sort(key=lambda r: r.start_index)

            new_lines = list(block.lines)
            for span in reversed(replacements):
                if span.instructions is None:
                    continue
                new_lines[span.start_index:span.end_index] = span.instructions

            block.lines = new_lines

        return cfg

    @staticmethod
    def _parse_llm_response(content: str) -> List[str]:
        """
        Parse LLM response into instruction groups split by '-----'.

        Strips markdown code block wrappers and splits by '-----' separator.

        Args:
            content: Raw LLM response text

        Returns:
            List of instruction group strings
        """
        text = content.strip()
        match = re.match(r'^```(?:[a-zA-Z]*)\s*\n(.*?)\n```\s*$', text, re.DOTALL)
        if match:
            text = match.group(1).strip()

        groups = []
        for group in re.split(r'\s*-----\s*', text):
            stripped = group.strip()
            if stripped:
                groups.append(stripped)
        return groups

    def _display_llm_results(self, groups: List[str]) -> None:
        """
        Display LLM deobfuscation results in '-----' separated format.

        Args:
            groups: Parsed instruction groups from LLM response
        """
        logger.info(f"LLM returned {len(groups)} instruction groups:")
        for i, group in enumerate(groups):
            for line in group.split('\n'):
                logger.debug(line)
            if i < len(groups) - 1:
                logger.debug('-----')

    def _analyse_replace_instructions(self, replace_map: Dict[AsmBlock, List[ReplacementSpan]]):
        """
        Resolve each replacement span to its deobfuscated instruction list.

        Deterministic patterns (CALL, RET, JCC, JMP) are handled locally.
        Remaining CUSTOM spans are batched into a single LLM request.

        Args:
            replace_map: Block -> replacement spans mapping from _collect_deterministic_replacements

        Returns:
            Updated replace_map with span.instructions filled in, or None on LLM failure
        """
        unanalyzed_span: List[ReplacementSpan] = []
        for block, replacements in replace_map.items():
            for replacement in replacements:
                if replacement.description == 'CALL':
                    assert 'CALL' in str(block.lines[replacement.end_index - 1])
                    replacement.instructions = [block.lines[replacement.end_index - 1]]

                elif replacement.description == 'RET':
                    assert 'RET' in str(block.lines[replacement.end_index - 1])
                    replacement.instructions = [block.lines[replacement.end_index - 1]]

                elif replacement.description == 'JCC':
                    assert 'CMOV' in str(block.lines[replacement.end_index - 2])
                    instr = block.lines[replacement.end_index - 2]
                    instr.b = b''
                    instr.name = 'J' + self._JCC_INVERSE_MAP[instr.name.split('CMOV')[1]]
                    instr.args = []
                    replacement.instructions = [instr]
                elif replacement.description == 'JMP':
                    assert 'MOV' in str(block.lines[replacement.end_index - 2])
                    instr = block.lines[replacement.end_index - 2]
                    instr.b = b''
                    instr.name = 'JMP'
                    instr.args = []
                    replacement.instructions = [instr]
                else:
                    unanalyzed_span.append(replacement)

        system_prompt = self.system_prompt
        user_prompt = ''
        for span in unanalyzed_span:
            user_prompt += '\n'
            for i in range(span.start_index, span.end_index):
                user_prompt += str(span.block.lines[i]) + '\n'
            user_prompt += '-----'

        content = self._create_completion(
            messages=[
                {
                    'role': 'system',
                    'content': system_prompt
                },
                {
                    'role': 'user',
                    'content': user_prompt
                }
            ]
        ).choices[0].message.content

        if not content:
            logger.error("llm chat error")
            return None

        llm_groups = self._parse_llm_response(content)
        if not llm_groups or len(llm_groups) != len(unanalyzed_span):
            logger.error(f"LLM output mismatch: got {len(llm_groups)} groups, expected {len(unanalyzed_span)}")
            logger.error("llm output error")
            return None

        # self._display_llm_results(llm_groups)

        for index, span in enumerate(unanalyzed_span):
            recovered_insts = []
            for inst in llm_groups[index].split('\n'):
                asm = bytes(self.ks.asm(inst)[0])
                code = Container.from_string(asm, self.loc_db)
                mdis = self.machine.dis_engine(code.bin_stream, loc_db=self.loc_db)
                recovered_insts.append(mdis.dis_instr(0))

            span.instructions = recovered_insts
        return replace_map

    def recover_cfg(
            self,
            cfg: AsmCFG,
    ) -> AsmCFG | None:
        """
        Recover stack operation instructions in the entire CFG.

        The workflow is:
        1. Deterministic preprocessing for stable templates
        2. stack_address-anchored candidate extraction
        3. Function-level batched LLM recovery for residual candidates
        4. Unified CFG-safe block reconstruction
        """
        replace_map = self._collect_deterministic_replacements(cfg)
        replace_map = self._analyse_replace_instructions(replace_map)
        if not replace_map:
            return None
        cfg = self._apply_replacements(cfg, replace_map)
        return cfg

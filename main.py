"""
Main entry point
Uses RobustAnalyzer for ROP obfuscation control flow recovery and optimization
"""

import argparse
import logging
import os
import sys
from pathlib import Path

from pygments.lexer import default

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from loader.loader_factory import LoaderFactory
from analyzer.analyzer import CFGAnalyzer
from utils.constants import LLM_CONFIG

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - ROParser - %(levelname)s - %(message)s'
)

# Suppress WARNING logs from Miasm asmblock module
logging.getLogger('asmblock').setLevel(logging.ERROR)

# Suppress DEBUG logs from third-party libraries
logging.getLogger('new').setLevel(logging.INFO)

logger = logging.getLogger(__name__)


def setup_argument_parser() -> argparse.ArgumentParser:
    """
    Setup command line argument parser

    Returns:
        Configured ArgumentParser object
    """
    parser = argparse.ArgumentParser(
        description='ROParser - Robust Deobfuscation for ROP Obfuscation Programs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze Raindrop obfuscated binary (no optimization)
  python main.py -i binary.rop -o output/ -m raindrop

  # Analyze only the 'main' function
  python main.py -i config.json -o output/ -m PE -f main

  # Analyze multiple specific functions
  python main.py -i config.json -o output/ -m PE -f main foo bar

  # Enable liveness analysis and constant propagation
  python main.py -i config.json -o output/ -m PE --liveness --constant-propagation

  # Full optimization with CFG graph
  python main.py -i config.json -o output/ -m PE --stack-recovery --liveness --constant-propagation --block-elimination --cfg-graph

"""
    )

    # Required arguments
    parser.add_argument(
        '-i', '--input',
        type=str,
        required=True,
        help='Input file path (binary file or JSON configuration)'
    )

    parser.add_argument(
        '-o', '--output',
        type=str,
        required=True,
        help='Output directory path for results'
    )

    parser.add_argument(
        '-m', '--mode',
        type=str,
        choices=LoaderFactory.get_supported_modes(),
        required=True,
        help=f'Loader mode: {", ".join(LoaderFactory.get_supported_modes())}'
    )

    # Optional arguments
    parser.add_argument(
        '--stack-recovery',
        action='store_true',
        help='Enable stack operation recovery (LLM-based)'
    )

    parser.add_argument(
        '--liveness',
        action='store_true',
        help='Enable liveness analysis and dead code elimination'
    )

    parser.add_argument(
        '--constant-propagation',
        action='store_true',
        help='Enable constant propagation'
    )

    parser.add_argument(
        '--block-elimination',
        action='store_true',
        help='Enable block-level semantic elimination'
    )

    parser.add_argument(
        '--cfg-graph',
        action='store_true',
        help='Generate CFG graph output',
        default=True
    )

    parser.add_argument(
        '-f', '--function',
        type=str,
        nargs='+',
        metavar='FUNC_NAME',
        help='Analyze specific function(s) by name (default: analyze all functions)'
    )

    parser.add_argument(
        '--log-level',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level (default: INFO)'
    )

    return parser


def validate_arguments(args: argparse.Namespace) -> bool:
    """
    Validate command line arguments

    Args:
        args: Parsed argument object

    Returns:
        True if arguments are valid
    """
    # Check input file
    if not os.path.exists(args.input):
        logger.error(f"Input file not found: {args.input}")
        return False

    # Check output directory
    output_dir = Path(args.output)
    if not output_dir.exists():
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created output directory: {output_dir}")
        except Exception as e:
            logger.error(f"Failed to create output directory: {e}")
            return False

    return True


def analyze_function(
    analyzer: CFGAnalyzer,
    func_name: str,
    output_dir: Path,
    optimization_config: dict,
    generate_graph: bool
):
    """
    Analyze a single function

    Args:
        analyzer: Analyzer instance
        func_name: Function name
        output_dir: Output directory
        optimization_config: Optimization configuration (opt-in flags)
        generate_graph: Whether to generate CFG graph
    """
    try:
        logger.info(f"Analyzing function: {func_name}")

        # Execute control flow recovery
        cfg = analyzer.analyze()

        # Execute optimization if any pass is enabled
        _OPT_KEYS = ('stack_recovery', 'liveness', 'constant_propagation', 'block_elimination')
        if any(optimization_config.get(k, False) for k in _OPT_KEYS):
            logger.info("Starting optimization phase")
            cfg = analyzer.optimize(
                enable_stack_recovery=optimization_config.get('stack_recovery', False),
                enable_liveness=optimization_config.get('liveness', False),
                enable_constant_propagation=optimization_config.get('constant_propagation', False),
                enable_block_elimination=optimization_config.get('block_elimination', False),
                llm_config=optimization_config.get('llm_config')
            )

        # Save assembly code
        output_file = output_dir / f"{func_name}.asm"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(str(cfg))
        logger.info(f"  Saved assembly to: {output_file}")

        # Generate CFG graph
        if generate_graph:
            try:
                graph_path = output_dir / func_name
                cfg.graphviz().render(str(graph_path))
                logger.info(f"  CFG graph saved to: {graph_path}.pdf")
            except Exception as e:
                logger.warning(f"  Failed to generate CFG graph: {e}")

        logger.info(f"  Analysis completed for {func_name}")

    except Exception as e:
        logger.error(f"  Error analyzing {func_name}: {e}", exc_info=True)


def main():
    """Main function"""
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Set log level
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    # Validate arguments
    if not validate_arguments(args):
        sys.exit(1)

    # Load binary file
    logger.info(f"Loading binary with mode: {args.mode}")
    loader, func_list = LoaderFactory.load(args.input, args.mode)

    if not loader or not func_list:
        logger.error("Failed to load binary or extract functions")
        sys.exit(1)

    logger.info(f"Successfully loaded {len(func_list)} functions")

    # Filter functions if --function is specified
    if args.function:
        target_names = set(args.function)
        func_list = [f for f in func_list if f[0] in target_names]
        if not func_list:
            logger.error(f"No matching functions found for: {', '.join(args.function)}")
            sys.exit(1)
        logger.info(f"Filtered to {len(func_list)} function(s): {', '.join(f[0] for f in func_list)}")

    # Log LLM configuration when stack recovery is enabled
    if args.stack_recovery:
        api_key = LLM_CONFIG.get('api_key')
        api_key_preview = f"{api_key[:10]}..." if api_key else '<not set>'
        base_url = LLM_CONFIG.get('base_url') or '<not set>'
        model_id = LLM_CONFIG.get('model_id') or '<not set>'

        logger.info(
            f"LLM configuration: api_key={api_key_preview}, "
            f"base_url={base_url}, model_id={model_id}"
        )
        if LLM_CONFIG.get('prompt_path'):
            logger.info(f"Using custom prompt from: {LLM_CONFIG['prompt_path']}")

    # Build optimization configuration
    optimization_config = {
        'stack_recovery': args.stack_recovery,
        'liveness': args.liveness,
        'constant_propagation': args.constant_propagation,
        'block_elimination': args.block_elimination,
        'llm_config': LLM_CONFIG if args.stack_recovery else None
    }

    output_dir = Path(args.output)

    # Process each function
    for func_name, stack_addr, start_addr, chain_end in func_list:
        logger.info(f"Processing function: {func_name}")
        logger.debug(f"  Start address: {hex(start_addr)}")
        logger.debug(f"  Stack address: {hex(stack_addr)}")
        logger.debug(f"  Chain end: {hex(chain_end) if chain_end else 'N/A'}")

        try:
            # Create analyzer
            analyzer = CFGAnalyzer(
                loader=loader,
                stack_address=stack_addr,
                chain_begin=start_addr,
                chain_end=chain_end
            )

            # Analyze function
            analyze_function(
                analyzer=analyzer,
                func_name=func_name,
                output_dir=output_dir,
                optimization_config=optimization_config,
                generate_graph=args.cfg_graph
            )

        except Exception as e:
            logger.error(f"  Fatal error processing {func_name}: {e}", exc_info=True)
            continue

    logger.info("All functions processed")


if __name__ == "__main__":
    main()

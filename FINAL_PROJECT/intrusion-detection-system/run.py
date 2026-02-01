"""
Hybrid IDS Main Entry Point
Production-ready launcher for the Intrusion Detection System.
"""

import argparse
import sys
from pathlib import Path
import logging

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from utils.logger import setup_logging
from utils.config import Config


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Hybrid Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                              # Launch GUI (default)
  python run.py --mode live                  # Live capture (requires admin)
  python run.py --mode offline --pcap-path capture.pcap
  python run.py --mode debug                 # Debug mode with synthetic data
  python run.py --no-gui --mode live         # CLI mode, live capture
        """
    )
    
    parser.add_argument(
        '--mode',
        choices=['live', 'offline', 'debug'],
        default='live',
        help='Capture mode: live (real-time), offline (PCAP), or debug (synthetic)'
    )
    
    parser.add_argument(
        '--pcap-path',
        type=Path,
        default=None,
        help='Path to PCAP file for offline mode'
    )
    
    parser.add_argument(
        '--models-path',
        type=Path,
        default=PROJECT_ROOT / 'models',
        help='Path to directory containing model files'
    )
    
    parser.add_argument(
        '--no-gui',
        action='store_true',
        help='Run in CLI mode without GUI'
    )
    
    parser.add_argument(
        '--suricata-off',
        action='store_true',
        help='Disable Suricata integration (ML-only mode)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level'
    )
    
    parser.add_argument(
        '--interface',
        type=str,
        default=None,
        help='Network interface for live capture (auto-detect if not specified)'
    )
    
    return parser.parse_args()


def check_admin_privileges():
    """Check if running with administrator privileges (Windows)."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def validate_args(args):
    """Validate argument combinations."""
    if args.mode == 'offline' and not args.pcap_path:
        print("ERROR: --pcap-path is required for offline mode")
        sys.exit(1)
    
    if args.pcap_path and not args.pcap_path.exists():
        print(f"ERROR: PCAP file not found: {args.pcap_path}")
        sys.exit(1)
    
    if args.mode == 'live' and not check_admin_privileges():
        print("WARNING: Live capture typically requires administrator privileges.")
        print("If you encounter permission errors, please run as administrator.")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    if not args.models_path.exists():
        print(f"WARNING: Models directory not found: {args.models_path}")
        print("The system will use fallback synthetic models for testing.")
        print("For production use, place trained models in the models/ directory.")
        response = input("Continue with fallback models? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)


def run_gui_mode(args, logger):
    """Launch the GUI application."""
    try:
        from gui.main import IDSApplication
        from PyQt6.QtWidgets import QApplication
        
        logger.info("Starting GUI mode...")
        app = QApplication(sys.argv)
        
        # Configure application
        app.setApplicationName("Hybrid IDS")
        app.setOrganizationName("SecOps")
        
        # Create main window
        window = IDSApplication(
            mode=args.mode,
            pcap_path=args.pcap_path,
            models_path=args.models_path,
            suricata_enabled=not args.suricata_off,
            interface=args.interface
        )
        
        window.show()
        logger.info("GUI launched successfully")
        
        sys.exit(app.exec())
        
    except ImportError as e:
        logger.error(f"Failed to import GUI dependencies: {e}")
        print("\nERROR: GUI dependencies not installed.")
        print("Please install PyQt6: pip install PyQt6")
        sys.exit(1)
    except Exception as e:
        logger.exception(f"GUI mode failed: {e}")
        sys.exit(1)


def run_cli_mode(args, logger):
    """Run in command-line interface mode."""
    from capture.packet_sniffer import PacketSniffer
    from capture.pcap_offline_loader import PCAPLoader
    from capture.flow_builder import FlowBuilder
    from inference.predictor import HybridPredictor
    from traditional_ids.suricata_parser import SuricataParser
    from fusion.decision_engine import DecisionEngine
    import json
    
    logger.info("Starting CLI mode...")
    
    try:
        # Initialize components
        predictor = HybridPredictor(models_path=args.models_path)
        decision_engine = DecisionEngine()
        flow_builder = FlowBuilder()
        
        # Initialize Suricata parser if enabled
        suricata_parser = None
        if not args.suricata_off:
            try:
                suricata_parser = SuricataParser()
                logger.info("Suricata integration enabled")
            except Exception as e:
                logger.warning(f"Suricata initialization failed: {e}")
        
        # Packet source
        if args.mode == 'offline':
            logger.info(f"Loading PCAP file: {args.pcap_path}")
            loader = PCAPLoader(str(args.pcap_path))
            packets = loader.load_packets()
            logger.info(f"Loaded {len(packets)} packets")
        else:
            logger.info(f"Starting live capture on interface: {args.interface or 'auto'}")
            sniffer = PacketSniffer(interface=args.interface)
            packets = sniffer.capture(count=100)  # Capture first 100 packets as demo
        
        # Build flows
        logger.info("Building flows from packets...")
        for pkt_dict in packets:
            flow_builder.add_packet(pkt_dict)
        
        flows = flow_builder.get_completed_flows()
        logger.info(f"Built {len(flows)} flows")
        
        # Analyze each flow
        print("\n" + "="*80)
        print("FLOW ANALYSIS RESULTS")
        print("="*80)
        
        for i, flow in enumerate(flows, 1):
            # ML prediction
            prediction = predictor.predict(flow)
            
            # Get Suricata alerts if available
            suricata_alert = None
            if suricata_parser:
                suricata_alert = suricata_parser.get_alert_for_flow(flow)
            
            # Fusion decision
            final_result = decision_engine.make_decision(
                ml_prediction=prediction,
                suricata_alert=suricata_alert
            )
            
            # Display results
            print(f"\nFlow {i}:")
            print(f"  {flow['src_ip']}:{flow['src_port']} -> "
                  f"{flow['dst_ip']}:{flow['dst_port']} "
                  f"(proto={flow['protocol']})")
            print(f"  Classification: {final_result['final_label']} "
                  f"(confidence: {final_result['final_confidence']:.2%})")
            print(f"  CNN: {prediction['models']['cnn']['predicted_class']} "
                  f"({prediction['models']['cnn']['confidence']:.2%})")
            print(f"  RF:  {prediction['models']['rf']['predicted_class']} "
                  f"({prediction['models']['rf']['confidence']:.2%})")
            
            if suricata_alert:
                print(f"  Suricata: {suricata_alert['signature']} "
                      f"(severity={suricata_alert['severity']})")
        
        print("\n" + "="*80)
        logger.info("Analysis complete")
        
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.exception(f"CLI mode error: {e}")
        sys.exit(1)


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logging(
        log_level=args.log_level,
        log_file=PROJECT_ROOT / 'logs' / 'app.log'
    )
    
    logger.info("="*60)
    logger.info("Hybrid Intrusion Detection System Starting")
    logger.info(f"Mode: {args.mode}")
    logger.info(f"GUI: {not args.no_gui}")
    logger.info(f"Suricata: {not args.suricata_off}")
    logger.info("="*60)
    
    # Validate arguments
    validate_args(args)
    
    # Update config
    Config.MODELS_PATH = args.models_path
    Config.SURICATA_ENABLED = not args.suricata_off
    
    # Run appropriate mode
    if args.no_gui:
        run_cli_mode(args, logger)
    else:
        run_gui_mode(args, logger)


if __name__ == '__main__':
    main()

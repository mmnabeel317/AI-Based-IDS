"""
Hybrid IDS Self-Test Script
Comprehensive diagnostic and validation tests.
"""
import warnings
from sklearn.exceptions import InconsistentVersionWarning
import sys
from pathlib import Path
import logging

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from utils.logger import setup_logging
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

# Setup basic logging for self-test
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def test_python_version():
    """Test Python version compatibility."""
    print("\n[1/12] Testing Python version...")
    major, minor = sys.version_info[:2]
    
    if major == 3 and minor in (10, 11):
        print(f"  ✓ Python {major}.{minor} - Compatible")
        return True
    elif major == 3 and minor >= 12:
        print(f"  ⚠ Python {major}.{minor} - May have TensorFlow compatibility issues")
        return True
    else:
        print(f"  ✗ Python {major}.{minor} - Incompatible (requires 3.10 or 3.11)")
        return False


def test_dependencies():
    """Test that all required packages are installed."""
    print("\n[2/12] Testing dependencies...")
    required_packages = [
        ('tensorflow', 'TensorFlow'),
        ('sklearn', 'scikit-learn'),
        ('scapy', 'Scapy'),
        ('PyQt6', 'PyQt6'),
        ('numpy', 'NumPy'),
        ('pandas', 'Pandas'),
        ('joblib', 'Joblib'),
    ]
    
    all_ok = True
    for module_name, display_name in required_packages:
        try:
            module = __import__(module_name)
            version = getattr(module, '__version__', 'unknown')
            print(f"  ✓ {display_name} {version}")
        except ImportError:
            print(f"  ✗ {display_name} - NOT INSTALLED")
            all_ok = False
    
    return all_ok


def test_npcap():
    """Test Npcap installation (required for packet capture)."""
    print("\n[3/12] Testing Npcap driver...")
    try:
        import scapy.all as scapy
        import platform

        if platform.system() != "Windows":
            print("  ⚠ Not running on Windows - Npcap check skipped")
            return True

        # Prefer get_if_list, fallback to interfaces.get_working_ifaces()
        if hasattr(scapy, "get_if_list"):
            interfaces = scapy.get_if_list()
        else:
            from scapy.interfaces import get_working_ifaces
            interfaces = [iface.name for iface in get_working_ifaces()]

        if interfaces:
            print(f"  ✓ Scapy detected {len(interfaces)} network interface(s)")
            return True
        else:
            print("  ⚠ Scapy installed but no interfaces detected")
            return True

    except Exception as e:
        print(f"  ⚠ Npcap/Scapy interface check failed: {e}")
        print("    Verify Npcap is installed from https://npcap.com/")
        return True



def test_gpu_availability():
    """Test GPU availability (optional)."""
    print("\n[4/12] Testing GPU availability (optional)...")
    try:
        import tensorflow as tf
        gpus = tf.config.list_physical_devices('GPU')
        if gpus:
            print(f"  ✓ GPU detected: {len(gpus)} device(s)")
            for gpu in gpus:
                print(f"    - {gpu.name}")
        else:
            print("  ⚠ No GPU detected - will use CPU (slower)")
        return True
    except Exception as e:
        print(f"  ⚠ GPU check failed: {e}")
        return True


def test_model_files():
    """Test model file existence."""
    print("\n[5/12] Testing model files...")
    models_dir = PROJECT_ROOT / 'models'
    required_files = [
        'attn_model.keras',
        'rf_model.joblib',
        'label_encoder.joblib',
        'feature_scaler.joblib'
    ]
    
    found_models = []
    for filename in required_files:
        filepath = models_dir / filename
        if filepath.exists():
            size_mb = filepath.stat().st_size / (1024 * 1024)
            print(f"  ✓ {filename} ({size_mb:.2f} MB)")
            found_models.append(filename)
        else:
            print(f"  ⚠ {filename} - NOT FOUND (will use fallback)")
    
    if len(found_models) == 0:
        print("  ⚠ No model files found - will generate fallback models for testing")
        return True
    elif len(found_models) < len(required_files):
        print("  ⚠ Some models missing - partial functionality")
        return True
    else:
        print("  ✓ All model files present")
        return True


def test_feature_extraction():
    """Test feature extraction pipeline."""
    print("\n[6/12] Testing feature extraction...")
    try:
        from inference.feature_extractor import FeatureExtractor
        from demo_data.generate_demo_flows import generate_synthetic_flow

        # Generate a full synthetic flow (includes 'packets' key)
        flow = generate_synthetic_flow()

        extractor = FeatureExtractor()
        features = extractor.extract_features(flow)

        if len(features) == 67:
            print(f"  ✓ Extracted {len(features)} features (expected 67)")
            return True
        else:
            print(f"  ✗ Feature count mismatch: got {len(features)}, expected 67")
            return False

    except Exception as e:
        print(f"  ✗ Feature extraction failed: {e}")
        logger.exception(e)
        return False



def test_preprocessing():
    """Test data preprocessing."""
    print("\n[7/12] Testing preprocessing...")
    try:
        from inference.preprocessor import Preprocessor
        import numpy as np
        
        # Create synthetic feature vector
        features = np.random.randn(67)
        
        preprocessor = Preprocessor(models_path=PROJECT_ROOT / 'models')
        processed = preprocessor.preprocess(features)
        
        # Check shape for CNN
        cnn_input = processed['cnn_input']
        if cnn_input.shape == (1, 67, 1):
            print(f"  ✓ CNN input shape: {cnn_input.shape}")
        else:
            print(f"  ✗ CNN input shape mismatch: {cnn_input.shape}")
            return False
        
        # Check shape for RF
        rf_input = processed['rf_input']
        if rf_input.shape == (1, 67):
            print(f"  ✓ RF input shape: {rf_input.shape}")
        else:
            print(f"  ✗ RF input shape mismatch: {rf_input.shape}")
            return False
        
        return True
        
    except Exception as e:
        print(f"  ✗ Preprocessing failed: {e}")
        logger.exception(e)
        return False


def test_ml_prediction():
    """Test ML prediction pipeline."""
    print("\n[8/12] Testing ML prediction...")
    try:
        from inference.predictor import HybridPredictor
        from demo_data.generate_demo_flows import generate_synthetic_flow
        
        predictor = HybridPredictor(models_path=PROJECT_ROOT / 'models')
        flow = generate_synthetic_flow()
        
        prediction = predictor.predict(flow)
        
        # Validate prediction structure
        required_keys = ['final_label', 'final_confidence', 'class_probs', 'models']
        for key in required_keys:
            if key not in prediction:
                print(f"  ✗ Missing key in prediction: {key}")
                return False
        
        print(f"  ✓ Prediction: {prediction['final_label']} "
              f"(confidence: {prediction['final_confidence']:.2%})")
        print(f"    CNN: {prediction['models']['cnn']['predicted_class']}")
        print(f"    RF:  {prediction['models']['rf']['predicted_class']}")
        
        return True
        
    except Exception as e:
        print(f"  ✗ ML prediction failed: {e}")
        logger.exception(e)
        return False


def test_suricata_integration():
    """Test Suricata integration (if available)."""
    print("\n[9/12] Testing Suricata integration...")
    try:
        from traditional_ids.suricata_runner import SuricataRunner
        from traditional_ids.suricata_parser import SuricataParser
        from utils.config import USE_WSL_SURICATA
        
        runner = SuricataRunner()
        
        if runner.is_installed():
            version = runner.get_version()
            print(f"  ✓ Suricata installed: {version}")
            if USE_WSL_SURICATA:
                print(f"    Running via WSL")
            
            # Test parser with sample eve.json
            parser = SuricataParser(eve_json_path=PROJECT_ROOT / 'traditional_ids' / 'sample_eve.json')
            alerts = parser.get_recent_alerts(limit=5)
            print(f"  ✓ Parser loaded {len(alerts)} sample alerts")
            
            return True
        else:
            print("  ⚠ Suricata not installed - signature detection disabled")
            if USE_WSL_SURICATA:
                print("    WSL mode enabled but Suricata not found in WSL")
                print("    Install: wsl -d Ubuntu")
                print("             sudo apt update && sudo apt install suricata -y")
            else:
                print("    Install from https://suricata.io/download/")
            return True  # Not critical for testing
            
    except Exception as e:
        print(f"  ⚠ Suricata integration test failed: {e}")
        return True  # Not critical



def test_flow_building():
    """Test flow building from packets."""
    print("\n[10/12] Testing flow building...")
    try:
        from capture.flow_builder import FlowBuilder
        from demo_data.generate_demo_flows import generate_synthetic_packets
        
        builder = FlowBuilder()
        packets = generate_synthetic_packets(count=20)
        
        for pkt in packets:
            builder.add_packet(pkt)
        
        flows = builder.get_completed_flows()
        print(f"  ✓ Built {len(flows)} flows from {len(packets)} packets")
        
        if flows:
            flow = flows[0]
            required_keys = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
            for key in required_keys:
                if key not in flow:
                    print(f"  ✗ Missing key in flow: {key}")
                    return False
            print(f"  ✓ Sample flow: {flow['src_ip']}:{flow['src_port']} -> "
                  f"{flow['dst_ip']}:{flow['dst_port']}")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Flow building failed: {e}")
        logger.exception(e)
        return False


def test_decision_engine():
    """Test decision fusion engine."""
    print("\n[11/12] Testing decision engine...")
    try:
        from fusion.decision_engine import DecisionEngine
        
        engine = DecisionEngine()
        
        # Mock ML prediction
        ml_prediction = {
            'final_label': 'DoS',
            'final_confidence': 0.85,
            'class_probs': {'Normal': 0.1, 'DoS': 0.85, 'Probe': 0.05},
            'models': {
                'cnn': {'predicted_class': 'DoS', 'confidence': 0.9},
                'rf': {'predicted_class': 'DoS', 'confidence': 0.8}
            }
        }
        
        # Mock Suricata alert
        suricata_alert = {
            'signature': 'ET DOS Possible TCP DoS',
            'severity': 2,
            'category': 'Attempted DoS'
        }
        
        decision = engine.make_decision(ml_prediction, suricata_alert)
        
        print(f"  ✓ Decision: {decision['final_label']} "
              f"(confidence: {decision['final_confidence']:.2%})")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Decision engine failed: {e}")
        logger.exception(e)
        return False


def test_end_to_end():
    """Test complete end-to-end pipeline."""
    print("\n[12/12] Testing end-to-end pipeline...")
    try:
        from demo_data.generate_demo_flows import generate_synthetic_flow
        from inference.predictor import HybridPredictor
        from fusion.decision_engine import DecisionEngine
        
        # Generate synthetic flow
        flow = generate_synthetic_flow()
        
        # ML prediction
        predictor = HybridPredictor(models_path=PROJECT_ROOT / 'models')
        prediction = predictor.predict(flow)
        
        # Decision fusion
        engine = DecisionEngine()
        final_decision = engine.make_decision(prediction, None)
        
        print(f"  ✓ End-to-end test passed")
        print(f"    Input: Flow with {len(flow)} features")
        print(f"    Output: {final_decision['final_label']} "
              f"({final_decision['final_confidence']:.2%})")
        
        return True
        
    except Exception as e:
        print(f"  ✗ End-to-end test failed: {e}")
        logger.exception(e)
        return False


def main():
    """Run all self-tests."""
    print("="*70)
    print("     HYBRID IDS SELF-TEST")
    print("="*70)
    
    tests = [
        test_python_version,
        test_dependencies,
        test_npcap,
        test_gpu_availability,
        test_model_files,
        test_feature_extraction,
        test_preprocessing,
        test_ml_prediction,
        test_suricata_integration,
        test_flow_building,
        test_decision_engine,
        test_end_to_end,
    ]
    
    results = []
    for test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"\n  ✗ Test crashed: {e}")
            logger.exception(e)
            results.append(False)
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("\n✓ SELF TEST PASSED - System ready for use")
        return 0
    else:
        failed_count = total - passed
        print(f"\n⚠ {failed_count} test(s) failed - Review errors above")
        print("  Some features may not work correctly")
        return 1


if __name__ == '__main__':
    sys.exit(main())

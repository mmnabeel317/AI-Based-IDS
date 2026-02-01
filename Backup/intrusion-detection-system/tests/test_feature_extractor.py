"""
Tests for Feature Extractor Module
"""

import pytest
import numpy as np
from inference.feature_extractor import FeatureExtractor, FEATURE_ORDER
from demo_data.generate_demo_flows import generate_synthetic_flow


class TestFeatureExtractor:
    """Test suite for FeatureExtractor."""
    
    def setup_method(self):
        """Setup before each test."""
        self.extractor = FeatureExtractor()
    
    def test_feature_count(self):
        """Test that exactly 67 features are extracted."""
        flow = generate_synthetic_flow()
        features = self.extractor.extract_features(flow)
        
        assert len(features) == 67, f"Expected 67 features, got {len(features)}"
        assert features.shape == (67,), f"Expected shape (67,), got {features.shape}"
    
    def test_feature_order_constant(self):
        """Test that FEATURE_ORDER has 67 elements."""
        assert len(FEATURE_ORDER) == 67, f"FEATURE_ORDER must have 67 features"
    
    def test_feature_types(self):
        """Test that features are numeric."""
        flow = generate_synthetic_flow()
        features = self.extractor.extract_features(flow)
        
        assert features.dtype == np.float32
        assert np.isfinite(features).all(), "Features contain NaN or Inf"
    
    def test_protocol_encoding(self):
        """Test protocol encoding."""
        assert self.extractor._encode_protocol(6) == 6
        assert self.extractor._encode_protocol('tcp') == 6
        assert self.extractor._encode_protocol('udp') == 17
        assert self.extractor._encode_protocol('icmp') == 1
    
    def test_service_encoding(self):
        """Test service port encoding."""
        service_code = self.extractor._encode_service(80)
        assert isinstance(service_code, int)
        assert 0 <= service_code < 100
    
    def test_flag_encoding(self):
        """Test TCP flag encoding."""
        assert self.extractor._encode_flag('SF') == 1
        assert self.extractor._encode_flag('S0') == 0
        assert self.extractor._encode_flag('REJ') == 2
        assert self.extractor._encode_flag('OTH') == 10
    
    def test_minimal_flow(self):
        """Test extraction with minimal flow data."""
        minimal_flow = {
            'src_ip': '192.168.1.1',
            'dst_ip': '10.0.0.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 6
        }
        
        features = self.extractor.extract_features(minimal_flow)
        assert len(features) == 67
        assert np.isfinite(features).all()
    
    def test_extended_features_with_packets(self):
        """Test that extended features are computed when packets present."""
        flow = generate_synthetic_flow()
        assert 'packets' in flow
        
        features = self.extractor.extract_features(flow)
        
        # Extended features should be non-zero if packets present
        assert features[-10:].sum() > 0, "Extended features should be non-zero with packets"
    
    def test_extended_features_without_packets(self):
        """Test fallback when no packets provided."""
        flow = {
            'src_ip': '192.168.1.1',
            'dst_ip': '10.0.0.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 6,
            'duration': 10.0
        }
        
        features = self.extractor.extract_features(flow)
        assert len(features) == 67
        assert np.isfinite(features).all()

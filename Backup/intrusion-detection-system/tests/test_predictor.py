"""
Tests for Hybrid Predictor Module
"""

import pytest
from pathlib import Path
from inference.predictor import HybridPredictor
from demo_data.generate_demo_flows import generate_synthetic_flow


class TestHybridPredictor:
    """Test suite for HybridPredictor."""
    
    def setup_method(self):
        """Setup before each test."""
        models_path = Path(__file__).parent.parent / 'models'
        self.predictor = HybridPredictor(models_path)
    
    def test_prediction_structure(self):
        """Test that prediction has correct structure."""
        flow = generate_synthetic_flow()
        result = self.predictor.predict(flow)
        
        # Check required keys
        required_keys = ['final_label', 'final_confidence', 'class_probs', 'models']
        for key in required_keys:
            assert key in result, f"Missing key: {key}"
        
        # Check models breakdown
        assert 'cnn' in result['models']
        assert 'rf' in result['models']
        
        assert 'predicted_class' in result['models']['cnn']
        assert 'confidence' in result['models']['cnn']
    
    def test_confidence_range(self):
        """Test that confidence is in [0, 1] range."""
        flow = generate_synthetic_flow()
        result = self.predictor.predict(flow)
        
        assert 0 <= result['final_confidence'] <= 1
        assert 0 <= result['models']['cnn']['confidence'] <= 1
        assert 0 <= result['models']['rf']['confidence'] <= 1
    
    def test_class_probabilities_sum(self):
        """Test that class probabilities sum to ~1.0."""
        flow = generate_synthetic_flow()
        result = self.predictor.predict(flow)
        
        prob_sum = sum(result['class_probs'].values())
        assert abs(prob_sum - 1.0) < 0.01, f"Probabilities sum to {prob_sum}"
    
    def test_valid_class_labels(self):
        """Test that predicted labels are valid."""
        flow = generate_synthetic_flow()
        result = self.predictor.predict(flow)
        
        valid_classes = self.predictor.class_names
        assert result['final_label'] in valid_classes
        assert result['models']['cnn']['predicted_class'] in valid_classes
        assert result['models']['rf']['predicted_class'] in valid_classes
    
    def test_batch_prediction(self):
        """Test batch prediction."""
        flows = [generate_synthetic_flow() for _ in range(5)]
        results = self.predictor.predict_batch(flows)
        
        assert len(results) == 5
        for result in results:
            assert 'final_label' in result
    
    def test_model_info(self):
        """Test model info retrieval."""
        info = self.predictor.get_model_info()
        
        assert 'classes' in info
        assert 'ensemble_weights' in info
        assert len(info['classes']) == 9

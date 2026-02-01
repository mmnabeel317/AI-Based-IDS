"""
Tests for Preprocessor Module
"""

import pytest
import numpy as np
from pathlib import Path
from inference.preprocessor import Preprocessor


class TestPreprocessor:
    """Test suite for Preprocessor."""
    
    def setup_method(self):
        """Setup before each test."""
        models_path = Path(__file__).parent.parent / 'models'
        self.preprocessor = Preprocessor(models_path)
    
    def test_preprocessing_shape(self):
        """Test that preprocessing produces correct shapes."""
        features = np.random.randn(67).astype(np.float32)
        
        result = self.preprocessor.preprocess(features)
        
        assert 'cnn_input' in result
        assert 'rf_input' in result
        
        assert result['cnn_input'].shape == (1, 67, 1)
        assert result['rf_input'].shape == (1, 67)
    
    def test_preprocessing_dtype(self):
        """Test that output dtype is float32."""
        features = np.random.randn(67)
        result = self.preprocessor.preprocess(features)
        
        assert result['cnn_input'].dtype == np.float32
        assert result['rf_input'].dtype == np.float32
    
    def test_handle_nan_values(self):
        """Test handling of NaN values."""
        features = np.random.randn(67)
        features[10] = np.nan
        features[20] = np.inf
        
        result = self.preprocessor.preprocess(features)
        
        # Should not contain NaN or Inf
        assert np.isfinite(result['cnn_input']).all()
        assert np.isfinite(result['rf_input']).all()
    
    def test_validate_input(self):
        """Test input validation."""
        valid_features = np.random.randn(67)
        assert self.preprocessor.validate_input(valid_features) == True
        
        # Invalid shape
        invalid_features = np.random.randn(50)
        assert self.preprocessor.validate_input(invalid_features) == False
        
        # Not numpy array
        assert self.preprocessor.validate_input([1, 2, 3]) == False
    
    def test_scaling_consistency(self):
        """Test that scaling is deterministic."""
        features = np.random.randn(67)
        
        result1 = self.preprocessor.preprocess(features)
        result2 = self.preprocessor.preprocess(features)
        
        np.testing.assert_array_equal(result1['cnn_input'], result2['cnn_input'])
        np.testing.assert_array_equal(result1['rf_input'], result2['rf_input'])

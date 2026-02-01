"""
Tests for Self-Test Module
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import self_test


class TestSelfTest:
    """Test suite for self-test functions."""
    
    def test_python_version(self):
        """Test Python version check."""
        result = self_test.test_python_version()
        assert isinstance(result, bool)
    
    def test_dependencies(self):
        """Test dependency check."""
        result = self_test.test_dependencies()
        assert isinstance(result, bool)
    
    def test_feature_extraction(self):
        """Test feature extraction."""
        result = self_test.test_feature_extraction()
        assert result == True
    
    def test_preprocessing(self):
        """Test preprocessing."""
        result = self_test.test_preprocessing()
        assert result == True
    
    def test_ml_prediction(self):
        """Test ML prediction."""
        result = self_test.test_ml_prediction()
        assert result == True
    
    def test_flow_building(self):
        """Test flow building."""
        result = self_test.test_flow_building()
        assert result == True
    
    def test_decision_engine(self):
        """Test decision engine."""
        result = self_test.test_decision_engine()
        assert result == True
    
    def test_end_to_end(self):
        """Test end-to-end pipeline."""
        result = self_test.test_end_to_end()
        assert result == True

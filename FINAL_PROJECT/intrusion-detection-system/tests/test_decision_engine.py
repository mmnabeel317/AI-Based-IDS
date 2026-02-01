"""
Tests for Decision Engine Module
"""

import pytest
from fusion.decision_engine import DecisionEngine


class TestDecisionEngine:
    """Test suite for DecisionEngine."""
    
    def setup_method(self):
        """Setup before each test."""
        self.engine = DecisionEngine()
    
    def test_ml_only_decision(self):
        """Test decision with ML prediction only."""
        ml_prediction = {
            'final_label': 'DoS',
            'final_confidence': 0.9,
            'class_probs': {'Normal': 0.05, 'DoS': 0.9, 'Probe': 0.05},
            'models': {
                'cnn': {'predicted_class': 'DoS', 'confidence': 0.92},
                'rf': {'predicted_class': 'DoS', 'confidence': 0.88}
            }
        }
        
        decision = self.engine.make_decision(ml_prediction, None)
        
        assert decision['final_label'] == 'DoS'
        assert decision['suricata'] is None
        assert 'alert_level' in decision
        assert 'requires_action' in decision
    
    def test_ml_with_suricata_agreement(self):
        """Test decision when ML and Suricata agree."""
        ml_prediction = {
            'final_label': 'DoS',
            'final_confidence': 0.85,
            'class_probs': {'Normal': 0.1, 'DoS': 0.85, 'Probe': 0.05},
            'models': {
                'cnn': {'predicted_class': 'DoS', 'confidence': 0.9},
                'rf': {'predicted_class': 'DoS', 'confidence': 0.8}
            }
        }
        
        suricata_alert = {
            'signature': 'ET DOS TCP DoS Attack',
            'category': 'Attempted Denial of Service',
            'severity': 2,
            'signature_id': 2000419
        }
        
        decision = self.engine.make_decision(ml_prediction, suricata_alert)
        
        assert decision['suricata'] is not None
        assert decision['alert_level'] in ['critical', 'high']
        assert decision['requires_action'] == True
        # Confidence should be boosted
        assert decision['final_confidence'] >= ml_prediction['final_confidence']
    
    def test_ml_with_suricata_disagreement(self):
        """Test decision when ML and Suricata disagree."""
        ml_prediction = {
            'final_label': 'Normal',
            'final_confidence': 0.7,
            'class_probs': {'Normal': 0.7, 'DoS': 0.2, 'Probe': 0.1},
            'models': {
                'cnn': {'predicted_class': 'Normal', 'confidence': 0.75},
                'rf': {'predicted_class': 'Normal', 'confidence': 0.65}
            }
        }
        
        suricata_alert = {
            'signature': 'ET SCAN Port Scan',
            'category': 'Attempted Information Leak',
            'severity': 3,
            'signature_id': 2001219
        }
        
        decision = self.engine.make_decision(ml_prediction, suricata_alert)
        
        assert decision['alert_level'] == 'warning'
        assert decision['requires_action'] == True
    
    def test_confidence_levels(self):
        """Test confidence level categorization."""
        assert self.engine._get_confidence_level(0.95) == 'HIGH'
        assert self.engine._get_confidence_level(0.75) == 'MEDIUM'
        assert self.engine._get_confidence_level(0.55) == 'LOW'
        assert self.engine._get_confidence_level(0.35) == 'VERY_LOW'
    
    def test_stats(self):
        """Test getting engine statistics."""
        stats = self.engine.get_stats()
        
        assert 'decisions_made' in stats
        assert 'thresholds' in stats
        assert isinstance(stats['decisions_made'], int)

"""
Decision Engine Module
Fuses ML predictions with Suricata alerts for final classification.
"""

import logging
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


"""
Decision Engine Module
Fuses ML predictions with Suricata alerts for final classification.
"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class DecisionEngine:
    """
    Fuses ML and signature-based detection results.
    """
    
    def __init__(self):
        """Initialize decision engine."""
        logger.info("Decision engine initialized")
    
    def make_decision(self, ml_prediction: Dict, suricata_alert: Optional[Dict] = None) -> Dict:
        """
        Make final decision by fusing ML and Suricata results.
        
        Args:
            ml_prediction: ML model prediction dictionary
            suricata_alert: Suricata alert dictionary (optional)
            
        Returns:
            Final decision dictionary
        """
        try:
            # Extract ML prediction - handle both formats
            ml_class = ml_prediction.get('final_label') or ml_prediction.get('predicted_class', '0')
            ml_confidence = ml_prediction.get('final_confidence') or ml_prediction.get('confidence', 0.0)
            
            # Check for Suricata alert
            if suricata_alert and suricata_alert.get('alert'):
                # Suricata detected something
                suricata_severity = suricata_alert.get('severity', 3)
                
                # High severity Suricata alert boosts confidence
                if suricata_severity <= 2:  # Critical or High
                    alert_level = 'critical' if suricata_severity == 1 else 'high'
                    
                    return {
                        'final_label': ml_class,
                        'final_confidence': max(ml_confidence, 0.9),
                        'alert_level': alert_level,
                        'source': 'suricata_override',
                        'models': ml_prediction.get('models', {}),
                        'suricata_alert': suricata_alert,
                        'class_probs': ml_prediction.get('class_probs', {}),
                        'ensemble_probs': ml_prediction.get('ensemble_probs', [])
                    }
            
            # No Suricata alert or low priority - use ML prediction
            alert_level = self._determine_alert_level(ml_class, ml_confidence)
            
            return {
                'final_label': ml_class,
                'final_confidence': ml_confidence,
                'alert_level': alert_level,
                'source': 'ml_only',
                'models': ml_prediction.get('models', {}),
                'suricata_alert': suricata_alert,
                'class_probs': ml_prediction.get('class_probs', {}),
                'ensemble_probs': ml_prediction.get('ensemble_probs', [])
            }
            
        except Exception as e:
            logger.error(f"Decision engine failed: {e}", exc_info=True)
            return {
                'final_label': '0',
                'final_confidence': 0.0,
                'alert_level': 'info',
                'source': 'error',
                'models': {},
                'error': str(e)
            }

    
    def _determine_alert_level(self, predicted_class: str, confidence: float) -> str:
        """
        Determine alert level based on prediction.
        
        Args:
            predicted_class: Predicted class label
            confidence: Prediction confidence
            
        Returns:
            Alert level string
        """
        # Class 0 is Benign
        if predicted_class == '0':
            return 'info'
        
        # High confidence attacks
        if confidence >= 0.9:
            return 'critical'
        elif confidence >= 0.7:
            return 'high'
        elif confidence >= 0.5:
            return 'medium'
        else:
            return 'low'

    
    def _get_confidence_level(self, confidence: float) -> str:
        """Map confidence to level string."""
        if confidence >= self.HIGH_CONFIDENCE_THRESHOLD:
            return 'HIGH'
        elif confidence >= self.MEDIUM_CONFIDENCE_THRESHOLD:
            return 'MEDIUM'
        elif confidence >= self.LOW_CONFIDENCE_THRESHOLD:
            return 'LOW'
        else:
            return 'VERY_LOW'
    
    def _check_ml_suricata_agreement(self, ml_label: str, suricata_category: str) -> bool:
        """
        Check if ML and Suricata agree on threat type.
        
        Args:
            ml_label: ML predicted label
            suricata_category: Suricata alert category
            
        Returns:
            True if agreement detected
        """
        ml_lower = ml_label.lower()
        suri_lower = suricata_category.lower()
        
        # Agreement mappings
        agreements = {
            'dos': ['dos', 'denial', 'flood'],
            'probe': ['scan', 'reconnaissance', 'probe', 'information'],
            'r2l': ['intrusion', 'exploit', 'attack', 'shellcode'],
            'u2r': ['privilege', 'root', 'escalation'],
            'normal': []
        }
        
        if ml_lower in agreements:
            keywords = agreements[ml_lower]
            return any(kw in suri_lower for kw in keywords)
        
        return False
    
    def get_stats(self) -> Dict:
        """Get decision engine statistics."""
        return {
            'decisions_made': self.decisions_made,
            'thresholds': {
                'high': self.HIGH_CONFIDENCE_THRESHOLD,
                'medium': self.MEDIUM_CONFIDENCE_THRESHOLD,
                'low': self.LOW_CONFIDENCE_THRESHOLD
            }
        }

"""
Suricata Correlator Module
Advanced correlation between Suricata alerts and ML predictions.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class SuricataCorrelator:
    """Correlates Suricata alerts with ML predictions."""
    
    # Severity mapping
    SEVERITY_MAP = {
        1: 'Critical',
        2: 'High',
        3: 'Medium',
        4: 'Low'
    }
    
    def __init__(self):
        """Initialize correlator."""
        self.correlation_history: List[Dict] = []
    
    def correlate(self, ml_prediction: Dict, suricata_alert: Optional[Dict]) -> Dict:
        """
        Correlate ML prediction with Suricata alert.
        
        Args:
            ml_prediction: ML prediction dictionary
            suricata_alert: Suricata alert dictionary (or None)
            
        Returns:
            Correlation result with combined information
        """
        result = {
            'has_suricata_match': suricata_alert is not None,
            'ml_label': ml_prediction['final_label'],
            'ml_confidence': ml_prediction['final_confidence'],
            'agreement': None,
            'severity_level': None,
            'combined_confidence': ml_prediction['final_confidence']
        }
        
        if suricata_alert:
            # Check for agreement
            result['suricata_category'] = suricata_alert['category']
            result['suricata_signature'] = suricata_alert['signature']
            result['suricata_severity'] = suricata_alert['severity']
            result['severity_level'] = self.SEVERITY_MAP.get(suricata_alert['severity'], 'Unknown')
            
            # Check if ML and Suricata agree
            agreement = self._check_agreement(ml_prediction['final_label'], suricata_alert['category'])
            result['agreement'] = agreement
            
            # Boost confidence if both agree
            if agreement:
                result['combined_confidence'] = min(1.0, ml_prediction['final_confidence'] * 1.2)
                logger.info("ML and Suricata agree - confidence boosted")
            else:
                # Disagreement - flag for review
                result['combined_confidence'] = ml_prediction['final_confidence'] * 0.9
                logger.warning(f"ML-Suricata disagreement: {ml_prediction['final_label']} vs {suricata_alert['category']}")
        
        # Store in history
        self.correlation_history.append(result)
        
        return result
    
    def _check_agreement(self, ml_label: str, suricata_category: str) -> bool:
        """
        Check if ML label and Suricata category agree.
        
        Args:
            ml_label: ML predicted label
            suricata_category: Suricata alert category
            
        Returns:
            True if they agree
        """
        # Normalize strings
        ml_lower = ml_label.lower()
        suri_lower = suricata_category.lower()
        
        # Define agreement mappings
        agreements = {
            'dos': ['dos', 'denial of service', 'attempted dos'],
            'probe': ['reconnaissance', 'scan', 'probe', 'information leak'],
            'r2l': ['intrusion', 'exploit', 'shellcode', 'web attack'],
            'u2r': ['privilege', 'exploit', 'trojan'],
            'normal': []  # Normal traffic shouldn't have alerts
        }
        
        if ml_lower in agreements:
            keywords = agreements[ml_lower]
            return any(keyword in suri_lower for keyword in keywords)
        
        return False
    
    def get_correlation_stats(self) -> Dict:
        """Get correlation statistics."""
        if not self.correlation_history:
            return {
                'total_correlations': 0,
                'suricata_matches': 0,
                'agreements': 0,
                'disagreements': 0
            }
        
        total = len(self.correlation_history)
        with_suricata = sum(1 for c in self.correlation_history if c['has_suricata_match'])
        agreements = sum(1 for c in self.correlation_history if c.get('agreement') is True)
        disagreements = sum(1 for c in self.correlation_history if c.get('agreement') is False)
        
        return {
            'total_correlations': total,
            'suricata_matches': with_suricata,
            'agreements': agreements,
            'disagreements': disagreements,
            'agreement_rate': agreements / with_suricata if with_suricata > 0 else 0.0
        }

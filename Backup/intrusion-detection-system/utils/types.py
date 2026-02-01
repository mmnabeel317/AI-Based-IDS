"""
Type Definitions
Common type aliases and data structures.
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime


# Type aliases
FlowDict = Dict[str, Any]
PacketDict = Dict[str, Any]
PredictionDict = Dict[str, Any]
AlertDict = Dict[str, Any]


@dataclass
class FlowInfo:
    """Flow identification information."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'protocol': self.protocol
        }
    
    def get_5tuple(self) -> Tuple:
        """Get 5-tuple identifier."""
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)


@dataclass
class PredictionResult:
    """ML prediction result."""
    final_label: str
    final_confidence: float
    class_probs: Dict[str, float]
    cnn_prediction: str
    cnn_confidence: float
    rf_prediction: str
    rf_confidence: float
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'final_label': self.final_label,
            'final_confidence': self.final_confidence,
            'class_probs': self.class_probs,
            'models': {
                'cnn': {
                    'predicted_class': self.cnn_prediction,
                    'confidence': self.cnn_confidence
                },
                'rf': {
                    'predicted_class': self.rf_prediction,
                    'confidence': self.rf_confidence
                }
            },
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class SuricataAlert:
    """Suricata alert information."""
    signature: str
    signature_id: int
    category: str
    severity: int
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            'signature': self.signature,
            'signature_id': self.signature_id,
            'category': self.category,
            'severity': self.severity,
            'timestamp': self.timestamp.isoformat()
        }

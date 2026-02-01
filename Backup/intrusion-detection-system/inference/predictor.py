"""
Hybrid Predictor Module
Main prediction pipeline combining CNN, RF, and preprocessing.
"""

import logging
from pathlib import Path
from typing import Dict, Any
import numpy as np

from inference.feature_extractor import FeatureExtractor
from inference.preprocessor import Preprocessor
from inference.ml_ensemble import MLEnsemble
from models.load_model_check import ModelValidator

logger = logging.getLogger(__name__)


class HybridPredictor:
    """Main predictor combining all ML components."""
    
    def __init__(self, models_path: Path, cnn_weight: float = 0.55, rf_weight: float = 0.45):
        """
        Initialize hybrid predictor.
        
        Args:
            models_path: Path to models directory
            cnn_weight: Weight for CNN in ensemble
            rf_weight: Weight for RF in ensemble
        """
        self.models_path = Path(models_path)
        
        logger.info("Initializing Hybrid Predictor...")
        
        # Load models
        validator = ModelValidator(self.models_path)
        self.cnn_model, self.rf_model, self.label_encoder, self.scaler = validator.load_all_models()
        
        # Initialize components
        self.feature_extractor = FeatureExtractor()
        self.preprocessor = Preprocessor(self.models_path)
        self.ensemble = MLEnsemble(cnn_weight=cnn_weight, rf_weight=rf_weight)
        
        # Cache class names
        self.class_names = list(self.label_encoder.classes_)
        
        logger.info(f"Predictor initialized with classes: {self.class_names}")
    
    def predict(self, flow: Dict[str, Any]) -> Dict:
        """
        Predict attack class for a network flow.
        
        Args:
            flow: Flow dictionary with features
            
        Returns:
            Prediction dictionary with labels, confidences, and metadata
        """
        try:
            # Extract features
            features = self.feature_extractor.extract_features(flow)
            
            # Preprocess
            preprocessed = self.preprocessor.preprocess(features)
            
            # CNN prediction
            cnn_input = preprocessed['cnn_input']
            cnn_probs = self.cnn_model.predict(cnn_input, verbose=0)[0]
            
            # RF prediction
            rf_input = preprocessed['rf_input']
            rf_probs = self.rf_model.predict_proba(rf_input)[0]
            
            # Ensemble
            result = self.ensemble.combine_predictions(cnn_probs, rf_probs, self.class_names)
            
            # Add flow metadata
            result['flow_id'] = self._generate_flow_id(flow)
            result['flow_info'] = {
                'src_ip': flow.get('src_ip', 'unknown'),
                'dst_ip': flow.get('dst_ip', 'unknown'),
                'src_port': flow.get('src_port', 0),
                'dst_port': flow.get('dst_port', 0),
                'protocol': flow.get('protocol', 6)
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Prediction failed: {e}", exc_info=True)
            return self._get_error_prediction(flow, str(e))
    
    def predict_batch(self, flows: list) -> list:
        """
        Predict for multiple flows.
        
        Args:
            flows: List of flow dictionaries
            
        Returns:
            List of prediction dictionaries
        """
        results = []
        for flow in flows:
            result = self.predict(flow)
            results.append(result)
        
        logger.info(f"Batch prediction complete: {len(results)} flows")
        return results
    
    def _generate_flow_id(self, flow: Dict) -> str:
        """Generate unique flow identifier."""
        return f"{flow.get('src_ip', '')}:{flow.get('src_port', 0)}->" \
               f"{flow.get('dst_ip', '')}:{flow.get('dst_port', 0)}" \
               f"@{flow.get('protocol', 6)}"
    
    def _get_error_prediction(self, flow: Dict, error_msg: str) -> Dict:
        """Return error prediction when processing fails."""
        return {
            'final_label': 'ERROR',
            'final_confidence': 0.0,
            'class_probs': {cls: 0.0 for cls in self.class_names},
            'models': {
                'cnn': {'predicted_class': 'ERROR', 'confidence': 0.0},
                'rf': {'predicted_class': 'ERROR', 'confidence': 0.0}
            },
            'error': error_msg,
            'flow_id': self._generate_flow_id(flow),
            'flow_info': {
                'src_ip': flow.get('src_ip', 'unknown'),
                'dst_ip': flow.get('dst_ip', 'unknown'),
                'src_port': flow.get('src_port', 0),
                'dst_port': flow.get('dst_port', 0),
                'protocol': flow.get('protocol', 6)
            }
        }
    
    def get_model_info(self) -> Dict:
        """Get information about loaded models."""
        return {
            'cnn_type': type(self.cnn_model).__name__,
            'rf_type': type(self.rf_model).__name__,
            'classes': self.class_names,
            'ensemble_weights': {
                'cnn': self.ensemble.cnn_weight,
                'rf': self.ensemble.rf_weight
            }
        }

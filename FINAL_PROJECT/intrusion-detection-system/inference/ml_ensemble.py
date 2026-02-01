"""
ML Ensemble using Random Forest model
"""

import numpy as np
import joblib
import os
from utils.logger import get_logger
from inference.label_mapping import get_class_name

logger = get_logger(__name__)


class MLEnsemble:
    """Wraps Random Forest model from training"""
    
    def __init__(self, models_path=None, rf_model=None):
        """
        Initialize with either path or model object
        
        Args:
            models_path: Path to models directory
            rf_model: Pre-loaded RF model object
        """
        self.models_path = models_path
        self.rf_model = rf_model
        self.is_loaded = False
        
        if rf_model is not None:
            self.is_loaded = True
            logger.info("✓ RF model provided directly")
        elif models_path:
            self._load_model()
    
    def _load_model(self):
        """Load RF model from joblib file"""
        try:
            rf_path = os.path.join(self.models_path, 'rf_model.joblib')
            
            if not os.path.exists(rf_path):
                logger.warning(f"RF model not found: {rf_path}")
                return
            
            logger.info(f"Loading RF model from: {rf_path}")
            self.rf_model = joblib.load(rf_path)
            self.is_loaded = True
            logger.info(f"✓ RF model loaded: {type(self.rf_model).__name__}")
            
        except Exception as e:
            logger.error(f"Failed to load RF model: {e}")
            import traceback
            traceback.print_exc()
            self.is_loaded = False
    
    def predict(self, features):
        """
        Predict using RF model
        
        Args:
            features: Feature array (67 features, already scaled)
        
        Returns:
            dict: Prediction result
        """
        if not self.is_loaded or self.rf_model is None:
            return {
                'class_index': -1,
                'class_name': 'N/A',
                'confidence': 0.0,
                'available': False
            }
        
        try:
            # Ensure 2D shape
            if features.ndim == 1:
                features = features.reshape(1, -1)
            
            # Predict
            pred = self.rf_model.predict(features)[0]
            
            # Get probability
            if hasattr(self.rf_model, 'predict_proba'):
                proba = self.rf_model.predict_proba(features)[0]
                confidence = float(proba[pred])
            else:
                confidence = 1.0
            
            return {
                'class_index': int(pred),
                'class_name': get_class_name(int(pred)),
                'confidence': confidence,
                'available': True,
                'method': 'random_forest'
            }
            
        except Exception as e:
            logger.error(f"RF prediction error: {e}")
            import traceback
            traceback.print_exc()
            return {
                'class_index': -1,
                'class_name': 'Error',
                'confidence': 0.0,
                'available': True,
                'error': str(e)
            }
    
    def predict_batch(self, features_batch):
        """Predict for multiple samples"""
        if not self.is_loaded:
            return [self.predict(None) for _ in range(len(features_batch))]
        
        return [self.predict(f) for f in features_batch]
    
    def get_model_names(self):
        """Get model name"""
        return ['RandomForest'] if self.is_loaded else []

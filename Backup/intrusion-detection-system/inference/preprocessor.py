"""
Data Preprocessing Module
Scales and normalizes features for ML models.
"""

import logging
from pathlib import Path
from typing import Dict
import numpy as np

logger = logging.getLogger(__name__)


class Preprocessor:
    """Preprocesses features for CNN and RF models."""
    
    def __init__(self, models_path: Path):
        """
        Initialize preprocessor.
        
        Args:
            models_path: Path to directory containing feature_scaler.joblib
        """
        self.models_path = Path(models_path)
        self.scaler = self._load_scaler()
    
    def _load_scaler(self):
        """Load feature scaler."""
        from models.load_model_check import ModelValidator
        
        validator = ModelValidator(self.models_path)
        scaler = validator.load_feature_scaler()
        
        return scaler
    
    def preprocess(self, features: np.ndarray) -> Dict[str, np.ndarray]:
        """
        Preprocess features for both CNN and RF.
        
        Args:
            features: Raw feature vector (67,)
            
        Returns:
            Dictionary with 'cnn_input' (1, 67, 1) and 'rf_input' (1, 67)
        """
        # Validate input
        if features.shape != (67,):
            raise ValueError(f"Expected feature shape (67,), got {features.shape}")
        
        # Handle missing values
        features = self._handle_missing_values(features)
        
        # Scale features
        features_2d = features.reshape(1, -1)
        scaled_features = self.scaler.transform(features_2d)
        
        # Clip outliers
        scaled_features = np.clip(scaled_features, -5, 5)
        
        # Prepare for CNN: reshape to (batch, 67, 1)
        cnn_input = scaled_features.reshape(1, 67, 1).astype(np.float32)
        
        # Prepare for RF: keep as (batch, 67)
        rf_input = scaled_features.astype(np.float32)
        
        return {
            'cnn_input': cnn_input,
            'rf_input': rf_input
        }
    
    def _handle_missing_values(self, features: np.ndarray) -> np.ndarray:
        """Replace NaN/Inf values with safe defaults."""
        features = features.copy()
        
        # Replace NaN with 0
        features[np.isnan(features)] = 0
        
        # Replace Inf with large finite values
        features[np.isinf(features) & (features > 0)] = 1e6
        features[np.isinf(features) & (features < 0)] = -1e6
        
        return features
    
    def validate_input(self, features: np.ndarray) -> bool:
        """
        Validate feature vector.
        
        Args:
            features: Feature vector to validate
            
        Returns:
            True if valid
        """
        if not isinstance(features, np.ndarray):
            logger.error("Features must be NumPy array")
            return False
        
        if features.shape != (67,):
            logger.error(f"Invalid feature shape: {features.shape}")
            return False
        
        if not np.isfinite(features).all():
            logger.warning("Features contain NaN or Inf values (will be handled)")
        
        return True

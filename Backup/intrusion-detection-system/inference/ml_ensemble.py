"""
ML Ensemble Module
Combines CNN and Random Forest predictions with weighted averaging.
"""

import logging
from typing import Dict, Tuple
import numpy as np

logger = logging.getLogger(__name__)


class MLEnsemble:
    """Ensemble combining CNN and Random Forest predictions."""
    
    def __init__(self, cnn_weight: float = 0.55, rf_weight: float = 0.45):
        """
        Initialize ensemble.
        
        Args:
            cnn_weight: Weight for CNN predictions (default: 0.55)
            rf_weight: Weight for RF predictions (default: 0.45)
        """
        if not np.isclose(cnn_weight + rf_weight, 1.0):
            logger.warning(f"Weights don't sum to 1.0: {cnn_weight} + {rf_weight} = {cnn_weight + rf_weight}")
            # Normalize
            total = cnn_weight + rf_weight
            cnn_weight /= total
            rf_weight /= total
        
        self.cnn_weight = cnn_weight
        self.rf_weight = rf_weight
        
        logger.info(f"Ensemble initialized: CNN={cnn_weight:.2f}, RF={rf_weight:.2f}")
    
    def combine_predictions(
        self,
        cnn_probs: np.ndarray,
        rf_probs: np.ndarray,
        class_names: list
    ) -> Dict:
        """
        Combine CNN and RF predictions using weighted averaging.
        
        Args:
            cnn_probs: CNN class probabilities (n_classes,)
            rf_probs: RF class probabilities (n_classes,)
            class_names: List of class names
            
        Returns:
            Dictionary with ensemble results
        """
        # Validate inputs
        if cnn_probs.shape != rf_probs.shape:
            raise ValueError(f"Probability shape mismatch: CNN={cnn_probs.shape}, RF={rf_probs.shape}")
        
        if len(class_names) != len(cnn_probs):
            raise ValueError(f"Class count mismatch: {len(class_names)} names vs {len(cnn_probs)} probs")
        
        # Weighted averaging
        ensemble_probs = (self.cnn_weight * cnn_probs) + (self.rf_weight * rf_probs)
        
        # Normalize (should already sum to 1, but ensure numerical stability)
        ensemble_probs = ensemble_probs / ensemble_probs.sum()
        
        # Get predicted class
        predicted_idx = np.argmax(ensemble_probs)
        predicted_class = class_names[predicted_idx]
        confidence = float(ensemble_probs[predicted_idx])
        
        # Build class probability dictionary
        class_probs = {
            class_names[i]: float(ensemble_probs[i])
            for i in range(len(class_names))
        }
        
        # Get individual model predictions
        cnn_pred_idx = np.argmax(cnn_probs)
        rf_pred_idx = np.argmax(rf_probs)
        
        result = {
            'final_label': predicted_class,
            'final_confidence': confidence,
            'class_probs': class_probs,
            'ensemble_probs': ensemble_probs.tolist(),
            'models': {
                'cnn': {
                    'predicted_class': class_names[cnn_pred_idx],
                    'confidence': float(cnn_probs[cnn_pred_idx]),
                    'probabilities': cnn_probs.tolist()
                },
                'rf': {
                    'predicted_class': class_names[rf_pred_idx],
                    'confidence': float(rf_probs[rf_pred_idx]),
                    'probabilities': rf_probs.tolist()
                }
            },
            'weights': {
                'cnn': self.cnn_weight,
                'rf': self.rf_weight
            }
        }
        
        # Check for model disagreement
        if class_names[cnn_pred_idx] != class_names[rf_pred_idx]:
            logger.info(f"Model disagreement: CNN={class_names[cnn_pred_idx]}, RF={class_names[rf_pred_idx]}")
            result['disagreement'] = True
        else:
            result['disagreement'] = False
        
        return result
    
    def update_weights(self, cnn_weight: float, rf_weight: float):
        """
        Update ensemble weights.
        
        Args:
            cnn_weight: New CNN weight
            rf_weight: New RF weight
        """
        total = cnn_weight + rf_weight
        self.cnn_weight = cnn_weight / total
        self.rf_weight = rf_weight / total
        
        logger.info(f"Weights updated: CNN={self.cnn_weight:.2f}, RF={self.rf_weight:.2f}")

"""
Model Loader for CNN and RF models
"""

import os
import tensorflow as tf
import joblib
from utils.logger import get_logger

logger = get_logger(__name__)


class ModelLoader:
    """Loads trained models"""
    
    def __init__(self, models_dir="models"):
        self.models_dir = models_dir
        self.cnn_model_path = os.path.join(models_dir, "attn_model.keras")
        self.rf_model_path = os.path.join(models_dir, "rf_model.joblib")
        self.cnn_model = None
        self.rf_model = None
        
    def load_cnn_model(self):
        """Load CNN-BiLSTM-Attention model"""
        if self.cnn_model is not None:
            return self.cnn_model
        
        try:
            if not os.path.exists(self.cnn_model_path):
                logger.error(f"CNN model not found: {self.cnn_model_path}")
                return None
            
            logger.info(f"Loading CNN model from: {self.cnn_model_path}")
            self.cnn_model = tf.keras.models.load_model(self.cnn_model_path, compile=True)
            logger.info(f"✓ CNN model loaded | Input: {self.cnn_model.input_shape} | Output: {self.cnn_model.output_shape}")
            
            return self.cnn_model
            
        except Exception as e:
            logger.error(f"Failed to load CNN model: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def load_rf_model(self):
        """Load Random Forest model"""
        if self.rf_model is not None:
            return self.rf_model
        
        try:
            if not os.path.exists(self.rf_model_path):
                logger.warning(f"RF model not found: {self.rf_model_path}")
                return None
            
            logger.info(f"Loading RF model from: {self.rf_model_path}")
            self.rf_model = joblib.load(self.rf_model_path)
            logger.info(f"✓ RF model loaded | Type: {type(self.rf_model).__name__}")
            
            return self.rf_model
            
        except Exception as e:
            logger.error(f"Failed to load RF model: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def check_model_availability(self):
        """Check which models exist"""
        return {
            'cnn_model': os.path.exists(self.cnn_model_path),
            'rf_model': os.path.exists(self.rf_model_path),
            'cnn_path': self.cnn_model_path,
            'rf_path': self.rf_model_path
        }

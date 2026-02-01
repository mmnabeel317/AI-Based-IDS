"""
Model Loading and Validation Module
Checks for model file existence, validates shapes, and provides fallback generators.
"""

import logging
from pathlib import Path
from typing import Dict, Tuple, Optional
import warnings


logger = logging.getLogger(__name__)


class ModelValidator:
    """Validates and loads ML models with fallback generation."""
    
    REQUIRED_FILES = {
        'cnn': 'attn_model.keras',
        'rf': 'rf_model.joblib',
        'label_encoder': 'label_encoder.joblib',
        'feature_scaler': 'feature_scaler.joblib'
    }
    
    def __init__(self, models_path: Path):
        """
        Initialize model validator.
        
        Args:
            models_path: Path to models directory
        """
        self.models_path = Path(models_path)
        self.models_path.mkdir(parents=True, exist_ok=True)
        
    def check_models_exist(self) -> Dict[str, bool]:
        """
        Check which model files exist.
        
        Returns:
            Dictionary mapping model names to existence status
        """
        status = {}
        for model_name, filename in self.REQUIRED_FILES.items():
            filepath = self.models_path / filename
            exists = filepath.exists()
            status[model_name] = exists
            
            if exists:
                size_mb = filepath.stat().st_size / (1024 * 1024)
                logger.info(f"Found {filename}: {size_mb:.2f} MB")
            else:
                logger.warning(f"Missing {filename}")
        
        return status
    
    def load_cnn_model(self):
        """Load CNN model or generate fallback."""
        filepath = self.models_path / self.REQUIRED_FILES['cnn']
        
        if filepath.exists():
            try:
                import tensorflow as tf
                model = tf.keras.models.load_model(str(filepath))
                
                # Validate input shape
                expected_shape = (None, 67, 1)
                actual_shape = model.input_shape
                
                if actual_shape == expected_shape:
                    logger.info(f"CNN model loaded successfully: {filepath}")
                    return model
                else:
                    logger.error(f"CNN model shape mismatch: expected {expected_shape}, got {actual_shape}")
                    raise ValueError("Invalid model shape")
                    
            except Exception as e:
                logger.error(f"Failed to load CNN model: {e}")
                return self._generate_fallback_cnn()
        else:
            logger.warning("CNN model not found, generating fallback")
            return self._generate_fallback_cnn()
    
    def load_rf_model(self):
        """Load Random Forest model or generate fallback."""
        filepath = self.models_path / self.REQUIRED_FILES['rf']
        
        if filepath.exists():
            try:
                import joblib
                model = joblib.load(filepath)
                
                # Validate it's a classifier
                if hasattr(model, 'predict_proba') and hasattr(model, 'classes_'):
                    logger.info(f"RF model loaded successfully: {filepath}")
                    logger.info(f"RF classes: {model.classes_}")
                    return model
                else:
                    logger.error("Invalid RF model structure")
                    raise ValueError("Invalid model type")
                    
            except Exception as e:
                logger.error(f"Failed to load RF model: {e}")
                return self._generate_fallback_rf()
        else:
            logger.warning("RF model not found, generating fallback")
            return self._generate_fallback_rf()
    
    def load_label_encoder(self):
        """Load label encoder or generate fallback."""
        filepath = self.models_path / self.REQUIRED_FILES['label_encoder']
        
        if filepath.exists():
            try:
                import joblib
                encoder = joblib.load(filepath)
                logger.info(f"Label encoder loaded: {filepath}")
                logger.info(f"Classes: {list(encoder.classes_)}")
                return encoder
            except Exception as e:
                logger.error(f"Failed to load label encoder: {e}")
                return self._generate_fallback_label_encoder()
        else:
            logger.warning("Label encoder not found, generating fallback")
            return self._generate_fallback_label_encoder()
    
    def load_feature_scaler(self):
        """Load feature scaler or generate fallback."""
        filepath = self.models_path / self.REQUIRED_FILES['feature_scaler']
        
        if filepath.exists():
            try:
                import joblib
                scaler = joblib.load(filepath)
                logger.info(f"Feature scaler loaded: {filepath}")
                return scaler
            except Exception as e:
                logger.error(f"Failed to load feature scaler: {e}")
                return self._generate_fallback_scaler()
        else:
            logger.warning("Feature scaler not found, generating fallback")
            return self._generate_fallback_scaler()
    
    def _generate_fallback_cnn(self):
        """Generate a minimal fallback CNN model for testing."""
        logger.warning("Generating fallback CNN model (FOR TESTING ONLY)")
        
        import tensorflow as tf
        from tensorflow.keras import layers, models
        
        # Simple CNN architecture matching expected input shape
        inputs = layers.Input(shape=(67, 1))
        
        x = layers.Conv1D(32, 3, activation='relu', padding='same')(inputs)
        x = layers.BatchNormalization()(x)
        x = layers.GlobalAveragePooling1D()(x)
        x = layers.Dense(64, activation='relu')(x)
        x = layers.Dropout(0.3)(x)
        outputs = layers.Dense(5, activation='softmax')(x)
        
        model = models.Model(inputs=inputs, outputs=outputs)
        model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
        
        logger.info("Fallback CNN model created")
        return model
    
    def _generate_fallback_rf(self):
        """Generate a minimal fallback Random Forest model for testing."""
        logger.warning("Generating fallback RF model (FOR TESTING ONLY)")
        
        from sklearn.ensemble import RandomForestClassifier
        import numpy as np
        
        # Create and train on synthetic data
        X_train = np.random.randn(100, 67)
        y_train = np.random.choice(['Normal', 'DoS', 'Probe', 'R2L', 'U2R'], size=100)
        
        model = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=42)
        model.fit(X_train, y_train)
        
        logger.info("Fallback RF model created")
        return model
    
    def _generate_fallback_label_encoder(self):
        """Generate a fallback label encoder."""
        logger.warning("Generating fallback label encoder (FOR TESTING ONLY)")
        
        from sklearn.preprocessing import LabelEncoder
        import numpy as np
        
        encoder = LabelEncoder()
        encoder.fit(['Normal', 'DoS', 'Probe', 'R2L', 'U2R'])
        
        logger.info("Fallback label encoder created")
        return encoder
    
    def _generate_fallback_scaler(self):
        """Generate a fallback feature scaler."""
        logger.warning("Generating fallback feature scaler (FOR TESTING ONLY)")
        
        from sklearn.preprocessing import RobustScaler
        import numpy as np
        
        # Fit on synthetic data
        X_train = np.random.randn(100, 67)
        
        scaler = RobustScaler(quantile_range=(5, 95))
        scaler.fit(X_train)
        
        logger.info("Fallback feature scaler created")
        return scaler
    
    def validate_model_shapes(self, cnn_model, rf_model) -> bool:
        """
        Validate that models accept correct input shapes.
        
        Args:
            cnn_model: CNN keras model
            rf_model: Random Forest sklearn model
            
        Returns:
            True if shapes are valid
        """
        import numpy as np
        
        try:
            # Test CNN with (1, 67, 1) input
            test_cnn_input = np.random.randn(1, 67, 1).astype(np.float32)
            cnn_output = cnn_model.predict(test_cnn_input, verbose=0)
            
            if cnn_output.shape[1] != 9:
                logger.error(f"CNN output shape mismatch: expected (1, 9), got {cnn_output.shape}")
                return False
            
            # Test RF with (1, 67) input
            test_rf_input = np.random.randn(1, 67)
            rf_output = rf_model.predict_proba(test_rf_input)
            
            if rf_output.shape[1] != 9:
                logger.error(f"RF output shape mismatch: expected (1, 9), got {rf_output.shape}")
                return False
            
            logger.info("Model shape validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Model shape validation failed: {e}")
            return False
    
    def load_all_models(self) -> Tuple:
        """
        Load all models with validation.
        
        Returns:
            Tuple of (cnn_model, rf_model, label_encoder, feature_scaler)
        """
        logger.info("Loading all models...")
        
        # Check existence
        status = self.check_models_exist()
        missing_count = sum(1 for exists in status.values() if not exists)
        
        if missing_count > 0:
            logger.warning(f"{missing_count} model file(s) missing - will use fallbacks")
        
        # Load models
        cnn_model = self.load_cnn_model()
        rf_model = self.load_rf_model()
        label_encoder = self.load_label_encoder()
        feature_scaler = self.load_feature_scaler()
        
        # Validate shapes
        if not self.validate_model_shapes(cnn_model, rf_model):
            logger.error("Model validation failed")
            raise ValueError("Invalid model shapes")
        
        logger.info("All models loaded successfully")
        return cnn_model, rf_model, label_encoder, feature_scaler


def save_fallback_models_to_disk(models_path: Path):
    """
    Generate and save fallback models to disk for testing.
    
    Args:
        models_path: Directory to save models
    """
    logger.info(f"Generating fallback models in {models_path}")
    
    validator = ModelValidator(models_path)
    
    # Generate and save CNN
    cnn_model = validator._generate_fallback_cnn()
    cnn_path = models_path / 'attn_model.keras'
    cnn_model.save(str(cnn_path))
    logger.info(f"Saved fallback CNN to {cnn_path}")
    
    # Generate and save RF
    rf_model = validator._generate_fallback_rf()
    rf_path = models_path / 'rf_model.joblib'
    import joblib
    joblib.dump(rf_model, rf_path)
    logger.info(f"Saved fallback RF to {rf_path}")
    
    # Generate and save label encoder
    label_encoder = validator._generate_fallback_label_encoder()
    encoder_path = models_path / 'label_encoder.joblib'
    joblib.dump(label_encoder, encoder_path)
    logger.info(f"Saved fallback label encoder to {encoder_path}")
    
    # Generate and save scaler
    scaler = validator._generate_fallback_scaler()
    scaler_path = models_path / 'feature_scaler.joblib'
    joblib.dump(scaler, scaler_path)
    logger.info(f"Saved fallback scaler to {scaler_path}")
    
    logger.info("All fallback models saved successfully")


if __name__ == '__main__':
    # CLI utility to generate fallback models
    import sys
    from pathlib import Path
    
    if len(sys.argv) > 1:
        models_dir = Path(sys.argv[1])
    else:
        models_dir = Path(__file__).parent
    
    logging.basicConfig(level=logging.INFO)
    save_fallback_models_to_disk(models_dir)

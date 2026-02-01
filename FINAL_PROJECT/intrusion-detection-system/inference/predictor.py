"""
Hybrid Predictor with CNN + RF ensemble - WITH DEBUG LOGGING
"""

import numpy as np
import tensorflow as tf
import os
from utils.logger import get_logger
from inference.label_mapping import get_class_name, format_prediction

logger = get_logger(__name__)


class Predictor:
    """CNN-only predictor"""
    
    def __init__(self, feature_extractor, preprocessor, model_loader):
        self.feature_extractor = feature_extractor
        self.preprocessor = preprocessor
        self.model_loader = model_loader
        self.model = None
        self._load_model()
    
    def _load_model(self):
        """Load CNN model"""
        try:
            self.model = self.model_loader.load_cnn_model()
            if self.model:
                logger.info("✓ CNN model ready")
        except Exception as e:
            logger.error(f"Failed to load CNN: {e}")
            self.model = None
    
    def predict(self, flow_data):
        """Make CNN prediction"""
        try:
            # Extract features
            features = self.feature_extractor.extract_features(flow_data)
            
            if features is None or len(features) != 67:
                logger.error(f"Invalid features: {len(features) if features is not None else 0}")
                return self._default_prediction()
            
            # DEBUG: Log feature statistics
            logger.debug(f"Features - Min: {features.min():.2f}, Max: {features.max():.2f}, "
                        f"Mean: {features.mean():.2f}, NonZero: {np.count_nonzero(features)}/67")
            
            # Check for zero/invalid features
            if np.all(features == 0):
                logger.warning("All features are zero - flow may be incomplete")
            
            # Preprocess
            preprocessed = self.preprocessor.preprocess(features)
            
            if preprocessed.shape != (1, 67, 1):
                logger.error(f"Invalid shape: {preprocessed.shape}")
                return self._default_prediction()
            
            # DEBUG: Log preprocessed statistics
            logger.debug(f"Preprocessed - Min: {preprocessed.min():.2f}, Max: {preprocessed.max():.2f}")
            
            # Predict
            if self.model is None:
                logger.error("Model not loaded")
                return self._default_prediction()
            
            predictions = self.model.predict(preprocessed, verbose=0)
            
            # DEBUG: Log raw predictions
            logger.debug(f"Raw predictions: {predictions[0]}")
            
            class_index = int(np.argmax(predictions[0]))
            confidence = float(predictions[0][class_index])
            
            # DEBUG: Log prediction result
            logger.info(f"CNN Prediction: Class {class_index} = {get_class_name(class_index)} (confidence: {confidence:.3f})")
            
            result = format_prediction(class_index, confidence)
            result['all_probabilities'] = predictions[0].tolist()
            result['method'] = 'cnn'
            
            return result
            
        except Exception as e:
            logger.error(f"CNN prediction failed: {e}")
            import traceback
            traceback.print_exc()
            return self._default_prediction()
    
    def _default_prediction(self):
        return {
            'class_index': 0,
            'class_name': 'Benign',
            'confidence': 0.0,
            'severity': 0,
            'category': 'Normal Traffic',
            'is_attack': False,
            'all_probabilities': [0.0] * 9,
            'error': True
        }


class HybridPredictor:
    """Hybrid CNN + RF predictor"""
    
    def __init__(self, feature_extractor=None, preprocessor=None, model_loader=None, 
                 ml_ensemble=None, models_path=None):
        
        if models_path is not None:
            logger.info(f"Initializing HybridPredictor from: {models_path}")
            self._init_from_path(models_path)
        else:
            if not all([feature_extractor, preprocessor, model_loader]):
                raise ValueError("Provide either models_path or all components")
            
            self.feature_extractor = feature_extractor
            self.preprocessor = preprocessor
            self.model_loader = model_loader
            self.ml_ensemble = ml_ensemble
            self.predictor = Predictor(feature_extractor, preprocessor, model_loader)
            self.model = self.predictor.model
    
    def _init_from_path(self, models_path):
        """Initialize all components"""
        try:
            from inference.feature_extractor import FeatureExtractor
            from inference.preprocessor import Preprocessor
            from models.load_model_check import ModelLoader
            from inference.ml_ensemble import MLEnsemble
            
            logger.info("Initializing components...")
            
            # Feature extractor
            self.feature_extractor = FeatureExtractor()
            logger.info("✓ FeatureExtractor ready")
            
            # Preprocessor with scaler
            scaler_path = os.path.join(models_path, 'scaler_complete_analysis.json')
            self.preprocessor = Preprocessor(scaler_path=scaler_path)
            logger.info("✓ Preprocessor ready")
            
            # Model loader
            self.model_loader = ModelLoader(models_dir=models_path)
            
            # Load RF model directly
            rf_model = self.model_loader.load_rf_model()
            
            # ML ensemble
            if rf_model is not None:
                self.ml_ensemble = MLEnsemble(models_path=models_path, rf_model=rf_model)
                logger.info("✓ ML Ensemble ready with RF model")
            else:
                self.ml_ensemble = None
                logger.warning("⚠ RF model not available - CNN only mode")
            
            # CNN predictor
            self.predictor = Predictor(self.feature_extractor, self.preprocessor, self.model_loader)
            self.model = self.predictor.model
            
            logger.info("✓ HybridPredictor initialization complete")
            
        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def predict(self, flow_data):
        """Make hybrid prediction (CNN + RF ensemble)"""
        
        logger.info(f"Predicting flow: {flow_data.get('flow_id', 'unknown')} | "
                   f"Packets: {len(flow_data.get('packets', []))} | "
                   f"Fwd: {len(flow_data.get('forward_packets', []))} | "
                   f"Bwd: {len(flow_data.get('backward_packets', []))}")
        
        # Get CNN prediction
        cnn_result = self.predictor.predict(flow_data)
        
        # Get RF prediction if available
        if self.ml_ensemble and self.ml_ensemble.is_loaded:
            try:
                features = self.feature_extractor.extract_features(flow_data)
                if features is not None and len(features) == 67:
                    scaled = self.preprocessor.transform(features)
                    rf_result = self.ml_ensemble.predict(scaled)
                    
                    logger.info(f"RF Prediction: Class {rf_result['class_index']} = {rf_result['class_name']} "
                               f"(confidence: {rf_result['confidence']:.3f})")
                    
                    # Ensemble: Use RF if both agree or RF has higher confidence
                    if rf_result['class_index'] == cnn_result['class_index']:
                        # Both agree - use average confidence
                        cnn_result['confidence'] = (cnn_result['confidence'] + rf_result['confidence']) / 2
                        cnn_result['method'] = 'hybrid_agree'
                        logger.info(f"✓ CNN and RF agree on: {cnn_result['class_name']}")
                    elif rf_result['confidence'] > cnn_result['confidence']:
                        # RF more confident - use RF
                        logger.info(f"→ Using RF prediction (higher confidence)")
                        cnn_result['class_index'] = rf_result['class_index']
                        cnn_result['class_name'] = rf_result['class_name']
                        cnn_result['confidence'] = rf_result['confidence']
                        cnn_result['method'] = 'hybrid_rf_primary'
                    else:
                        # CNN more confident - keep CNN
                        logger.info(f"→ Using CNN prediction (higher confidence)")
                        cnn_result['method'] = 'hybrid_cnn_primary'
                    
                    cnn_result['rf_prediction'] = rf_result
                    cnn_result['rf_class'] = rf_result['class_name']
                    cnn_result['rf_confidence'] = rf_result['confidence']
                    
            except Exception as e:
                logger.warning(f"RF prediction failed: {e}")
                cnn_result['method'] = 'cnn_only'
        else:
            cnn_result['method'] = 'cnn_only'
        
        logger.info(f"FINAL: {cnn_result['class_name']} ({cnn_result['confidence']:.1%}) via {cnn_result['method']}")
        logger.info("=" * 80)
        
        return cnn_result


# Backward compatibility
CNNPredictor = Predictor

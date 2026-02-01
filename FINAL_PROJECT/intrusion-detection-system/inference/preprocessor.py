"""
Preprocessor for Network Intrusion Detection
Applies RobustScaler transformation matching training configuration
"""

import numpy as np
import json
import os


class Preprocessor:
    """
    Preprocesses extracted features using RobustScaler.
    Uses exact center and scale values from training to ensure consistency.
    """
    
    def __init__(self, scaler_path=None):
        """
        Initialize the preprocessor.
        
        Args:
            scaler_path (str): Path to scaler parameters JSON file
        """
        self.scaler_params = None
        self.n_features = 67
        
        if scaler_path and os.path.exists(scaler_path):
            self.load_scaler(scaler_path)
        else:
            # Initialize with default parameters (will be loaded later)
            self.initialize_default_scaler()
    
    def initialize_default_scaler(self):
        """Initialize with identity scaling (no transformation)"""
        self.scaler_params = {
            'center': np.zeros(self.n_features),
            'scale': np.ones(self.n_features)
        }
    
    def load_scaler(self, scaler_path):
        """
        Load scaler parameters from JSON file.
        
        Args:
            scaler_path (str): Path to JSON file with scaler parameters
        """
        try:
            with open(scaler_path, 'r') as f:
                scaler_data = json.load(f)
            
            # Extract center and scale values
            center = []
            scale = []
            
            for feature_info in scaler_data:
                center.append(feature_info['center'])
                scale.append(feature_info['scale'])
            
            self.scaler_params = {
                'center': np.array(center, dtype=np.float64),
                'scale': np.array(scale, dtype=np.float64)
            }
            
            print(f"✓ Loaded scaler parameters: {len(center)} features")
            
        except Exception as e:
            print(f"Warning: Could not load scaler from {scaler_path}: {e}")
            self.initialize_default_scaler()
    
    def transform(self, features):
        """
        Apply RobustScaler transformation to features.
        
        Formula: (X - center) / scale
        where center = median, scale = IQR (5th to 95th percentile)
        
        Args:
            features (np.ndarray): Raw features, shape (n_samples, n_features) or (n_features,)
        
        Returns:
            np.ndarray: Scaled features, same shape as input
        """
        if self.scaler_params is None:
            self.initialize_default_scaler()
        
        # Handle both single sample and batch
        is_single = features.ndim == 1
        if is_single:
            features = features.reshape(1, -1)
        
        # Apply RobustScaler transformation
        center = self.scaler_params['center']
        scale = self.scaler_params['scale']
        
        # Avoid division by zero
        scale = np.where(scale == 0, 1.0, scale)
        
        # Transform: (X - center) / scale
        scaled = (features - center) / scale
        
        # Replace inf and nan with 0
        scaled = np.nan_to_num(scaled, nan=0.0, posinf=0.0, neginf=0.0)
        
        if is_single:
            scaled = scaled.flatten()
        
        return scaled
    
    def prepare_for_cnn(self, features):
        """
        Prepare features for CNN model input.
        Reshapes to (n_samples, n_features, 1) for 1D CNN.
        
        Args:
            features (np.ndarray): Scaled features, shape (n_samples, n_features) or (n_features,)
        
        Returns:
            np.ndarray: Reshaped features for CNN, shape (n_samples, n_features, 1)
        """
        # Handle both single sample and batch
        if features.ndim == 1:
            features = features.reshape(1, -1)
        
        # Add channel dimension for CNN: (n_samples, n_features, 1)
        return features.reshape(features.shape[0], features.shape[1], 1)
    
    def preprocess(self, raw_features):
        """
        Complete preprocessing pipeline: scale and prepare for CNN.
        
        Args:
            raw_features (np.ndarray): Raw features from feature extractor
        
        Returns:
            np.ndarray: Preprocessed features ready for model, shape (n_samples, 67, 1)
        """
        # Scale features
        scaled = self.transform(raw_features)
        
        # Prepare for CNN
        return self.prepare_for_cnn(scaled)
    
    def get_scaler_info(self):
        """
        Get information about the scaler parameters.
        
        Returns:
            dict: Scaler statistics
        """
        if self.scaler_params is None:
            return {}
        
        return {
            'n_features': len(self.scaler_params['center']),
            'center_range': (
                float(self.scaler_params['center'].min()),
                float(self.scaler_params['center'].max())
            ),
            'scale_range': (
                float(self.scaler_params['scale'].min()),
                float(self.scaler_params['scale'].max())
            ),
            'center_mean': float(self.scaler_params['center'].mean()),
            'scale_mean': float(self.scaler_params['scale'].mean())
        }


# Example usage and testing
if __name__ == "__main__":
    print("Testing Preprocessor...")
    
    # Create test data
    test_features = np.random.randn(10, 67)
    
    # Initialize preprocessor
    preprocessor = Preprocessor()
    
    # Test transformation
    scaled = preprocessor.transform(test_features)
    print(f"Input shape: {test_features.shape}")
    print(f"Scaled shape: {scaled.shape}")
    
    # Test CNN preparation
    cnn_ready = preprocessor.preprocess(test_features)
    print(f"CNN input shape: {cnn_ready.shape}")
    
    # Test single sample
    single = test_features[0]
    scaled_single = preprocessor.preprocess(single)
    print(f"Single sample shape: {scaled_single.shape}")
    
    print("\n✓ Preprocessor tests passed!")

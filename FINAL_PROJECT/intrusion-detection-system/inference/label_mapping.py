"""
Label Mapping for Network Intrusion Detection
Maps model output indices to attack type names
"""

# Class mapping (9 classes from CIC-IDS2018 dataset)
# Based on the training data Label encoding
CLASS_NAMES = {
    0: "Benign",
    1: "Bot",
    2: "Brute Force -Web",
    3: "Brute Force -XSS", 
    4: "DDOS attack-HOIC",
    5: "DDOS attack-LOIC-UDP",
    6: "DDoS attacks-LOIC-HTTP",
    7: "DoS attacks-Hulk",
    8: "FTP-BruteForce"
}

# Reverse mapping: name to index
NAME_TO_CLASS = {v: k for k, v in CLASS_NAMES.items()}

# Attack severity levels
SEVERITY = {
    "Benign": 0,
    "Bot": 3,
    "Brute Force -Web": 2,
    "Brute Force -XSS": 2,
    "DDOS attack-HOIC": 4,
    "DDOS attack-LOIC-UDP": 4,
    "DDoS attacks-LOIC-HTTP": 4,
    "DoS attacks-Hulk": 4,
    "FTP-BruteForce": 2
}

# Attack categories
CATEGORIES = {
    "Benign": "Normal Traffic",
    "Bot": "Botnet",
    "Brute Force -Web": "Brute Force",
    "Brute Force -XSS": "Brute Force",
    "DDOS attack-HOIC": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "DoS attacks-Hulk": "DoS",
    "FTP-BruteForce": "Brute Force"
}


def get_class_name(class_index):
    """
    Get class name from index.
    
    Args:
        class_index (int): Class index (0-8)
    
    Returns:
        str: Class name
    """
    return CLASS_NAMES.get(class_index, "Unknown")


def get_label_name(label_index):
    """
    Alias for get_class_name for backward compatibility.
    
    Args:
        label_index (int): Label index (0-8)
    
    Returns:
        str: Label name
    """
    return get_class_name(label_index)


def get_class_index(class_name):
    """
    Get class index from name.
    
    Args:
        class_name (str): Class name
    
    Returns:
        int: Class index or -1 if not found
    """
    return NAME_TO_CLASS.get(class_name, -1)


def get_severity(class_name):
    """
    Get severity level for a class.
    
    Args:
        class_name (str): Class name
    
    Returns:
        int: Severity level (0=benign, 1-4=increasing severity)
    """
    return SEVERITY.get(class_name, 0)


def get_category(class_name):
    """
    Get attack category.
    
    Args:
        class_name (str): Class name
    
    Returns:
        str: Attack category
    """
    return CATEGORIES.get(class_name, "Unknown")


def format_prediction(class_index, confidence):
    """
    Format a prediction result.
    
    Args:
        class_index (int): Predicted class index
        confidence (float): Confidence score (0-1)
    
    Returns:
        dict: Formatted prediction
    """
    class_name = get_class_name(class_index)
    
    return {
        'class_index': int(class_index),
        'class_name': class_name,
        'confidence': float(confidence),
        'severity': get_severity(class_name),
        'category': get_category(class_name),
        'is_attack': class_name != "Benign"
    }


# Example usage
if __name__ == "__main__":
    print("CIC-IDS2018 Class Mapping:")
    print("=" * 50)
    for idx, name in CLASS_NAMES.items():
        print(f"{idx}: {name:30s} | Severity: {get_severity(name)} | Category: {get_category(name)}")
    
    print("\n" + "=" * 50)
    print("Example prediction formatting:")
    example = format_prediction(7, 0.95)
    print(example)

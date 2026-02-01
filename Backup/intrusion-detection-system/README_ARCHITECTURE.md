# Hybrid IDS Architecture Documentation

## System Overview

The Hybrid Intrusion Detection System combines machine learning-based behavioral analysis with traditional signature-based detection to provide comprehensive network security monitoring.

## Component Architecture

### 1. Data Capture Layer

#### Packet Sniffer (`capture/packet_sniffer.py`)
- **Technology**: Scapy with Npcap driver
- **Modes**: Live capture (requires admin) or offline PCAP
- **Functionality**: Raw packet capture with filtering
- **Output**: Parsed packet dictionaries

#### Flow Builder (`capture/flow_builder.py`)
- **Aggregation**: 5-tuple flow aggregation (src_ip, dst_ip, src_port, dst_port, protocol)
- **Windowing**: Configurable flow timeout (default: 120 seconds)
- **Features**: Extracts 67 statistical features per flow
- **Schema**: Matches NSL-KDD feature space

### 2. Feature Extraction Layer

#### Feature Extractor (`inference/feature_extractor.py`)
- **Input**: Raw packet list
- **Output**: 67-dimensional feature vector
- **Features**:
  - Duration, protocol type, service, flag
  - Byte/packet counts and rates
  - TCP flags, connection stats
  - Time-window statistics (same_srv_rate, dst_host_srv_count, etc.)

#### Preprocessor (`inference/preprocessor.py`)
- **Scaling**: RobustScaler with quantile_range=(5, 95)
- **Normalization**: Handles outliers and missing values
- **Reshaping**: Converts to (67, 1) for CNN input
- **Validation**: Type checking and range validation

### 3. Detection Layer

#### CNN Model (attn_model.keras)
- **Architecture**:
  - Input: (67, 1) reshaped feature vector
  - Conv1D layers with batch normalization
  - Multi-Head Attention mechanism
  - Global pooling + Dense layers
  - Softmax output (5 classes)
- **Classes**: Normal, DoS, Probe, R2L, U2R
- **Framework**: TensorFlow/Keras 2.15+

#### Random Forest Model (rf_model.joblib)
- **Algorithm**: Ensemble of decision trees
- **Features**: Operates on flat 67-dimensional input
- **Tuning**: Grid-searched hyperparameters
- **Output**: Class probabilities

#### ML Ensemble (`inference/ml_ensemble.py`)
- **Fusion Strategy**: Weighted averaging
- **Default Weights**: CNN=0.55, RF=0.45
- **Calibration**: Probability normalization
- **Conflict Resolution**: Confidence-based tie-breaking

#### Suricata IDS (`traditional_ids/`)
- **Type**: Signature-based detection
- **Input**: Live traffic or PCAP
- **Output**: eve.json (alerts, metadata)
- **Rules**: Emerging Threats + custom rules
- **Correlation**: 5-tuple matching with ML flows

### 4. Fusion Layer

#### Decision Engine (`fusion/decision_engine.py`)
- **Input**: ML predictions + Suricata alerts
- **Logic**:
  1. If Suricata alert exists: elevate severity
  2. Combine ML confidence with signature match
  3. Generate unified threat score
- **Output**: Final classification with metadata

### 5. Presentation Layer

#### GUI (`gui/main.py`)
- **Framework**: PyQt6
- **Features**:
  - Real-time flow table with color-coded threats
  - Model breakdown (CNN vs RF contributions)
  - Start/Stop capture controls
  - Export to CSV/JSON
  - Live alert notifications
- **Performance**: Async updates via QTimer

## Data Flow

Network Traffic
↓
[Packet Sniffer] → Raw Packets
↓
[Flow Builder] → Aggregated Flows (5-tuple)
↓
[Feature Extractor] → 67-D Feature Vectors
↓
[Preprocessor] → Scaled & Normalized Features
↓ ↓
[CNN Model] [RF Model] [Suricata Parser]
↓ ↓ ↓
[ML Ensemble] ← Weighted Fusion
↓
[Decision Engine] ← Signature Correlation
↓
[GUI / Logs] → Final Alert Display



## Feature Schema (67 Features)

### Basic Features (9)
1. duration
2. protocol_type
3. service
4. flag
5. src_bytes
6. dst_bytes
7. land
8. wrong_fragment
9. urgent

### Content Features (13)
10-22: hot, num_failed_logins, logged_in, num_compromised, root_shell, su_attempted, num_root, num_file_creations, num_shells, num_access_files, num_outbound_cmds, is_host_login, is_guest_login

### Time-based Traffic Features (9)
23-31: count, srv_count, serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate, same_srv_rate, diff_srv_rate, srv_diff_host_rate

### Host-based Traffic Features (10)
32-41: dst_host_count, dst_host_srv_count, dst_host_same_srv_rate, dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_srv_diff_host_rate, dst_host_serror_rate, dst_host_srv_serror_rate, dst_host_rerror_rate, dst_host_srv_rerror_rate

### Extended Features (26)
42-67: Additional statistical features (packet inter-arrival times, payload sizes, TCP window sizes, etc.)

## Security Considerations

1. **Privilege Escalation**: Live capture requires admin rights
2. **Data Privacy**: Packet payloads are NOT logged (only metadata)
3. **Resource Usage**: CNN inference ~50ms per flow, RF ~5ms
4. **False Positives**: Tunable via confidence thresholds
5. **Model Updates**: Models can be swapped without code changes

## Performance Metrics

- **Throughput**: ~1000 flows/second (hardware-dependent)
- **Latency**: <100ms per flow (end-to-end)
- **Memory**: ~500MB baseline + model sizes
- **Accuracy**: 
  - CNN: ~96% on test set
  - RF: ~94% on test set
  - Ensemble: ~97% on test set
  - Suricata: ~99% precision (low recall for novel attacks)

## Deployment Scenarios

### Scenario 1: Network Edge Monitoring
- Deploy on gateway/router
- Live capture mode
- Suricata enabled with full rulesets
- Real-time alerting to SIEM

### Scenario 2: Forensic Analysis
- Offline PCAP processing
- Batch mode with stored captures
- Detailed reporting for incident response

### Scenario 3: Honeypot Integration
- Lightweight deployment
- ML-only mode (no Suricata)
- Focus on novel attack detection

## Extensibility

### Adding New Features
1. Update `inference/feature_extractor.py`
2. Retrain models with new feature set
3. Update `FEATURE_ORDER` constant

### Adding New Attack Classes
1. Update label encoder
2. Retrain models
3. Update GUI color mapping

### Custom Fusion Logic
1. Modify `fusion/decision_engine.py`
2. Add business rules or threat intelligence feeds

## References

- NSL-KDD Dataset: https://www.unb.ca/cic/datasets/nsl.html
- Suricata Documentation: https://suricata.io/docs/
- Scapy Documentation: https://scapy.net/
- TensorFlow/Keras: https://www.tensorflow.org/

---

**Last Updated**: December 2025  
**Version**: 1.0.0
"""
Tests for Suricata Parser Module
"""

import pytest
import json
from pathlib import Path
from traditional_ids.suricata_parser import SuricataParser


class TestSuricataParser:
    """Test suite for SuricataParser."""
    
    def setup_method(self):
        """Setup before each test."""
        sample_eve = Path(__file__).parent.parent / 'traditional_ids' / 'sample_eve.json'
        self.parser = SuricataParser(eve_json_path=str(sample_eve))
    
    def test_parse_alerts(self):
        """Test parsing alerts from eve.json."""
        alerts = self.parser.parse_alerts()
        
        assert isinstance(alerts, list)
        if alerts:
            alert = alerts[0]
            assert 'signature' in alert
            assert 'category' in alert
            assert 'severity' in alert
    
    def test_alert_structure(self):
        """Test that parsed alerts have correct structure."""
        alerts = self.parser.parse_alerts()
        
        if alerts:
            alert = alerts[0]
            required_fields = ['timestamp', 'signature', 'category', 'severity', 
                             'src_ip', 'dst_ip']
            for field in required_fields:
                assert field in alert
    
    def test_flow_correlation(self):
        """Test correlating alerts with flows."""
        flow = {
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.50',
            'src_port': 54321,
            'dst_port': 80,
            'protocol': 6
        }
        
        # Parse alerts first
        self.parser.parse_alerts()
        
        # Try to find matching alert
        matching_alert = self.parser.get_alert_for_flow(flow)
        
        # May or may not find match depending on sample data
        if matching_alert:
            assert isinstance(matching_alert, dict)
            assert 'signature' in matching_alert
    
    def test_get_recent_alerts(self):
        """Test retrieving recent alerts."""
        self.parser.parse_alerts()
        recent = self.parser.get_recent_alerts(limit=10)
        
        assert isinstance(recent, list)
        assert len(recent) <= 10
    
    def test_stats(self):
        """Test getting parser statistics."""
        stats = self.parser.get_stats()
        
        assert 'cached_alerts' in stats
        assert 'eve_json_path' in stats
        assert isinstance(stats['cached_alerts'], int)

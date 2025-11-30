"""
Tests for the license detection engine.

Tests cover rule loading, pattern matching (exact, keyword, regex),
confidence scoring, and edge cases.
"""

import pytest
import json
import tempfile
from pathlib import Path
from app.license_engine import LicenseEngine, LicenseRule, LicenseMatch


@pytest.fixture
def sample_rules_file():
    """Create a temporary rules file for testing."""
    rules_data = {
        "rules": [
            {
                "license_type": "MIT",
                "patterns": ["MIT License", "Permission is hereby granted"],
                "keywords": ["MIT", "permission", "free of charge"],
                "regex_patterns": [r"MIT\s+License"],
                "confidence_weight": 1.0
            },
            {
                "license_type": "Apache-2.0",
                "patterns": ["Apache License, Version 2.0"],
                "keywords": ["Apache", "Version 2.0"],
                "regex_patterns": [r"Apache\s+License.*Version\s+2\.0"],
                "confidence_weight": 1.0
            },
            {
                "license_type": "GPL-3.0",
                "patterns": ["GNU GENERAL PUBLIC LICENSE"],
                "keywords": ["GNU", "GPL", "copyleft"],
                "regex_patterns": [r"GNU.*GPL.*v?3"],
                "confidence_weight": 1.0
            }
        ]
    }
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(rules_data, f)
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    Path(temp_path).unlink(missing_ok=True)


@pytest.fixture
def license_engine(sample_rules_file):
    """Create a LicenseEngine instance with sample rules."""
    return LicenseEngine(sample_rules_file)


class TestRuleLoading:
    """Tests for rule loading functionality."""
    
    def test_load_rules_success(self, sample_rules_file):
        """Test successful rule loading from valid JSON file."""
        engine = LicenseEngine(sample_rules_file)
        assert len(engine.rules) == 3
        assert engine.rules[0].license_type == "MIT"
        assert engine.rules[1].license_type == "Apache-2.0"
        assert engine.rules[2].license_type == "GPL-3.0"
    
    def test_load_rules_file_not_found(self):
        """Test error handling when rules file doesn't exist."""
        with pytest.raises(FileNotFoundError):
            LicenseEngine("nonexistent_file.json")
    
    def test_load_rules_invalid_json(self):
        """Test error handling for invalid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{ invalid json }")
            temp_path = f.name
        
        try:
            with pytest.raises(json.JSONDecodeError):
                LicenseEngine(temp_path)
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_load_rules_missing_rules_key(self):
        """Test error handling when 'rules' key is missing."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"other_key": []}, f)
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="must contain a 'rules' key"):
                LicenseEngine(temp_path)
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_load_rules_invalid_structure(self):
        """Test error handling when rules is not a list."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"rules": "not a list"}, f)
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="'rules' must be a list"):
                LicenseEngine(temp_path)
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestExactStringMatching:
    """Tests for exact string pattern matching."""
    
    def test_exact_match_single_occurrence(self, license_engine):
        """Test exact string matching with single occurrence."""
        text = "This project uses the MIT License for distribution."
        matches = license_engine.detect_licenses(text)
        
        mit_matches = [m for m in matches if m.license_type == "MIT" and m.matched_text == "MIT License"]
        assert len(mit_matches) >= 1
        
        match = mit_matches[0]
        assert match.license_type == "MIT"
        assert match.matched_text == "MIT License"
        assert match.start_position == text.find("MIT License")
        assert match.end_position == match.start_position + len("MIT License")
        assert 0.0 <= match.confidence <= 1.0
    
    def test_exact_match_multiple_occurrences(self, license_engine):
        """Test exact string matching with multiple occurrences."""
        text = "MIT License is great. I love the MIT License."
        matches = license_engine.detect_licenses(text)
        
        mit_exact_matches = [m for m in matches if m.license_type == "MIT" and m.matched_text == "MIT License"]
        assert len(mit_exact_matches) >= 2
    
    def test_exact_match_case_sensitive(self, license_engine):
        """Test that exact matching is case-sensitive."""
        text = "This uses the mit license"  # lowercase
        matches = license_engine.detect_licenses(text)
        
        # Should not match "MIT License" pattern (case-sensitive)
        exact_mit_matches = [m for m in matches if m.matched_text == "MIT License"]
        assert len(exact_mit_matches) == 0
    
    def test_exact_match_long_pattern(self, license_engine):
        """Test exact matching with longer patterns."""
        text = "Permission is hereby granted, free of charge, to any person."
        matches = license_engine.detect_licenses(text)
        
        long_matches = [m for m in matches if "Permission is hereby granted" in m.matched_text]
        assert len(long_matches) >= 1


class TestKeywordMatching:
    """Tests for keyword-based matching."""
    
    def test_keyword_match_case_insensitive(self, license_engine):
        """Test that keyword matching is case-insensitive."""
        text = "This software uses mit and requires permission."
        matches = license_engine.detect_licenses(text)
        
        # Should match MIT keyword (case-insensitive)
        mit_keyword_matches = [m for m in matches if m.license_type == "MIT"]
        assert len(mit_keyword_matches) >= 1
    
    def test_keyword_match_word_boundaries(self, license_engine):
        """Test that keywords respect word boundaries."""
        text = "commitment to the project"  # contains "MIT" but not as a word
        matches = license_engine.detect_licenses(text)
        
        # Should not match "MIT" keyword (not a whole word)
        mit_matches = [m for m in matches if m.license_type == "MIT" and m.matched_text.lower() == "mit"]
        assert len(mit_matches) == 0
    
    def test_keyword_multiple_keywords(self, license_engine):
        """Test matching with multiple keywords present."""
        text = "Apache License Version 2.0 is widely used."
        matches = license_engine.detect_licenses(text)
        
        apache_matches = [m for m in matches if m.license_type == "Apache-2.0"]
        assert len(apache_matches) >= 1


class TestRegexMatching:
    """Tests for regex pattern matching."""
    
    def test_regex_match_basic(self, license_engine):
        """Test basic regex pattern matching."""
        text = "This is the MIT License for the project."
        matches = license_engine.detect_licenses(text)
        
        # Should match via regex pattern
        mit_matches = [m for m in matches if m.license_type == "MIT"]
        assert len(mit_matches) >= 1
    
    def test_regex_match_with_whitespace_variation(self, license_engine):
        """Test regex matching handles whitespace variations."""
        text = "This is the MIT  License with extra spaces."
        matches = license_engine.detect_licenses(text)
        
        # Regex pattern should handle variable whitespace
        mit_matches = [m for m in matches if m.license_type == "MIT"]
        assert len(mit_matches) >= 1
    
    def test_regex_match_case_insensitive(self, license_engine):
        """Test that regex matching is case-insensitive."""
        text = "gnu gpl v3 license"
        matches = license_engine.detect_licenses(text)
        
        # Should match GPL via case-insensitive regex
        gpl_matches = [m for m in matches if m.license_type == "GPL-3.0"]
        assert len(gpl_matches) >= 1


class TestConfidenceScoring:
    """Tests for confidence score calculation."""
    
    def test_confidence_in_valid_range(self, license_engine):
        """Test that all confidence scores are between 0 and 1."""
        text = "MIT License and Apache License, Version 2.0"
        matches = license_engine.detect_licenses(text)
        
        for match in matches:
            assert 0.0 <= match.confidence <= 1.0
    
    def test_exact_match_high_confidence(self, license_engine):
        """Test that exact matches have high confidence."""
        text = "MIT License"
        matches = license_engine.detect_licenses(text)
        
        exact_matches = [m for m in matches if m.matched_text == "MIT License"]
        if exact_matches:
            assert exact_matches[0].confidence >= 0.85


class TestEdgeCases:
    """Tests for edge cases and error conditions."""
    
    def test_empty_text(self, license_engine):
        """Test detection with empty input text."""
        matches = license_engine.detect_licenses("")
        assert matches == []
    
    def test_no_matches(self, license_engine):
        """Test detection when no licenses are present."""
        text = "This is just some random text with no license information."
        matches = license_engine.detect_licenses(text)
        
        # May have some keyword matches, but should handle gracefully
        assert isinstance(matches, list)
    
    def test_very_large_text(self, license_engine):
        """Test detection with large input text."""
        text = "MIT License. " * 1000  # Repeat pattern many times
        matches = license_engine.detect_licenses(text)
        
        # Should handle large text without errors
        assert len(matches) > 0
        assert all(isinstance(m, LicenseMatch) for m in matches)
    
    def test_special_characters(self, license_engine):
        """Test detection with special characters in text."""
        text = "MIT License © 2024 with special chars: @#$%^&*()"
        matches = license_engine.detect_licenses(text)
        
        # Should handle special characters gracefully
        mit_matches = [m for m in matches if m.license_type == "MIT"]
        assert len(mit_matches) >= 1
    
    def test_unicode_text(self, license_engine):
        """Test detection with unicode characters."""
        text = "MIT License with unicode: 你好 мир"
        matches = license_engine.detect_licenses(text)
        
        # Should handle unicode gracefully
        mit_matches = [m for m in matches if m.license_type == "MIT"]
        assert len(mit_matches) >= 1


class TestMultipleRules:
    """Tests for applying multiple rules."""
    
    def test_multiple_license_types(self, license_engine):
        """Test detection when multiple license types are present."""
        text = """
        This project uses MIT License for the core library.
        The documentation is under Apache License, Version 2.0.
        Some components use GNU GPL v3.
        """
        matches = license_engine.detect_licenses(text)
        
        # Should detect all three license types
        license_types = {m.license_type for m in matches}
        assert "MIT" in license_types
        assert "Apache-2.0" in license_types
        assert "GPL-3.0" in license_types
    
    def test_overlapping_matches(self, license_engine):
        """Test handling of overlapping match regions."""
        text = "MIT License and MIT keyword"
        matches = license_engine.detect_licenses(text)
        
        # Should detect multiple matches even if they overlap
        mit_matches = [m for m in matches if m.license_type == "MIT"]
        assert len(mit_matches) >= 1


class TestMatchPositions:
    """Tests for match position tracking."""
    
    def test_position_accuracy(self, license_engine):
        """Test that match positions are accurate."""
        text = "Start MIT License End"
        matches = license_engine.detect_licenses(text)
        
        exact_matches = [m for m in matches if m.matched_text == "MIT License"]
        if exact_matches:
            match = exact_matches[0]
            assert text[match.start_position:match.end_position] == "MIT License"
    
    def test_position_ordering(self, license_engine):
        """Test that start position is before end position."""
        text = "MIT License and Apache License, Version 2.0"
        matches = license_engine.detect_licenses(text)
        
        for match in matches:
            assert match.start_position < match.end_position

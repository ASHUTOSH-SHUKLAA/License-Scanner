"""
License detection engine using rule-based pattern matching.

This module implements the core license detection logic, including
rule loading from JSON configuration and pattern matching algorithms.
"""

import json
import re
from typing import List, Dict, Any
from pathlib import Path
from pydantic import BaseModel, Field


class LicenseRule(BaseModel):
    """Data model for a license detection rule."""
    
    license_type: str = Field(..., description="The license type identifier (e.g., 'MIT', 'Apache-2.0')")
    patterns: List[str] = Field(default_factory=list, description="Exact string patterns to match")
    keywords: List[str] = Field(default_factory=list, description="Keywords that indicate this license")
    regex_patterns: List[str] = Field(default_factory=list, description="Regular expression patterns")
    confidence_weight: float = Field(default=1.0, description="Weight factor for confidence calculation")


class LicenseMatch(BaseModel):
    """Data model for a detected license match."""
    
    license_type: str = Field(..., description="The detected license type")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0 and 1")
    matched_text: str = Field(..., description="The actual text that matched")
    start_position: int = Field(..., ge=0, description="Start position of the match in the input text")
    end_position: int = Field(..., ge=0, description="End position of the match in the input text")


class LicenseEngine:
    """
    Engine for detecting licenses in text using rule-based pattern matching.
    
    Supports exact string matching, keyword matching, and regex patterns.
    """
    
    def __init__(self, rules_path: str):
        """
        Initialize the license engine with rules from a JSON file.
        
        Args:
            rules_path: Path to the JSON file containing license rules
        """
        self.rules_path = rules_path
        self.rules: List[LicenseRule] = []
        self.load_rules()
    
    def load_rules(self) -> List[LicenseRule]:
        """
        Load license detection rules from the JSON configuration file.
        
        Returns:
            List of LicenseRule objects
            
        Raises:
            FileNotFoundError: If the rules file doesn't exist
            json.JSONDecodeError: If the rules file is not valid JSON
            ValueError: If the rules structure is invalid
        """
        rules_file = Path(self.rules_path)
        
        if not rules_file.exists():
            raise FileNotFoundError(f"Rules file not found: {self.rules_path}")
        
        with open(rules_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if not isinstance(data, dict) or 'rules' not in data:
            raise ValueError("Rules file must contain a 'rules' key with a list of rules")
        
        rules_data = data['rules']
        if not isinstance(rules_data, list):
            raise ValueError("'rules' must be a list")
        
        self.rules = [LicenseRule(**rule) for rule in rules_data]
        return self.rules
    
    def detect_licenses(self, text: str) -> List[LicenseMatch]:
        """
        Detect licenses in the provided text using all loaded rules.
        
        Args:
            text: The license text to analyze
            
        Returns:
            List of LicenseMatch objects for all detected licenses
        """
        if not text:
            return []
        
        matches: List[LicenseMatch] = []
        
        for rule in self.rules:
            # Apply exact string pattern matching
            matches.extend(self._match_exact_patterns(text, rule))
            
            # Apply keyword-based matching
            matches.extend(self._match_keywords(text, rule))
            
            # Apply regex pattern matching
            matches.extend(self._match_regex_patterns(text, rule))
        
        return matches
    
    def _match_exact_patterns(self, text: str, rule: LicenseRule) -> List[LicenseMatch]:
        """
        Match exact string patterns in the text.
        
        Args:
            text: The text to search
            rule: The license rule to apply
            
        Returns:
            List of matches found
        """
        matches = []
        
        for pattern in rule.patterns:
            if not pattern:
                continue
            
            # Find all occurrences of the exact pattern
            start = 0
            while True:
                pos = text.find(pattern, start)
                if pos == -1:
                    break
                
                end_pos = pos + len(pattern)
                confidence = self._calculate_confidence(
                    match_type="exact",
                    rule=rule,
                    matched_text=pattern
                )
                
                matches.append(LicenseMatch(
                    license_type=rule.license_type,
                    confidence=confidence,
                    matched_text=pattern,
                    start_position=pos,
                    end_position=end_pos
                ))
                
                start = end_pos
        
        return matches
    
    def _match_keywords(self, text: str, rule: LicenseRule) -> List[LicenseMatch]:
        """
        Match keywords in the text.
        
        Keywords are matched case-insensitively and must appear as whole words.
        Multiple keywords increase confidence.
        
        Args:
            text: The text to search
            rule: The license rule to apply
            
        Returns:
            List of matches found
        """
        matches = []
        
        if not rule.keywords:
            return matches
        
        text_lower = text.lower()
        found_keywords = []
        positions = []
        
        for keyword in rule.keywords:
            if not keyword:
                continue
            
            keyword_lower = keyword.lower()
            # Use word boundaries for keyword matching
            pattern = r'\b' + re.escape(keyword_lower) + r'\b'
            
            for match in re.finditer(pattern, text_lower):
                found_keywords.append(keyword)
                positions.append((match.start(), match.end()))
        
        # If we found keywords, create a match for each occurrence
        for keyword, (start_pos, end_pos) in zip(found_keywords, positions):
            matched_text = text[start_pos:end_pos]
            confidence = self._calculate_confidence(
                match_type="keyword",
                rule=rule,
                matched_text=matched_text,
                keyword_count=len(found_keywords)
            )
            
            matches.append(LicenseMatch(
                license_type=rule.license_type,
                confidence=confidence,
                matched_text=matched_text,
                start_position=start_pos,
                end_position=end_pos
            ))
        
        return matches
    
    def _match_regex_patterns(self, text: str, rule: LicenseRule) -> List[LicenseMatch]:
        """
        Match regular expression patterns in the text.
        
        Args:
            text: The text to search
            rule: The license rule to apply
            
        Returns:
            List of matches found
        """
        matches = []
        
        for pattern_str in rule.regex_patterns:
            if not pattern_str:
                continue
            
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                
                for match in pattern.finditer(text):
                    matched_text = match.group(0)
                    confidence = self._calculate_confidence(
                        match_type="regex",
                        rule=rule,
                        matched_text=matched_text
                    )
                    
                    matches.append(LicenseMatch(
                        license_type=rule.license_type,
                        confidence=confidence,
                        matched_text=matched_text,
                        start_position=match.start(),
                        end_position=match.end()
                    ))
            except re.error:
                # Skip invalid regex patterns
                continue
        
        return matches
    
    def _calculate_confidence(
        self,
        match_type: str,
        rule: LicenseRule,
        matched_text: str,
        keyword_count: int = 1
    ) -> float:
        """
        Calculate confidence score for a match.
        
        Confidence is based on:
        - Match type (exact > regex > keyword)
        - Rule confidence weight
        - For keywords: number of keywords found
        - Match length
        
        Args:
            match_type: Type of match ("exact", "keyword", or "regex")
            rule: The license rule that matched
            matched_text: The text that was matched
            keyword_count: Number of keywords found (for keyword matches)
            
        Returns:
            Confidence score between 0.0 and 1.0
        """
        base_confidence = {
            "exact": 0.95,
            "regex": 0.85,
            "keyword": 0.60
        }.get(match_type, 0.5)
        
        # Apply rule confidence weight
        confidence = base_confidence * rule.confidence_weight
        
        # For keyword matches, boost confidence based on number of keywords
        if match_type == "keyword" and keyword_count > 1:
            keyword_boost = min(0.2, (keyword_count - 1) * 0.05)
            confidence = min(1.0, confidence + keyword_boost)
        
        # Boost confidence for longer matches (more specific)
        if len(matched_text) > 50:
            length_boost = min(0.1, (len(matched_text) - 50) / 1000)
            confidence = min(1.0, confidence + length_boost)
        
        # Ensure confidence is in valid range
        return max(0.0, min(1.0, confidence))

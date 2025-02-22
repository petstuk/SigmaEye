import yaml
from pathlib import Path
from typing import List, Dict, Any
import logging

class SigmaRuleLoader:
    def __init__(self, sigma_path: str):
        """
        Initialize Sigma rule loader
        
        Args:
            sigma_path: Path to Sigma rules directory
        """
        self.sigma_path = Path(sigma_path)
        self.rules = []
        self.field_mappings = {
            'Image': 'exe',
            'ParentImage': 'parent_exe',
            'ProcessName': 'name',
            'ParentProcessName': 'parent_name',
            'CommandLine': 'cmdline',
            'User': 'username',
            'CurrentDirectory': 'cwd'
        }
    
    def load_rules(self) -> List[dict]:
        """Load compatible Sigma rules"""
        rules_loaded = 0
        rules_skipped = 0
        
        # Focus on process creation rules first
        process_rules_path = self.sigma_path / 'rules' / 'windows' / 'process_creation'
        
        if not process_rules_path.exists():
            logging.error(f"Sigma rules path not found: {process_rules_path}")
            return []
        
        for rule_file in process_rules_path.glob('*.yml'):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                    
                    if self._is_compatible_rule(rule):
                        # Add file path to rule for reference
                        rule['file_path'] = str(rule_file)
                        self.rules.append(rule)
                        rules_loaded += 1
                    else:
                        rules_skipped += 1
                        logging.debug(f"Skipped incompatible rule: {rule_file}")
            
            except Exception as e:
                logging.error(f"Error loading rule {rule_file}: {str(e)}")
                rules_skipped += 1
        
        logging.info(f"Loaded {rules_loaded} rules, skipped {rules_skipped} incompatible rules")
        return self.rules
    
    def _is_compatible_rule(self, rule: dict) -> bool:
        """Check if rule is compatible with our monitoring capabilities"""
        try:
            # Must have basic required fields
            if not all(k in rule for k in ['title', 'detection']):
                return False
            
            detection = rule['detection']
            if not isinstance(detection, dict):
                return False
            
            # Check if we support all fields used in the rule
            for selection_name, selection in detection.items():
                if isinstance(selection, dict):
                    if not all(self._can_handle_field(field) for field in selection.keys()):
                        return False
            
            return True
        
        except Exception:
            return False
    
    def _can_handle_field(self, field: str) -> bool:
        """Check if we can handle this field"""
        # Handle base field
        base_field = field.split('|')[0]  # Handle modifiers like 'CommandLine|contains'
        return base_field in self.field_mappings
    
    def match_rule(self, rule: dict, process_info: dict) -> bool:
        """Match a process against a single rule"""
        try:
            detection = rule['detection']
            matches = {}
            
            # Process each selection
            for selection_name, selection in detection.items():
                if isinstance(selection, dict):
                    matches[selection_name] = self._check_selection(selection, process_info)
            
            # Evaluate condition
            condition = detection.get('condition', '')
            if condition:
                # Handle basic conditions
                if condition == 'selection':
                    return matches.get('selection', False)
                elif ' and ' in condition:
                    return all(matches.get(sel, False) for sel in condition.split(' and '))
                elif ' or ' in condition:
                    return any(matches.get(sel, False) for sel in condition.split(' or '))
            
            return False
        
        except Exception as e:
            logging.error(f"Error matching rule {rule.get('title', 'unknown')}: {str(e)}")
            return False
    
    def _check_selection(self, selection: dict, process_info: dict) -> bool:
        """Check if a selection matches process information"""
        for field, expected in selection.items():
            # Handle field modifiers
            base_field, *modifiers = field.split('|')
            
            # Get actual value using field mapping
            mapped_field = self.field_mappings.get(base_field)
            if not mapped_field:
                return False
            
            actual_value = str(process_info.get(mapped_field, '')).lower()
            
            # Handle different match types
            if isinstance(expected, list):
                if not any(self._check_value(actual_value, str(exp).lower(), modifiers) 
                          for exp in expected):
                    return False
            else:
                if not self._check_value(actual_value, str(expected).lower(), modifiers):
                    return False
        
        return True
    
    def _check_value(self, actual: str, expected: str, modifiers: List[str]) -> bool:
        """Check value with modifiers"""
        if 'contains' in modifiers:
            return expected in actual
        elif 'startswith' in modifiers:
            return actual.startswith(expected)
        elif 'endswith' in modifiers:
            return actual.endswith(expected)
        elif expected.startswith('*') and expected.endswith('*'):
            return expected[1:-1] in actual
        else:
            return actual == expected

# Example usage
if __name__ == "__main__":
    # Test with a sample rule
    sample_rule = {
        'title': 'Suspicious PowerShell Command Line',
        'detection': {
            'selection': {
                'ProcessName': 'powershell.exe',
                'CommandLine|contains': ['-enc', '-EncodedCommand']
            },
            'condition': 'selection'
        }
    }
    
    sample_process = {
        'name': 'powershell.exe',
        'cmdline': 'powershell.exe -enc ZQBjAGgAbwAgACIASABlAGwAbABvACI=',
        'exe': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
    }
    
    loader = SigmaRuleLoader("path/to/sigma")
    print(loader.match_rule(sample_rule, sample_process))  # Should print True
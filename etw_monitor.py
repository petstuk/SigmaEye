import sys
import logging
from typing import Dict, List, Optional
import yaml
import json
from datetime import datetime
import win32evtlog
import win32con
import win32evtlogutil
import wmi
import os
from pathlib import Path
from sigma_rule_loader import SigmaRuleLoader

class ETWMonitor:
    def __init__(self, config_path: str):
        """
        Initialize ETW Monitor with configuration
        
        Args:
            config_path: Path to YAML configuration file
        """
        self.config = self._load_config(config_path)
        self.wmi = wmi.WMI()
        self.process_cache: Dict[int, dict] = {}
        self.suspicious_chains: List[dict] = []
        
        # Initialize logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=self.config.get('log_file', 'etw_monitor.log')
        )
        
        sigma_path = Path('sigma')  # Use relative path to sigma folder
        self.sigma_loader = SigmaRuleLoader(sigma_path)
        self.rules = self.sigma_loader.load_rules()
        logging.info(f"Loaded {len(self.rules)} Sigma rules")
        
    def _load_config(self, config_path: str) -> dict:
        """Load YAML configuration file"""
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def _check_process_chain(self, process: dict) -> bool:
        suspicious = False
        parent_pid = process.get('ParentProcessId')
        
        # Check Sigma rules first
        for rule in self.rules:
            if self.sigma_loader.match_rule(rule, process):
                suspicious = True
                if parent_pid in self.process_cache:
                    parent = self.process_cache[parent_pid]
                    chain = {
                        'timestamp': datetime.now().isoformat(),
                        'parent': parent,
                        'child': process,
                        'alerts': [{
                            'type': 'sigma_rule_match',
                            'details': f"Matched rule: {rule['title']}"
                        }]
                    }
                    self.suspicious_chains.append(chain)
                    self._alert_on_chain(chain)
        
        # Check for known suspicious parent-child relationships
        if parent_pid in self.process_cache:
            parent = self.process_cache[parent_pid]
            chain = {
                'timestamp': datetime.now().isoformat(),
                'parent': parent,
                'child': process,
                'alerts': []
            }
            
            # Check suspicious patterns from config
            for pattern in self.config['suspicious_patterns']:
                if (parent['Name'].lower() == pattern['parent'].lower() and
                    process['Name'].lower() == pattern['child'].lower()):
                    chain['alerts'].append({
                        'type': 'suspicious_chain',
                        'details': pattern['description']
                    })
                    suspicious = True
            
            # Check for living-off-the-land binaries (LOLBins)
            if process['Name'].lower() in self.config['lolbins']:
                chain['alerts'].append({
                    'type': 'lolbin_execution',
                    'details': f"Known LOLBin {process['Name']} executed"
                })
                suspicious = True
            
            if suspicious:
                self.suspicious_chains.append(chain)
                self._alert_on_chain(chain)
        
        return suspicious
    
    def _check_dll_injection(self, process_id: int) -> List[dict]:
        """
        Monitor for DLL injection attempts
        
        Args:
            process_id: Process ID to monitor
        Returns:
            List of detected injection attempts
        """
        injections = []
        process = self.wmi.Win32_Process(ProcessId=process_id)
        
        # Monitor for common injection patterns
        try:
            for module in process[0].modules():
                # Check for unsigned DLLs
                if not module.VerifySignature():
                    injections.append({
                        'type': 'unsigned_dll',
                        'dll_name': module.Name,
                        'load_addr': hex(module.BaseAddress)
                    })
                
                # Check for DLLs loaded from suspicious paths
                for sus_path in self.config['suspicious_paths']:
                    if sus_path.lower() in module.Name.lower():
                        injections.append({
                            'type': 'suspicious_path_dll',
                            'dll_name': module.Name,
                            'path': module.Name
                        })
        except Exception as e:
            logging.error(f"Error checking DLL injection: {str(e)}")
        
        return injections
    
    def _alert_on_chain(self, chain: dict):
        """Generate alerts for suspicious process chains"""
        # Simple console output
        for alert in chain['alerts']:
            print(f"⚠️ {alert['details']}")
        
        # Create detailed log entry
        detailed_info = {
            'timestamp': chain['timestamp'],
            'process': {
                'name': chain['child']['Name'],
                'pid': chain['child']['ProcessId'],
                'command_line': chain['child']['CommandLine'],
                'create_time': chain['child']['CreationTime'],
                'parent_pid': chain['child']['ParentProcessId'],
                'parent_process': chain['parent']['Name'],
                'parent_command_line': chain['parent'].get('CommandLine', 'Unknown')
            },
            'alerts': chain['alerts'],
            'additional_info': {
                'event_id': '4688',
                'alert_type': 'process_chain'
            }
        }
        
        # Save detailed log - this part was incorrectly indented
        with open('suspicious_chains.json', 'a') as f:
            json.dump(detailed_info, f, indent=2)
            f.write('\n')
    
    def monitor_events(self):
        """Main monitoring loop for ETW events"""
        handle = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            
            for event in events:
                if event.EventID == 4688:  # Process Creation
                    try:
                        process = {
                            'Name': event.StringInserts[5],
                            'ProcessId': int(event.StringInserts[4]),
                            'ParentProcessId': int(event.StringInserts[7]),
                            'CommandLine': event.StringInserts[8],
                            'CreationTime': event.TimeGenerated.isoformat()
                        }
                        
                        # Update process cache
                        self.process_cache[process['ProcessId']] = process
                        
                        # Check for suspicious patterns
                        if self._check_process_chain(process):
                            # Check for DLL injection if process is suspicious
                            injections = self._check_dll_injection(process['ProcessId'])
                            if injections:
                                logging.warning(f"DLL injection detected in process {process['Name']}:")
                                for injection in injections:
                                    logging.warning(f"Type: {injection['type']}")
                                    logging.warning(f"DLL: {injection['dll_name']}")
                    
                    except Exception as e:
                        logging.error(f"Error processing event: {str(e)}")

def check_admin():
    """Check if script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    import ctypes
    
    # Check for admin privileges
    if not check_admin():
        print("This script requires administrator privileges!")
        print("Please run as administrator.")
        sys.exit(1)
    
    # Create default config if not provided
    config_path = 'config.yaml'
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    
    if not os.path.exists(config_path):
        print(f"No config file found at {config_path}, creating default configuration...")
        with open(config_path, 'w') as f:
            yaml.dump(DEFAULT_CONFIG, f)
        print(f"Default configuration saved to {config_path}")
    
    print("Starting ETW Monitor...")
    print("Press Ctrl+C to stop monitoring")
    
    try:
        monitor = ETWMonitor(config_path)
        monitor.monitor_events()
    except KeyboardInterrupt:
        print("\nStopping ETW Monitor...")
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
import psutil
import time
import json
import yaml
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from sigma_rule_loader import SigmaRuleLoader

class UserProcessMonitor:
    def __init__(self, config_path: str = None):
        """Initialize process monitor with user-level permissions"""
        self.config = self._load_config(config_path)
        self.process_cache: Dict[int, dict] = {}
        self.suspicious_activities: List[dict] = []
        self.start_time = datetime.now()
        
        # Set up logging directory structure
        self.log_dir = Path('logs')
        self.log_dir.mkdir(exist_ok=True)
        
        # Create a new log file for each session
        session_time = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.session_dir = self.log_dir / session_time
        self.session_dir.mkdir(exist_ok=True)
        
        # Set up logging configuration
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.session_dir / 'monitor.log'),
                logging.FileHandler(self.log_dir / 'full_history.log', mode='a')
            ]
        )
        
        # Initialize Sigma rules
        sigma_path = Path('sigma')
        self.sigma_loader = SigmaRuleLoader(sigma_path)
        self.rules = self.sigma_loader.load_rules()
        logging.info(f"Started new monitoring session. Loaded {len(self.rules)} Sigma rules")

    def _load_config(self, config_path: Optional[str]) -> dict:
        """Load or create default configuration"""
        default_config = {
            'suspicious_processes': [
                'powershell.exe',
                'cmd.exe',
                'wscript.exe',
                'cscript.exe',
                'rundll32.exe',
                'regsvr32.exe'
            ],
            'suspicious_paths': [
                r'\Temp\\',
                r'\Downloads\\',
                r'\Public\\',
                'AppData\\Local\\Temp'
            ],
            'check_interval': 1.0  # seconds
        }
        
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        return default_config

    def _get_process_info(self, proc: psutil.Process) -> dict:
        """Safely get process information"""
        info = {
            'pid': proc.pid,
            'name': '',
            'exe': '',
            'cmdline': [],
            'username': '',
            'create_time': '',
            'parent_pid': ''
        }
        
        try:
            info.update({
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': proc.cmdline(),
                'username': proc.username(),
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'parent_pid': proc.ppid()
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        
        return info

    def _check_suspicious_activity(self, proc_info: dict) -> List[str]:
        """Check for suspicious process characteristics"""
        alerts = []
        
        # Check Sigma rules
        for rule in self.rules:
            if self.sigma_loader.match_rule(rule, proc_info):
                alerts.append(f"Sigma Rule Match: {rule['title']}")
        
        # Check process name
        if proc_info['name'].lower() in (p.lower() for p in self.config['suspicious_processes']):
            alerts.append(f"Suspicious process name: {proc_info['name']}")
        
        # Check process path
        for sus_path in self.config['suspicious_paths']:
            if sus_path.lower() in str(proc_info['exe']).lower():
                alerts.append(f"Suspicious path: {proc_info['exe']}")
        
        # Check parent-child relationship if parent in cache
        if proc_info['parent_pid'] in self.process_cache:
            parent = self.process_cache[proc_info['parent_pid']]
            if parent['name'].lower() in (p.lower() for p in self.config['suspicious_processes']):
                alerts.append(f"Suspicious parent process: {parent['name']} -> {proc_info['name']}")
        
        return alerts

    def _log_suspicious_activity(self, proc_info: dict, alerts: List[str]):
        """Log suspicious activity to files and console"""
        # Create detailed activity record
        activity = {
            'timestamp': datetime.now().isoformat(),
            'process': {
                'name': proc_info['name'],
                'pid': proc_info['pid'],
                'command_line': proc_info['cmdline'],
                'executable_path': proc_info['exe'],
                'parent_pid': proc_info['parent_pid'],
                'parent_process': self.process_cache.get(proc_info['parent_pid'], {}).get('name', 'Unknown'),
                'parent_command_line': self.process_cache.get(proc_info['parent_pid'], {}).get('cmdline', []),
                'username': proc_info['username'],
                'create_time': proc_info['create_time']
            },
            'alerts': alerts,
            'additional_info': {
                'working_directory': proc_info.get('cwd', 'Unknown'),
                'parent_path': self.process_cache.get(proc_info['parent_pid'], {}).get('exe', 'Unknown'),
                'environment': proc_info.get('environ', {})
            }
        }
        
        self.suspicious_activities.append(activity)
        
        # Simple console output
        for alert in alerts:
            print(f"⚠️ {alert}")
        
        # Save detailed log
        with open(self.session_dir / 'alerts.json', 'a') as f:
            json.dump(activity, f, indent=2)
            f.write('\n')

    def _save_session_summary(self):
        """Save a summary of the monitoring session"""
        end_time = datetime.now()
        duration = end_time - self.start_time
        
        summary = {
            'session_start': self.start_time.isoformat(),
            'session_end': end_time.isoformat(),
            'duration_seconds': duration.total_seconds(),
            'total_alerts': len(self.suspicious_activities),
            'total_processes_monitored': len(self.process_cache),
            'sigma_rules_loaded': len(self.rules),
            'alert_types': {},
            'most_common_alerts': []
        }
        
        # Count alert types
        for activity in self.suspicious_activities:
            for alert in activity['alerts']:
                summary['alert_types'][alert] = summary['alert_types'].get(alert, 0) + 1
        
        # Sort alert types by frequency
        sorted_alerts = sorted(summary['alert_types'].items(), key=lambda x: x[1], reverse=True)
        summary['most_common_alerts'] = sorted_alerts[:10]  # Top 10 alerts
        
        # Save summary
        with open(self.session_dir / 'session_summary.json', 'w') as f:
            json.dump(summary, f, indent=2)
        
        logging.info(f"Monitoring session ended. Duration: {duration.total_seconds():.2f} seconds. "
                    f"Total alerts: {len(self.suspicious_activities)}")

    def monitor_processes(self):
        """Main monitoring loop"""
        logging.info("Starting process monitoring...")
        
        try:
            while True:
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
                    try:
                        if proc.pid in self.process_cache:
                            continue
                        
                        proc_info = self._get_process_info(proc)
                        self.process_cache[proc.pid] = proc_info
                        
                        alerts = self._check_suspicious_activity(proc_info)
                        if alerts:
                            self._log_suspicious_activity(proc_info, alerts)
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                # Clean up old processes
                for pid in list(self.process_cache.keys()):
                    if not psutil.pid_exists(pid):
                        del self.process_cache[pid]
                
                time.sleep(self.config['check_interval'])
        
        except KeyboardInterrupt:
            logging.info("Stopping process monitor...")
        finally:
            self._save_session_summary()

if __name__ == "__main__":
    monitor = UserProcessMonitor()
    monitor.monitor_processes()
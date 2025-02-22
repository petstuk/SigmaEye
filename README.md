# SigmaEye

A Windows process monitoring toolkit that combines ETW (Event Tracing for Windows) and user-level monitoring capabilities with Sigma rules integration. SigmaEye provides real-time detection of suspicious process behavior, LOLBins usage, and potential threats.

## Features

- **Dual Monitoring Capabilities**
  - ETW Monitor (Admin required) for system-level visibility
  - User-level Process Monitor for non-privileged monitoring
  
- **Integrated Detection**
  - Sigma rules integration
  - LOLBins (Living off the Land Binaries) detection
  - Suspicious process chain analysis
  - DLL injection monitoring

## Requirements

- Python 3.6+
- Windows Operating System
- Administrator privileges (for ETW monitoring)

### Python Dependencies
```bash
pip install pywin32 wmi pyyaml psutil
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ProcessGuardian
cd ProcessGuardian
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Clone Sigma rules (An older version of these already exist in this repository - to update this, delete the existing `sigma` folder and clone using the below command):
```bash
git clone https://github.com/SigmaHQ/sigma.git
```

4. Run either monitor:
```bash
# For ETW Monitor (as admin):
python3 etw_monitor.py

# For User Process Monitor:
python3 user_process_monitor.py
```

## Configuration

The `config.yaml` file allows customization of:
- LOLBins detection rules
- Suspicious process patterns
- DLL monitoring paths
- Alert thresholds

## Logging

- ETW Monitor logs to `etw_monitor.log`
- User Process Monitor creates logs in `logs/` directory
- Detailed JSON output for all alerts
- Process relationship tracking

## Contributing

Contributions welcome! Feel free to submit issues or pull requests.

## License

MIT License

# Rootkit Detector

This script detects hidden processes, startup anomalies, and suspicious drivers or DLLs in Windows. 

## Features
- Detect hidden processes using `psutil` vs `tasklist`
- Check startup folder entries
- Scan `System32` for suspicious DLLs and drivers
- Generate timestamped reports
- VirusTotal lookup support (limited to 4 requests/min)

## Requirements
- Python 3.x
- `psutil`, `requests`

## Install Dependencies

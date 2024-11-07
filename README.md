# BrightSec Scan Automation Project
This project automates the process of creating projects, fetching entrypoints, and initiating scans using BrightSec's API. It uses a set of Python scripts to integrate with BrightSec's DAST scanning capabilities.

### Files
- create_project.py: Creates a new project in BrightSec.
- create_discovery.py: Initiates a discovery scan for a given project.
- run_scan.py: Initiates a DAST scan on specified entrypoints.
- run_ep_scan_from_file.py: Main script to run a scan based on entrypoints from a file.
- run_ep_scan.py: Script to run all discovered enterypoints in project to scan.

### Prerequisites
- Python 3.x
- install requirements.txt 
- BrightSec API Key
### Example how to run 

`python3 run_ep_scan_from_file.py --api_key "<YOUR_API_KEY>" --scan_name "<SCAN_NAME>" --project_name "<PROJECT_NAME>" --project_id "<PROJECT_ID>" --entrypoints_file "enterypointIDs.txt"`






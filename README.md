# BrightSec Scan Automation Project
This project automates the processes of creating BrightSec projects, running discovery scans, retrieving entry points, and initiating Dynamic Application Security Testing (DAST) scans. It leverages BrightSec’s API and Python scripts to streamline security workflows, making it ideal for CI/CD pipelines or security operations.

## Table of Contents
### Prerequisites
Scripts Overview
1. Project Creation Script
2. Discovery Scan Script
3. Entry Points Fetch and Filter Script
4. Scan Automation Scripts
- Usage Examples
- Error Handling
- Use Cases

### Overview
BrightSec Scan Automation Project simplifies BrightSec API integrations to reduce repetitive tasks. The scripts provide a complete workflow from creating projects to performing targeted scans on specific entry points.

### Features
Automated Project Creation: Create BrightSec projects in bulk with group associations.
Discovery Scans: Identify and map application entry points efficiently.
Entry Point Filtering: Target specific URLs for customized scans.
Scan Automation: Execute DAST scans on selected or all entry points.
Pagination Handling: Fetch data without losing information in large datasets.
Dynamic Configurations: Customize parameters like scan names, project IDs, and entry points.
### Prerequisites
- Python 3.7 or later installed.
- BrightSec API key with appropriate permissions.
- Access to BrightSec projects and configurations.
- Required Python libraries (argparse, requests, etc.).
### Scripts Overview
1. Project Creation Script
File: create_project.py

Reads project names from a file and creates projects in BrightSec.
Associates projects with specific group IDs.
Introduces a delay to avoid API rate-limiting.
Execution Example:
`python create_project.py --apiKey <API_KEY> --groupIds <GROUP_IDS> --projectFile <FILE_PATH>`
2. Discovery Scan Script
File: create_discovery.py

Initiates discovery scans to map entry points and subdomains.
Supports custom configurations for optimized crawling.
Execution Example:

`python create_discovery.py --apiKey <API_KEY> --projectId <PROJECT_ID> --targetUrl <TARGET_URL> --nameDiscovery <DISCOVERY_NAME>`
3. Entry Points Fetch and Filter Script
File: run_ep_scan.py and filter_ep_run_scan.py 

First one is running scan based on all enterypoints found, second one is going to filter the enterypoints(for now containing "hm") and run the scan.
Retrieves all entry points for a project and filters them based on specified criteria.
Handles pagination to ensure all entry points are fetched.
Execution Example:

`python run_ep_scan.py --apiKey <API_KEY> --projectId <PROJECT_ID> --filter "specific-string"`
4. Scan Automation Scripts
Files: run_scan.py and run_ep_scan_from_file.py 

Automate DAST scans using either a file-based entry point list or filtered entry points.
Construct detailed payloads for customized scan execution.
Execution Example (File-Based):

`python run_ep_scan_from_file.py --apiKey <API_KEY> --scanName <SCAN_NAME> --projectId <PROJECT_ID> --entrypointsFile <FILE_PATH>`
### Usage Examples
- Create Projects from File:
Use create_project.py to create multiple projects based on a text file.

- Run a Discovery Scan:
Initiate a scan to identify all application entry points with create_discovery.py.

- Filter and Scan Entry Points:
Target specific URLs by filtering entry points with run_ep_scan.py and execute a focused scan.

- Scan Entry Points from File:
Load entry points from a file and initiate a scan using run_ep_scan_from_file.py.

#### Error Handling
API Request Failures: Logs detailed error messages with HTTP status codes and responses.
File Handling Errors: Ensures user-friendly feedback for missing or malformed files.
Graceful Exit: Provides meaningful logs for troubleshooting without abrupt terminations.
### Use Cases
Automate security scanning as part of CI/CD pipelines.
Manage large BrightSec projects with minimal manual intervention.
Perform targeted scans on specific application sections.
Simplify onboarding for new applications into the BrightSec platform.
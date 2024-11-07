import argparse
import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="BrightSec Scan Script")
    parser.add_argument('--api_key', type=str, required=True, help="API Key for BrightSec")
    parser.add_argument('--scan_name', type=str, required=True, help="Scan name for BrightSec")
    parser.add_argument('--project_name', type=str, required=True, help="Project name")
    parser.add_argument('--project_id', type=str, required=True, help="Project ID")
    parser.add_argument('--entrypoints_file', type=str, required=True, help="Path to the file with entry point IDs")
    return parser.parse_args()

args = get_args()

api_key = args.api_key  
scan_name = args.scan_name  
project_name = args.project_name  
project_id = args.project_id 
entrypoints_file = args.entrypoints_file

def get_entry_points_from_file(filepath):
    """Reads entry points from a file."""
    try:
        with open(filepath, 'r') as file:
            entry_points = [line.strip() for line in file.readlines() if line.strip()]
            logger.info(f"Loaded {len(entry_points)} entry points from {filepath}")
            return entry_points
    except Exception as e:
        logger.error(f"Error reading entry points from file: {e}")
        return []

def start_scan(api_key, project_id, project_name, entry_point_ids, scan_name):
    """Starts a scan with the provided entry points."""
    if len(entry_point_ids) == 0:
        logger.info(f"No entry points found for project {project_name}. Skipping scan.")
        return

    scan_payload = {
        "name": scan_name,
        "poolSize": 10,
        "smart": True,
        "optimizedCrawler": True,
        "maxInteractionsChainLength": 3,
        "skipStaticParams": True,
        "slowEpTimeout": None,
        "extraHosts": None,
        "fileId": None,
        "targetTimeout": 5,
        "exclusions": {
            "requests": [
                {
                    "patterns": [
                        r"(?<excluded_file_ext>(\/\/[^?#]+\.)((?<image>jpg|jpeg|png|gif|svg|eps|webp|tif|tiff|bmp|psd|ai|raw|cr|pcx|tga|ico)|(?<video>mp4|avi|3gp|flv|h264|m4v|mkv|mov|mpg|mpeg|vob|wmv)|(?<audio>wav|mp3|ogg|wma|mid|midi|aif)|(?<document>doc|docx|odt|pdf|rtf|ods|xls|xlsx|odp|ppt|pptx)|(?<font>ttf|otf|fnt|fon))(?:$|#|\?))"
                    ],
                    "methods": []
                },
                {
                    "patterns": ["logout|signout"]
                }
            ]
        },
        "projectId": project_id,
        "entryPointIds": entry_point_ids,
        "schedule": {"type": "future", "nextRunAt": "2024-08-24T07:00:54.830Z"},
#        "repeaters": ["nqV2nLFHVY97a1RPgeMwBG"],
        "labels": [],
        "attackParamLocations": ["query", "fragment", "body"],
        "module": "dast",
        "buckets": ["api", "business_logic", "client_side", "cve", "legacy", "server_side"],
        "info": {
            "source": "api"
        }
    }

    url = f"https://eu.brightsec.com/api/v1/scans"
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': f"api-key {api_key}",
    }

    session = requests.Session()
    request = requests.Request('POST', url, headers=headers, json=scan_payload)
    prepared_request = session.prepare_request(request)

    try:
        response = session.send(prepared_request)
        if response.status_code == 201:
            response_json = response.json()
            scan_id = response_json.get('id', 'No ID found in response')
            logger.info(f"Request succeeded with status code 201. Scan ID: {scan_id}")
        else:
            logger.error(f"Request failed with status code {response.status_code}: {response.text}")
    except ValueError as e:
        logger.error(f"ValueError: {e}")

# Load entry point IDs from file and start scan
entry_point_ids = get_entry_points_from_file(entrypoints_file)
if entry_point_ids:
    start_scan(api_key, project_id, project_name, entry_point_ids, scan_name)

print(f"Entry point IDs have been processed and scans have been initiated.")

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
    return parser.parse_args()

args = get_args()

api_key = args.api_key  # API key passed as argument
scan_name = args.scan_name  
project_name = args.project_name  
project_id = args.project_id 

# Function to fetch entry points for a specific project
def fetch_entry_points(project_id):
    """Fetch entry points for a specific project from the BrightSec API."""
    headers = {
        "accept": "application/json",
        "Authorization": f"api-key {api_key}",
        "Content-Type": "application/json",
    }

    base_url = f'https://eu.brightsec.com/api/v2/projects/{project_id}/entry-points'
    url = f"{base_url}?limit=500"
    entry_point_ids = []

    page_number = 1
    while url:
        logger.info(f"Fetching page {page_number} of entry points for project {project_id}")
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            new_entry_points = [item['id'] for item in data['items'] if item.get('status') != 'tested']
            entry_point_ids.extend(new_entry_points)

            # Pagination handling
            if 'items' in data and data['items']:
                last_id = data['items'][-1]['id']
                last_created_at = data['items'][-1]['createdAt']
                url = f"{base_url}?limit=500&nextId={last_id}&nextCreatedAt={last_created_at}"
                page_number += 1
            else:
                url = None
        else:
            logger.error(f"Failed to fetch data for project {project_id}: {response.status_code}")
            url = None

    logger.info(f"Fetched {len(entry_point_ids)} entry points for project {project_id}.")
    
    # Save entry points to a .txt file
    with open('entrypoints.txt', 'w') as f:
        for entry_point in entry_point_ids:
            f.write(f"{entry_point}\n")
    
    logger.info(f"Entry points have been saved to 'entrypoints.txt'.")
    return entry_point_ids

# Function to start a scan
def start_scan(project_id, project_name, entry_point_ids):
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
        "targetTimeout": 5,
        "projectId": project_id,
        "entryPointIds": entry_point_ids,
        "schedule": {"type": "future", "nextRunAt": "2024-08-24T07:00:54.830Z"},
        "module": "dast",
        "buckets": ["api", "business_logic", "client_side", "cve", "legacy", "server_side"],
        "info": {"source": "api"}
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

# Fetch entry points and write to file
entry_point_ids = fetch_entry_points(project_id)

# If there are entry points, start the scan
if entry_point_ids:
    start_scan(project_id, project_name, entry_point_ids)

print(f"Entry point IDs have been processed and scans have been initiated.")

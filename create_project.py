import requests
import json
import time
import logging
import os
import sys
import argparse

# Configure logging
logging.basicConfig(filename='project_creation.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def create_project(api_key, group_ids, project_name):
    payload = {
        "name": project_name,
        "groupIds": group_ids.split(',')  # Expecting a comma-separated string
    }

    headers = {
        "Authorization": f"Api-Key {api_key}",
        "Content-Type": "application/json"
    }

    print("Creating project with payload:")
    print(json.dumps(payload, indent=2))

    response = requests.post("https://app.brightsec.com/api/v1/projects", headers=headers, json=payload)
    http_code = response.status_code
    response_body = response.text

    if http_code == 204:  # Success
        logging.info(f"Project '{project_name}' created successfully.")
    else:
        print(f"Failed to create project '{project_name}' due to an error: {http_code}")
def main():
    parser = argparse.ArgumentParser(description='Create projects in BrightSec.')
    parser.add_argument('--apiKey', required=True, help='API Key for authentication')
    parser.add_argument('--groupIds', required=True, help='Comma-separated group IDs')
    parser.add_argument('--projectFile', required=True, help='Path to the project name file')
    
    args = parser.parse_args()

    try:
        with open(args.projectFile, 'r') as file:
            for line in file:
                project_name = line.strip()
                create_project(args.apiKey, args.groupIds, project_name)
                time.sleep(7)  # Sleep to prevent rate limiting

        print("All projects have been created.")
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

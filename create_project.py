import requests
import json
import time
import logging
import os
import sys

# Configure logging to output to the pipeline logs
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Retrieve API key, project file path, and group IDs from environment variables
API_KEY = os.getenv('BRIGHTSEC_API_KEY')
PROJECT_FILE = os.getenv('PROJECT_FILE')
GROUP_IDS = os.getenv('GROUP_IDS', '').split(',')  # Split comma-separated group IDs into a list
API_URL = "https://app.brightsec.com/project"

if not API_KEY:
    logging.error("API key not found. Please set the BRIGHTSEC_API_KEY environment variable.")
    sys.exit(1)

if not PROJECT_FILE:
    logging.error("Project file not found. Please set the PROJECT_FILE environment variable.")
    sys.exit(1)

if not GROUP_IDS or GROUP_IDS == ['']:
    logging.error("Group IDs not found. Please set the GROUP_IDS environment variable.")
    sys.exit(1)

def create_project(project_name):
    payload = {
        "name": project_name,
        "groupIds": GROUP_IDS
    }

    headers = {
        "Authorization": f"api-key {API_KEY}",
        "Content-Type": "application/json"
    }

    logging.info(f"Creating project: {project_name}")
    response = requests.post(API_URL, headers=headers, json=payload)
    http_code = response.status_code
    response_body = response.text

    if http_code == 201:
        logging.info(f"Project '{project_name}' created successfully.")
    else:
        logging.error(f"Failed to create project '{project_name}'. HTTP code: {http_code}. Response: {response_body}")

def main():
    try:
        with open(PROJECT_FILE, 'r') as file:
            for line in file:
                project_name = line.strip()
                create_project(project_name)
                time.sleep(7)  # Delay to avoid overwhelming the API
        logging.info("All projects have been created.")
    except Exception as e:
        logging.error(f"Error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

import requests
import json
import time
import logging
import os
import sys 

# Configure logging
logging.basicConfig(filename='/home/hana/project_creation.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Fixed file path for the project file
PROJECT_FILE = os.getenv('PROJECT_FILE')
API_KEY = os.getenv('BRIGHTSEC_API_KEY') 
GROUP_IDS = os.getenv('GROUP_IDS', '').split(',')
API_URL = "https://app.brightsec.com/project"

if not API_KEY:
    print("API key not found. Please set the BRIGHTSEC_API_KEY environment variable.")
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

    print("Creating project with payload:")
    print(json.dumps(payload, indent=2))

    response = requests.post(API_URL, headers=headers, json=payload)
    http_code = response.status_code
    response_body = response.text

    if http_code == 201:  # Ensure 201 status for success
        logging.info(f"Project '{project_name}' created successfully.")
    else:
        logging.error(f"Failed to create project '{project_name}'. HTTP code: {http_code}. Response: {response_body}")

def main():
    with open(PROJECT_FILE, 'r') as file:
        for line in file:
            project_name = line.strip()
            create_project(project_name)
            time.sleep(7)

    print("All projects have been created.")

if __name__ == "__main__":
    main()
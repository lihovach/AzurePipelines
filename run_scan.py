import requests
import json
import argparse

def run_scan(api_key, project_id, target_url, scan_name):
    url = "https://app.brightsec.com/api/v1/scans"

    headers = {
        'Authorization': f"Api-Key {api_key}",
        'Content-Type': 'application/json'
    }

    payload = {
        "name": scan_name,  # Use the provided scan name here
        "poolSize": 10,
        "smart": True,
        "optimizedCrawler": True,
        "maxInteractionsChainLength": 3,
        "skipStaticParams": True,
        "slowEpTimeout": 1000,
        "exclusions": {
            "requests": [
                {
                    "methods": [],
                    "patterns": [
                        r"(?<excluded_file_ext>(\/\/[^?#]+\.)((?<image>jpg|jpeg|png|gif|svg|eps|webp|tif|tiff|bmp|psd|ai|raw|cr|pcx|tga|ico)|(?<video>mp4|avi|3gp|flv|h264|m4v|mkv|mov|mpg|mpeg|vob|wmv)|(?<audio>wav|mp3|ogg|wma|mid|midi|aif)|(?<document>doc|docx|odt|pdf|rtf|ods|xls|xlsx|odp|ppt|pptx)|(?<font>ttf|otf|fnt|fon))(?:$|#|\?))"
                    ]
                },
                {
                    "methods": [],
                    "patterns": ["logout|signout"]
                }
            ]
        },
        "projectId": project_id,
        "crawlerUrls": [target_url],
        "labels": [],
        "discoveryTypes": ["crawler"],
        "attackParamLocations": ["query", "fragment", "body"],
        "module": "dast",
        "tests": [
            "amazon_s3_takeover", "jwt", "broken_saml_auth", "brute_force_login", 
            "common_files", "cookie_security", "csrf", "xss", "css_injection", 
            "default_login_location", "directory_listing", "email_injection", 
            "file_upload", "full_path_disclosure", "graphql_introspection", 
            "header_security", "html_injection", "http_method_fuzzing", 
            "iframe_injection", "improper_asset_management", 
            "insecure_tls_configuration", "ldapi", "lfi", "nosql", 
            "open_cloud_storage", "open_database", "osi", "proto_pollution", 
            "rfi", "secret_tokens", "ssti", "server_side_js_injection", 
            "ssrf", "sqli", "stored_xss", "unvalidated_redirect", 
            "version_control_systems", "wordpress", "xxe", "xpathi", 
            "business_constraint_bypass", "date_manipulation", 
            "excessive_data_exposure", "id_enumeration", 
            "insecure_output_handling", "mass_assignment", 
            "prompt_injection", "cve_test", "retire_js"
        ],
        "info": {
            "source": "ui",
            "client": {
                "name": "bright-ui",
                "version": "v4.91.0"
            }
        }
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(payload))
        if response.status_code == 201:
            print(f"Scan '{scan_name}' for project {project_id} started successfully!")
        else:
            print(f"Failed to start scan. Status code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"Error during the scan: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run a BrightSSec scan')
    
    parser.add_argument('--apiKey', required=True, help='BrightSec API Key')
    parser.add_argument('--projectId', required=True, help='Project ID for the scan')
    parser.add_argument('--targetUrl', required=True, help='Target URL for the scan')
    parser.add_argument('--nameScan', required=True, help='Name for the scan')  # New argument for the scan name

    args = parser.parse_args()
    
    run_scan(args.apiKey, args.projectId, args.targetUrl, args.nameScan)

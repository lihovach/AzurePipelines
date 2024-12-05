import argparse
import gzip
import os
import requests

def fetch_and_save_file(api_key, scan_id, output_directory="."):
    """
    Fetch a GZIP file from BrightSec API, decompress it, and save without any extension.
    """
    url = f"https://eu.brightsec.com/api/v1/scans/{scan_id}/logs/archive"
    headers = {
        "Authorization": f"Api-Key {api_key}",
        "Accept": "application/json"
    }

    try:
        # Send GET request to the API
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        # Save the fetched GZIP file
        gz_path = os.path.join(output_directory, "response.gz")
        with open(gz_path, "wb") as gz_file:
            gz_file.write(response.content)
        print(f"GZIP file saved to {gz_path}")

        # Decompress the GZIP file
        decompressed_path = os.path.join(output_directory, "response")
        with gzip.open(gz_path, "rb") as gz_file:
            with open(decompressed_path, "wb") as decompressed_file:
                decompressed_file.write(gz_file.read())
        print(f"Decompressed file saved to {decompressed_path}")

        # Process the decompressed file to filter High and Critical vulnerabilities
        filter_vulnerabilities(decompressed_path, output_directory)

    except requests.exceptions.RequestException as e:
        print(f"Error fetching the file: {e}")
    except gzip.BadGzipFile:
        print("Error: The file fetched is not a valid GZIP archive.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def filter_vulnerabilities(file_path, output_directory):
    """
    Read the decompressed file and filter lines containing High or Critical vulnerabilities.
    """
    filtered_path = os.path.join(output_directory, "filtered_vulnerabilities.txt")
    try:
        print(f"Opening decompressed file: {file_path}")
        with open(file_path, "r") as file, open(filtered_path, "w") as output_file:
            has_matches = False
            for line in file:
                if "High" in line or "Critical" in line:
                    output_file.write(line)
                    has_matches = True

            if has_matches:
                print(f"Filtered vulnerabilities saved to {filtered_path}")
            else:
                print("No High or Critical vulnerabilities found.")
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
    except Exception as e:
        print(f"Error filtering vulnerabilities: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch, decompress, and filter vulnerabilities from BrightSec API.")
    parser.add_argument("--api-key", required=True, help="Your BrightSec API key.")
    parser.add_argument("--scan-id", required=True, help="The scan ID for fetching logs.")
    parser.add_argument("--output-dir", default=".", help="Directory to save the files (default: current directory).")

    args = parser.parse_args()

    fetch_and_save_file(args.api_key, args.scan_id, args.output_dir)

import argparse
import gzip
import os
import csv
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
    Read the decompressed file, extract and filter lines containing High or Critical vulnerabilities,
    and save them into a CSV file with appropriate fields.
    """
    csv_path = os.path.join(output_directory, "filtered_vulnerabilities.csv")
    try:
        print(f"Opening decompressed file: {file_path}")
        with open(file_path, "r") as file, open(csv_path, "w", newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            # Define CSV header
            csv_writer.writerow(["Timestamp", "Severity", "Type", "Details", "URL"])

            has_matches = False
            for line in file:
                if "High" in line or "Critical" in line:
                    try:
                        # Parse the line
                        timestamp, _, log_details = line.partition(" - WARNING - Found new ")
                        vulnerability_type, _, rest = log_details.partition("’ (")
                        severity, _, details_url = rest.partition(") vulnerability at: ")
                        url, _, _ = details_url.partition(" | {}")

                        # Write to CSV
                        csv_writer.writerow([
                            timestamp.strip(),
                            severity.strip(),
                            vulnerability_type.strip("‘’"),
                            "Vulnerability found",  # Static description for now
                            url.strip()
                        ])
                        has_matches = True
                    except Exception as e:
                        print(f"Error parsing line: {line}\n{e}")
            
            if has_matches:
                print(f"Filtered vulnerabilities saved to {csv_path}")
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

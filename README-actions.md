# BrightSec Full Scan GitHub Actions Workflow

This document describes how to use and customize the provided GitHub Actions workflow for running a full security scan of your project with Bright Security (BrightSec).

---

## Workflow Overview

- **Name:** BrightSec Full Scan
- **Trigger:** On push to the `main` branch.
- **Purpose:** Automate the process of discovery, entrypoint listing, and scanning of your application using BrightSec’s GitHub Actions integrations.

---

## Prerequisites

Before using this workflow, **ensure you have:**

1. **BrightSec Account:**  
   An active BrightSec account with required permissions for API access.

2. **Project Setup on BrightSec:**  
   - The `PROJECT_ID` for your target project.
   - The `AUTH_ID` if authentication is required for scans.

3. **GitHub Secrets and Variables:**  
   - `BRIGHTSEC_TOKEN` as a GitHub Actions secret (API token from your BrightSec account).
   - `PROJECT_ID`, `AUTH_ID`, and `HOSTNAME` as repository variables or secrets.
   - Example for `HOSTNAME`: `eu.brightsec.com` (just the domain, no protocol).

   To add these:
   - Go to your GitHub repository > Settings > Secrets and variables > Actions.

---

## Workflow Steps

1. **Checkout Repository**
    - Uses `actions/checkout@v4` to fetch your code.

2. **Run a Bright Discovery**
    - Starts discovery using `NeuraLegion/run-discovery@v1.1`.
    - Discovers entrypoints and prepares the application for scanning.

3. **Extract Discovery ID**
    - Parses the discovery URL to extract the discovery ID for use in later steps.
    - Uses Bash string manipulation for reliability.

4. **List Project Entrypoints**
    - Uses `NeuraLegion/list-entrypoints@v1` to retrieve discovered entrypoints for the project.
    - Filters by connectivity and status (e.g., only new and vulnerable).

5. **Run a Bright Security Scan**
    - Uses `NeuraLegion/run-scan@v1.2` to perform the security scan on discovered targets.
    - Excludes file extensions typically not relevant for web security scans.

---

## Customization Tips

- **Discovery & Scan URLs:**  
  Edit `crawler_urls` to match your application's base URL.

- **Discovery & Scan Types:**  
  The workflow uses `"crawler"` for discovery and scanning; modify as required for your use case.

- **Scan Exclusions:**  
  The `exclude_params` field excludes common static assets. Adjust as needed for your project.

- **Entry Points Filtering:**  
  Adjust `limit`, `connectivity`, and `status` in the List Entrypoints step to control which endpoints are scanned.

- **Uncomment Steps as Needed:**
  - The `wait-for-discovery` and `stop-scan` steps are commented out for optional use. Uncomment if you want to wait for discovery completion or stop a scan programmatically.

---

## Security Recommendations

- **Do not log sensitive tokens or secrets.**
- Use the smallest required permissions for your GitHub token and BrightSec API token.
- Regularly rotate your API tokens.

---

## Troubleshooting

- **Invalid URL or Credentials:**  
  Ensure `HOSTNAME` is set to the domain only (e.g., `eu.brightsec.com`).  
  Do not include `https://` or trailing slashes.

- **Missing Variables:**  
  If steps fail due to missing variables, make sure all required secrets and variables are populated.

- **BrightSec Scan/Test Errors:**  
  If scan fails due to invalid test types, consult the [BrightSec documentation](https://docs.brightsec.com/docs/scan-tests) for a list of supported tests.

---

## Example Workflow File

Here’s a simplified and readable version of your workflow.  
**Replace placeholder values as necessary.**

```yaml
name: BrightSec Full Scan

on:
  push:
    branches:
      - main

jobs:
  brightsec-full-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Run a Bright Discovery
        id: run_discovery
        uses: NeuraLegion/run-discovery@v1.1
        with:
          api_token: ${{ secrets.BRIGHTSEC_TOKEN }}
          project_id: ${{ vars.PROJECT_ID }}
          hostname: ${{ vars.HOSTNAME }}
          auth_object_id: ${{ vars.AUTH_ID }}
          discovery_types: '[ "crawler" ]'
          crawler_urls: '[ "https://brokencrystals.com" ]'
          name: GitHub discovery ${{ github.sha }}

      - name: Get the output discovery id
        id: extract_id
        run: |
          url="${{ steps.run_discovery.outputs.url }}"
          id="${url##*/}"
          echo "Discovery ID is: $id"
          echo "discovery_id=$id" >> $GITHUB_OUTPUT

      - name: List Project Entrypoints
        id: entrypoints
        uses: NeuraLegion/list-entrypoints@v1
        with:
          api_token: ${{ secrets.BRIGHTSEC_TOKEN  }}
          project_id: ${{ vars.PROJECT_ID }}
          hostname: ${{ vars.HOSTNAME }}
          limit: 50
          connectivity: ok,unreachable
          status: new,vulnerable

      - name: Run a Bright Security Scan
        id: run_scan
        uses: NeuraLegion/run-scan@v1.2
        with:
          name: GitHub scan ${{ github.sha }}
          api_token: ${{ secrets.BRIGHTSEC_TOKEN }}
          hostname: ${{ vars.HOSTNAME }}
          project_id: ${{ vars.PROJECT_ID }}
          auth_object_id: ${{ vars.AUTH_ID }}
          discovery_types: |
            [ "crawler" ]
          crawler_urls: |
            [ "https://brokencrystals.com" ]
          exclude_params: |
            [ "?<excluded_file_ext>(\/\/[^?#]+\.)((?<image>jpg|jpeg|png|gif|svg|eps|webp|tif|tiff|bmp|psd|ai|raw|cr|pcx|tga|ico)|(?<video>mp4|avi|3gp|flv|h264|m4v|mkv|mov|mpg|mpeg|vob|wmv)|(?<audio>wav|mp3|ogg|wma|mid|midi|aif)|(?<document>doc|docx|odt|pdf|rtf|ods|xls|xlsx|odp|ppt|pptx)|(?<font>ttf|otf|fnt|fon))(?:$|#|\?))", "logout|signout" ]
```

---

## References

- [BrightSec Official Documentation](https://docs.brightsec.com/)
- [BrightSec GitHub Actions Marketplace](https://github.com/marketplace?query=NeuraLegion)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)


**If you have questions or encounter issues, consult the BrightSec documentation or your security team.**

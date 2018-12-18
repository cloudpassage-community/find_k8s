# find_k8s
Find Kubernetes across your environment, even if it's not installed via your package manager.

## What it does

This script uses the server processes inventory feature as well as the SVM
module's installed software inventory feature to search for all instances of
Kubernetes in your Halo-protected environment. Indicates which are vulnerable
to CVE-2018-1002105.

## Requirements
* Python 2.7
* CloudPassage Python SDK
* CloudPassage API keys (auditor, or read-only)

## Running the tool
* Set environment variables for `HALO_API_KEY` and `HALO_API_SECRET_KEY`
* Run the tool: `python2.7 /find_k8s.py`

## Output
This produces verbose information to STDOUT as well as CSV and JSON files

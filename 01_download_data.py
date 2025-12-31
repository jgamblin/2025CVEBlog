#!/usr/bin/env python3
"""
Download CVE Data Sources for 2025 CVE Review
1. NVD JSON from handsonhacking.org (large file ~1GB+)
2. CVE V5 List from GitHub
"""

import os
import json
import requests
from pathlib import Path
import subprocess
from tqdm import tqdm

# Create data directory
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

def download_nvd_json():
    """Download the large NVD JSON file with progress bar"""
    url = "https://nvd.handsonhacking.org/nvd.json"
    output_file = DATA_DIR / "nvd.json"
    
    if output_file.exists():
        print(f"NVD JSON already exists at {output_file}")
        print(f"File size: {output_file.stat().st_size / (1024**3):.2f} GB")
        return output_file
    
    print(f"Downloading NVD JSON from {url}...")
    print("This is a large file (~1GB+), please be patient...")
    
    # Stream the download with progress bar
    response = requests.get(url, stream=True)
    response.raise_for_status()
    
    total_size = int(response.headers.get('content-length', 0))
    
    with open(output_file, 'wb') as f:
        with tqdm(total=total_size, unit='iB', unit_scale=True, unit_divisor=1024) as pbar:
            for chunk in response.iter_content(chunk_size=8192):
                size = f.write(chunk)
                pbar.update(size)
    
    print(f"Downloaded NVD JSON to {output_file}")
    print(f"File size: {output_file.stat().st_size / (1024**3):.2f} GB")
    return output_file

def clone_cvelistv5():
    """Clone the CVE V5 list repository"""
    repo_url = "https://github.com/CVEProject/cvelistV5.git"
    output_dir = DATA_DIR / "cvelistV5"
    
    if output_dir.exists():
        print(f"CVE List V5 repository already exists at {output_dir}")
        print("Pulling latest changes...")
        subprocess.run(["git", "-C", str(output_dir), "pull"], check=True)
        return output_dir
    
    print(f"Cloning CVE List V5 from {repo_url}...")
    print("This repository is large, please be patient...")
    
    # Shallow clone to save time and space
    subprocess.run([
        "git", "clone", 
        "--depth", "1",  # Shallow clone
        repo_url, 
        str(output_dir)
    ], check=True)
    
    print(f"Cloned CVE List V5 to {output_dir}")
    return output_dir

def verify_data():
    """Verify downloaded data"""
    nvd_file = DATA_DIR / "nvd.json"
    cvelist_dir = DATA_DIR / "cvelistV5"
    
    print("\n" + "="*50)
    print("Data Verification")
    print("="*50)
    
    if nvd_file.exists():
        size_gb = nvd_file.stat().st_size / (1024**3)
        print(f"✓ NVD JSON: {size_gb:.2f} GB")
        
        # Quick validation - read first few bytes
        with open(nvd_file, 'r') as f:
            first_char = f.read(1)
            if first_char in ['{', '[']:
                print("  ✓ Valid JSON structure detected")
            else:
                print("  ✗ Warning: May not be valid JSON")
    else:
        print("✗ NVD JSON not found")
    
    if cvelist_dir.exists():
        # Count CVE files
        cve_count = sum(1 for _ in cvelist_dir.rglob("CVE-*.json"))
        print(f"✓ CVE List V5: {cve_count:,} CVE files found")
    else:
        print("✗ CVE List V5 not found")

def main():
    print("="*50)
    print("2025 CVE Data Download Script")
    print("="*50)
    
    # Download NVD JSON
    print("\n[1/2] Downloading NVD JSON...")
    try:
        download_nvd_json()
    except Exception as e:
        print(f"Error downloading NVD JSON: {e}")
    
    # Clone CVE List V5
    print("\n[2/2] Cloning CVE List V5...")
    try:
        clone_cvelistv5()
    except Exception as e:
        print(f"Error cloning CVE List V5: {e}")
    
    # Verify data
    verify_data()
    
    print("\n" + "="*50)
    print("Download complete! Run 02_process_data.py next.")
    print("="*50)

if __name__ == "__main__":
    main()

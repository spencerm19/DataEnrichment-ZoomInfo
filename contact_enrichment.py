import json
import logging
import os
import time
import requests
from datetime import datetime
from pathlib import Path
import pandas as pd
from typing import Dict, Any, Optional
from requests_ratelimiter import LimiterSession
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from pythonjsonlogger import jsonlogger

# Configure logging
logger = logging.getLogger('data-enrichment')
handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Load environment variables
load_dotenv()

# Rate limiting configuration
API_RATE_LIMIT = "100/minute"  # Adjust based on your API tier
session = LimiterSession(per_second=2)  # 2 requests per second max

# Constants for file paths
INPUT_DIR = Path("data/input")
OUTPUT_DIR = Path("data/output")
ARCHIVE_DIR = Path("data/archive")

def get_contact_enrichment_data(entry: dict, jwt_token: str) -> Optional[dict]:
    """
    Retrieves contact enrichment data from the ZoomInfo API.
    
    Args:
        entry (dict): Dictionary containing contact information
        jwt_token (str): JWT token for authentication
        
    Returns:
        dict: Enriched contact data or None if error
    """
    url = "https://api.zoominfo.com/enrich/contact-master"
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {jwt_token}"
    }
    
    payload = {
        "matchContactInput": [{
            "zi_c_name": f"{entry.get('first_name', '')} {entry.get('last_name', '')}",
            "email": entry.get('email', ''),
            "phone": entry.get('phone', ''),
            "company": {
                "zi_c_name": entry.get('company_name', '')
            }
        }],
        "outputFields": [
            "zi_c_name",
            "zi_c_first_name",
            "zi_c_last_name",
            "zi_c_email",
            "zi_c_title",
            "zi_c_phone",
            "zi_c_direct_phone",
            "zi_c_mobile_phone",
            "zi_c_company_name",
            "zi_c_company_website",
            "zi_c_company_id",
            "zi_c_location_id",
            "zi_c_street",
            "zi_c_city",
            "zi_c_state",
            "zi_c_zip",
            "zi_c_country",
            "zi_c_linkedin_url",
            "zi_c_department",
            "zi_c_job_function",
            "zi_c_management_level"
        ]
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error enriching contact: {str(e)}")
        return None

def update_contact_data(entry: dict, new_data_item: dict) -> dict:
    """
    Updates contact data with enriched information.
    
    Args:
        entry (dict): Original contact data
        new_data_item (dict): New enriched data
        
    Returns:
        dict: Updated contact data
    """
    if "data" in new_data_item and new_data_item["data"].get("result"):
        contact_data = new_data_item["data"]["result"][0]["data"]
        
        fields_to_update = [
            "zi_c_name",
            "zi_c_first_name",
            "zi_c_last_name",
            "zi_c_email",
            "zi_c_title",
            "zi_c_phone",
            "zi_c_direct_phone",
            "zi_c_mobile_phone",
            "zi_c_company_name",
            "zi_c_company_website",
            "zi_c_company_id",
            "zi_c_location_id",
            "zi_c_street",
            "zi_c_city",
            "zi_c_state",
            "zi_c_zip",
            "zi_c_country",
            "zi_c_linkedin_url",
            "zi_c_department",
            "zi_c_job_function",
            "zi_c_management_level"
        ]
        
        for field in fields_to_update:
            if entry.get(field, "") == "" and field in contact_data:
                entry[field] = contact_data[field]
    else:
        logger.warning("No 'data' key in response or 'result' list is empty")
        
    return entry

def process_file(input_file: str, jwt_token: str, last_auth_time: float, username: str, password: str) -> tuple:
    """
    Process a single input file for contact enrichment.
    
    Args:
        input_file (str): Path to input CSV file
        jwt_token (str): JWT token for authentication
        last_auth_time (float): Timestamp of last authentication
        username (str): ZoomInfo username
        password (str): ZoomInfo password
        
    Returns:
        tuple: Updated JWT token and last auth time
    """
    try:
        # Read input CSV
        df = pd.read_csv(input_file)
        
        required_columns = ['first_name', 'last_name', 'company_name']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            raise ValueError(f"Input file missing required columns: {missing_columns}")
            
        # Convert DataFrame to list of dicts
        records = df.to_dict('records')
        
        # Process each contact
        enriched_records = []
        contacts_processed = 0
        
        for entry in records:
            # Check if token needs refresh (55 minute expiry)
            if time.time() - last_auth_time >= 55 * 60:
                jwt_token = authenticate(username, password)
                last_auth_time = time.time()
                
            # Get enriched data
            new_data = get_contact_enrichment_data(entry, jwt_token)
            
            if new_data and new_data.get("success") and new_data["data"].get("result"):
                entry = update_contact_data(entry, new_data)
                entry["enrichment_status"] = "Success"
            else:
                entry["enrichment_status"] = "Failed"
                
            enriched_records.append(entry)
            contacts_processed += 1
            logger.info(f"Contacts processed: {contacts_processed}")
            
        # Generate output filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        input_filename = os.path.basename(input_file)
        output_filename = f"enriched_contacts_{timestamp}_{input_filename}"
        archive_filename = f"{timestamp}_{input_filename}"
        
        # Save output file
        output_path = OUTPUT_DIR / output_filename
        pd.DataFrame(enriched_records).to_csv(output_path, index=False)
        
        # Archive input file
        archive_path = ARCHIVE_DIR / archive_filename
        os.rename(input_file, archive_path)
        
        logger.info(f"Processing complete. Results saved to: {output_path}")
        logger.info(f"Input file archived to: {archive_path}")
        
        return jwt_token, last_auth_time
        
    except Exception as e:
        logger.error(f"Error processing file {input_file}: {str(e)}")
        raise

def main():
    """Main function to process all files in the input directory"""
    logger.info("Starting contact enrichment process")
    
    # Get credentials
    username = os.getenv('ZOOMINFO_USERNAME')
    password = os.getenv('ZOOMINFO_PASSWORD')
    
    if not username or not password:
        raise ValueError("Missing required environment variables ZOOMINFO_USERNAME and ZOOMINFO_PASSWORD")
    
    # Initial authentication
    jwt_token = authenticate(username, password)
    last_auth_time = time.time()
    
    # Process all CSV files in input directory
    processed_files = 0
    error_files = 0
    
    for file in INPUT_DIR.glob('*contacts*.csv'):
        logger.info(f"Processing file: {file}")
        try:
            jwt_token, last_auth_time = process_file(file, jwt_token, last_auth_time, username, password)
            processed_files += 1
        except Exception as e:
            logger.error(f"Error processing {file}: {str(e)}")
            error_files += 1
            
    logger.info(f"Processing complete. Processed {processed_files} files successfully. Encountered {error_files} errors.")

if __name__ == "__main__":
    main() 
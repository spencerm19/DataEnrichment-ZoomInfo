import json
import logging
import os
import shutil
import requests
from datetime import datetime
from pathlib import Path
import pandas as pd
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
from requests_ratelimiter import LimiterSession
from pydantic import BaseModel, Field
import jwt
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from pythonjsonlogger import jsonlogger
import base64
from zi_api_auth_client.zi_api_auth_client import AuthClient
from requests.exceptions import RequestException
import re
import time
from test_zoominfo_auth import authenticate
from preprocess import preprocess_csv

# Configure logging
logger = logging.getLogger('data-enrichment')
handler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Load environment variables
load_dotenv()
logger.info(f"Environment variables loaded. ZOOMINFO_CLIENT_ID present: {'ZOOMINFO_CLIENT_ID' in os.environ}")

# Rate limiting configuration
API_RATE_LIMIT = "100/minute"  # Adjust based on your API tier
session = LimiterSession(per_second=2)  # 2 requests per second max

# Data validation models
class CompanyData(BaseModel):
    company_name: str = Field(..., min_length=1, max_length=200)
    contact_email: Optional[str] = None
    revenue: Optional[float] = None
    employees: Optional[int] = None
    country: Optional[str] = None

class EnrichedData(BaseModel):
    website: Optional[str] = None
    industry: Optional[str] = None
    revenue: Optional[str] = None
    employee_count: Optional[int] = None
    hq_location: Optional[str] = None

# Token encryption for caching
class TokenEncryption:
    def __init__(self):
        self.key = os.getenv('ENCRYPTION_KEY')
        if not self.key:
            self.key = Fernet.generate_key()
            os.environ['ENCRYPTION_KEY'] = self.key.decode()
        self.cipher_suite = Fernet(self.key if isinstance(self.key, bytes) else self.key.encode())

    def encrypt_token(self, token: str) -> str:
        return self.cipher_suite.encrypt(token.encode()).decode()

    def decrypt_token(self, encrypted_token: str) -> str:
        return self.cipher_suite.decrypt(encrypted_token.encode()).decode()

# Secret Management
class SecretProvider(ABC):
    """Abstract base class for secret providers"""
    @abstractmethod
    def get_secret(self, secret_name: str) -> str:
        """Retrieve a secret by name"""
        pass

class EnvironmentSecretProvider(SecretProvider):
    """Environment variable based secret provider"""
    def get_secret(self, secret_name: str) -> str:
        value = os.getenv(secret_name)
        if not value:
            raise ConfigurationError(f"Environment variable {secret_name} not set")
        return value

class AWSSecretsProvider(SecretProvider):
    """AWS Secrets Manager based secret provider"""
    def __init__(self):
        try:
            import boto3
            self.client = boto3.client('secretsmanager')
        except ImportError:
            raise ConfigurationError("boto3 is required for AWS Secrets Manager")
        except Exception as e:
            raise ConfigurationError(f"Failed to initialize AWS Secrets Manager: {str(e)}")

    def get_secret(self, secret_name: str) -> str:
        try:
            response = self.client.get_secret_value(SecretId=secret_name)
            if 'SecretString' in response:
                return response['SecretString']
            raise ConfigurationError("Secret value not found")
        except Exception as e:
            raise ConfigurationError(f"Failed to get secret from AWS: {str(e)}")

# Custom exceptions
class ConfigurationError(Exception):
    """Raised when there is a configuration error"""
    pass

class APIError(Exception):
    """Raised when there is an API error"""
    pass

class DataProcessingError(Exception):
    """Raised when there is a data processing error"""
    pass

class AuthenticationError(Exception):
    """Raised when there is an authentication error"""
    pass

# Constants for file paths
INPUT_DIR = Path("data/input")
OUTPUT_DIR = Path("data/output")
ARCHIVE_DIR = Path("data/archive")

def validate_jwt_token(token: str) -> bool:
    """
    Validate JWT token format and expiration
    
    Args:
        token: JWT token string
    
    Returns:
        bool: True if token is valid
    """
    try:
        # Decode without verification (we don't have the secret)
        decoded = jwt.decode(token, options={"verify_signature": False})
        exp = decoded.get('exp')
        if not exp:
            return False
        # Check if token is expired
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).timestamp()
        return exp > now
    except jwt.InvalidTokenError:
        return False

def get_zoominfo_credentials() -> Dict[str, str]:
    """Get ZoomInfo API credentials from environment variables or AWS Secrets Manager."""
    try:
        # Initialize secret provider based on configuration
        secret_provider: SecretProvider
        if os.getenv('USE_AWS_SECRETS') == 'true':
            secret_provider = AWSSecretsProvider()
        else:
            secret_provider = EnvironmentSecretProvider()

        # Get secrets using the provider
        client_id = secret_provider.get_secret('ZOOMINFO_CLIENT_ID')
        private_key = secret_provider.get_secret('ZOOMINFO_PRIVATE_KEY')
        
        logger.info(f"Retrieved credentials - Client ID length: {len(client_id) if client_id else 0}")
        logger.info(f"Retrieved credentials - Private Key length: {len(private_key) if private_key else 0}")
        
        return {
            'client_id': client_id,
            'private_key': private_key
        }
    except Exception as e:
        msg = f"Failed to get ZoomInfo credentials: {str(e)}"
        logger.error(msg)
        raise ConfigurationError(msg) from e

def log_message(message, task_name=None):
    """Log a message in JSON format"""
    logger.info(json.dumps({"message": message, "taskName": task_name}))

def clean_company_name(name):
    """Clean company name by removing legal entities and common suffixes"""
    # Remove common legal entities and suffixes
    patterns = [
        r'\s+(Inc\.?|Incorporated|Corp\.?|Corporation|LLC|Ltd\.?|Limited|GmbH|B\.?V\.?|SAS|S\.A\.?S\.?|AG|N\.?V\.?)\.?$',
        r'\s*\([^)]*\)',  # Remove anything in parentheses
        r'[,&]',  # Remove commas and ampersands
        r'\s+'  # Replace multiple spaces with single space
    ]
    
    cleaned = name
    for pattern in patterns:
        cleaned = re.sub(pattern, ' ', cleaned, flags=re.IGNORECASE)
    
    return cleaned.strip()

def format_private_key(key_str):
    """Format private key string into proper PEM format"""
    # Remove existing headers if present
    key_str = key_str.replace('-----BEGIN PRIVATE KEY-----', '')
    key_str = key_str.replace('-----END PRIVATE KEY-----', '')
    key_str = key_str.replace('\n', '')
    key_str = key_str.strip()
    
    # Add proper headers and line breaks
    formatted = '-----BEGIN PRIVATE KEY-----\n'
    # Add key content with line breaks every 64 characters
    chunks = [key_str[i:i+64] for i in range(0, len(key_str), 64)]
    formatted += '\n'.join(chunks)
    formatted += '\n-----END PRIVATE KEY-----'
    
    return formatted

def get_jwt_token(client_id, private_key):
    """Get JWT token with better error handling"""
    try:
        # Format the private key
        formatted_key = format_private_key(private_key)
        log_message(f"Formatted private key (length: {len(formatted_key)})")
        
        # Initialize auth client
        auth_client = AuthClient("api-client@zoominfo.com")
        
        # Try to get JWT token
        try:
            jwt_token = auth_client.pki_authentication(client_id, formatted_key)
            return jwt_token
        except Exception as e:
            log_message(f"Error during PKI authentication: {str(e)}")
            raise
                
    except Exception as e:
        log_message(f"Failed to get JWT token: {str(e)}")
        raise

def search_company(session, company_name):
    """Search for a company using the ZoomInfo search endpoint"""
    search_url = "https://api.zoominfo.com/search/company"
    
    # Clean the company name for better matching
    cleaned_name = clean_company_name(company_name)
    
    payload = {
        "companyName": cleaned_name,
        "rpp": 1,  # Results per page
        "page": 1
    }
    
    try:
        response = session.post(search_url, json=payload)
        response.raise_for_status()
        data = response.json()
        
        if data.get('companies') and len(data['companies']) > 0:
            return data['companies'][0].get('id')
        return None
        
    except Exception as e:
        log_message(f"Error searching for company {company_name}: {str(e)}")
        return None

def clean_company_data(data: dict) -> dict:
    """
    Clean company data by removing NaN values and empty strings.
    
    Args:
        data (dict): Company data to clean
        
    Returns:
        dict: Cleaned company data
    """
    cleaned = {}
    for key, value in data.items():
        if pd.isna(value) or value == "":
            cleaned[key] = None
        else:
            cleaned[key] = value
    return cleaned

def create_enrichment_payload(company_data: dict) -> dict:
    """
    Create the payload for the ZoomInfo company enrichment API.
    
    Args:
        company_data (dict): Company data from the CSV
        
    Returns:
        dict: API payload
    """
    # Clean the data first
    company_data = clean_company_data(company_data)
    
    # Create the payload using the company-master endpoint structure
    payload = {
        "matchCompanyInput": [{
            "zi_c_name": company_data.get("company_name", ""),
            "address": {
                "zi_c_street": company_data.get("street", ""),
                "zi_c_city": company_data.get("city", ""),
                "zi_c_state": company_data.get("state", ""),
                "zi_c_zip": company_data.get("zip", ""),
                "zi_c_country": company_data.get("country", "")
            }
        }],
        "outputFields": [
            "zi_c_location_id",
            "zi_c_name",
            "zi_c_company_name",
            "zi_c_phone",
            "zi_c_url",
            "zi_c_company_url",
            "zi_c_naics6",
            "zi_c_employees",
            "zi_c_revenue_range",
            "zi_c_employee_range",
            "zi_c_street",
            "zi_c_city",
            "zi_c_state",
            "zi_c_zip",
            "zi_c_country",
            "zi_c_company_id",
            "zi_c_linkedin_url",
            "zi_c_facebook_url"
        ]
    }
    
    # Add phone if available
    if company_data.get("phone"):
        payload["matchCompanyInput"][0]["phone"] = {"zi_c_phone": company_data["phone"]}
    
    # Clean up empty address fields
    address = payload["matchCompanyInput"][0]["address"]
    payload["matchCompanyInput"][0]["address"] = {k: v for k, v in address.items() if v and str(v).strip()}
    
    return payload

def enrich_company(company_data: dict, jwt_token: str) -> dict:
    """
    Enrich a company using the ZoomInfo API.
    
    Args:
        company_data (dict): Company data to enrich
        jwt_token (str): JWT token for authentication
        
    Returns:
        dict: Enriched company data
    """
    try:
        # Create payload
        payload = create_enrichment_payload(company_data)
        
        # Set up headers
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {jwt_token}",
            "User-Agent": "ZoomInfo Python Client/1.0"
        }
        
        # Make API request
        response = session.post(
            "https://api.zoominfo.com/enrich/company-master",
            json=payload,
            headers=headers
        )
        
        # Check response
        if response.status_code == 200:
            response_data = response.json()
            logger.debug(f"Raw API response: {json.dumps(response_data, indent=2)}")
            
            # Check if we got a successful match
            if response_data.get("success") and response_data.get("data", {}).get("result"):
                result = response_data["data"]["result"][0]  # Get first match
                logger.info(f"Successfully enriched company {company_data.get('company_name')}")
                logger.debug(f"Match result: {json.dumps(result, indent=2)}")
                
                # Get the enriched data from the result
                enriched_data = result.get("data", {})
                
                # Map the response data to our format
                mapped_data = {
                    "zi_company_id": enriched_data.get("zi_c_company_id"),
                    "zi_company_name": enriched_data.get("zi_c_company_name"),
                    "zi_website": enriched_data.get("zi_c_url"),
                    "zi_company_url": enriched_data.get("zi_c_company_url"),
                    "zi_revenue_range": enriched_data.get("zi_c_revenue_range"),
                    "zi_employees": enriched_data.get("zi_c_employees"),
                    "zi_employee_range": enriched_data.get("zi_c_employee_range"),
                    "zi_naics_codes": enriched_data.get("zi_c_naics6"),
                    "zi_linkedin_url": enriched_data.get("zi_c_linkedin_url"),
                    "zi_facebook_url": enriched_data.get("zi_c_facebook_url"),
                    "zi_street": enriched_data.get("zi_c_street"),
                    "zi_city": enriched_data.get("zi_c_city"),
                    "zi_state": enriched_data.get("zi_c_state"),
                    "zi_zip": enriched_data.get("zi_c_zip"),
                    "zi_country": enriched_data.get("zi_c_country"),
                    "zi_phone": enriched_data.get("zi_c_phone"),
                    "enrichment_status": "Success",
                    "match_confidence": result.get("matchConfidence", "Unknown")
                }
                
                return {**company_data, **mapped_data}
            else:
                error_msg = f"No match found for company {company_data.get('company_name')}"
                logger.warning(error_msg)
                if response_data.get("data"):
                    logger.debug(f"Response data: {json.dumps(response_data['data'], indent=2)}")
                company_data["enrichment_status"] = "No Match"
                company_data["error_message"] = error_msg
                return company_data
        else:
            error_msg = f"Error enriching company {company_data.get('company_name')}: {response.status_code} {response.text}"
            logger.error(error_msg)
            company_data["enrichment_status"] = "Failed"
            company_data["error_message"] = error_msg
            return company_data
            
    except Exception as e:
        error_msg = f"Error enriching company {company_data.get('company_name')}: {str(e)}"
        logger.error(error_msg)
        company_data["enrichment_status"] = "Failed"
        company_data["error_message"] = str(e)
        return company_data

def process_company(session, company_name):
    """Process a single company by searching and then enriching if found"""
    # First search for the company
    company_id = search_company(session, company_name)
    
    if not company_id:
        return {
            "status": "not_found",
            "message": f"Company not found in ZoomInfo database: {company_name}",
            "data": None
        }
    
    # If found, enrich the company
    enriched_data = enrich_company(session, company_id)
    
    if enriched_data:
        return {
            "status": "found",
            "message": "Successfully retrieved company data",
            "data": enriched_data
        }
    else:
        return {
            "status": "error",
            "message": f"Error enriching company data for: {company_name}",
            "data": None
        }

def get_company_enrichment_data(entry: dict, jwt_token: str, strict: bool = True) -> Optional[dict]:
    """
    Retrieves company enrichment data from the ZoomInfo API using the provided entry and JWT token.
    
    Args:
        entry (dict): A dictionary containing the company information to be enriched.
        jwt_token (str): A JWT token used for authentication with the ZoomInfo API.
        strict (bool): Whether to use strict matching criteria
        
    Returns:
        dict: A dictionary containing the enriched company data, or None if an error occurred.
    """
    url = "https://api.zoominfo.com/enrich/company-master"
    
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {jwt_token}"
    }

    def create_payload(include_email: bool) -> dict:
        payload = {
            "matchCompanyInput": [{
                "zi_c_name": entry["company_name"],
                "phone": {"zi_c_phone": entry.get("phone", "")},
                "address": {"zi_c_country": entry.get("country", "")},
                "match_reasons": [{"zi_c_country": "E"}]
            }],
            "outputFields": [
                "zi_c_location_id",
                "zi_c_name",
                "zi_c_company_name", 
                "zi_c_phone",
                "zi_c_url",
                "zi_c_company_url",
                "zi_c_naics6",
                "zi_c_employees",
                "zi_c_street",
                "zi_c_city",
                "zi_c_state",
                "zi_c_zip",
                "zi_c_country",
                "zi_c_company_id",
                "zi_c_linkedin_url"
            ]
        }
        
        if include_email and entry.get("email"):
            payload["matchCompanyInput"][0]["email"] = entry["email"]
            
        if strict:
            updated_address = {
                "zi_c_street": entry.get("street", ""),
                "zi_c_city": entry.get("city", ""),
                "zi_c_state": entry.get("state", ""),
                "zi_c_zip": entry.get("zip", "")
            }
            payload["matchCompanyInput"][0]["address"].update(updated_address)
            payload["matchCompanyInput"][0]["match_reasons"] = [
                {"zi_c_country": "E", "zi_c_name": "F"}
            ]
            
        return payload

    try:
        # First try with email if available
        payload = create_payload(include_email=True)
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 400:
            # Retry without email
            payload = create_payload(include_email=False)
            response = requests.post(url, headers=headers, json=payload)
            response.raise_for_status()
        else:
            entry["enrichment_status"] = "Failed"
            entry["error_message"] = str(e)
            return None
            
    except requests.exceptions.RequestException as e:
        entry["enrichment_status"] = "Failed"
        entry["error_message"] = str(e)
        return None

    return response.json()

def update_company_data(entry: dict, new_data_item: dict) -> dict:
    """
    Updates the company data in the given entry with the new data item.
    
    Args:
        entry (dict): A dictionary containing the company data to be updated.
        new_data_item (dict): A dictionary containing the new data item to update the company data with.
        
    Returns:
        dict: The updated company data.
    """
    if "data" in new_data_item and new_data_item["data"].get("result"):
        company_data = new_data_item["data"]["result"][0]["data"]
        
        fields_to_update = [
            "zi_c_location_id",
            "zi_c_company_name",
            "zi_c_phone",
            "zi_c_url",
            "zi_c_naics6",
            "zi_c_employees",
            "zi_c_street",
            "zi_c_city",
            "zi_c_state",
            "zi_c_zip",
            "zi_c_country",
            "zi_c_name",
            "zi_c_company_id",
            "zi_c_linkedin_url"
        ]
        
        for field in fields_to_update:
            if entry.get(field, "") == "" and field in company_data:
                entry[field] = company_data[field]
    else:
        logger.warning("No 'data' key in the response or 'result' list is empty.")
        
    return entry

def process_file(input_file: str, jwt_token: str, last_auth_time: float, username: str, password: str) -> tuple:
    """
    Process a single input file for company enrichment.
    
    Args:
        input_file (str): Path to the input CSV file
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
        
        if 'company_name' not in df.columns:
            raise ValueError("Input file must contain a 'company_name' column")
            
        # Convert DataFrame to list of dicts for processing
        records = df.to_dict('records')
        
        # Process each company
        enriched_records = []
        companies_processed = 0
        
        for entry in records:
            # Check if token needs refresh (55 minute expiry)
            if time.time() - last_auth_time >= 55 * 60:
                jwt_token = authenticate(username, password)
                last_auth_time = time.time()
                
            entry["company_match_criteria"] = "None"
            
            # Try strict matching first
            new_data = get_company_enrichment_data(entry, jwt_token, strict=True)
            
            if (new_data and new_data.get("success") and 
                new_data["data"].get("result") and 
                new_data["data"]["result"][0].get("data")):
                entry["company_match_criteria"] = "Strict"
            else:
                # Try non-strict matching
                new_data = get_company_enrichment_data(entry, jwt_token, strict=False)
                if new_data and new_data.get("success") and new_data["data"].get("result"):
                    entry["company_match_criteria"] = "Non-strict"
                    
            if new_data and new_data.get("success") and new_data["data"].get("result"):
                entry = update_company_data(entry, new_data)
                
            enriched_records.append(entry)
            companies_processed += 1
            logger.info(f"Companies processed: {companies_processed}")
            
        # Generate output filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        input_filename = os.path.basename(input_file)
        output_filename = f"enriched_{timestamp}_{input_filename}"
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

def process_csv_file(file_path: str, jwt_token: str) -> None:
    """
    Process a CSV file and enrich company data.
    
    Args:
        file_path (str): Path to the CSV file
        jwt_token (str): JWT token for authentication
    """
    try:
        # Preprocess the file
        preprocessed_file = preprocess_csv(file_path)
        
        # Read preprocessed CSV file
        df = pd.read_csv(preprocessed_file)
        
        # Check required columns
        if 'company_name' not in df.columns:
            raise ValueError("Input file must contain a 'company_name' column")
        
        # Process each company
        enriched_data = []
        for _, row in df.iterrows():
            company_data = row.to_dict()
            enriched_company = enrich_company(company_data, jwt_token)
            enriched_data.append(enriched_company)
            logger.info(f"Companies processed: {len(enriched_data)}")
        
        # Create output filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = Path("data/output") / f"enriched_{timestamp}.csv"
        
        # Save enriched data
        pd.DataFrame(enriched_data).to_csv(output_file, index=False)
        logger.info(f"Enriched data saved to: {output_file}")
        
        # Archive input file
        archive_dir = Path("data/archive")
        archive_file = archive_dir / f"{Path(file_path).name}_{timestamp}"
        Path(file_path).rename(archive_file)
        logger.info(f"Input file archived to: {archive_file}")
        
    except Exception as e:
        logger.error(f"Error processing file {file_path}: {str(e)}")
        raise

def main():
    """Main function to process all input files"""
    try:
        # Load environment variables
        load_dotenv()
        
        # Check for required environment variables
        username = os.getenv('ZOOMINFO_USERNAME')
        password = os.getenv('ZOOMINFO_PASSWORD')
        
        if not username or not password:
            raise ValueError("Missing required environment variables: ZOOMINFO_USERNAME, ZOOMINFO_PASSWORD")
            
        logger.info(f"Environment variables loaded. ZOOMINFO_USERNAME present: {bool(username)}")
        
        # Start processing
        logger.info("Starting data enrichment process")
        
        # Get JWT token
        jwt_token = authenticate(username, password)
        if not jwt_token:
            raise ValueError("Failed to obtain JWT token")
        logger.info("Successfully obtained JWT token")
        
        # Process all CSV files in input directory
        input_files = list(INPUT_DIR.glob("*.csv"))
        successful_files = 0
        error_files = 0
        
        for file_path in input_files:
            try:
                logger.info(f"Processing file: {file_path}")
                process_csv_file(str(file_path), jwt_token)
                successful_files += 1
            except Exception as e:
                logger.error(f"Error processing {file_path}: {str(e)}")
                error_files += 1
        
        logger.info(f"Processing complete. Processed {successful_files} files successfully. Encountered {error_files} errors.")
        
    except Exception as e:
        logger.error(f"Error in main process: {str(e)}")
        raise

if __name__ == "__main__":
    main() 
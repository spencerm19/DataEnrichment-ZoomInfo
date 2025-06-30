import os
import pandas as pd
from dotenv import load_dotenv
import logging
from test_zoominfo_auth import authenticate
from app import enrich_company
from requests_ratelimiter import LimiterSession

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Set debug level for data-enrichment logger
data_enrichment_logger = logging.getLogger('data-enrichment')
data_enrichment_logger.setLevel(logging.DEBUG)

# Load environment variables
load_dotenv()

def test_company_enrichment():
    """Test the company enrichment process with sample companies"""
    
    # Get credentials
    username = os.getenv('ZOOMINFO_USERNAME')
    password = os.getenv('ZOOMINFO_PASSWORD')
    
    if not username or not password:
        raise ValueError("Missing required environment variables ZOOMINFO_USERNAME and ZOOMINFO_PASSWORD")
    
    # Authenticate
    logger.info("Authenticating with ZoomInfo...")
    jwt_token = authenticate(username, password)
    if not jwt_token:
        raise Exception("Failed to authenticate with ZoomInfo")
    logger.info("Authentication successful")
    
    # Read test companies
    input_file = "data/input/test_companies.csv"
    df = pd.read_csv(input_file)
    logger.info(f"Loaded {len(df)} companies for testing")
    
    # Process each company
    enriched_records = []
    session = LimiterSession(per_second=2)  # 2 requests per second max
    
    for _, row in df.iterrows():
        company_data = row.to_dict()
        logger.info(f"Processing company: {company_data['company_name']}")
        
        # Enrich company
        enriched_data = enrich_company(company_data, jwt_token)
        enriched_records.append(enriched_data)
        
        # Log result
        status = enriched_data.get('enrichment_status', 'Unknown')
        if status == 'Success':
            logger.info(f"Successfully enriched {company_data['company_name']}")
            logger.debug(f"Enriched data: {enriched_data}")
        else:
            error = enriched_data.get('error_message', 'Unknown error')
            logger.warning(f"Failed to enrich {company_data['company_name']}: {error}")
    
    # Save results
    output_df = pd.DataFrame(enriched_records)
    output_file = "data/output/test_enrichment_results.csv"
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    output_df.to_csv(output_file, index=False)
    logger.info(f"Results saved to {output_file}")

if __name__ == "__main__":
    test_company_enrichment() 
import pandas as pd
from pathlib import Path
import logging

# Configure logging
logger = logging.getLogger('data-enrichment')
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def preprocess_csv(input_file: str) -> str:
    """
    Preprocess the input CSV file to match our expected column format.
    
    Args:
        input_file (str): Path to the input CSV file
        
    Returns:
        str: Path to the preprocessed CSV file
    """
    try:
        # Read the input CSV
        df = pd.read_csv(input_file)
        
        # Define column mapping
        column_mapping = {
            'Supplier Company': 'company_name',
            'Supplier Street': 'street',
            'Supplier City': 'city',
            'Supplier State': 'state',
            'Supplier Zip Code': 'zip',
            'Supplier Country': 'country',
            'Supplier First Name': 'first_name',
            'Supplier Last Name': 'last_name',
            'Supplier Email': 'email',
            'Supplier Phone': 'phone',
            'Site Name': 'site_name',
            'Site ID': 'site_id',
            'Additional Contact Info': 'additional_contact_info',
            'Lookup ID': 'lookup_id'
        }
        
        # Rename columns
        df = df.rename(columns=column_mapping)
        
        # Fill empty strings for missing values
        df = df.fillna("")
        
        # Create preprocessed filename
        input_path = Path(input_file)
        output_file = input_path.parent / f"preprocessed_{input_path.name}"
        
        # Save preprocessed file
        df.to_csv(output_file, index=False)
        logger.info(f"Preprocessed file saved to: {output_file}")
        
        return str(output_file)
        
    except Exception as e:
        logger.error(f"Error preprocessing file: {str(e)}")
        raise

if __name__ == "__main__":
    input_file = "data/input/Data_Enrichment_Sample.csv"
    try:
        output_file = preprocess_csv(input_file)
        print(f"Successfully preprocessed file. Output saved to: {output_file}")
    except Exception as e:
        print(f"Error: {str(e)}") 
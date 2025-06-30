import os
from dotenv import load_dotenv

def check_key_format():
    load_dotenv()
    private_key = os.getenv('ZOOMINFO_PRIVATE_KEY')
    
    if not private_key:
        print("Error: ZOOMINFO_PRIVATE_KEY not found in environment variables")
        return
    
    print("Private key length:", len(private_key))
    print("\nFirst 100 characters:")
    print(private_key[:100])
    print("\nLast 100 characters:")
    print(private_key[-100:])
    
    # Check if key has proper headers
    if not private_key.startswith("-----BEGIN PRIVATE KEY-----"):
        print("\nError: Key does not start with proper header")
    if not private_key.endswith("-----END PRIVATE KEY-----"):
        print("\nError: Key does not end with proper footer")
    
    # Check line lengths
    lines = private_key.split('\n')
    print("\nNumber of lines:", len(lines))
    for i, line in enumerate(lines, 1):
        if line and not line.startswith("-----") and not line.endswith("-----"):
            if len(line) != 64:
                print(f"Warning: Line {i} has length {len(line)} (should be 64)")

if __name__ == "__main__":
    check_key_format() 
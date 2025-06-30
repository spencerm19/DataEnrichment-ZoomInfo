# Data Enrichment with ZoomInfo - Docker Version

This project provides a Docker-based solution for enriching company data using the ZoomInfo API. It processes CSV files containing company names and enriches them with additional data from ZoomInfo.

## Deployment Instructions

### Ubuntu Deployment (Production)

1. Install Docker and Docker Compose:
```bash
sudo apt update
sudo apt install docker.io docker-compose
sudo systemctl enable docker
sudo systemctl start docker
```

2. Add your user to the docker group:
```bash
sudo usermod -aG docker $USER
newgrp docker  # Apply group changes without logout
```

3. Clone the repository and navigate to the project directory:
```bash
git clone <repository-url>
cd Data-Enrichment-ZoomInfo/Data\ Enrichment\ ZoomInfo\ -\ Docker
```

4. Create and configure your `.env` file with your ZoomInfo API credentials:
```bash
cp env.example .env
# Edit .env with your credentials
```

5. Build and run the container:
```bash
docker-compose build
docker-compose up -d
```

### Windows Development Environment

Due to corporate proxy settings, you might encounter issues with Docker builds. Here are some workarounds:

#### Option 1: Configure Docker Desktop Proxy Settings

1. Open Docker Desktop
2. Go to Settings > Resources > Proxies
3. Configure your corporate proxy settings
4. Click "Apply & Restart"

#### Option 2: Run Without Docker During Development

1. Create a Python virtual environment:
```powershell
python -m venv venv
.\venv\Scripts\Activate
```

2. Install dependencies:
```powershell
pip install -r requirements.txt
```

3. Run the application:
```powershell
python app.py
```

#### Option 3: Use WSL2 for Development

1. Install WSL2 and Ubuntu from the Microsoft Store
2. Follow the Ubuntu deployment instructions above within WSL2

## Security Notes

- The application runs as a non-root user inside the container
- Input directory is mounted read-only
- Container filesystem is read-only with temporary storage mounted
- All capabilities are dropped except those required for operation
- Resource limits are in place
- Proper logging configuration is implemented

## API Endpoints

- Health Check: `GET http://localhost:8080/health`
- Main API: `POST http://localhost:8080/enrich`

## Data Directories

- `/data/input`: Place input CSV files here (read-only)
- `/data/output`: Enriched data output location
- `/data/archive`: Processed files are moved here

## Monitoring

The container includes a health check that runs every 30 seconds. You can monitor the container status using:

```bash
docker ps
docker logs enrichment
```

## Prerequisites

- Docker and Docker Compose installed
- ZoomInfo API credentials (client ID and private key)

## Setup

1. Create a `.env` file in the project root with your ZoomInfo credentials:
   ```
   ZOOMINFO_CLIENT_ID=your_client_id_here
   ZOOMINFO_PRIVATE_KEY=your_private_key_here
   ```

2. Create the required data directories:
   ```bash
   mkdir -p data/input data/output data/archive
   ```

3. Build and start the container:
   ```bash
   docker-compose up --build
   ```

## Usage

1. Place your input CSV files in the `data/input` directory. Files must have a `company_name` column.

2. The service will automatically process any CSV files in the input directory:
   - Enriched data will be saved to `data/output`
   - Original files will be moved to `data/archive`

3. Monitor the logs for processing status and any errors.

## Testing

You can generate test data using the included test script:

```bash
python test_enrichment.py
```

This will create sample CSV files in the `data/input` directory.

## Data Format

### Input CSV Requirements
- Must contain a `company_name` column
- Additional columns will be preserved in the output

### Output CSV Format
The output will contain all original columns plus the following enriched data:
- enriched_website
- enriched_industry
- enriched_revenue
- enriched_employee_count
- enriched_hq_location

## Error Handling

The service includes robust error handling:
- Invalid input file format
- Missing required columns
- API authentication failures
- Rate limiting
- Network issues

All errors are logged with appropriate context for troubleshooting.

## Monitoring

- Check the Docker logs for processing status and errors
- Monitor the output directory for processed files
- Review the archive directory for processed input files

## Directory Structure

```
.
├── data/
│   ├── input/    # Place CSV files here for processing
│   ├── output/   # Enriched files will be saved here
│   └── archive/  # Processed input files are moved here
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── app.py
├── test_enrichment.py
└── README.md
```

## Quick Start

1. Clone the repository and navigate to this directory:
```bash
cd "Data Enrichment ZoomInfo - Docker"
```

2. Generate test data (optional):
```bash
python3 test_enrichment.py
```

3. Build and run the Docker container:
```bash
docker-compose up --build
```

## Development

1. To modify the enrichment logic, edit the `process_file` function in `app.py`
2. To test changes:
   ```bash
   # Stop any running containers
   docker-compose down
   
   # Rebuild and start
   docker-compose up --build
   ```

## Troubleshooting

1. If the container fails to start:
   - Check Docker service: `sudo systemctl status docker`
   - Verify directory permissions: `ls -l data/`
   - Check logs: `docker-compose logs`

2. If files aren't being processed:
   - Verify file permissions: `ls -l data/input/`
   - Check file format (must be .csv)
   - Look for error messages in the container logs

3. For permission issues:
   ```bash
   # Fix directory permissions
   sudo chown -R $USER:$USER data/
   chmod -R 755 data/
   ```

## Notes

- The application monitors the input directory continuously
- Files are processed as soon as they appear in the input directory
- Processed files are automatically archived
- All operations are logged with timestamps
- The container runs with local user permissions to avoid file ownership issues 
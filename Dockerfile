FROM python:3.12-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1

# Set proxy environment variables if they exist
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ENV HTTP_PROXY=$HTTP_PROXY \
    HTTPS_PROXY=$HTTPS_PROXY \
    NO_PROXY=$NO_PROXY

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser -s /sbin/nologin -d /app appuser

# Set working directory
WORKDIR /app

# Create data directories with appropriate permissions
RUN mkdir -p /data/input /data/output /data/archive \
    && chown -R appuser:appuser /data \
    && chmod -R 750 /data

# Copy requirements file
COPY --chown=appuser:appuser requirements.txt .

# Configure pip to use proxy
RUN if [ ! -z "$HTTP_PROXY" ]; then \
        mkdir -p ~/.pip && \
        echo "[global]" > ~/.pip/pip.conf && \
        echo "proxy = $HTTP_PROXY" >> ~/.pip/pip.conf; \
    fi

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appuser . .

# Clean up Python cache
RUN python3 -c "import pathlib; import shutil; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__')]" \
    && python3 -c "import pathlib; [p.unlink() for p in pathlib.Path('.').rglob('*.pyc')]"

# Set proper permissions
RUN chown -R appuser:appuser /app \
    && chmod -R 750 /app

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python3 -c "import requests; requests.get('http://localhost:8080/health')"

# Set the entrypoint
ENTRYPOINT ["python3", "app.py"] 
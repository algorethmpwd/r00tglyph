# R00tGlyph - Advanced Web Security Training Platform
# Multi-stage Docker build for production deployment

# Stage 1: Build stage with development dependencies
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=100

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libjpeg-dev \
    libpng-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Stage 2: Runtime stage
FROM python:3.11-slim as runtime

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    FLASK_APP=app:create_app \
    PATH="/opt/venv/bin:$PATH"

# Install runtime system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    netcat-openbsd \
    libxml2 \
    libxslt1.1 \
    libjpeg62-turbo \
    libpng16-16 \
    redis-tools \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get autoremove -y \
    && apt-get clean

# Create application user
RUN groupadd -r rootglyph && useradd -r -g rootglyph rootglyph

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=rootglyph:rootglyph . .

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs /app/instance /app/instance/uploads /app/backup && \
    chown -R rootglyph:rootglyph /app && \
    chmod -R 755 /app

# Create data directories for persistent storage
RUN mkdir -p /app/data/challenges /app/data/hints /app/data/solutions && \
    chown -R rootglyph:rootglyph /app/data && \
    chmod -R 755 /app/data

# Copy health check script
COPY --chown=rootglyph:rootglyph docker/healthcheck.py /app/healthcheck.py
RUN chmod +x /app/healthcheck.py

# Copy entrypoint script
COPY --chown=rootglyph:rootglyph docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Switch to non-root user
USER rootglyph

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python /app/healthcheck.py || exit 1

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--worker-class", "eventlet", "--worker-connections", "1000", "--timeout", "120", "--keepalive", "2", "--max-requests", "1000", "--max-requests-jitter", "100", "--preload", "--log-level", "info", "--access-logfile", "-", "--error-logfile", "-", "app:create_app()"]

# Metadata
LABEL maintainer="R00tGlyph Team" \
      version="2.0.0" \
      description="Advanced Web Security Training Platform" \
      org.opencontainers.image.title="R00tGlyph" \
      org.opencontainers.image.description="Comprehensive web security training platform with 115+ challenges" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.vendor="R00tGlyph" \
      org.opencontainers.image.licenses="Educational" \
      org.opencontainers.image.source="https://github.com/algorethmpwd/R00tGlyph"

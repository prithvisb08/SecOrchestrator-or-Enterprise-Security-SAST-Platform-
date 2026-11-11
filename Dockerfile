FROM python:3.12-slim

WORKDIR /app

# Install system dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml .
COPY src/ ./src/

# Install the application
RUN pip install --no-cache-dir .

# Create a non-root user for security
RUN useradd -m secuser
USER secuser

# Expose the API port
EXPOSE 8000

# Start the FastAPI server
CMD ["uvicorn", "security_platform.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
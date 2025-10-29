# Use a lightweight Python base image
FROM python:3.9-slim

# Set working directory
WORKDIR /opt/imperva

# Install dependencies
RUN pip install requests

# Copy the Python script and credentials into container
COPY imp.py .
COPY credentials.conf .

# Set environment variables for configuration (optional, can be overridden)
ENV TCP_IP=127.0.0.1
ENV TCP_PORT=12228

# Command to run the script
CMD ["python", "imp.py"]

#######################################
# docker build -t imperva-beat . #
#######################################

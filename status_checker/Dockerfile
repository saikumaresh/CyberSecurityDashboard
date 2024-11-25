# Use a Python base image
FROM python:3.12-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file to the container
COPY requirements.txt .

# Install the dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install necessary system packages
RUN apt-get update && apt-get install -y \
    hping3 \
    tshark \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Copy the rest of the application code to the container
COPY . .

# Set environment variables if needed (optional)
ENV VULNERABLE_SITE_IP=172.30.0.10
ENV CAPTURE_INTERFACE=eth0

# Command to run the status-checker
CMD ["python", "status_checker.py"]

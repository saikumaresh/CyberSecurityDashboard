# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install the Python dependencies
RUN pip install --no-cache-dir Flask requests scapy pyshark schedule

# Install system packages for network functionality
RUN apt-get update && \
    apt-get install -y hping3 iputils-ping tcpdump iproute2 tshark && \
    rm -rf /var/lib/apt/lists/*

RUN pip install gunicorn 

# Expose the port that Flask will use
EXPOSE 5000

# Define environment variables
ENV FLASK_APP=app.py
ENV CAPTURE_INTERFACE=eth0
ENV VULNERABLE_SITE_IP=172.30.0.10
ENV DDOS_PACKET_THRESHOLD=100

# Run both Flask and packet capture script concurrently
CMD flask run --host=0.0.0.0


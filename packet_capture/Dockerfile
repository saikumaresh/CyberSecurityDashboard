# Use an official Python runtime as a parent image
FROM python:3.8-slim

# Install necessary system packages
RUN apt-get update && \
    apt-get install -y tshark && \
    rm -rf /var/lib/apt/lists/*

# Install PyShark
RUN pip install pyshark schedule

# Install tshark for packet capture
RUN apt-get update && apt-get install -y tshark

RUN apt-get update && apt-get install -y iputils-ping hping3 tcpdump iproute2 && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the packet capture script into the container
# COPY packet_capture.py .
COPY packet_capture.py /app/packet_capture.py

# # Run the packet capture script
# CMD ["python", "packet_capture.py"]

# Set the entry point to run the Python script
ENTRYPOINT ["python", "packet_capture.py"]
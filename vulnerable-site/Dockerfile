# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install the Python dependencies
RUN pip install --no-cache-dir Flask requests scapy

# Expose the port that Flask will use
EXPOSE 5000

# Define environment variable
ENV FLASK_APP=app.py

RUN apt-get update && apt-get install -y iproute2

RUN apt-get update && apt-get install -y hping3 iputils-ping tcpdump iproute2 && rm -rf /var/lib/apt/lists/*

# Run flask when the container launches
CMD ["flask", "run", "--host=0.0.0.0"]

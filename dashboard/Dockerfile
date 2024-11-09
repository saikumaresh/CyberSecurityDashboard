# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any necessary dependencies
RUN pip install Flask

# Expose the port that Flask will use
EXPOSE 5001

# Set the Flask environment to development for debugging
ENV FLASK_ENV=development

# Run the Flask app when the container launches
CMD ["python", "app.py"]

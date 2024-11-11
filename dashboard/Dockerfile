# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set the working directory in the container
WORKDIR /app

# Copy the contents of the dashboard directory into the container at /app
COPY . /app

# Copy the shared database setup script from the root directory into the container
COPY ../database_setup.py /app/database_setup.py

# Install any necessary dependencies
RUN pip install Flask

# Run the database setup script to ensure tables are created
RUN python /app/database_setup.py

# Expose the port that Flask will use
EXPOSE 5001

# Set the Flask environment to development for debugging
ENV FLASK_ENV=development

# Run the Flask app when the container launches
CMD ["python", "app.py"]

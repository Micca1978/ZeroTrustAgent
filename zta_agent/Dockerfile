# Dockerfile for Python-Based Zero Trust Agent

# Use the official Python 3.11 slim image as the base image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file (if you have one) to install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code to the container
COPY . .

# Expose port 8000 for the application
EXPOSE 8000

# Command to run the application (modify as needed)
CMD ["python", "your_application.py"]

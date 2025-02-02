# Use the official Python base image
FROM python:latest

# Set the working directory inside the container
WORKDIR /svr

# Install SQLite
RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*

# Set up and activate virtual environment
ENV VIRTUAL_ENV="/venv"
RUN python -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Copy the application script into the container
COPY . .

# Run the Python script
CMD ["python3", "test.py"]

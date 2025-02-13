# Use the official Python base image
FROM python:latest

# Set the working directory inside the container
WORKDIR /client

# Set up and activate virtual environment
ENV VIRTUAL_ENV="/venv"
RUN python -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# install requiremets
# --no-cache-dir is useful to reduce the container/image dimension
RUN pip install --no-cache-dir numpy pycryptodome

# Copy the application script into the container
COPY . .

# Run the Python script
CMD ["python3", "client.py"]
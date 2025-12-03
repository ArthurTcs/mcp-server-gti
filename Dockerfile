
# Use the official Python image.
# https://hub.docker.com/_/python
FROM python:3.11-slim

# Allow statements and log messages to immediately appear in the Knative logs
ENV PYTHONUNBUFFERED True

# Copy local code to the container image.
ENV APP_HOME /app
WORKDIR $APP_HOME
COPY . ./

# Install production dependencies.
RUN pip install --no-cache-dir .

# Run the web service on container startup.
# Use uvicorn to run the ASGI app.
# The PORT environment variable is defined by Cloud Run (default 8080).
CMD exec python -m gti_mcp.server

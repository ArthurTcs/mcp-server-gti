# Use a lightweight Python base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install uv for fast package management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/uv

# Copy project files
COPY pyproject.toml .
COPY README.md .
COPY gti_mcp/ gti_mcp/

# Install dependencies
# We use --system to install into the system python, which is fine in a container
RUN uv pip install --system .

# Expose the port
ENV PORT=8080
ENV FORWARDED_ALLOW_IPS="*"
EXPOSE 8080

# Run the server using uvicorn
CMD ["uvicorn", "gti_mcp.server:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]


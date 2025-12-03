# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Use Python 3.11 slim image as base
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install uv for fast Python package management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project files
COPY pyproject.toml setup.py ./
COPY gti_mcp/ ./gti_mcp/
COPY README.md ./

# Install dependencies using uv
RUN uv pip install --system -e .

# Set environment variables for Cloud Run
# STATELESS=1 ensures the server creates fresh transports for each request

# Expose the port Cloud Run expects
EXPOSE 8080

# Run the MCP server with SSE transport on /sse endpoint
CMD ["uv", "run", "python", "-m", "mcp.server.fastmcp.sse_server", "gti_mcp.server:server", "--port", "8080", "--sse-path", "/sse"]
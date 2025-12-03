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
# Add lifespan support for startup/shutdown with strong typing
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass

import logging
import os
import vt

from mcp.server.fastmcp import FastMCP, Context

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# If True, creates a completely fresh transport for each request
# with no session tracking or state persistence between requests.
stateless = False
if os.getenv("STATELESS") == "1":
  stateless = True


def _vt_client_factory(unused_ctx) -> vt.Client:
  api_key = os.getenv("VT_APIKEY")
  if not api_key:
    raise ValueError("VT_APIKEY environment variable is required")
  return vt.Client(api_key)

vt_client_factory = _vt_client_factory


@asynccontextmanager
async def vt_client(ctx: Context) -> AsyncIterator[vt.Client]:
  """Provides a vt.Client instance for the current request."""
  client = vt_client_factory(ctx)

  try:
    yield client
  finally:
    await client.close_async()

# Create a named server and specify dependencies for deployment and development
server = FastMCP(
    "Google Threat Intelligence MCP server",
    dependencies=["vt-py"],
    stateless_http=stateless)

# Load tools.
from gti_mcp.tools import *

# Run the server
def main():
  # Check if running in Cloud Run (or any environment with PORT env var)
  port = os.getenv('PORT')
  logger.info(f"Starting GTI MCP Server - PORT env var: {port}")
  
  if port:
    # Running in Cloud Run or similar - use SSE transport
    # FastMCP uses environment variables for port configuration
    logger.info(f"Running in Cloud Run mode with SSE transport on 0.0.0.0:{port}")
    os.environ['HOST'] = '0.0.0.0'
    server.run(transport='sse')
  else:
    # Running locally - use stdio transport
    logger.info("Running in local mode with stdio transport")
    server.run(transport='stdio')


if __name__ == '__main__':
  main()

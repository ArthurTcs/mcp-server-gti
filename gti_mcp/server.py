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

logging.basicConfig(level=logging.ERROR)


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
    dependencies=["vt-py"])

# Load tools.
from gti_mcp.tools import *

# Run the server
def main():
  server.run(transport='stdio')

# Create ASGI app for Cloud Run
# Create ASGI app for Cloud Run
app = None
try:
    if hasattr(server, 'create_asgi_app') and callable(server.create_asgi_app):
        app = server.create_asgi_app()
    elif hasattr(server, 'sse_app') and callable(server.sse_app):
        app = server.sse_app()
    elif hasattr(server, 'sse_app'):
        app = server.sse_app
    elif hasattr(server, '_mcp_server') and hasattr(server._mcp_server, 'app'):
        app = server._mcp_server.app
except Exception as e:
    logging.error(f"Error creating ASGI app: {e}")

if app is None:
    logging.warning("Could not create ASGI app from FastMCP. Falling back to Starlette.")
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.responses import JSONResponse

    async def health(request):
        return JSONResponse({"status": "ok"})

    app = Starlette(routes=[Route("/health", health)])

if __name__ == '__main__':
  import uvicorn
  import sys

  # Configure logging to ensure we see startup messages
  logging.basicConfig(level=logging.INFO)
  logger = logging.getLogger("gti_mcp.server")

  try:
    port = int(os.environ.get("PORT", 8080))
    logger.info(f"Starting server on port {port}")
    if app is None:
        logger.error("Failed to initialize ASGI app. Exiting.")
        sys.exit(1)
    uvicorn.run(app, host="0.0.0.0", port=port)
  except Exception as e:
    logger.exception("Failed to start server")
    sys.exit(1)


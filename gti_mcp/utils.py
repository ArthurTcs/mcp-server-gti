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
import asyncio
import logging
import vt
import typing
import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from mcp.server.fastmcp import Context


async def consume_vt_iterator(
    vt_client: vt.Client, endpoint: str, params: dict | None = None, limit: int = 10):
  """Consumes a vt.Iterator iterator and return the list of objects."""
  res = []
  async for obj in vt_client.iterator(endpoint, params=params, limit=limit):
    res.append(obj)
  return res


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


async def fetch_object(
    vt_client: vt.Client,
    resource_collection_type: str,
    resource_type: str,
    resource_id: str,
    attributes: list[str] | None = None,
    relationships: list[str] | None = None,
    params: dict[str, typing.Any] | None = None):
  """Fetches objects from Google Threat Intelligence API."""
  logging.info(
      f"Fetching comprehensive {resource_collection_type} "
      f"report for id: {resource_id}")
  
  params = {k: v for k, v in params.items()} if params else {}

  # Retrieve a selection of object attributes and/or relationships.
  if attributes:
    params["attributes"] = ",".join(attributes)
  if relationships:
    params["relationships"] = ",".join(relationships)

  obj = await vt_client.get_object_async(
      f"/{resource_collection_type}/{resource_id}", params=params)

  if obj.error:
    logging.error(
        f"Error fetching main {resource_type} report for {resource_id}: {obj.error}"
    )
    return {
        "error": f"Failed to get main {resource_type} report: {obj.error}",
        # "details": report.get("details"),
    }

  # Build response.
  obj_dict = obj.to_dict()
  obj_dict['id'] = obj.id
  if 'aggregations' in obj_dict['attributes']:
    del obj_dict['attributes']['aggregations']

  logging.info(
      f"Successfully generated concise threat summary for id: {resource_id}")
  return obj_dict


async def fetch_object_relationships(
    vt_client: vt.Client,
    resource_collection_type: str,
    resource_id: str,
    relationships: typing.List[str],
    params: dict[str, typing.Any] | None = None,
    descriptors_only: bool = True,
    limit: int = 10):
  """Fetches the given relationships descriptors from the given object."""
  rel_futures = {}
  # If true, returns descriptors instead of full objects.
  descriptors = '/relationship' if descriptors_only else ''
  async with asyncio.TaskGroup() as tg:
    for rel_name in relationships:
      rel_futures[rel_name] = tg.create_task(
          consume_vt_iterator(
              vt_client,
              f"/{resource_collection_type}/{resource_id}"
              f"{descriptors}/{rel_name}", params=params, limit=limit))

  data = {}
  for name, items in rel_futures.items():
    data[name] = []
    for obj in items.result():
      obj_dict = obj.to_dict()
      if 'aggregations' in obj_dict['attributes']:
        del obj_dict['attributes']['aggregations']
      data[name].append(obj_dict)

  return data


def sanitize_response(data: typing.Any) -> typing.Any:
  """Removes empty dictionaries and lists recursively from a response."""
  if isinstance(data, dict):
    sanitized_dict = {}
    for key, value in data.items():
      sanitized_value = sanitize_response(value)
      if sanitized_value is not None:
        sanitized_dict[key] = sanitized_value
    return sanitized_dict if sanitized_dict else None
  elif isinstance(data, list):
    sanitized_list = []
    for item in data:
      sanitized_item = sanitize_response(item)
      if sanitized_item is not None:
        sanitized_list.append(sanitized_item)
    return sanitized_list if sanitized_list else None
  elif isinstance(data, str):
    return data if data else None
  else:
    return data


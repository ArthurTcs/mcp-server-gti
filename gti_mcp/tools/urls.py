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
import base64
import typing

from mcp.server.fastmcp import Context

from .. import utils
from ..server import server, vt_client


URL_RELATIONSHIPS = [
    "analyses",
    "associations",
    "campaigns",
    "collections",
    "comments",
    "communicating_files",
    "contacted_domains",
    "contacted_ips",
    "downloaded_files",
    "embedded_js_files",
    "graphs",
    "http_response_contents",
    "last_serving_ip_address",
    "malware_families",
    "memory_pattern_parents",
    "network_location",
    "redirecting_urls",
    "referrer_files",
    "related_comments",
    "related_reports",
    "related_threat_actors",
    "reports",
    "submissions",
    "screenshots",
    "software_toolkits",
    "user_votes",
    "votes",
]

URL_KEY_RELATIONSHIPS = [
    "last_serving_ip_address",
    "network_location",
]


def register_tools(mcp: FastMCP):
    @mcp.tool()
    async def get_url_report(url: str, ctx: Context) -> typing.Dict[str, typing.Any]:
      """Get a comprehensive URL analysis report from Google Threat Intelligence.

      Args:
        url (required): URL to analyze.
      Returns:
        Report with insights about the URL.
      """
      async with vt_client(ctx) as client:
        res = await utils.fetch_object(
            client,
            "urls",
            "url",
            utils.url_id(url),
            relationships=URL_KEY_RELATIONSHIPS,
            params={"exclude_attributes": "last_analysis_results"})
      return utils.sanitize_response(res)


    @mcp.tool()
    async def get_entities_related_to_a_url(
        url: str, relationship_name: str, descriptors_only: bool, ctx: Context, limit: int = 10
    ) -> typing.Dict[str, typing.Any]:
      """Retrieve entities related to the the given URL.

        The following table shows a summary of available relationships for URL objects.

        | Relationship                | Description                                                | Return type  |
        | --------------------------- | ---------------------------------------------------------- | ------------ |
        | analyses                    | Analyses for the URL.                                      | analysis     |
        | comments                    | Community posted comments about the URL.                   | comment      |
        | communicating_files         | Files that communicate with the URL.                       | file         |
        | contacted_domains           | Domains contacted by the URL.                              | domain       |
        | contacted_ips               | IP addresses contacted by the URL.                         | ip_address   |
        | downloaded_files            | Files downloaded from that URL.                            | file         |
        | graphs                      | Graphs including the URL.                                  | graph        |
        | last_serving_ip_address     | Last IP address that served the URL.                       | ip_address   |
        | memory_pattern_parents      | Files having a URL as string on memory during sandbox execution. | file   |
        | network_location            | Network location of the URL.                               | domain/ip_address |
        | redirecting_urls            | URLs redirecting to the URL.                               | url          |
        | referrer_files              | Files containing the URL.                                  | file         |
        | related_comments            | Community posted comments in the URL's related objects.    | comment      |
        | related_reports             | Reports that are directly and indirectly related to the URL. | collection |
        | related_threat_actors       | Threat actors related to the URL.                          | collection   |
        | reports                     | Reports directly associated to the URL.                    | collection   |
        | submissions                 | Submissions of the URL.                                    | submission   |
        | screenshots                 | Screenshots of the URL.                                    | screenshot   |
        | software_toolkits           | Software and Toolkits associated to the URL.               | collection   |
        | user_votes                  | Current user's votes.                                      | vote         |
        | votes                       | URL's votes.                                               | vote         |

        Args:
          url (required): URL to analyse.
          relationship_name (required): Relationship name.
          descriptors_only (required): Bool. Must be True when the target object type is one of file, domain, url, ip_address or collection.
          limit: Limit the number of entities to retrieve. 10 by default.
        Returns:
          List of entities related to the URL.
      """
      if not relationship_name in URL_RELATIONSHIPS:
        return {
           "error": f"Relationship {relationship_name} does not exist. "
                    f"Available relationships are: {','.join(URL_RELATIONSHIPS)}"
        }

      async with vt_client(ctx) as client:
        res = await utils.fetch_object_relationships(
            client,
            "urls", utils.url_id(url),
            relationships=[relationship_name],
            descriptors_only=descriptors_only,
            limit=limit)
      return utils.sanitize_response(res.get(relationship_name, []))

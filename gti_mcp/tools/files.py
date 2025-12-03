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
import logging
import typing

from mcp.server.fastmcp import FastMCP, Context

from .. import utils
from ..utils import vt_client


FILE_RELATIONSHIPS = [
    "bundled_files",
    "carbonblack_children",
    "carbonblack_parents",
    "cloned_files",
    "collections",
    "comments",
    "compressed_parents",
    "contacted_domains",
    "contacted_ips",
    "contacted_urls",
    "dropped_files",
    "email_parents",
    "embedded_domains",
    "embedded_ips",
    "embedded_urls",
    "execution_parents",
    "graphs",
    "historical_ssl_certificates",
    "historical_whois",
    "itw_domains",
    "itw_ips",
    "itw_urls",
    "memory_pattern_domains",
    "memory_pattern_ips",
    "memory_pattern_urls",
    "overlay_parents",
    "pcap_parents",
    "pe_resource_children",
    "pe_resource_parents",
    "related_comments",
    "related_reports",
    "related_threat_actors",
    "reports",
    "similar_files",
    "submissions",
    "screenshots",
    "software_toolkits",
    "target_domains",
    "target_ips",
    "target_urls",
    "urls",
    "user_votes",
    "votes",
    "vulnerabilities",
]

FILE_KEY_RELATIONSHIPS = [
    "contacted_domains",
    "contacted_ips",
    "contacted_urls",
]


def register_tools(mcp: FastMCP):
    @mcp.tool()
    async def get_file_report(hash: str, ctx: Context) -> typing.Dict[str, typing.Any]:
      """Get a comprehensive file analysis report from Google Threat Intelligence.

      Args:
        hash (required): SHA-256, SHA-1 or MD5 of the file.
      Returns:
        Report with insights about the file.
      """
      async with vt_client(ctx) as client:
        res = await utils.fetch_object(
            client,
            "files",
            "file",
            hash,
            relationships=FILE_KEY_RELATIONSHIPS,
            params={"exclude_attributes": "last_analysis_results"})
      return utils.sanitize_response(res)


    @mcp.tool()
    async def get_entities_related_to_a_file(
        hash: str, relationship_name: str, descriptors_only: bool, ctx: Context, limit: int = 10
    ) -> typing.Dict[str, typing.Any]:
      """Retrieve entities related to the the given file hash.

        The following table shows a summary of available relationships for file objects.

        | Relationship                | Description                                                | Return type  |
        | --------------------------- | ---------------------------------------------------------- | ------------ |
        | bundled_files               | Files bundled within the file.                             | file         |
        | carbonblack_children        | Files created by the file (CarbonBlack).                   | file         |
        | carbonblack_parents         | Files that created the file (CarbonBlack).                 | file         |
        | cloned_files                | Files containing the file.                                 | file         |
        | collections                 | IoC Collections associated to the file.                    | collection   |
        | comments                    | Community posted comments about the file.                  | comment      |
        | compressed_parents          | Compressed files that contain the file.                    | file         |
        | contacted_domains           | Domains contacted by the file.                             | domain       |
        | contacted_ips               | IP addresses contacted by the file.                        | ip_address   |
        | contacted_urls              | URLs contacted by the file.                                | url          |
        | dropped_files               | Files dropped by the file.                                 | file         |
        | email_parents               | Emails that contain the file.                              | file         |
        | embedded_domains            | Domains embedded in the file.                              | domain       |
        | embedded_ips                | IP addresses embedded in the file.                         | ip_address   |
        | embedded_urls               | URLs embedded in the file.                                 | url          |
        | execution_parents           | Files that executed the file.                              | file         |
        | graphs                      | Graphs including the file.                                 | graph        |
        | historical_ssl_certificates | SSL certificates associated with the file.                 | ssl-cert     |
        | historical_whois            | WHOIS information for the file.                            | whois        |
        | itw_domains                 | In-the-wild domains from which the file has been downloaded. | domain     |
        | itw_ips                     | In-the-wild IP addresses from which the file has been downloaded. | ip_address |
        | itw_urls                    | In-the-wild URLs from which the file has been downloaded.  | url          |
        | memory_pattern_domains      | Domains found in memory during sandbox execution.          | domain       |
        | memory_pattern_ips          | IP addresses found in memory during sandbox execution.     | ip_address   |
        | memory_pattern_urls         | URLs found in memory during sandbox execution.             | url          |
        | overlay_parents             | Files that contain the file as an overlay.                 | file         |
        | pcap_parents                | PCAP files that contain the file.                          | file         |
        | pe_resource_children        | Files contained in the file as PE resources.               | file         |
        | pe_resource_parents         | Files that contain the file as a PE resource.              | file         |
        | related_comments            | Community posted comments in the file's related objects.   | comment      |
        | related_reports             | Reports that are directly and indirectly related to the file. | collection |
        | related_threat_actors       | Threat actors related to the file.                         | collection   |
        | reports                     | Reports directly associated to the file.                   | collection   |
        | similar_files               | Files that are similar to the file.                        | file         |
        | submissions                 | Submissions of the file.                                   | submission   |
        | screenshots                 | Screenshots of the file.                                   | screenshot   |
        | software_toolkits           | Software and Toolkits associated to the file.              | collection   |
        | target_domains              | Domains targeted by the file (e.g. exploit).               | domain       |
        | target_ips                  | IP addresses targeted by the file (e.g. exploit).          | ip_address   |
        | target_urls                 | URLs targeted by the file (e.g. exploit).                  | url          |
        | urls                        | URLs related to the file.                                  | url          |
        | user_votes                  | Current user's votes.                                      | vote         |
        | votes                       | File's votes.                                              | vote         |
        | vulnerabilities             | Vulnerabilities associated to the file.                    | collection   |

        Args:
          hash (required): SHA-256, SHA-1 or MD5 of the file.
          relationship_name (required): Relationship name.
          descriptors_only (required): Bool. Must be True when the target object type is one of file, domain, url, ip_address or collection.
          limit: Limit the number of entities to retrieve. 10 by default.
        Returns:
          List of entities related to the file.
      """
      if not relationship_name in FILE_RELATIONSHIPS:
        return {
           "error": f"Relationship {relationship_name} does not exist. "
                    f"Available relationships are: {','.join(FILE_RELATIONSHIPS)}"
        }

      async with vt_client(ctx) as client:
        res = await utils.fetch_object_relationships(
            client, 
            "files", hash, 
            relationships=[relationship_name],
            descriptors_only=descriptors_only,
            limit=limit)
      return utils.sanitize_response(res.get(relationship_name, []))


@server.tool()
async def get_file_behavior_report(
    file_behaviour_id: str, ctx: Context
) -> typing.Dict[str, typing.Any]:
  """Retrieve the file behaviour report of the given file behaviour identifier.

  You can get all the file behaviour of a given a file by calling `get_entities_related_to_a_file` as the file hash and the `behaviours` as relationship name.

  The file behaviour ID is composed using the following pattern: "{file hash}_{sandbox name}".

  Args:
    file_behaviour_id (required): File behaviour ID.
  Returns:
    The file behaviour report.
  """
  async with vt_client(ctx) as client:
    res = await utils.fetch_object(
        client,
        "file_behaviours",
        "file_behaviour",
        file_behaviour_id,
        relationships=[
            "contacted_domains",
            "contacted_ips",
            "contacted_urls",
            "dropped_files",
            "embedded_domains",
            "embedded_ips",
            "embedded_urls",
            "associations",
        ],
    )
  return utils.sanitize_response(res)


@server.tool()
async def get_file_behavior_summary(hash: str, ctx: Context) -> typing.Dict[str, typing.Any]:
  """Retrieve a summary of all the file behavior reports from all the sandboxes.

  Args:
    hash (required): MD5/SHA1/SHA256) hash that identifies the file.
  Returns:
    The file behavior summary.
  """
  async with vt_client(ctx) as client:
    res = await client.get_async(f"/files/{hash}/behaviour_summary")
    res = await res.json_async()
  return utils.sanitize_response(res["data"])


@server.tool()
async def analyse_file(file_path: str, ctx: Context):
  """Upload and analyse the file in VirusTotal.

  The file will be uploaded to VirusTotal and shared with the community.

  Args:
    file_path (required): Path to the file for analysis. Use absolute path.
  Returns:
    The analysis report.
  """
  async with vt_client(ctx) as client:
    with open(file_path, "rb") as f:    
      analysis = await client.scan_file_async(file=f)
      logging.info(f"File {file_path} uploaded.")

    res = await client.wait_for_analysis_completion(analysis)
    logging.info(f"Analysis has completed with ID %s", res.id)
    return utils.sanitize_response(res.to_dict())

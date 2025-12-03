import typing
from mcp.server.fastmcp import FastMCP, Context
from .. import utils
from ..utils import vt_client

HUNTING_RULESET_RELATIONSHIPS = [
    "hunting_notification_files",
]

def register_tools(mcp: FastMCP):
    @mcp.tool()
    async def search(
        query: str, ctx: Context, limit: int = 10, order_by: str = "relevance-"
    ) -> typing.List[typing.Dict[str, typing.Any]]:
      """Search for threats in Google Threat Intelligence.

      You can use order_by to sort the results by: "relevance", "last_analysis_date", "first_submission_date", "last_submission_date". You can use the sign "+" to make it order ascending, or "-" to make it descending. By default is "relevance-"

      Args:
        query (required): Search query.
        limit: Limit the number of objects to retrieve. 10 by default.
        order_by: Order results by the given order key. "relevance-" by default.

      Returns:
        List of objects matching the query.
      """
      async with vt_client(ctx) as client:
        res = await utils.consume_vt_iterator(
            client,
            "/intelligence/search",
            params={"query": query, "order": order_by},
            limit=limit)
      return utils.sanitize_response([o.to_dict() for o in res])


    @mcp.tool()
    async def get_whois(
        query: str, ctx: Context, limit: int = 10
    ) -> typing.List[typing.Dict[str, typing.Any]]:
      """Get WHOIS information for a domain or IP address.

      Args:
        query (required): Domain or IP address.
        limit: Limit the number of objects to retrieve. 10 by default.

      Returns:
        List of WHOIS objects.
      """
      async with vt_client(ctx) as client:
        res = await utils.consume_vt_iterator(
            client,
            "/intelligence/whois_search",
            params={"query": query},
            limit=limit)
      return utils.sanitize_response([o.to_dict() for o in res])


    @mcp.tool()
    async def get_hunting_ruleset(ruleset_id: str, ctx: Context) -> typing.Dict[str, typing.Any]:
      """Get a Hunting Ruleset object from Google Threat Intelligence.

      A Hunting Ruleset object describes a user's hunting ruleset. It may contain multiple
      Yara rules. 

      The content of the Yara rules is in the `rules` attribute.

      Some important object attributes:
        - creation_date: creation date as UTC timestamp.
        - modification_date (int): last modification date as UTC timestamp.
        - name (str): ruleset name.
        - rule_names (list[str]): contains the names of all rules in the ruleset.
        - number_of_rules (int): number of rules in the ruleset.
        - rules (str): rule file contents.
        - tags (list[str]): ruleset's custom tags.
        
      Args:
        ruleset_id (required): Hunting ruleset identifier.

      Returns:
        Hunting Ruleset object.
      """
      async with vt_client(ctx) as client:
        res = await utils.fetch_object(
            client,
            "intelligence/hunting_rulesets",
            "hunting_ruleset",
            ruleset_id,
        )
      return utils.sanitize_response(res)


    @mcp.tool()
    async def get_entities_related_to_a_hunting_ruleset(
        ruleset_id: str, relationship_name: str, ctx: Context, limit: int = 10
    ) -> typing.Dict[str, typing.Any]:
      """Retrieve entities related to the the given Hunting Ruleset.

        The following table shows a summary of available relationships for Hunting ruleset objects.

        | Relationship         | Return object type                                |
        | :------------------- | :------------------------------------------------ |
        | hunting_notification_files | Files that matched with the ruleset filters |

        Args:
          ruleset_id (required): Hunting ruleset identifier.
          relationship_name (required): Relationship name.
          limit: Limit the number of entities to retrieve. 10 by default.
        Returns:
          List of objects related to the Hunting ruleset.
      """
      if not relationship_name in HUNTING_RULESET_RELATIONSHIPS:
          return {
              "error": f"Relationship {relationship_name} does not exist. "
              f"Available relationships are: {','.join(HUNTING_RULESET_RELATIONSHIPS)}"
          }

      async with vt_client(ctx) as client:
        res = await utils.fetch_object_relationships(
            client,
            "intelligence/hunting_rulesets",
            ruleset_id,
            [relationship_name],
            limit=limit)
      return utils.sanitize_response(res.get(relationship_name, []))

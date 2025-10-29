import asyncio
import os

from fastmcp import Client
from fastmcp.client.auth import OAuth

oauth = OAuth(
    mcp_url="http://localhost:5000",
    scopes=["openid"],
)

# Pass the JWT from IDCS login
token = os.getenv("TOKEN")
if token:
    print("using token")

client = Client("http://localhost:5000/mcp", auth=token or oauth)


async def main():
    async with client:
        await client.ping()

        # list available operations
        tools = await client.list_tools()
        print(f"Tools: {tools}")
        resources = await client.list_resources()
        print(f"Resources: {resources}")
        prompts = await client.list_prompts()
        print(f"Prompts: {prompts}")

        # call list regions tool
        # result = await client.call_tool("list_regions", {})
        result = await client.call_tool(
            "run_oci_command",
            {
                "command": "iam region list",
            },
        )
        print(result)


asyncio.run(main())

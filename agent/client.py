from langgraph_sdk import get_client
import asyncio

client = get_client(url="http://localhost:2024")

async def main():
    while True:
        prompt = input(">>> ")
        async for chunk in client.runs.stream(
            None,  # Threadless run
            "agent", # Name of assistant. Defined in langgraph.json.
            input={
            "messages": [{
                "role": "human",
                #"content": "What is LangGraph?",
                "content": prompt,
                }],
            },
            context={
                "model": "ollama:gpt-oss",
                # uncomment to enable reasoning
                #"model_args": {"reasoning": "high"},
                "system_prompt": """You are a helpful AI assistant. Use
                all tools at your disposal to help the person chatting with
                you and don't stop until you have completed the
                tasks they give you and answering the questions they ask you.
                Always run the commands and use the tools, don't tell the user
                how to run them.
                """,
            },
            stream_mode="messages-tuple"
        ):
            if chunk.event != "messages":
                continue
            message_chunk, metadata = chunk.data
            if message_chunk["additional_kwargs"] and message_chunk["additional_kwargs"]["reasoning_content"]:
                 print(message_chunk["additional_kwargs"]["reasoning_content"], end="", flush=True)
            if message_chunk["content"]:
                print(message_chunk["content"], end="", flush=True)
            #print(chunk.data)
        print("\n")

asyncio.run(main())

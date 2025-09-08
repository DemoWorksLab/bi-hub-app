import chainlit as cl
from utils.logging import logger
from auth.ensure_identity import ensure_identity
from services.mas_client import MASChatClient
from services.mas_normalizer import normalize
from services.renderer import ChainlitStream
from config import settings

mas_client = MASChatClient()

HIST_MAX_TURNS = settings.history_max_turns
HIST_MAX_CHARS = settings.history_max_turns

def _msg_char_len(msg: dict) -> int:
    """Heuristic length of a message's content; works for string content."""
    c = msg.get("content", "")
    if isinstance(c, str):
        return len(c)
    # If your MAS uses the newer content blocks [{type,text}, ...], sum lengths
    try:
        return sum(len(block.get("text", "")) for block in c if isinstance(c, list))
    except Exception:
        return 0

def _build_messages_with_history(user_text: str) -> list[dict]:
    """
    Build OpenAI-style messages with a trimmed history:
      - Keep the earliest system message (if present)
      - Keep up to HIST_MAX_TURNS most recent non-system turns
      - Enforce a coarse HIST_MAX_CHARS budget
      - Append the current user message last
    """
    history = cl.chat_context.to_openai() or []

    # 1) Extract and keep at most one system message (the first system in history)
    system_msgs = [m for m in history if m.get("role") == "system"]
    system_prefix = [system_msgs[0]] if system_msgs else []

    # 2) Non-system messages, newest → oldest
    non_system = [m for m in history if m.get("role") != "system"]

    # Keep last N turns
    recent = non_system[-HIST_MAX_TURNS:] if len(non_system) > HIST_MAX_TURNS else non_system[:]

    # 3) Enforce a rough char budget (walk from the end backwards)
    budget = HIST_MAX_CHARS
    trimmed: list[dict] = []
    for m in reversed(recent):
        l = _msg_char_len(m)
        if l > budget and trimmed:
            break
        budget -= l
        trimmed.append(m)
    trimmed.reverse()  # restore chronological order

    # 4) Append current user message
    current = {"role": "user", "content": user_text}

    messages = [*system_prefix, *trimmed, current]

    # Optional observability
    logger.info(
        "history_built",
        extra={
            "system": len(system_prefix),
            "kept_turns": len(trimmed),
            "total_chars": sum(_msg_char_len(m) for m in trimmed),
        },
    )
    return messages

@cl.set_starters
async def set_starters():
    starters = []
    for starter in settings.chat_starter_messages:
        starter_obj = cl.Starter(
            label=starter["label"], 
            message=starter["message"]
        )
        # Add optional fields if they exist
        if "command" in starter:
            starter_obj.command = starter["command"]
        if "icon" in starter:
            starter_obj.icon = starter["icon"]
        starters.append(starter_obj)
    return starters


@cl.on_chat_start
async def on_chat_start():
    identity = await ensure_identity()
    logger.info("Chat started")


@cl.on_message
async def on_message(message: cl.Message):
    identity = await ensure_identity()
    logger.info(f"Identity: {identity}")

    messages = _build_messages_with_history(message.content)

    renderer = ChainlitStream()
    await renderer.start()

    try:
        raw_events = mas_client.stram_raw(identity, messages)
        async for event in normalize(raw_events):
            if event["type"] == "text.delta":
                await renderer.on_text_delta(event["delta"])
            elif event["type"] == "text.done":
                await renderer.on_text_done(event["text"])
            elif event["type"] == "tool.call":
                await renderer.on_tool_call(event["name"], event["args"])
            elif event["type"] == "tool.output":
                await renderer.on_tool_output(event["name"], event["output"])
    except Exception as e:
        logger.error(f"Error: {e}")
        await cl.Message(content=str(e)).send()


@cl.on_chat_resume
async def on_chat_resume():
    identity = await ensure_identity()
    logger.info(f"Identity: {identity}")
    logger.info("Chat resumed")


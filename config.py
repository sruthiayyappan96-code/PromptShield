"""Settings and the Ollama client, shared by every module."""
import os

import ollama

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
CHAT_MODEL = os.getenv("CHAT_MODEL", "llama3.1")      # answers questions
JUDGE_MODEL = os.getenv("JUDGE_MODEL", "llama3.2")    # small, fast attack detector
EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")
CHROMA_PATH = os.getenv("CHROMA_PATH", "chroma_db")
LOG_PATH = os.getenv("LOG_PATH", "logs/blocked.jsonl")

client = ollama.Client(host=OLLAMA_HOST)


def missing_models():
    """Return None if Ollama is unreachable, else the list of models still to pull."""
    try:
        installed = [m.get("model") or m.get("name") for m in client.list()["models"]]
    except Exception:
        return None
    needed = {CHAT_MODEL, JUDGE_MODEL, EMBED_MODEL}
    return sorted(
        n for n in needed
        if not any(i and (i == n or i.startswith(n + ":")) for i in installed)
    )
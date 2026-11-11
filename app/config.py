from dataclasses import dataclass
import os
from dotenv import load_dotenv

load_dotenv()

@dataclass(frozen=True)
class Settings:
    provider: str = os.getenv("AI1_PROVIDER", "gemini").lower()
    api_key: str = os.getenv("AI1_API_KEY", "")
    base_url: str = os.getenv("AI1_BASE_URL", "https://api.openai.com/v1")
    model: str = os.getenv("AI1_MODEL", "gpt-4o-mini")
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "qwen2.5:1.5b")
    database_path: str = os.getenv("AI1_DATABASE_PATH", "data/ai1.sqlite3")
    max_message_chars: int = int(os.getenv("AI1_MAX_MESSAGE_CHARS", "12000"))

settings = Settings()

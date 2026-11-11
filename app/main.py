from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from app.config import settings
from app.db import ChatStore
from app.provider import OpenAICompatibleProvider

BASE_DIR = Path(__file__).resolve().parent
store = ChatStore(settings.database_path)

if settings.provider == "gemini":
    provider = OpenAICompatibleProvider(
        settings.api_key, settings.base_url, settings.model
    )
    active_model = settings.model
elif settings.provider == "ollama":
    provider = OpenAICompatibleProvider(
        "", settings.ollama_base_url, settings.ollama_model
    )
    active_model = settings.ollama_model
else:
    raise ValueError("AI1_PROVIDER must be 'gemini' or 'ollama'")

app = FastAPI(title="AI-1", version="0.1.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

class ChatRequest(BaseModel):
    message: str = Field(min_length=1)

@app.get("/")
async def index():
    return FileResponse(BASE_DIR / "static" / "index.html")

@app.get("/api/health")
async def health():
    return {
        "ok": True,
        "provider": settings.provider,
        "provider_configured": bool(settings.api_key) if settings.provider == "gemini" else True,
        "model": active_model
    }

@app.get("/api/history")
async def history():
    return {"messages": store.history()}

@app.delete("/api/history")
async def clear_history():
    store.clear()
    return {"ok": True}

@app.post("/api/chat")
async def chat(request: ChatRequest):
    message = request.message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="Message cannot be empty")
    if len(message) > settings.max_message_chars:
        raise HTTPException(status_code=413, detail=f"Message is too long (max {settings.max_message_chars} characters)")
    previous = store.history(limit=20)
    context = [{"role": m["role"], "content": m["content"]} for m in previous]
    context.append({"role": "user", "content": message})
    try:
        answer = await provider.reply(context)
        return {"reply": answer}
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        print(f"AI-1 connection error: {type(exc).__name__}: {exc}", flush=True)
        raise HTTPException(status_code=502, detail="Could not reach the AI provider. Check the connection and provider settings.") from exc

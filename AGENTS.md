# AI-1 agent instructions

- Read the AI-01 project page in Notion before substantial changes.
- Keep source code in this repository; use Notion for decisions and dated handoffs.
- Keep secrets in local `.env`; never commit or paste keys into chat/Notion.
- Preserve localhost-only binding unless the user explicitly approves a reviewed security design.
- Do not add arbitrary shell execution or unrestricted filesystem access.
- Run `python -m pytest -q` after changes and report exact results.
- Inspect licenses before reusing external code; prefer official upstream examples and minimal dependencies.

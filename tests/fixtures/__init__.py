"""Payload fixtures. Secrets are placeholders filled in at load time."""

import json
from pathlib import Path

from claude_guard.payload import JsonObject

FIXTURES = Path(__file__).parent

# Built at runtime so no credential-shaped strings are committed.
PLACEHOLDERS = {
    "{{ANTHROPIC_KEY}}": "sk-" + "ant-api03-" + "Qw7Er9Ty2Ui4Op6As8Df1Gh3Jk5Lz0Xc",
    "{{GITHUB_TOKEN}}": "gh" + "p_" + "Ab3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zCaBcD",
}


def load(name: str) -> JsonObject:
    text = (FIXTURES / f"{name}.json").read_text(encoding="utf-8")
    for placeholder, value in PLACEHOLDERS.items():
        text = text.replace(placeholder, value)
    data = json.loads(text)
    assert isinstance(data, dict)
    return data

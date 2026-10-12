"""Tests for the secrets detector.

Fake credentials are assembled at runtime so the repository never contains strings that
secret scanners (including this project) would flag.
"""

import pytest

from claude_guard.config import Policy, SecretsPolicy
from claude_guard.detectors.secrets import (
    SecretsDetector,
    iban_valid,
    luhn_valid,
    nrb_valid,
    pesel_valid,
    shannon_entropy,
)
from claude_guard.models import Action, Direction
from tests.detectors.helpers import findings, rules, text_ctx

ALNUM = "Ab3dE5gH7jK9mN1pQ2rS4tU6vW8xY0zC"


def fake(prefix: str, length: int, alphabet: str = ALNUM) -> str:
    body = (alphabet * (length // len(alphabet) + 1))[:length]
    return prefix + body


ANTHROPIC_KEY = fake("sk-" + "ant-api03-", 40)
OPENAI_KEY = fake("sk-" + "proj-", 48)
AWS_KEY_ID = "AKIA" + "Q3EGRZ7JYXPLM4TN"
AWS_SECRET = fake("", 40, "wJalrXUtnFEMIK7MDENGbPxRfiCYzKEY0123456789/+")
GITHUB_TOKEN = fake("gh" + "p_", 36)
SLACK_TOKEN = "xo" + "xb-1234567890-abcdefghijkl"
STRIPE_KEY = fake("sk" + "_live_", 24)
GOOGLE_KEY = fake("AI" + "za", 35)
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)
GITLAB_TOKEN = fake("gl" + "pat-", 20)
HF_TOKEN = fake("h" + "f_", 34)
NPM_TOKEN = fake("np" + "m_", 36)
PYPI_TOKEN = fake("py" + "pi-AgEIcHlwaS5vcmc", 60)
SENDGRID_KEY = fake("S" + "G.", 22) + "." + fake("", 43)
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"


@pytest.fixture
def detector() -> SecretsDetector:
    return SecretsDetector(Policy())


# --- Positive ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "rule"),
    [
        (f"export ANTHROPIC_API_KEY={ANTHROPIC_KEY}", "anthropic_api_key"),
        (f"key: {OPENAI_KEY}", "openai_api_key"),
        (f"id={AWS_KEY_ID}", "aws_access_key_id"),
        (f"aws_secret_access_key = {AWS_SECRET}", "aws_secret_access_key"),
        (f"token {GITHUB_TOKEN} here", "github_token"),
        (f"SLACK={SLACK_TOKEN}", "slack_token"),
        (f"stripe {STRIPE_KEY}", "stripe_live_key"),
        (f"maps {GOOGLE_KEY}", "google_api_key"),
        (f"Authorization: Bearer {JWT}", "jwt"),
        (f"key file:\n{PEM}\n", "private_key"),
        ("-----BEGIN " + "OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk (truncated", "private_key"),
        ("Card: 4111 1111 1111 1111, exp 12/29", "payment_card"),
        ("card=5555555555554444", "payment_card"),
        ("PESEL: 44051401359", "pesel"),
        ("IBAN PL61 1090 1014 0000 0712 1981 2874", "iban"),
        ("konto DE89370400440532013000", "iban"),
        ("GB82 WEST 1234 5698 7654 32", "iban"),
        ("nr konta 61 1090 1014 0000 0712 1981 2874", "nrb"),
        ('db_password = "S3cure!Passw0rd"', "credential_assignment"),
        ('{"api_key": "q8Lm2Zr7Tn"}', "credential_assignment"),
        (f"git clone https://oauth2:{GITLAB_TOKEN}@gitlab.com/g/p.git", "gitlab_token"),
        (f"HF_TOKEN={HF_TOKEN}", "huggingface_token"),
        (f"//registry.npmjs.org/:_authToken={NPM_TOKEN}", "npm_token"),
        (f"password = {PYPI_TOKEN}", "pypi_token"),
        (f"SENDGRID={SENDGRID_KEY}", "sendgrid_api_key"),
        ("psql postgres://admin:S3cr3tPassw0rd@db.internal:5432/app", "url_credentials"),
        ("REDIS_URL=redis://:hunter2hunter2@cache:6379/0", "url_credentials"),
        ("amqp://guest:Rabb1tPw!@mq.local//", "url_credentials"),
    ],
)
async def test_detects_secret(detector: SecretsDetector, text: str, rule: str) -> None:
    assert rule in await rules(detector, text_ctx(text))


async def test_high_entropy_string_warns(detector: SecretsDetector) -> None:
    result = await findings(detector, text_ctx("token: dGhpcyBpcyBhIHRlc3Q9PT0K8xQ2ZpLm"))
    assert [f.rule for f in result] == ["high_entropy"]
    assert result[0].action is Action.WARN


async def test_random_token_with_separators_still_flagged(detector: SecretsDetector) -> None:
    token = "aB3dE5gH7jK9mN1p-Q2rS4tU6vW8xY0zC_d4F6h8J0k2M4"
    assert await rules(detector, text_ctx(f"token={token}")) == ["high_entropy"]


async def test_high_entropy_segment_inside_path_still_flagged(detector: SecretsDetector) -> None:
    text = "/srv/app/dGhpcyBpcyBhIHRlc3Q9PT0K8xQ2ZpLm/config"
    [finding] = await findings(detector, text_ctx(text))
    assert finding.rule == "high_entropy"
    assert finding.span is not None
    assert text[finding.span.start : finding.span.end] == "dGhpcyBpcyBhIHRlc3Q9PT0K8xQ2ZpLm"


async def test_finding_has_span_redacted_excerpt_and_replacement(detector: SecretsDetector) -> None:
    text = f"key={ANTHROPIC_KEY} end"
    [finding] = await findings(detector, text_ctx(text))
    assert finding.span is not None
    assert text[finding.span.start : finding.span.end] == ANTHROPIC_KEY
    assert finding.excerpt == f"sk-ant-***{ANTHROPIC_KEY[-4:]}"
    assert ANTHROPIC_KEY not in (finding.excerpt or "")
    assert finding.replacement == "[REDACTED:anthropic_api_key]"
    assert finding.action is Action.REDACT
    assert finding.location == "messages[0].content[0].text"


async def test_url_credentials_redact_only_the_password(detector: SecretsDetector) -> None:
    text = "DATABASE_URL=postgres://app:S3cr3tPassw0rd@db:5432/app"
    [finding] = await findings(detector, text_ctx(text))
    assert finding.span is not None
    assert text[finding.span.start : finding.span.end] == "S3cr3tPassw0rd"


async def test_value_reported_once(detector: SecretsDetector) -> None:
    # The key is also high-entropy and sits in an assignment; only the specific rule reports it.
    assert await rules(detector, text_ctx(f'api_key = "{ANTHROPIC_KEY}"')) == ["anthropic_api_key"]


async def test_iban_digits_not_reported_as_card(detector: SecretsDetector) -> None:
    assert await rules(detector, text_ctx("PL61 1090 1014 0000 0712 1981 2874")) == ["iban"]


async def test_multiple_secrets_in_order(detector: SecretsDetector) -> None:
    text = f"{GITHUB_TOKEN} and {AWS_KEY_ID}"
    assert await rules(detector, text_ctx(text)) == ["github_token", "aws_access_key_id"]


async def test_inspects_all_directions(detector: SecretsDetector) -> None:
    ctx = text_ctx(f"leak {GITHUB_TOKEN}", direction=Direction.RESPONSE, role="assistant")
    assert await rules(detector, ctx) == ["github_token"]


# --- Negative ---------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Hello, please summarize this document.",
        "Order number 4111111111111112 shipped",  # fails Luhn
        "Phone: +48 601 234 567",
        "PESEL 44051401358",  # bad checksum
        "ID 00000000000",  # invalid date
        "IBAN DE89 3704 0044 0532 0130 01",  # bad mod-97
        "sk-ant-short",
        "eyJhbGciOi.notajwt.atall",
        "commit 3f786850e387550fdab836ed7e6dc881de23001b",  # hex hash
        "uuid 123e4567-e89b-12d3-a456-426614174000",
        "def test_function_name_with_many_words(): pass",
        "src/claude_guard/detectors/secrets.py",
        "cat /private/tmp/claude-501/-Users-alice-Projects-claude-guard/"
        "fcd58e72-4c7c-48c5-94cd-054b9643944e/scratchpad/live/hooks-test/notes.txt",
        "~/Library/Application_Support/Code/User/workspaceStorage/a1B2c3D4e5",
        "memory: ~/.claude/projects/-Users-alice-Projects-claude-guard9/memory/",
        "project -private-tmp-claude-501--Users-Alice-Projects-x-fcd58e72-4c7c-scratchpad-live",
    ],
)
async def test_no_findings(detector: SecretsDetector, text: str) -> None:
    assert await rules(detector, text_ctx(text)) == []


# --- False positives --------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "AWS docs example: AKIAIOSFODNN7EXAMPLE",
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        'password = "${DB_PASSWORD}"',
        'password: "<your-password>"',
        "api_key = os.environ['API_KEY']",
        "password = settings.database_password",
        'secret = get_secret("name")',
        "PASSWORD=changeme123",
        "api_key: your_api_key_here",
        'password = "********"',
        "password: str",
        "postgres://user:password@localhost:5432/db",
        "mysql://root:${DB_PASSWORD}@localhost/app",
        "https://user:<token>@example.com/repo.git",
        "ssh://git@github.com/org/repo.git",
        "git@github.com:org/repo.git",
        "http://[::1]:8080/health",
        "hf_hub_download(repo_id='x')",
        "npm_config_cache=/tmp/npm",
        "SG.example",
    ],
)
async def test_false_positives_ignored(detector: SecretsDetector, text: str) -> None:
    assert await rules(detector, text_ctx(text)) == []


async def test_custom_allowlist() -> None:
    policy = Policy(secrets=SecretsPolicy(allowlist=[r"^gh" + r"p_Ab3d"]))
    assert await rules(SecretsDetector(policy), text_ctx(GITHUB_TOKEN)) == []


async def test_disabled_category() -> None:
    policy = Policy(secrets=SecretsPolicy(enabled=False))
    assert await rules(SecretsDetector(policy), text_ctx(GITHUB_TOKEN)) == []


# --- Validators -------------------------------------------------------------


def test_validators() -> None:
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")
    assert pesel_valid("44051401359")
    assert not pesel_valid("4405140135")
    assert iban_valid("GB82WEST12345698765432")
    assert not iban_valid("GB82WEST1234569876543")  # wrong length for GB
    assert nrb_valid("61109010140000071219812874")
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0

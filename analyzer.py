"""Explainable English-language cue matching. No network, model or risk score."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

VERSION = "0.1.0"
MAX_CHARACTERS = 30000
LIMITATION = (
    "Textual cues are prompts for review, not proof of phishing. "
    "No matches does not mean safe. Sender identity, links and attachments are not verified."
)


@dataclass(frozen=True)
class Category:
    label: str
    mechanism: str
    check: str
    caveat: str


CATEGORIES = {
    "urgency": Category(
        "Time pressure",
        "A short deadline may encourage action before the request is checked.",
        "Pause and confirm the deadline through a contact channel you already trust.",
        "Legitimate reminders and time-sensitive work can contain the same wording.",
    ),
    "authority": Category(
        "Claimed authority",
        "A reference to a senior role or trusted team may encourage compliance.",
        "Confirm who sent the request using an independently known contact.",
        "Mentioning a role is not evidence of impersonation; this tool cannot authenticate a sender.",
    ),
    "threat": Category(
        "Threatened consequence",
        "A threatened loss of access or money may pressure the reader to comply.",
        "Check the account through its usual app or an independently obtained address.",
        "Genuine service notices can also describe account restrictions or consequences.",
    ),
    "reward": Category(
        "Reward or special offer",
        "An unexpected benefit may encourage engagement before its conditions are checked.",
        "Verify the offer independently, especially before sharing information or paying.",
        "Legitimate promotions may use similar language; an offer alone does not establish fraud.",
    ),
}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: str
    rationale: str


# Small, inspectable phrase rules. These are project heuristics, not NIST rules.
RULES = (
    Rule("U01", "urgency", r"\b(?:act|respond|reply|verify|pay|confirm|update)\s+(?:now|immediately|urgently)\b", "An action verb is paired with an immediate deadline."),
    Rule("U02", "urgency", r"\bwithin\s+(?:\d{1,3}|one|two|three|four|six|twelve|twenty[- ]four)\s+(?:minutes?|hours?)\b", "The message specifies a short time window."),
    Rule("U03", "urgency", r"\b(?:urgent\s+(?:action|request|notice)|immediate\s+action\s+required|last\s+chance|limited[- ]time\s+offer|by\s+(?:the\s+)?end\s+of\s+(?:the\s+)?day|before\s+midnight)\b", "A phrase creates a sense of limited time."),
    Rule("A01", "authority", r"\b(?:IT\s+(?:department|support|team)|security\s+(?:department|team)|help\s*desk|human\s+resources|payroll\s+(?:department|team))\b", "The text refers to an institutional or support role."),
    Rule("A02", "authority", r"\b(?:CEO|chief\s+executive\s+officer|managing\s+director|your\s+(?:manager|supervisor)|on\s+behalf\s+of\s+(?:the\s+)?(?:director|president|dean))\b", "The text refers to a senior or supervisory role."),
    Rule("T01", "threat", r"\b(?:account|access|mailbox|service)\s+(?:(?:will|may)\s+be|has\s+been|is)\s+(?:permanently\s+)?(?:suspended|blocked|terminated|disabled|closed|deleted)\b", "The message describes a loss of account or service access."),
    Rule("T02", "threat", r"\b(?:failure\s+to\s+(?:comply|respond|pay|verify)|(?:avoid|face)\s+(?:a\s+)?(?:penalty|fine|legal\s+action)|lose\s+(?:your\s+)?access)\b", "The message links inaction with a negative consequence."),
    Rule("R01", "reward", r"\b(?:you\s+(?:have\s+)?won|you['’]ve\s+won|claim\s+(?:your\s+)?(?:prize|reward|bonus)|free\s+gift|guaranteed\s+(?:returns?|profit)|exclusive\s+reward)\b", "The text promises a benefit or invites a reward claim."),
    Rule("R02", "reward", r"\b(?:you\s+have\s+been\s+(?:specially\s+)?selected|you['’]ve\s+been\s+(?:specially\s+)?selected|selected\s+(?:as\s+)?(?:a\s+)?(?:winner|lucky\s+recipient))\b", "The message suggests that the recipient has been specially selected."),
)
COMPILED_RULES = tuple((rule, re.compile(rule.pattern, re.IGNORECASE)) for rule in RULES)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    start: int
    end: int
    matched_text: str
    context: str
    rationale: str
    context_note: str


def context_for(text: str, start: int, end: int) -> str:
    """Return bounded surrounding text without changing source offsets."""
    left = text.rfind("\n", max(0, start - 120), start) + 1
    left = max(left, start - 120)
    right = text.find("\n", end, min(len(text), end + 120))
    if right == -1:
        right = min(len(text), end + 120)
    return text[left:right].strip()


def context_note(text: str, start: int) -> str:
    # Nearby negation or quotation is a reason to review context, not silently drop a cue.
    prefix = re.split(r"[.!?\n]", text[max(0, start - 65):start])[-1]
    if re.search(r"\b(?:do\s+not|don['’]t|never|not\s+required\s+to|no\s+need\s+to)\b", prefix, re.I):
        return "Nearby negative wording may reverse the meaning. Read the whole statement."
    local = text[max(0, start - 85):start].lower()
    if any(word in local for word in ("example", "training", "phrase", "quoted", "scam says")):
        return "This may be quoted or educational wording rather than a request to act."
    return ""


def analyze(text: str) -> dict:
    if not isinstance(text, str):
        raise TypeError("Email text must be a string.")
    if not text.strip():
        raise ValueError("Paste an email or load an example first.")
    if len(text) > MAX_CHARACTERS:
        raise ValueError(f"Keep the input to {MAX_CHARACTERS:,} characters or fewer.")
    findings = []
    for rule, pattern in COMPILED_RULES:
        for match in pattern.finditer(text):
            findings.append(Finding(
                rule.id, rule.category, match.start(), match.end(), match.group(),
                context_for(text, match.start(), match.end()), rule.rationale,
                context_note(text, match.start()),
            ))
    findings.sort(key=lambda item: (item.start, item.end, item.rule_id))
    counts = {key: sum(item.category == key for item in findings) for key in CATEGORIES}
    # The export contains matched excerpts and nearby context, but not a full input field.
    return {
        "app": "PhishWise", "version": VERSION,
        "scope": "English phrase-based cue analysis; no phishing classification",
        "input_characters": len(text), "counts": counts,
        "total_matches": len(findings), "categories_present": sum(n > 0 for n in counts.values()),
        "limitation": LIMITATION,
        "findings": [asdict(item) for item in findings],
        "guidance": {key: asdict(value) for key, value in CATEGORIES.items()},
    }

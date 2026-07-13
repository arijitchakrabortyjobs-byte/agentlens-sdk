"""
AgentLens Pre-Model PII Firewall
-----------------------------------
Tokenizes PII in user messages BEFORE they are sent to the LLM.
No personal identifier crosses the network boundary to the model.

DPDP Act 2023 §8: Data minimisation — only data strictly necessary
                   for the stated purpose may be processed.
RBI FREE-AI Pillar 5: Protection — user data must not be exposed
                       to model providers beyond what is necessary.

How it works:
  1. Scan user message for PII patterns (PAN, Aadhaar, account, phone, email)
  2. Replace each match with a deterministic token: [PAN_1], [AADHAAR_1], etc.
  3. Store the original values in a short-lived in-memory vault (PIIVault)
  4. Send the tokenized message to the LLM — no PII leaves the perimeter
  5. After the LLM responds, restore tokens in the response text for user display
  6. The vault is discarded after the turn — originals never hit the audit log

The audit log only ever sees hashes (via detect_pii_in_user_input), never raw PII.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# PII patterns — ordered from most-specific to least-specific to avoid
# the account-number pattern swallowing Aadhaar matches first.
# ─────────────────────────────────────────────────────────────────────────────

_PAN_RE      = re.compile(r'\b([A-Z]{5}[0-9]{4}[A-Z])\b')
_AADHAAR_RE  = re.compile(r'\b(\d{4}[\s-]\d{4}[\s-]\d{4})\b')
# Account numbers: 9–18 digits, not part of a longer number.
# Excluded: 10-digit mobile numbers (handled separately), Aadhaar (12 digits with spaces).
_ACCOUNT_RE  = re.compile(r'(?<!\d)(\d{9,18})(?!\d)')
_PHONE_RE    = re.compile(r'(\+91[\s-]?)?([6-9]\d{9})\b')
_EMAIL_RE    = re.compile(r'\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b')

# Toll-free prefixes — these are not personal phone numbers; don't tokenize them.
_TOLLFREE_RE = re.compile(r'^(1800|1860|1900)')


@dataclass
class PIIVault:
    """
    Short-lived in-memory mapping of tokens → original PII values.
    Discarded after each conversation turn.
    Never persisted to disk or included in audit logs.
    """
    _tokens: Dict[str, str] = field(default_factory=dict)

    def store(self, token: str, original: str) -> None:
        self._tokens[token] = original

    def restore(self, text: str) -> str:
        """Replace all tokens in text with their original values."""
        for token, original in self._tokens.items():
            text = text.replace(token, original)
        return text

    @property
    def token_count(self) -> int:
        return len(self._tokens)

    @property
    def pii_types_found(self) -> List[str]:
        """Returns list of PII type labels for audit metadata (no raw values)."""
        types = set()
        for token in self._tokens:
            # Token format: [TYPE_N]
            if token.startswith("[") and "_" in token:
                types.add(token[1:token.index("_")])
        return sorted(types)


def tokenize_pii(text: str) -> Tuple[str, PIIVault]:
    """
    Scan text for PII and replace with safe tokens.

    Returns:
        (tokenized_text, vault)
        tokenized_text: original text with PII replaced by [TYPE_N] tokens
        vault: PIIVault that can restore tokens in the LLM response

    The order of substitution matters:
        PAN first (most specific 10-char alphanumeric pattern)
        Aadhaar second (12-digit with spaces/dashes)
        Phone third (10-digit mobile — before account to avoid false matches)
        Account last (9-18 digits — broadest numeric pattern)
    """
    vault = PIIVault()
    counters: Dict[str, int] = {}
    result = text

    def _replace(match_text: str, pii_type: str) -> str:
        counters[pii_type] = counters.get(pii_type, 0) + 1
        token = f"[{pii_type}_{counters[pii_type]}]"
        vault.store(token, match_text)
        return token

    # 1. PAN — ABCDE1234F
    result = _PAN_RE.sub(lambda m: _replace(m.group(1), "PAN"), result)

    # 2. Aadhaar — 1234 5678 9012 or 1234-5678-9012
    result = _AADHAAR_RE.sub(lambda m: _replace(m.group(1), "AADHAAR"), result)

    # 3. Phone — +91-XXXXXXXXXX or 9XXXXXXXXX (skip toll-free)
    def _phone_replace(m: re.Match) -> str:
        full = m.group(0)
        number_part = m.group(2)
        if _TOLLFREE_RE.match(number_part):
            return full
        return _replace(full, "PHONE")
    result = _PHONE_RE.sub(_phone_replace, result)

    # 4. Email
    result = _EMAIL_RE.sub(lambda m: _replace(m.group(1), "EMAIL"), result)

    # 5. Account numbers — broadest pattern, must run last
    def _account_replace(m: re.Match) -> str:
        raw = m.group(1)
        # Skip if this is already a tokenized value or a year-like 4-digit number
        if raw in vault._tokens.values():
            return raw
        if len(raw) <= 4:
            return raw
        return _replace(raw, "ACCOUNT")
    result = _ACCOUNT_RE.sub(_account_replace, result)

    return result, vault


def firewall_messages(
    messages: List[Dict],
    enabled: bool = True,
) -> Tuple[List[Dict], PIIVault]:
    """
    Apply the PII firewall to a full messages list (OpenAI-style).
    Only tokenizes 'user' role messages — system and assistant messages
    are passed through unchanged.

    Returns:
        (clean_messages, vault)
        clean_messages: messages with PII tokenized in user turns
        vault: PIIVault for restoring tokens in the response
    """
    if not enabled:
        return messages, PIIVault()

    clean = []
    combined_vault = PIIVault()

    for msg in messages:
        if msg.get("role") == "user" and isinstance(msg.get("content"), str):
            clean_content, vault = tokenize_pii(msg["content"])
            combined_vault._tokens.update(vault._tokens)
            clean.append({**msg, "content": clean_content})
        else:
            clean.append(msg)

    return clean, combined_vault

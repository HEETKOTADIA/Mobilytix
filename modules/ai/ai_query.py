# modules/ai/ai_query.py

"""
AI Query Engine for Mobile Forensics

This module provides a high-level query interface over the enriched
ChromaDB vector store created by `ai_indexer.py`.

Core design goals (Smart Chat Mode):
- Use STRUCTURED analytics whenever possible (Python-side stats, filters)
- Use the LLM primarily for:
    - Explanation
    - Narrative
    - Pattern interpretation
- Keep everything grounded in the actual forensic data
- Avoid context-overflow errors with Groq (400) by trimming aggressively
"""

from __future__ import annotations

from groq import Groq
from modules.ai.ai_embedding import embed_text

from pathlib import Path
from collections import Counter
from datetime import datetime
import chromadb
import re
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def shrink_text(text: str, max_chars: int = 500) -> str:
    """
    Truncate a text chunk for inclusion in the LLM context.
    """
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]..."


def _normalize_phone(num: Any) -> str:
    """
    Normalize phone number by keeping only digits.
    Used for loose matching when country codes vary.
    """
    if num is None:
        return ""
    return "".join(ch for ch in str(num) if ch.isdigit())


def _parse_dt_flex(s: Any) -> Optional[datetime]:
    """
    Very forgiving datetime parser for metadata date fields.
    """
    if not s:
        return None

    s = str(s)
    # Try known formats
    fmts = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y",
        "%Y-%m-%d",
    ]
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            continue

    # Try timestamp-ish
    try:
        ts = float(s)
        if ts > 10_000_000:  # crude
            return datetime.fromtimestamp(ts)
    except Exception:
        pass

    return None


def _extract_phone_numbers_from_question(q: str) -> List[str]:
    """
    Extract potential phone-like tokens from a natural-language question.
    """
    if not q:
        return []

    # Basic patterns: +91..., 10-digit numbers, hyphenated, spaced
    patterns = [
        r"\+\d[\d\s\-]{8,}",      # +91 12345 67890 or +911234567890
        r"\b\d{10}\b",            # 10-digit local number
        r"\b\d{3}-\d{3}-\d{4}\b", # US-style
    ]
    found: List[str] = []
    for pat in patterns:
        matches = re.findall(pat, q)
        found.extend(matches)

    # Deduplicate while preserving order
    seen = set()
    normed = []
    for raw in found:
        n = _normalize_phone(raw)
        if n and n not in seen:
            seen.add(n)
            normed.append(n)

    return normed


# ---------------------------------------------------------------------------
# AI Query Engine
# ---------------------------------------------------------------------------

class AIQueryEngine:
    """
    High-level smart query engine over the 'forensics' Chroma collection.

    Responsibilities:
    - Detect structured / analytical queries (call stats, longest call, etc.)
    - Detect number-based queries ("analyze calls from +91...")
    - Use Python to compute reliable stats
    - Use LLM for natural explanations, pattern descriptions, correlation
    """

    MAX_CONTEXT_CHARS = 15000
    MAX_DOC_SNIPPET_CHARS = 1500

    def __init__(self, api_key: str, session_path: str | Path):
        self.client = Groq(api_key=api_key)
        self.session_path = Path(session_path)

        db_path = self.session_path / "vector_store"
        self.chroma = chromadb.PersistentClient(path=str(db_path))
        self.collection = self.chroma.get_or_create_collection("forensics")

    # -----------------------------------------------------------------------
    # Core analytical routing
    # -----------------------------------------------------------------------

    def _handle_analytical_query(self, question: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Attempt to answer the question with pure analytics / deterministic logic.

        Returns:
            (analytical_context, direct_answer)

            - If direct_answer is not None → return it directly to the user.
            - If analytical_context is not None → feed it into LLM with question.
            - If both None → fall back to semantic retrieval.
        """
        q_lower = question.lower().strip()

        # 1) Direct phone-based call analysis
        analytical_context, direct_answer = self._handle_phone_number_analysis(question, q_lower)
        if analytical_context or direct_answer:
            return analytical_context, direct_answer

        # 2) Call analytics (longest, shortest, stats...)
        analytical_context, direct_answer = self._handle_call_analytics(q_lower)
        if analytical_context or direct_answer:
            return analytical_context, direct_answer

        # 3) SMS analytics
        analytical_context, direct_answer = self._handle_sms_analytics(q_lower)
        if analytical_context or direct_answer:
            return analytical_context, direct_answer

        # 4) Contact analytics
        analytical_context, direct_answer = self._handle_contact_analytics(q_lower)
        if analytical_context or direct_answer:
            return analytical_context, direct_answer

        # Nothing matched analytically
        return None, None

    # -----------------------------------------------------------------------
    # 1) PHONE NUMBER-BASED ANALYSIS
    # -----------------------------------------------------------------------

    def _handle_phone_number_analysis(
        self,
        question: str,
        q_lower: str,
    ) -> Tuple[Optional[str], Optional[str]]:
        """
        Handle queries like:
            - "Show all calls with +917990337983"
            - "Analyze calls from 7990337983"
            - "What messages are from this number +91 ...?"
        """
        numbers = _extract_phone_numbers_from_question(question)
        if not numbers:
            return None, None

        wants_calls = "call" in q_lower or "voice" in q_lower or "phone" in q_lower
        wants_sms = any(t in q_lower for t in ["sms", "message", "text", "otp"])

        # If user didn't specify, default to both calls + SMS
        if not wants_calls and not wants_sms:
            wants_calls = True
            wants_sms = True

        target_norm = numbers[0]  # take first detected
        target_raw_for_display = numbers[0]

        # 1A) CALLS for that number
        call_summary_block = ""
        if wants_calls:
            call_summary_block = self._analyze_calls_for_number(target_norm)

        # 1B) SMS for that number
        sms_summary_block = ""
        if wants_sms:
            sms_summary_block = self._analyze_sms_for_number(target_norm)

        if not call_summary_block and not sms_summary_block:
            # Deterministic: no records at all
            return None, (
                f"No calls or SMS records were found for number '{target_raw_for_display}' "
                f"(normalized: {target_norm}) in the available forensic dataset."
            )

        # Build analytical context to feed LLM (Smart Chat Mode)
        blocks = [
            f"TARGET NUMBER (normalized digits only): {target_norm}",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        ]
        if call_summary_block:
            blocks.append(call_summary_block)
        if sms_summary_block:
            if call_summary_block:
                blocks.append("\n")
            blocks.append(sms_summary_block)

        analytical_context = "\n".join(blocks)
        # No direct short answer; we want LLM to narrate it nicely
        return analytical_context, None

    def _analyze_calls_for_number(self, target_norm: str) -> str:
        """
        Collect and summarize all calls involving the normalized number.
        Returns a plain-text analytics block or "" if none exist.
        """
        results = self.collection.get(where={"type": {"$in": ["call", "call_fallback"]}})
        if not results.get("documents"):
            return ""

        matched_calls: List[Dict[str, Any]] = []
        for doc, meta in zip(results["documents"], results["metadatas"]):
            number_meta = meta.get("number", "") or meta.get("normalized_number", "")
            if not number_meta:
                continue

            number_norm = _normalize_phone(number_meta)
            if not number_norm:
                continue

            # Match exact or as suffix (handles missing country code)
            if not (number_norm == target_norm or number_norm.endswith(target_norm)):
                continue

            try:
                duration = float(meta.get("duration_seconds", 0.0))
            except Exception:
                duration = 0.0

            matched_calls.append(
                {
                    "duration": duration,
                    "minutes": duration / 60.0 if duration else 0.0,
                    "doc": doc,
                    "name": meta.get("name", "Unknown"),
                    "number": number_meta,
                    "date": meta.get("date", "Unknown"),
                    "direction": meta.get("call_direction", "unknown"),
                    "time_category": meta.get("time_category", "unknown"),
                }
            )

        if not matched_calls:
            return ""

        total_calls = len(matched_calls)
        total_duration = sum(c["duration"] for c in matched_calls)
        avg_duration = total_duration / total_calls if total_calls else 0.0

        incoming = sum(1 for c in matched_calls if c["direction"] == "incoming")
        outgoing = sum(1 for c in matched_calls if c["direction"] == "outgoing")
        missed = sum(1 for c in matched_calls if c["direction"] == "missed")

        # Sort chronologically (best-effort)
        def _dt_key(call: Dict[str, Any]) -> datetime:
            dt = _parse_dt_flex(call.get("date"))
            return dt or datetime.min

        matched_calls_sorted = sorted(matched_calls, key=_dt_key)

        lines: List[str] = []
        lines.append("CALLS INVOLVING THE TARGET NUMBER")
        lines.append("---------------------------------")
        lines.append(f"Total Calls     : {total_calls}")
        lines.append(f"Total Duration  : {total_duration/60:.1f} minutes")
        lines.append(f"Average Duration: {avg_duration:.1f} seconds")
        lines.append("")
        lines.append("Breakdown by Type:")
        lines.append(f"- Incoming: {incoming}")
        lines.append(f"- Outgoing: {outgoing}")
        lines.append(f"- Missed  : {missed}")
        lines.append("")
        lines.append("Sample Call Records (up to 20):")

        for idx, call in enumerate(matched_calls_sorted[:20], 1):
            lines.append(
                f"{idx}. {call['name']} ({call['number']}) | "
                f"{call['duration']:.0f} sec ({call['minutes']:.2f} min) | "
                f"{call['direction']} | {call['date']} | period={call['time_category']}"
            )

        return "\n".join(lines)

    def _analyze_sms_for_number(self, target_norm: str) -> str:
        """
        Collect and summarize all SMS involving the normalized number.
        Returns a plain-text analytics block or "" if none exist.
        """
        results = self.collection.get(where={"type": "sms"})
        if not results.get("documents"):
            return ""

        matched_msgs: List[Dict[str, Any]] = []
        for doc, meta in zip(results["documents"], results["metadatas"]):
            addr = meta.get("address", "")
            if not addr:
                continue
            addr_norm = _normalize_phone(addr)
            if not addr_norm:
                # Could be an alphanumeric sender (e.g., AD-SNITCH)
                continue

            if not (addr_norm == target_norm or addr_norm.endswith(target_norm)):
                continue

            try:
                body_len = int(meta.get("body_length", 0))
            except Exception:
                body_len = 0

            matched_msgs.append(
                {
                    "length": body_len,
                    "address": addr,
                    "date": meta.get("date", "Unknown"),
                    "direction": meta.get("direction", "unknown"),
                    "keywords": meta.get("keywords", ""),
                    "body": meta.get("body", ""),
                }
            )

        if not matched_msgs:
            return ""

        total_msgs = len(matched_msgs)
        total_chars = sum(m["length"] for m in matched_msgs)
        avg_len = total_chars / total_msgs if total_msgs else 0.0
        sent = sum(1 for m in matched_msgs if m["direction"] == "sent")
        received = sum(1 for m in matched_msgs if m["direction"] == "received")

        # Sort chronologically (best-effort)
        def _dt_key(m: Dict[str, Any]) -> datetime:
            dt = _parse_dt_flex(m.get("date"))
            return dt or datetime.min

        matched_msgs_sorted = sorted(matched_msgs, key=_dt_key)

        lines: List[str] = []
        lines.append("SMS MESSAGES INVOLVING THE TARGET NUMBER")
        lines.append("----------------------------------------")
        lines.append(f"Total Messages  : {total_msgs}")
        lines.append(f"Sent            : {sent}")
        lines.append(f"Received        : {received}")
        lines.append(f"Total Characters: {total_chars}")
        lines.append(f"Average Length  : {avg_len:.0f} characters")
        lines.append("")
        lines.append("Sample Messages (up to 15):")

        for idx, msg in enumerate(matched_msgs_sorted[:15], 1):
            preview = msg["body"][:200].replace("\n", " ")
            if len(msg["body"]) > 200:
                preview += "..."
            lines.append(
                f"{idx}. [{msg['direction']}] {msg['address']} @ {msg['date']} | "
                f"len={msg['length']} | keywords={msg['keywords'] or 'none'}\n"
                f"   \"{preview}\""
            )

        return "\n".join(lines)

    # -----------------------------------------------------------------------
    # 2) CALL ANALYTICS (non-number-specific)
    # -----------------------------------------------------------------------

    def _handle_call_analytics(self, q_lower: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Handle high-level call analytics:
        - longest/shortest call
        - totals
        - most frequent caller
        - missed calls
        - night calls
        - long calls
        """
        # LONGEST CALL
        if "longest call" in q_lower:
            return self._analytics_longest_call()

        # SHORTEST CALL
        if "shortest call" in q_lower:
            return self._analytics_shortest_call()

        # MOST FREQUENT CALLER / CONTACT
        if any(t in q_lower for t in ["most frequent call", "most calls", "who calls most", "most contacted"]):
            return self._analytics_most_frequent_caller()

        # NIGHT CALLS
        if any(t in q_lower for t in ["night call", "late night call", "calls at night"]):
            return self._analytics_night_calls()

        # MISSED CALLS
        if "missed call" in q_lower:
            return self._analytics_missed_calls()

        # LONG CALLS (general)
        if "long call" in q_lower and "longest" not in q_lower:
            return self._analytics_long_calls()

        # TOTAL CALL STATISTICS
        if any(t in q_lower for t in ["how many calls", "total calls", "call statistics", "call stats"]):
            return self._analytics_call_stats()

        return None, None

    def _get_all_calls(self) -> Dict[str, Any]:
        return self.collection.get(where={"type": {"$in": ["call", "call_fallback"]}})

    def _analytics_longest_call(self) -> Tuple[Optional[str], Optional[str]]:
        results = self._get_all_calls()
        if not results.get("documents"):
            return None, "No call data found in the database."

        calls = []
        for doc, meta in zip(results["documents"], results["metadatas"]):
            try:
                duration = float(meta.get("duration_seconds", 0))
            except Exception:
                continue
            calls.append(
                {
                    "duration": duration,
                    "minutes": duration / 60.0,
                    "doc": doc,
                    "name": meta.get("name", "Unknown"),
                    "number": meta.get("number", "Unknown"),
                    "date": meta.get("date", "Unknown"),
                    "direction": meta.get("call_direction", "unknown"),
                    "time_category": meta.get("time_category", "unknown"),
                }
            )

        if not calls:
            return None, "No valid call duration data found."

        longest = max(calls, key=lambda x: x["duration"])
        context = f"""
LONGEST CALL ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Duration   : {longest['duration']:.0f} seconds ({longest['minutes']:.2f} minutes)
Contact    : {longest['name']}
Number     : {longest['number']}
Type       : {longest['direction']}
Time Period: {longest['time_category']}
Date/Time  : {longest['date']}

Total Calls Analyzed: {len(calls)}
Average Duration    : {sum(c['duration'] for c in calls) / len(calls):.1f} seconds

Representative Record:
{shrink_text(longest['doc'], 800)}
"""
        # Let LLM narrate this
        return context, None

    def _analytics_shortest_call(self) -> Tuple[Optional[str], Optional[str]]:
        results = self._get_all_calls()
        if not results.get("documents"):
            return None, "No call data found."

        calls = []
        for doc, meta in zip(results["documents"], results["metadatas"]):
            try:
                duration = float(meta.get("duration_seconds", 0))
            except Exception:
                continue
            if duration <= 0:
                # skip missed/zero-duration
                continue
            calls.append(
                {
                    "duration": duration,
                    "minutes": duration / 60.0,
                    "doc": doc,
                    "name": meta.get("name", "Unknown"),
                    "number": meta.get("number", "Unknown"),
                    "date": meta.get("date", "Unknown"),
                    "direction": meta.get("call_direction", "unknown"),
                }
            )

        if not calls:
            return None, "No valid non-zero call durations found."

        shortest = min(calls, key=lambda x: x["duration"])
        context = f"""
SHORTEST NON-MISSED CALL ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Duration: {shortest['duration']:.0f} seconds ({shortest['minutes']:.2f} minutes)
Contact : {shortest['name']}
Number  : {shortest['number']}
Type    : {shortest['direction']}
Date/Time: {shortest['date']}

Total non-missed calls analyzed: {len(calls)}
"""
        return context, None

    def _analytics_most_frequent_caller(self) -> Tuple[Optional[str], Optional[str]]:
        results = self._get_all_calls()
        if not results.get("documents"):
            return None, "No call data found."

        contact_data: Dict[str, Dict[str, Any]] = {}
        for meta in results["metadatas"]:
            name = meta.get("name", "Unknown")
            number = meta.get("number", "Unknown")
            try:
                duration = float(meta.get("duration_seconds", 0))
            except Exception:
                duration = 0.0
            direction = meta.get("call_direction", "unknown")

            key = f"{name} ({number})"
            if key not in contact_data:
                contact_data[key] = {
                    "count": 0,
                    "total_duration": 0.0,
                    "incoming": 0,
                    "outgoing": 0,
                    "missed": 0,
                }

            contact_data[key]["count"] += 1
            contact_data[key]["total_duration"] += duration

            if direction == "incoming":
                contact_data[key]["incoming"] += 1
            elif direction == "outgoing":
                contact_data[key]["outgoing"] += 1
            elif direction == "missed":
                contact_data[key]["missed"] += 1

        sorted_contacts = sorted(contact_data.items(), key=lambda x: x[1]["count"], reverse=True)[:10]

        lines = []
        lines.append("MOST FREQUENT CONTACTS (by call count)")
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append("")
        for idx, (contact, stats) in enumerate(sorted_contacts, 1):
            avg = stats["total_duration"] / stats["count"] if stats["count"] else 0.0
            lines.append(
                f"{idx}. {contact}\n"
                f"   Total Calls     : {stats['count']}\n"
                f"   Total Duration  : {stats['total_duration']/60:.1f} minutes\n"
                f"   Avg Call Length : {avg:.1f} seconds\n"
                f"   Breakdown       : {stats['incoming']} incoming, "
                f"{stats['outgoing']} outgoing, {stats['missed']} missed\n"
            )

        lines.append(f"Total unique contacts: {len(contact_data)}")

        context = "\n".join(lines)
        return context, None

    def _analytics_night_calls(self) -> Tuple[Optional[str], Optional[str]]:
        results = self.collection.get(where={"type": {"$in": ["call", "call_fallback"]}, "time_category": "night"})
        if not results.get("documents"):
            return None, "No night-time calls found."

        lines = []
        lines.append(f"NIGHT-TIME CALLS (total: {len(results['documents'])})")
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append("")

        for idx, (doc, meta) in enumerate(zip(results["documents"][:20], results["metadatas"][:20]), 1):
            try:
                dur_min = float(meta.get("duration_seconds", 0)) / 60.0
            except Exception:
                dur_min = 0.0
            lines.append(
                f"{idx}. {meta.get('name', 'Unknown')} ({meta.get('number', 'Unknown')})\n"
                f"   Duration: {dur_min:.1f} minutes\n"
                f"   Type    : {meta.get('call_direction', 'unknown')}\n"
                f"   Time    : {meta.get('date', 'Unknown')}\n"
            )

        context = "\n".join(lines)
        return context, None

    def _analytics_missed_calls(self) -> Tuple[Optional[str], Optional[str]]:
        results = self.collection.get(
            where={"type": {"$in": ["call", "call_fallback"]}, "is_missed": True}
        )
        if not results.get("documents"):
            return None, "No missed calls found."

        missed_by_contact = Counter()
        for meta in results["metadatas"]:
            c = f"{meta.get('name', 'Unknown')} ({meta.get('number', 'Unknown')})"
            missed_by_contact[c] += 1

        lines = []
        lines.append(f"MISSED CALLS ANALYSIS (total missed events: {len(results['documents'])})")
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append("")
        lines.append("Top contacts with missed calls:")
        for idx, (c, count) in enumerate(missed_by_contact.most_common(10), 1):
            lines.append(f"{idx}. {c} - {count} missed calls")

        context = "\n".join(lines)
        return context, None

    def _analytics_long_calls(self) -> Tuple[Optional[str], Optional[str]]:
        results = self.collection.get(
            where={"type": {"$in": ["call", "call_fallback"]}, "is_long_call": True}
        )
        if not results.get("documents"):
            return None, "No long calls (>10 minutes) found."

        call_list = []
        for doc, meta in zip(results["documents"], results["metadatas"]):
            try:
                duration = float(meta.get("duration_seconds", 0))
            except Exception:
                duration = 0.0
            call_list.append(
                {
                    "name": meta.get("name", "Unknown"),
                    "number": meta.get("number", "Unknown"),
                    "duration": duration,
                    "date": meta.get("date", "Unknown"),
                    "direction": meta.get("call_direction", "unknown"),
                    "doc": doc,
                }
            )

        call_list.sort(key=lambda x: x["duration"], reverse=True)

        lines = []
        lines.append(f"LONG CALLS (>10 minutes) - {len(call_list)} found")
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append("")
        for idx, call in enumerate(call_list[:15], 1):
            lines.append(
                f"{idx}. {call['name']} ({call['number']})\n"
                f"   Duration: {call['duration']/60:.1f} minutes\n"
                f"   Type    : {call['direction']}\n"
                f"   Date    : {call['date']}\n"
            )

        context = "\n".join(lines)
        return context, None

    def _analytics_call_stats(self) -> Tuple[Optional[str], Optional[str]]:
        results = self._get_all_calls()
        if not results.get("documents"):
            return None, "No call data found."

        total = len(results["documents"])
        total_duration = 0.0
        incoming = outgoing = missed = 0
        night = long_calls = 0

        for meta in results["metadatas"]:
            try:
                dur = float(meta.get("duration_seconds", 0))
            except Exception:
                dur = 0.0
            total_duration += dur
            direction = meta.get("call_direction", "")

            if direction == "incoming":
                incoming += 1
            elif direction == "outgoing":
                outgoing += 1
            elif direction == "missed":
                missed += 1

            if meta.get("time_category") == "night":
                night += 1

            if meta.get("is_long_call"):
                long_calls += 1

        avg = total_duration / total if total else 0.0

        context = f"""
CALL STATISTICS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Calls          : {total}
Total Duration       : {total_duration/60:.1f} minutes
Average Call Duration: {avg:.1f} seconds

Breakdown by Type:
- Incoming: {incoming}
- Outgoing: {outgoing}
- Missed  : {missed}

Special Categories:
- Night-time Calls (approx 9PM–5AM): {night}
- Long Calls (>10 minutes)         : {long_calls}
"""
        return context, None

    # -----------------------------------------------------------------------
    # 3) SMS ANALYTICS
    # -----------------------------------------------------------------------

    def _handle_sms_analytics(self, q_lower: str) -> Tuple[Optional[str], Optional[str]]:
        if any(t in q_lower for t in ["longest sms", "longest message", "longest text"]):
            return self._analytics_longest_sms()

        if any(t in q_lower for t in ["most sms", "most messages", "most texted", "most frequent sms"]):
            return self._analytics_most_frequent_sms_contact()

        if any(t in q_lower for t in ["how many sms", "total sms", "total messages"]):
            return self._analytics_sms_stats()

        return None, None

    def _get_all_sms(self) -> Dict[str, Any]:
        return self.collection.get(where={"type": "sms"})

    def _analytics_longest_sms(self) -> Tuple[Optional[str], Optional[str]]:
        results = self._get_all_sms()
        if not results.get("documents"):
            return None, "No SMS data found."

        messages = []
        for doc, meta in zip(results["documents"], results["metadatas"]):
            try:
                length = int(meta.get("body_length", 0))
            except Exception:
                length = 0
            messages.append(
                {
                    "length": length,
                    "body": meta.get("body", ""),
                    "address": meta.get("address", "Unknown"),
                    "date": meta.get("date", "Unknown"),
                    "direction": meta.get("direction", "unknown"),
                    "keywords": meta.get("keywords", "none"),
                    "doc": doc,
                }
            )

        if not messages:
            return None, "No valid SMS data found."

        longest = max(messages, key=lambda x: x["length"])
        avg_len = sum(m["length"] for m in messages) / len(messages)

        context = f"""
LONGEST SMS MESSAGE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Length   : {longest['length']} characters
Address  : {longest['address']}
Direction: {longest['direction']}
Date     : {longest['date']}
Keywords : {longest['keywords']}

Message Preview (first 500 chars):
{longest['body'][:500]}{'...' if len(longest['body']) > 500 else ''}

Dataset Stats:
- Total messages analyzed: {len(messages)}
- Average message length : {avg_len:.0f} characters
"""
        return context, None

    def _analytics_most_frequent_sms_contact(self) -> Tuple[Optional[str], Optional[str]]:
        results = self._get_all_sms()
        if not results.get("documents"):
            return None, "No SMS data found."

        contact_data: Dict[str, Dict[str, Any]] = {}
        for meta in results["metadatas"]:
            addr = meta.get("address", "Unknown")
            try:
                length = int(meta.get("body_length", 0))
            except Exception:
                length = 0
            direction = meta.get("direction", "unknown")

            if addr not in contact_data:
                contact_data[addr] = {
                    "count": 0,
                    "sent": 0,
                    "received": 0,
                    "total_chars": 0,
                }

            contact_data[addr]["count"] += 1
            contact_data[addr]["total_chars"] += length

            if direction == "sent":
                contact_data[addr]["sent"] += 1
            elif direction == "received":
                contact_data[addr]["received"] += 1

        sorted_contacts = sorted(contact_data.items(), key=lambda x: x[1]["count"], reverse=True)[:10]

        lines = []
        lines.append("MOST FREQUENT SMS CONTACTS")
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append("")
        for idx, (addr, data) in enumerate(sorted_contacts, 1):
            avg_len = data["total_chars"] / data["count"] if data["count"] else 0.0
            lines.append(
                f"{idx}. {addr}\n"
                f"   Total Messages: {data['count']}\n"
                f"   Sent          : {data['sent']}\n"
                f"   Received      : {data['received']}\n"
                f"   Avg Length    : {avg_len:.0f} characters\n"
            )

        lines.append(f"Total contacts: {len(contact_data)}")
        lines.append(f"Total messages: {sum(d['count'] for d in contact_data.values())}")

        context = "\n".join(lines)
        return context, None

    def _analytics_sms_stats(self) -> Tuple[Optional[str], Optional[str]]:
        results = self._get_all_sms()
        if not results.get("documents"):
            return None, "No SMS data found."

        total = len(results["documents"])
        sent = received = 0
        has_question = has_url = 0
        total_chars = 0

        for meta in results["metadatas"]:
            direction = meta.get("direction", "")
            if direction == "sent":
                sent += 1
            elif direction == "received":
                received += 1

            try:
                total_chars += int(meta.get("body_length", 0))
            except Exception:
                pass

            if meta.get("has_question"):
                has_question += 1
            if meta.get("has_url"):
                has_url += 1

        avg_len = total_chars / total if total else 0.0

        context = f"""
SMS STATISTICS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Messages          : {total}
Sent                    : {sent}
Received                : {received}
Average Message Length  : {avg_len:.0f} characters
Messages with Questions : {has_question}
Messages with URLs      : {has_url}
Total Characters        : {total_chars:,}
"""
        return context, None

    # -----------------------------------------------------------------------
    # 4) CONTACT ANALYTICS
    # -----------------------------------------------------------------------

    def _handle_contact_analytics(self, q_lower: str) -> Tuple[Optional[str], Optional[str]]:
        if any(t in q_lower for t in ["how many contacts", "total contacts"]):
            return self._analytics_contact_stats()

        if "business contact" in q_lower or "business contacts" in q_lower:
            return self._analytics_business_contacts()

        return None, None

    def _get_all_contacts(self) -> Dict[str, Any]:
        return self.collection.get(where={"type": "contact"})

    def _analytics_contact_stats(self) -> Tuple[Optional[str], Optional[str]]:
        results = self._get_all_contacts()
        if not results.get("documents"):
            return None, "No contact data found."

        total = len(results["documents"])
        business = with_email = emergency = 0

        for meta in results["metadatas"]:
            if meta.get("is_business"):
                business += 1
            if meta.get("has_email"):
                with_email += 1
            if meta.get("is_emergency"):
                emergency += 1

        personal = total - business

        context = f"""
CONTACT DATABASE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Contacts     : {total}
Personal Contacts  : {personal}
Business Contacts  : {business}
Contacts with Email: {with_email}
Emergency Contacts : {emergency}
"""
        return context, None

    def _analytics_business_contacts(self) -> Tuple[Optional[str], Optional[str]]:
        results = self.collection.get(where={"type": "contact", "is_business": True})
        if not results.get("documents"):
            return None, "No business contacts found."

        lines = []
        lines.append(f"BUSINESS CONTACTS (total: {len(results['documents'])})")
        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        lines.append("")
        for idx, meta in enumerate(results["metadatas"][:20], 1):
            lines.append(
                f"{idx}. {meta.get('name', 'Unknown')}\n"
                f"   Number: {meta.get('number', 'Unknown')}\n"
                f"   Email : {meta.get('email', 'Not provided')}\n"
            )

        context = "\n".join(lines)
        return context, None

    # -----------------------------------------------------------------------
    # SEMANTIC FALLBACK + LLM ORCHESTRATION
    # -----------------------------------------------------------------------

    def _build_semantic_context(self, question: str, k: int) -> str:
        """
        Use semantic search over the vector store to retrieve relevant documents.
        """
        q_embed = embed_text(question)
        results = self.collection.query(
            query_embeddings=[q_embed],
            n_results=k,
        )

        docs_list = results.get("documents") or []
        if not docs_list or not docs_list[0]:
            return "No matching forensic records were retrieved from the vector store."

        raw_docs = docs_list[0]
        docs = [shrink_text(d, self.MAX_DOC_SNIPPET_CHARS) for d in raw_docs]
        context = "\n\n--- DOCUMENT SPLIT ---\n\n".join(docs)
        return context

    def _trim_context(self, context: str) -> str:
        """
        Ensure the final context fed to Groq does not exceed safe size.
        """
        if len(context) <= self.MAX_CONTEXT_CHARS:
            return context
        return context[: self.MAX_CONTEXT_CHARS] + "\n\n...[context truncated due to size limit]..."

    # -----------------------------------------------------------------------
    # PUBLIC ENTRYPOINT
    # -----------------------------------------------------------------------

    def query(self, question: str, k: int = 12) -> str:
        """
        Entry point used by your Flask app.

        Strategy:
        1. Try structured analytics / deterministic logic.
        2. If a deterministic 'direct_answer' exists → return it immediately.
        3. If we have 'analytical_context' → LLM explains and interprets it.
        4. Otherwise → semantic search + LLM (Smart Chat Mode).
        """
        question = (question or "").strip()
        if not question:
            return "No question provided."

        # First: structured analytics
        analytical_context, direct_answer = self._handle_analytical_query(question)

        # Deterministic short answer (e.g., "No data found for this number")
        if direct_answer:
            return direct_answer

        # Build context for LLM
        if analytical_context:
            context = analytical_context
        else:
            context = self._build_semantic_context(question, k=k)

        # Trim to avoid Groq 400 errors
        context = self._trim_context(context)

        # Smart Chat forensic prompt
        prompt = f"""
You are a **digital forensics analyst** specializing in **Android mobile device forensics**.

You are given:
- User's natural-language question
- Structured forensic context (calls, SMS, contacts, device info)

YOUR JOB:
1. Answer the question as clearly as possible.
2. Base everything on the context; do NOT invent records that are not present.
3. You MAY:
   - infer patterns (e.g., "frequent night calls to X", "mostly short calls")
   - reason about likely behavior based on the data
   - correlate calls, SMS, contacts logically
4. You MUST:
   - clearly state if the data is missing, incomplete, or limited
   - avoid claiming that specific calls/SMS exist if the context suggests none
   - identify concrete evidence when making claims (e.g., "there are 12 calls to this number")

FORMAT:
- Start with a 2–3 line high-level conclusion.
- Then provide bullet-pointed evidence referencing the data.
- End with a short 'Forensic Notes' section mentioning limitations or caveats.

USER QUESTION:
{question}

FORENSIC CONTEXT:
{context}

Now provide your professional forensic analysis in clear, concise English.
"""

        resp = self.client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.45,  # slightly higher for smarter "chat" but still grounded
        )

        return resp.choices[0].message.content

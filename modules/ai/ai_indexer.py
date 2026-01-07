# modules/ai/ai_indexer.py

import json
from pathlib import Path
import chromadb
from modules.ai.ai_embedding import embed_text
from datetime import datetime
import re

# NEW: use the formatter for clean, consistent forensic docs + metadata
from modules.ai.ai_formatter import (
    format_call_entry,
    format_sms_entry,
    format_contact_entry,
    format_device_info,
    parse_contacts_raw_output,
)


# -----------------------------
# Metadata Flattener (Critical)
# -----------------------------
def flatten_metadata(meta: dict):
    """Flatten nested dicts and ensure all values are strings, numbers, or booleans"""
    flat = {}
    for k, v in meta.items():
        if isinstance(v, dict):
            for subk, subv in v.items():
                flat[f"{k}_{subk}"] = _sanitize_value(subv)
        else:
            flat[k] = _sanitize_value(v)
    return flat


def _sanitize_value(value):
    """Ensure metadata values are ChromaDB-compatible"""
    if value is None:
        return "Unknown"
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return str(value)
    return str(value)


def extract_phone_numbers(text: str):
    """Extract phone numbers from text for better searchability"""
    patterns = [
        r'\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
        r'\d{10}',
        r'\d{3}-\d{3}-\d{4}',
    ]
    numbers = []
    for pattern in patterns:
        numbers.extend(re.findall(pattern, text))
    return list(set(numbers))


def parse_timestamp(date_str):
    """Try to parse various date formats into a standardized timestamp (float)"""
    if not date_str or date_str == "Unknown":
        return None

    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y",
        "%Y%m%d",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(str(date_str), fmt)
            return dt.timestamp()
        except Exception:
            continue

    try:
        return float(date_str)
    except Exception:
        return None


class SessionIndexer:
    def __init__(self, session_path: str | Path):
        self.session_path = Path(session_path)
        self.db_path = self.session_path / "vector_store"
        self.db_path.mkdir(exist_ok=True)

        self.client = chromadb.PersistentClient(path=str(self.db_path))
        self.collection = self.client.get_or_create_collection(
            "forensics",
            metadata={"hnsw:space": "cosine"},
        )

    # -----------------------------
    # Index Device Info (FORMATTED)
    # -----------------------------
    def index_device_info(self):
        print("[+] Indexing device info...")
        dev_dir = self.session_path / "device_info_logs"
        if not dev_dir.exists():
            print("[!] No device_info_logs folder.")
            return

        for f in dev_dir.glob("*"):
            try:
                # First try: treat as JSON from new logger
                try:
                    with open(f, "r", encoding="utf-8") as fh:
                        data = json.load(fh)
                except Exception:
                    data = None

                if isinstance(data, dict) and data.get("log_type") == "device_info":
                    # NEW structured mode
                    doc, meta = format_device_info(data)
                    emb = embed_text(doc)
                    self.collection.add(
                        ids=[f"device_{f.name}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[doc],
                    )
                    print(f"    ✓ Indexed: {f.name} (structured device_info)")
                    continue

                # Fallback: legacy text file mode
                text = f.read_text(errors="ignore")

                meta = {
                    "type": "device_info",
                    "filename": f.name,
                    "content_length": len(text),
                }

                # Simple regex-based enrichments for legacy logs
                text_lower = text.lower()

                if "model" in text_lower:
                    model_match = re.search(r'model[:\s]+([^\n]+)', text, re.IGNORECASE)
                    if model_match:
                        meta["device_model"] = model_match.group(1).strip()

                if "android" in text_lower:
                    version_match = re.search(r'android[:\s]+([0-9.]+)', text, re.IGNORECASE)
                    if version_match:
                        meta["android_version"] = version_match.group(1).strip()

                if "ios" in text_lower:
                    version_match = re.search(r'ios[:\s]+([0-9.]+)', text, re.IGNORECASE)
                    if version_match:
                        meta["ios_version"] = version_match.group(1).strip()

                imei_match = re.search(r'imei[:\s]+([0-9]+)', text, re.IGNORECASE)
                if imei_match:
                    meta["imei"] = imei_match.group(1).strip()

                enhanced_text = f"""
DEVICE INFORMATION - {f.name}
{text}

Searchable fields: device info, hardware, system, model, version
"""
                emb = embed_text(enhanced_text)
                self.collection.add(
                    ids=[f"device_{f.name}"],
                    embeddings=[emb],
                    metadatas=[flatten_metadata(meta)],
                    documents=[enhanced_text],
                )
                print(f"    ✓ Indexed: {f.name} (legacy device_info)")
            except Exception as e:
                print(f"[!] Device info indexing error for {f.name}: {e}")

    # -----------------------------
    # Index SMS (FORMATTED)
    # -----------------------------
    def index_sms(self):
        print("[+] Indexing SMS with enhanced metadata...")
        sms_dir = self.session_path / "sms_logs"
        if not sms_dir.exists():
            print("[!] No sms_logs folder.")
            return

        for f in sms_dir.glob("*.json"):
            print(f"    -> {f.name}")
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception as e:
                print(f"[!] Error loading {f.name}: {e}")
                # last resort: index raw text
                raw_text = f.read_text(errors="ignore")
                emb = embed_text(raw_text)
                meta = {"type": "sms_fallback", "filename": f.name}
                self.collection.add(
                    ids=[f"sms_fallback_{f.name}"],
                    embeddings=[emb],
                    metadatas=[flatten_metadata(meta)],
                    documents=[raw_text],
                )
                print(f"    ⚠ Indexed {f.name} as raw text fallback")
                continue

            # NEW: structured SMS log format
            if isinstance(data, dict) and ("data" in data or data.get("log_type") == "sms"):
                records = data.get("data") or []
                if not isinstance(records, list):
                    records = []

                global_ctx = {
                    "device_serial": data.get("device_serial"),
                    "timestamp": data.get("timestamp"),
                    "extraction_method": data.get("extraction_method"),
                }

                count = 0
                for i, sms in enumerate(records):
                    if not isinstance(sms, dict):
                        continue
                    doc, meta = format_sms_entry(sms, global_ctx)
                    emb = embed_text(doc)
                    self.collection.add(
                        ids=[f"sms_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[doc],
                    )
                    count += 1

                print(f"    ✓ Indexed {count} structured SMS records from {f.name}")
                # Optionally index raw_output too, if present
                if data.get("raw_output"):
                    raw_doc = f"SMS RAW OUTPUT ({f.name}):\n{data['raw_output']}"
                    raw_emb = embed_text(raw_doc)
                    raw_meta = {
                        "type": "sms_raw_output",
                        "filename": f.name,
                        "raw_length": len(data["raw_output"]),
                    }
                    self.collection.add(
                        ids=[f"sms_rawout_{f.name}"],
                        embeddings=[raw_emb],
                        metadatas=[flatten_metadata(raw_meta)],
                        documents=[raw_doc],
                    )
                continue

            # LEGACY CASE 1 → whole file is raw string
            if isinstance(data, str):
                lines = [line for line in data.splitlines() if line.strip()]
                for i, line in enumerate(lines):
                    phone_numbers = extract_phone_numbers(line)
                    text = f"Raw SMS Line: {line}\nExtracted numbers: {', '.join(phone_numbers)}"
                    emb = embed_text(text)
                    meta = {
                        "type": "sms_raw",
                        "line": line,
                        "extracted_numbers": ", ".join(phone_numbers) if phone_numbers else "None",
                        "line_length": len(line),
                    }
                    self.collection.add(
                        ids=[f"sms_raw_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[text],
                    )
                print(f"    ✓ Indexed {len(lines)} raw SMS lines (legacy)")
                continue

            # LEGACY CASE 2 → list of strings
            if isinstance(data, list) and all(isinstance(x, str) for x in data):
                lines = [line for line in data if line.strip()]
                for i, line in enumerate(lines):
                    phone_numbers = extract_phone_numbers(line)
                    text = f"Raw SMS Entry: {line}\nExtracted numbers: {', '.join(phone_numbers)}"
                    emb = embed_text(text)
                    meta = {
                        "type": "sms_raw",
                        "line": line,
                        "extracted_numbers": ", ".join(phone_numbers) if phone_numbers else "None",
                        "line_length": len(line),
                    }
                    self.collection.add(
                        ids=[f"sms_rawlist_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[text],
                    )
                print(f"    ✓ Indexed {len(lines)} raw SMS entries (legacy)")
                continue

            # LEGACY CASE 3 → list of dicts
            if isinstance(data, list) and all(isinstance(x, dict) for x in data):
                count = 0
                for i, sms in enumerate(data):
                    doc, meta = format_sms_entry(sms, global_context=None)
                    emb = embed_text(doc)
                    self.collection.add(
                        ids=[f"sms_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[doc],
                    )
                    count += 1
                print(f"    ✓ Indexed {count} SMS messages with formatted metadata (legacy list[dict])")
                continue

            # FALLBACK: unknown shape
            text = json.dumps(data, indent=2)
            emb = embed_text(text)
            meta = {"type": "sms_fallback", "filename": f.name}
            self.collection.add(
                ids=[f"sms_fallback_{f.name}"],
                embeddings=[emb],
                metadatas=[flatten_metadata(meta)],
                documents=[text],
            )
            print(f"    ⚠ Indexed {f.name} as SMS fallback (unknown JSON shape)")

    # -----------------------------
    # Index CALLS (FORMATTED)
    # -----------------------------
    def index_calls(self):
        print("[+] Indexing Call Logs with enhanced metadata...")
        call_dir = self.session_path / "call_logs"
        if not call_dir.exists():
            print("[!] No call_logs folder.")
            return

        for f in call_dir.glob("*.json"):
            print(f"    -> {f.name}")
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception as e:
                print(f"[!] Error loading {f.name}: {e}")
                # last resort: index raw text
                raw_text = f.read_text(errors="ignore")
                emb = embed_text(raw_text)
                meta = {"type": "call_fallback", "filename": f.name}
                self.collection.add(
                    ids=[f"call_fallback_{f.name}"],
                    embeddings=[emb],
                    metadatas=[flatten_metadata(meta)],
                    documents=[raw_text],
                )
                print(f"    ⚠ Indexed {f.name} as raw call fallback")
                continue

            # NEW: structured call log format
            if isinstance(data, dict) and ("data" in data or data.get("log_type") == "call_logs"):
                records = data.get("data") or []
                if not isinstance(records, list):
                    records = []

                global_ctx = {
                    "device_serial": data.get("device_serial"),
                    "timestamp": data.get("timestamp"),
                    "extraction_method": data.get("extraction_method"),
                }

                count = 0
                for i, call in enumerate(records):
                    if not isinstance(call, dict):
                        continue
                    doc, meta = format_call_entry(call, global_ctx)
                    emb = embed_text(doc)
                    self.collection.add(
                        ids=[f"call_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[doc],
                    )
                    count += 1

                print(f"    ✓ Indexed {count} structured call records from {f.name}")
                # Optionally index raw_output as a separate document
                if data.get("raw_output"):
                    raw_doc = f"CALL RAW OUTPUT ({f.name}):\n{data['raw_output']}"
                    raw_emb = embed_text(raw_doc)
                    raw_meta = {
                        "type": "call_raw_output",
                        "filename": f.name,
                        "raw_length": len(data["raw_output"]),
                    }
                    self.collection.add(
                        ids=[f"call_rawout_{f.name}"],
                        embeddings=[raw_emb],
                        metadatas=[flatten_metadata(raw_meta)],
                        documents=[raw_doc],
                    )
                continue

            # LEGACY CASE 1 – raw string dump
            if isinstance(data, str):
                lines = [line for line in data.splitlines() if line.strip()]
                for i, line in enumerate(lines):
                    phone_numbers = extract_phone_numbers(line)
                    text = f"Raw Call Line: {line}\nExtracted numbers: {', '.join(phone_numbers)}"
                    emb = embed_text(text)
                    meta = {
                        "type": "call_raw",
                        "line": line,
                        "extracted_numbers": ", ".join(phone_numbers) if phone_numbers else "None",
                    }
                    self.collection.add(
                        ids=[f"call_raw_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[text],
                    )
                print(f"    ✓ Indexed {len(lines)} raw call lines (legacy)")
                continue

            # LEGACY CASE 2 – list of strings
            if isinstance(data, list) and all(isinstance(x, str) for x in data):
                lines = [line for line in data if line.strip()]
                for i, line in enumerate(lines):
                    phone_numbers = extract_phone_numbers(line)
                    text = f"Raw Call Entry: {line}\nExtracted numbers: {', '.join(phone_numbers)}"
                    emb = embed_text(text)
                    meta = {
                        "type": "call_raw",
                        "line": line,
                        "extracted_numbers": ", ".join(phone_numbers) if phone_numbers else "None",
                    }
                    self.collection.add(
                        ids=[f"call_rawlist_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[text],
                    )
                print(f"    ✓ Indexed {len(lines)} raw call entries (legacy)")
                continue

            # LEGACY CASE 3 – list of dicts
            if isinstance(data, list) and all(isinstance(x, dict) for x in data):
                count = 0
                for i, call in enumerate(data):
                    doc, meta = format_call_entry(call, global_context=None)
                    emb = embed_text(doc)
                    self.collection.add(
                        ids=[f"call_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[doc],
                    )
                    count += 1
                print(f"    ✓ Indexed {count} call records with formatted metadata (legacy list[dict])")
                continue

            # FALLBACK
            text = json.dumps(data, indent=2)
            emb = embed_text(text)
            meta = {"type": "call_fallback", "filename": f.name}
            self.collection.add(
                ids=[f"call_fallback_{f.name}"],
                embeddings=[emb],
                metadatas=[flatten_metadata(meta)],
                documents=[text],
            )
            print(f"    ⚠ Indexed {f.name} as call fallback (unknown JSON shape)")

    # -----------------------------
    # Index Contacts (FORMATTED)
    # -----------------------------
    def index_contacts(self):
        print("[+] Indexing Contacts with enhanced metadata...")
        cont_dir = self.session_path / "contacts_logs"
        if not cont_dir.exists():
            print("[!] No contacts_logs folder.")
            return

        for f in cont_dir.glob("*.json"):
            print(f"    -> {f.name}")
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception as e:
                print(f"[!] Error loading {f.name}: {e}")
                # fallback: raw text
                raw_text = f.read_text(errors="ignore")
                emb = embed_text(raw_text)
                meta = {"type": "contact_fallback", "filename": f.name}
                self.collection.add(
                    ids=[f"contact_fallback_{f.name}"],
                    embeddings=[emb],
                    metadatas=[flatten_metadata(meta)],
                    documents=[raw_text],
                )
                print(f"    ⚠ Indexed {f.name} as raw contact fallback")
                continue

            # NEW: structured contacts log
            if isinstance(data, dict) and ("data" in data or data.get("log_type") == "contacts"):
                records = data.get("data") or []
                if not isinstance(records, list):
                    records = []

                device_serial = data.get("device_serial")
                timestamp = data.get("timestamp")

                global_ctx = {
                    "device_serial": device_serial,
                    "timestamp": timestamp,
                }

                # Some of your contacts logs have record_count=0, but raw_output with all rows
                extra_from_raw = []
                if data.get("raw_output"):
                    extra_from_raw = parse_contacts_raw_output(
                        data["raw_output"],
                        device_serial=device_serial,
                        log_timestamp=timestamp,
                    )

                all_records = []
                for rec in records:
                    if isinstance(rec, dict):
                        all_records.append(rec)
                all_records.extend(extra_from_raw)

                count = 0
                for i, c in enumerate(all_records):
                    doc, meta = format_contact_entry(c, global_ctx)
                    emb = embed_text(doc)
                    self.collection.add(
                        ids=[f"contact_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[doc],
                    )
                    count += 1

                print(f"    ✓ Indexed {count} structured contacts from {f.name}")
                continue

            # LEGACY CASE 1 – raw string
            if isinstance(data, str):
                lines = [line for line in data.splitlines() if line.strip()]
                for i, line in enumerate(lines):
                    phone_numbers = extract_phone_numbers(line)
                    text = f"Raw Contact Line: {line}\nExtracted numbers: {', '.join(phone_numbers)}"
                    emb = embed_text(text)
                    meta = {
                        "type": "contact_raw",
                        "line": line,
                        "extracted_numbers": ", ".join(phone_numbers) if phone_numbers else "None",
                    }
                    self.collection.add(
                        ids=[f"contact_raw_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[text],
                    )
                print(f"    ✓ Indexed {len(lines)} raw contact lines (legacy)")
                continue

            # LEGACY CASE 2 – list of strings
            if isinstance(data, list) and all(isinstance(x, str) for x in data):
                lines = [line for line in data if line.strip()]
                for i, line in enumerate(lines):
                    phone_numbers = extract_phone_numbers(line)
                    text = f"Raw Contact Entry: {line}\nExtracted numbers: {', '.join(phone_numbers)}"
                    emb = embed_text(text)
                    meta = {
                        "type": "contact_raw",
                        "line": line,
                        "extracted_numbers": ", ".join(phone_numbers) if phone_numbers else "None",
                    }
                    self.collection.add(
                        ids=[f"contact_rawlist_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[text],
                    )
                print(f"    ✓ Indexed {len(lines)} raw contact entries (legacy)")
                continue

            # LEGACY CASE 3 – list of dicts
            if isinstance(data, list) and all(isinstance(x, dict) for x in data):
                count = 0
                for i, c in enumerate(data):
                    doc, meta = format_contact_entry(c, global_context=None)
                    emb = embed_text(doc)
                    self.collection.add(
                        ids=[f"contact_{f.name}_{i}"],
                        embeddings=[emb],
                        metadatas=[flatten_metadata(meta)],
                        documents=[doc],
                    )
                    count += 1
                print(f"    ✓ Indexed {count} contacts with formatted metadata (legacy list[dict])")
                continue

            # FALLBACK
            text = json.dumps(data, indent=2)
            emb = embed_text(text)
            meta = {"type": "contact_fallback", "filename": f.name}
            self.collection.add(
                ids=[f"contact_fallback_{f.name}"],
                embeddings=[emb],
                metadatas=[flatten_metadata(meta)],
                documents=[text],
            )
            print(f"    ⚠ Indexed {f.name} as contact fallback (unknown JSON shape)")

    # -----------------------------
    # SKIP Timeline (your request)
    # -----------------------------
    def index_timeline(self):
        print("[~] Skipping timeline_data.json (redundant & heavy)")
        return

    # -----------------------------
    # Full Index
    # -----------------------------
    def index_all(self):
        print("\n======= Starting ENHANCED Indexing =======")
        print("[INFO] Using formatter-based enrichment for maximum accuracy")
        self.index_device_info()
        self.index_sms()
        self.index_contacts()
        self.index_calls()
        self.index_timeline()
        print("======= Enhanced Indexing Complete =======\n")

        return "Enhanced indexing complete with rich metadata."

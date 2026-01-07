# modules/ai/ai_formatter.py

import re
from datetime import datetime

# ============================
# PHONE NORMALIZATION
# ============================
def normalize_phone(num: str) -> str:
    """Normalize phone number into a consistent format."""
    if not num:
        return "Unknown"

    raw = "".join(ch for ch in str(num) if ch.isdigit() or ch == "+")

    # Already international
    if raw.startswith("+"):
        return raw

    # Handle Indian 10-digit numbers
    digits = "".join(ch for ch in raw if ch.isdigit())
    if len(digits) == 10:
        return "+91" + digits

    # Handle 0-prefixed Indian numbers
    if len(digits) == 11 and digits.startswith("0"):
        return "+91" + digits[1:]

    # Fallback
    return raw


# ============================
# TIMESTAMP PARSER
# ============================
def parse_timestamp(date_str):
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
        except:
            continue

    try:
        return float(date_str)
    except:
        return None


# ============================
# DEVICE INFO FORMATTER
# ============================
def format_device_info(log: dict):
    """
    Format a structured device info log into clean text + metadata.
    Required by indexer.
    """

    device = log.get("data", {})
    raw_output = log.get("raw_output", "")
    meta = {
        "type": "device_info",
        "device_serial": log.get("device_serial"),
        "capture_timestamp": log.get("timestamp"),
        "extraction_method": log.get("extraction_method"),
    }

    # Flatten device details
    for k, v in device.items():
        meta[k] = v

    # Build clean text
    lines = ["DEVICE INFORMATION", "-------------------"]

    for k, v in device.items():
        lines.append(f"{k}: {v}")

    text = "\n".join(lines)

    # Attach raw output at bottom
    if raw_output:
        text += f"\n\nRAW_DEVICE_OUTPUT:\n{raw_output}"

    return text, meta


# ============================
# CALL LOG FORMATTER
# ============================
def format_call_entry(call: dict, global_metadata=None):
    global_metadata = global_metadata or {}

    name = call.get("name") or "Unknown"
    number = normalize_phone(call.get("number", "Unknown"))

    # Duration
    duration = call.get("duration_seconds", call.get("duration", 0))
    try:
        duration = float(duration)
    except:
        duration = 0.0

    # Call direction
    call_type = call.get("type", call.get("call_type", "unknown"))
    type_map = {
        "1": "incoming",
        "2": "outgoing",
        "3": "missed",
        "4": "voicemail",
        "5": "rejected",
        "6": "blocked",
    }
    direction = type_map.get(str(call_type), str(call_type))

    date = call.get("date", "Unknown")
    ts = parse_timestamp(date)

    # Duration categories
    if duration == 0:
        duration_category = "missed"
    elif duration < 30:
        duration_category = "brief"
    elif duration < 120:
        duration_category = "short"
    elif duration < 600:
        duration_category = "medium"
    else:
        duration_category = "long"

    # Time of day
    time_category = "unknown"
    hour = None
    if ts:
        try:
            dt = datetime.fromtimestamp(ts)
            hour = dt.hour
            if 5 <= hour < 12:
                time_category = "morning"
            elif 12 <= hour < 17:
                time_category = "afternoon"
            elif 17 <= hour < 21:
                time_category = "evening"
            else:
                time_category = "night"
        except:
            pass

    doc = f"""CALL LOG ENTRY
-------------------
Name: {name}
Number: {number}
Direction: {direction}
Duration: {duration} seconds ({duration/60:.2f} minutes)
Duration Category: {duration_category}
Date: {date}
Time of Day: {time_category}
"""

    meta = {
        "type": "call",
        "name": name,
        "number": number,
        "duration_seconds": duration,
        "duration_minutes": duration / 60,
        "date": date,
        "timestamp": ts or 0.0,
        "call_direction": direction,
        "duration_category": duration_category,
        "time_category": time_category,
        "hour": hour if hour is not None else -1,
        "is_missed": duration == 0,
        "is_long_call": duration > 600,
        "is_night_call": time_category == "night",
    }

    # Merge global metadata
    for k, v in global_metadata.items():
        meta[k] = v

    return doc, meta


# ============================
# SMS FORMATTER
# ============================
def format_sms_entry(sms: dict, global_metadata=None):
    global_metadata = global_metadata or {}

    address = normalize_phone(sms.get("address", "Unknown"))
    body = sms.get("body", "")
    date = sms.get("date", "Unknown")
    ts = parse_timestamp(date)

    msg_type = sms.get("type", sms.get("msg_type", "unknown"))
    direction = "sent" if str(msg_type) == "2" else "received" if str(msg_type) == "1" else "unknown"

    keywords = []
    body_lower = body.lower()

    if "?" in body:
        keywords.append("question")

    if any(word in body_lower for word in ["http", "https", "www."]):
        keywords.append("has_url")

    if any(word in body_lower for word in ["urgent", "asap", "emergency"]):
        keywords.append("urgent")

    doc = f"""SMS MESSAGE
-------------------
Address: {address}
Direction: {direction}
Date: {date}
Length: {len(body)} characters
Keywords: {', '.join(keywords) if keywords else 'none'}

Message:
{body}
"""

    meta = {
        "type": "sms",
        "address": address,
        "direction": direction,
        "date": date,
        "timestamp": ts or 0.0,
        "body_length": len(body),
        "has_question": "?" in body,
        "has_url": any(x in body_lower for x in ["http", "https", "www."]),
        "keywords": ", ".join(keywords) if keywords else "none",
        "word_count": len(body.split()),
    }

    for k, v in sms.items():
        if k not in meta:
            meta[k] = v

    for k, v in global_metadata.items():
        meta[k] = v

    return doc, meta


# ============================
# CONTACT FORMATTER
# ============================
def format_contact_entry(contact: dict, global_metadata=None):
    global_metadata = global_metadata or {}

    name = contact.get("name") or contact.get("display_name") or "Unknown"
    number = normalize_phone(contact.get("number", contact.get("phone", "Unknown")))
    email = contact.get("email") or ""

    name_lower = name.lower()
    is_business = any(word in name_lower for word in [
        "ltd", "inc", "corp", "company", "bank", "service",
        "support", "customer", "hospital", "clinic", "store"
    ])
    is_emergency = number in ["911", "112", "100", "101", "102"] or \
                   any(word in name_lower for word in ["police", "ambulance", "fire"])

    doc = f"""CONTACT ENTRY
-------------------
Name: {name}
Number: {number}
Email: {email or 'None'}
Type: {"Business" if is_business else "Personal"}
Emergency: {"Yes" if is_emergency else "No"}
"""

    meta = {
        "type": "contact",
        "name": name,
        "number": number,
        "email": email or "None",
        "is_business": is_business,
        "is_emergency": is_emergency,
        "has_email": bool(email),
    }

    for k, v in contact.items():
        if k not in meta:
            meta[k] = v

    for k, v in global_metadata.items():
        meta[k] = v

    return doc, meta


# ============================
# CONTACT RAW OUTPUT PARSER
# ============================
def parse_contacts_raw_output(raw_output, device_serial=None, log_timestamp=None):
    """
    Parse adb shell dumpsys raw_output to contact dicts.
    """
    contacts = []

    if not raw_output:
        return contacts

    lines = raw_output.splitlines()
    current = {}

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Detect contact start
        if line.lower().startswith("contact"):
            if current:
                contacts.append(current)
                current = {}
            continue

        m = re.match(r"([A-Za-z_]+):\s*(.*)", line)
        if m:
            key, value = m.group(1), m.group(2)
            current[key] = value
            continue

    if current:
        contacts.append(current)

    # Add metadata
    for c in contacts:
        c["device_serial"] = device_serial
        c["log_timestamp"] = log_timestamp

    return contacts

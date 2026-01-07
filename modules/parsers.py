import re
from modules.adb_utils import epoch_ms_to_str

def safe_strip(value):
    """Safely strip a value that might be None"""
    if value is None:
        return ""
    return str(value).strip()

def safe_group(match, group_name, default=""):
    """Safely extract a regex group that might not exist"""
    try:
        val = match.group(group_name)
        return safe_strip(val) if val is not None else default
    except (AttributeError, IndexError):
        return default

# -----------------------------
# SMS Parsing with multiple strategies
# -----------------------------
def parse_sms_text(raw_text):
    """
    Parse SMS with multiple fallback strategies for different device formats.
    Handles: stock Android, Xiaomi MIUI, Samsung, OnePlus, etc.
    """
    results = []
    if not raw_text:
        return results
    
    # Skip metadata lines
    lines = [line for line in raw_text.splitlines() if not line.startswith("#")]
    text = "\n".join(lines)
    
    if not text.strip():
        return results
    
    # ==================== STRATEGY 1: Multi-line grouped pattern ====================
    # Matches: address=..., date=..., body=...
    # Works across multiple lines until next "Row" marker
    row_re = re.compile(
        r'address=(?P<address>.*?),\s*date=(?P<date>\d+),\s*body=(?P<body>.*?)(?=(?:\nRow)|\Z)', 
        re.DOTALL
    )
    for m in row_re.finditer(text):
        addr = safe_group(m, "address")
        date_ms = safe_group(m, "date")
        body = safe_group(m, "body")
        
        if addr or body:  # Valid if we have at least address or body
            results.append({
                "address": addr,
                "date_epoch_ms": date_ms,
                "date": epoch_ms_to_str(date_ms) if date_ms else "Unknown",
                "body": body
            })
    
    if results:
        return results
    
    # ==================== STRATEGY 2: Single-line pattern ====================
    # Xiaomi/MIUI often returns single-line format
    for line in text.splitlines():
        if "address=" in line and "date=" in line and "body=" in line:
            try:
                # Try comprehensive regex
                match = re.search(r'address=(?P<addr>.*?),\s*date=(?P<date>\d+).*?body=(?P<body>.*?)(?:,\s*type=|$)', line, re.DOTALL)
                if match:
                    addr = safe_group(match, "addr")
                    date_ms = safe_group(match, "date")
                    body = safe_group(match, "body")
                    
                    results.append({
                        "address": addr,
                        "date_epoch_ms": date_ms,
                        "date": epoch_ms_to_str(date_ms) if date_ms else "Unknown",
                        "body": body
                    })
            except Exception:
                continue
    
    if results:
        return results
    
    # ==================== STRATEGY 3: Alternate column names ====================
    # Some devices use "phone_number" instead of "address", "message" instead of "body"
    alt_patterns = [
        (r'phone_number=(?P<addr>.*?),\s*date=(?P<date>\d+).*?message=(?P<body>.*?)(?:,|$)', "phone_number"),
        (r'sender=(?P<addr>.*?),\s*timestamp=(?P<date>\d+).*?text=(?P<body>.*?)(?:,|$)', "sender"),
        (r'number=(?P<addr>.*?),\s*date_sent=(?P<date>\d+).*?body=(?P<body>.*?)(?:,|$)', "number"),
    ]
    
    for pattern, label in alt_patterns:
        for line in text.splitlines():
            try:
                match = re.search(pattern, line, re.DOTALL)
                if match:
                    addr = safe_group(match, "addr")
                    date_ms = safe_group(match, "date")
                    body = safe_group(match, "body")
                    
                    results.append({
                        "address": addr,
                        "date_epoch_ms": date_ms,
                        "date": epoch_ms_to_str(date_ms) if date_ms else "Unknown",
                        "body": body
                    })
            except Exception:
                continue
        
        if results:
            return results
    
    # ==================== STRATEGY 4: Key-value pair extraction ====================
    # Last resort: extract any key=value pairs we can find
    for line in text.splitlines():
        if not line.strip() or line.startswith("Row:"):
            continue
        
        try:
            # Extract all key=value pairs
            pairs = re.findall(r'(\w+)=(.*?)(?:,\s*\w+=|$)', line)
            data = {k: v.strip() for k, v in pairs}
            
            # Try to find address-like and body-like fields
            addr = (data.get("address") or data.get("phone_number") or 
                   data.get("sender") or data.get("number") or "")
            
            body = (data.get("body") or data.get("message") or 
                   data.get("text") or "")
            
            date_ms = (data.get("date") or data.get("timestamp") or 
                      data.get("date_sent") or "")
            
            if addr or body:
                results.append({
                    "address": addr,
                    "date_epoch_ms": date_ms,
                    "date": epoch_ms_to_str(date_ms) if date_ms else "Unknown",
                    "body": body
                })
        except Exception:
            continue
    
    return results

# -----------------------------
# Contacts Parsing with multiple strategies
# -----------------------------
def parse_contacts_text(raw_text):
    """Parse contacts from standard ADB provider dump (Row: X display_name=..., data1=...)."""
    results = []
    if not raw_text:
        return results
    
    # Regex for your exact format
    pattern = re.compile(
        r'Row:\s*\d+\s+display_name=(?P<name>.*?),\s*data1=(?P<number>[\+\d\s\(\)-]+)',
        re.IGNORECASE
    )
    
    for match in pattern.finditer(raw_text):
        name = match.group("name").strip()
        number = match.group("number").strip()
        results.append({
            "name": name,
            "number": number
        })
    
    return results


# -----------------------------
# Call Log Parsing with multiple strategies
# -----------------------------
def parse_calls_text(raw_text):
    """
    Parse call logs with multiple fallback strategies.
    Handles different formats across manufacturers.
    """
    results = []
    if not raw_text:
        return results
    
    # Skip metadata
    lines = [line for line in raw_text.splitlines() if not line.startswith("#")]
    text = "\n".join(lines)
    
    if not text.strip():
        return results
    
    # ==================== STRATEGY 1: Standard format ====================
    pattern = re.compile(
        r'(?:name|cached_name)=(?P<name>.*?),\s*number=(?P<number>.*?),\s*duration=(?P<duration>\d+),\s*date=(?P<date>\d+)',
        re.IGNORECASE
    )
    for m in pattern.finditer(text):
        name = safe_group(m, "name")
        number = safe_group(m, "number")
        duration = safe_group(m, "duration")
        date_ms = safe_group(m, "date")
        
        results.append({
            "name": name,
            "number": number,
            "duration_seconds": duration,
            "date_epoch_ms": date_ms,
            "date": epoch_ms_to_str(date_ms) if date_ms else "Unknown"
        })
    
    if results:
        return results
    
    # ==================== STRATEGY 2: Line-by-line ====================
    for line in text.splitlines():
        if 'duration=' in line and 'date=' in line:
            try:
                name_match = re.search(r'(?:name|cached_name)=(.*?)(?:,|$)', line, re.IGNORECASE)
                number_match = re.search(r'number=(.*?)(?:,|$)', line, re.IGNORECASE)
                duration_match = re.search(r'duration=(\d+)', line, re.IGNORECASE)
                date_match = re.search(r'date=(\d+)', line, re.IGNORECASE)
                
                name = safe_strip(name_match.group(1)) if name_match else ""
                number = safe_strip(number_match.group(1)) if number_match else ""
                duration = safe_strip(duration_match.group(1)) if duration_match else "0"
                date_ms = safe_strip(date_match.group(1)) if date_match else ""
                
                results.append({
                    "name": name,
                    "number": number,
                    "duration_seconds": duration,
                    "date_epoch_ms": date_ms,
                    "date": epoch_ms_to_str(date_ms) if date_ms else "Unknown"
                })
            except Exception:
                continue
    
    if results:
        return results
    
    # ==================== STRATEGY 3: Alternate formats ====================
    alt_patterns = [
        r'caller_name=(?P<name>.*?),\s*phone_number=(?P<number>.*?),\s*call_duration=(?P<duration>\d+),\s*timestamp=(?P<date>\d+)',
        r'contact=(?P<name>.*?),\s*number=(?P<number>.*?),\s*duration=(?P<duration>\d+),\s*time=(?P<date>\d+)',
    ]
    
    for pattern in alt_patterns:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            name = safe_group(m, "name")
            number = safe_group(m, "number")
            duration = safe_group(m, "duration")
            date_ms = safe_group(m, "date")
            
            results.append({
                "name": name,
                "number": number,
                "duration_seconds": duration,
                "date_epoch_ms": date_ms,
                "date": epoch_ms_to_str(date_ms) if date_ms else "Unknown"
            })
        
        if results:
            return results
    
    # ==================== STRATEGY 4: Generic key-value ====================
    for line in text.splitlines():
        if not line.strip() or line.startswith("Row:"):
            continue
        
        try:
            pairs = re.findall(r'(\w+)=(.*?)(?:,\s*\w+=|$)', line)
            data = {k.lower(): v.strip() for k, v in pairs}
            
            name = (data.get("name") or data.get("cached_name") or 
                   data.get("caller_name") or data.get("contact") or "")
            
            number = (data.get("number") or data.get("phone_number") or 
                     data.get("phone") or "")
            
            duration = (data.get("duration") or data.get("call_duration") or "0")
            
            date_ms = (data.get("date") or data.get("timestamp") or 
                      data.get("time") or "")
            
            if number or name:
                results.append({
                    "name": name,
                    "number": number,
                    "duration_seconds": duration,
                    "date_epoch_ms": date_ms,
                    "date": epoch_ms_to_str(date_ms) if date_ms else "Unknown"
                })
        except Exception:
            continue
    
    return results

# -----------------------------
# Manifest parsing
# -----------------------------
def manifest_to_table_rows(manifest):
    """Convert manifest to table format for display"""
    headers = ["Remote Path", "Local Path", "Size", "MD5", "SHA1", "SHA256"]
    rows = []
    if not isinstance(manifest, list):
        return headers, rows
    for entry in manifest:
        hashes = entry.get("hashes", {}) or {}
        rows.append([
            entry.get("remote_path", ""),
            entry.get("local_path", ""),
            entry.get("size", 0),
            hashes.get("md5", ""),
            hashes.get("sha1", ""),
            hashes.get("sha256", "")
        ])
    return headers, rows
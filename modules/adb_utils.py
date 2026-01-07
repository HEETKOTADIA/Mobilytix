import os
import re
import subprocess
import datetime
import hashlib
import json
import struct
from pathlib import Path

# -----------------------------
# Helpers
# -----------------------------
def timestamp(fmt="%Y-%m-%d %H:%M:%S"):
    return datetime.datetime.now().strftime(fmt)

def fname_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def epoch_ms_to_str(ms):
    try:
        ms = int(ms)
        if ms > 10**12:
            dt = datetime.datetime.fromtimestamp(ms / 1000.0)
        else:
            dt = datetime.datetime.fromtimestamp(ms)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ms)

# -----------------------------
# ADB wrapper with better error handling
# -----------------------------
def run_adb(args, timeout=60):
    """
    Executes adb command and returns stdout if present otherwise stderr.
    Handles Unicode properly on Windows.
    """
    try:
        # Use bytes mode and decode manually for better control
        proc = subprocess.run(
            ["adb"] + args, 
            capture_output=True, 
            timeout=timeout
        )
        
        # Try UTF-8 first, fallback to latin-1 if needed
        try:
            out = proc.stdout.decode('utf-8').strip()
        except UnicodeDecodeError:
            out = proc.stdout.decode('latin-1', errors='replace').strip()
        
        try:
            err = proc.stderr.decode('utf-8').strip()
        except UnicodeDecodeError:
            err = proc.stderr.decode('latin-1', errors='replace').strip()
        
        return out if out else err
        
    except subprocess.TimeoutExpired:
        return "adb command timed out."
    except FileNotFoundError:
        return "adb not found."
    except Exception as e:
        return f"adb error: {str(e)}"

def grant_adb_permissions():
    """Grant necessary permissions to ADB shell for forensics"""
    permissions = [
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_SMS",
        "android.permission.READ_CALL_LOG",
    ]
    
    results = []
    shell_package = "com.android.shell"
    
    for perm in permissions:
        result = run_adb(["shell", "pm", "grant", shell_package, perm])
        results.append(f"{perm}: {result if result else 'OK'}")
    
    return "\n".join(results)

# -----------------------------
# Device detection
# -----------------------------
def detect_device_manufacturer():
    """Detect device manufacturer and model for device-specific handling"""
    mfg = run_adb(["shell", "getprop", "ro.product.manufacturer"]).lower()
    model = run_adb(["shell", "getprop", "ro.product.model"]).lower()
    brand = run_adb(["shell", "getprop", "ro.product.brand"]).lower()
    sdk = run_adb(["shell", "getprop", "ro.build.version.sdk"])
    
    try:
        sdk_int = int(sdk)
    except:
        sdk_int = 0
    
    return {
        "manufacturer": mfg,
        "model": model,
        "brand": brand,
        "sdk": sdk_int,
        "is_xiaomi": "xiaomi" in mfg or "xiaomi" in brand or "redmi" in model,
        "is_samsung": "samsung" in mfg or "samsung" in brand,
        "is_oneplus": "oneplus" in mfg or "oneplus" in brand,
        "is_oppo": "oppo" in mfg or "oppo" in brand or "realme" in brand,
        "is_motorola": "motorola" in mfg or "motorola" in brand,
        "is_google": "google" in mfg or "google" in brand,
    }

# -----------------------------
# Enhanced content provider queries with fallbacks
# -----------------------------
def query_content_provider_with_fallbacks(uri_variants, projection_variants, label="data"):
    """
    Try multiple URI and projection combinations until one works.
    Returns (success_flag, raw_output, uri_used, projection_used)
    """
    for uri in uri_variants:
        for projection in projection_variants:
            if projection:
                result = run_adb(["shell", "content", "query", "--uri", uri, "--projection", projection])
            else:
                result = run_adb(["shell", "content", "query", "--uri", uri])
            
            # Check if result indicates success
            if result and not any(err in result.lower() for err in [
                "error", "exception", "denied", "failed", "unknown", 
                "no such", "unable", "cannot", "not found"
            ]):
                return True, result, uri, projection
    
    return False, f"All {label} query attempts failed.", None, None

def dump_sms_enhanced(dest):
    """Enhanced SMS dump with multiple fallback strategies"""
    if not dest:
        return "Destination not provided."
    
    device_info = detect_device_manufacturer()
    
    # Comprehensive list of SMS URIs used by different manufacturers
    uri_variants = [
        "content://sms/",
        "content://sms/inbox",
        "content://sms/sent",
        "content://mms-sms/conversations",
        "content://sms/conversations",
    ]
    
    # Multiple projection combinations
    projection_variants = [
        "address:date:body:type",
        "address:date:body",
        "address:date_sent:body:type",
        "_id:address:date:body:type:read",
        "",  # No projection - get all columns
    ]
    
    # Try queries
    success, result, uri_used, proj_used = query_content_provider_with_fallbacks(
        uri_variants, projection_variants, "SMS"
    )
    
    # Save result
    path = os.path.join(dest, f"sms_{fname_timestamp()}.txt")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Device: {device_info['manufacturer']} {device_info['model']}\n")
            f.write(f"# SDK: {device_info['sdk']}\n")
            f.write(f"# URI used: {uri_used}\n")
            f.write(f"# Projection: {proj_used}\n")
            f.write(f"# Timestamp: {timestamp()}\n")
            f.write(f"# Success: {success}\n\n")
            f.write(result)
        
        if success:
            return f"SMS dumped successfully -> {path}"
        else:
            return f"SMS dump attempted with errors -> {path}\nTry: adb shell content query --uri content://sms/"
    except Exception as e:
        return f"Failed to save SMS dump: {e}"

def dump_contacts_enhanced(dest):
    """Enhanced contacts dump with multiple fallback strategies"""
    if not dest:
        return "Destination not provided."
    
    device_info = detect_device_manufacturer()
    
    # Comprehensive list of Contacts URIs
    uri_variants = [
        "content://com.android.contacts/data/phones",
        "content://contacts/phones/",
        "content://com.android.contacts/contacts",
        "content://com.android.contacts/raw_contacts",
        "content://com.android.contacts/data",
    ]
    
    projection_variants = [
        "display_name:data1",
        "display_name:number",
        "display_name_alt:data1",
        "contact_id:display_name:data1",
        "",
    ]
    
    success, result, uri_used, proj_used = query_content_provider_with_fallbacks(
        uri_variants, projection_variants, "Contacts"
    )
    
    path = os.path.join(dest, f"contacts_{fname_timestamp()}.txt")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Device: {device_info['manufacturer']} {device_info['model']}\n")
            f.write(f"# SDK: {device_info['sdk']}\n")
            f.write(f"# URI used: {uri_used}\n")
            f.write(f"# Projection: {proj_used}\n")
            f.write(f"# Timestamp: {timestamp()}\n")
            f.write(f"# Success: {success}\n\n")
            f.write(result)
        
        if success:
            return f"Contacts dumped successfully -> {path}"
        else:
            return f"Contacts dump attempted with errors -> {path}"
    except Exception as e:
        return f"Failed to save contacts dump: {e}"

def dump_calls_enhanced(dest):
    """Enhanced call log dump with multiple fallback strategies"""
    if not dest:
        return "Destination not provided."
    
    device_info = detect_device_manufacturer()
    
    uri_variants = [
        "content://call_log/calls",
        "content://call_log/calls/",
        "content://logs/calls",
    ]
    
    projection_variants = [
        "name:number:duration:date:type",
        "name:number:duration:date",
        "cached_name:number:duration:date:type",
        "_id:name:number:duration:date:type",
        "",
    ]
    
    success, result, uri_used, proj_used = query_content_provider_with_fallbacks(
        uri_variants, projection_variants, "Call Logs"
    )
    
    path = os.path.join(dest, f"calls_{fname_timestamp()}.txt")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Device: {device_info['manufacturer']} {device_info['model']}\n")
            f.write(f"# SDK: {device_info['sdk']}\n")
            f.write(f"# URI used: {uri_used}\n")
            f.write(f"# Projection: {proj_used}\n")
            f.write(f"# Timestamp: {timestamp()}\n")
            f.write(f"# Success: {success}\n\n")
            f.write(result)
        
        if success:
            return f"Call logs dumped successfully -> {path}"
        else:
            return f"Call log dump attempted with errors -> {path}"
    except Exception as e:
        return f"Failed to save call log dump: {e}"

# -----------------------------
# Direct query functions for viewer (live queries)
# -----------------------------
def query_sms_live():
    """Live SMS query for viewer - returns raw text with metadata"""
    device_info = detect_device_manufacturer()
    
    uri_variants = [
        "content://sms/",
        "content://sms/inbox",
        "content://sms/sent",
    ]
    
    projection_variants = [
        "address:date:body:type",
        "address:date:body",
        "",
    ]
    
    success, result, uri_used, proj_used = query_content_provider_with_fallbacks(
        uri_variants, projection_variants, "SMS"
    )
    
    metadata = f"# Device: {device_info['manufacturer']} {device_info['model']}\n"
    metadata += f"# URI: {uri_used}\n# Projection: {proj_used}\n# Success: {success}\n\n"
    
    return metadata + result

def query_contacts_live():
    """Live contacts query for viewer"""
    device_info = detect_device_manufacturer()
    
    uri_variants = [
        "content://com.android.contacts/data/phones",
        "content://contacts/phones/",
        "content://com.android.contacts/data",
    ]
    
    projection_variants = [
        "display_name:data1",
        "display_name:number",
        "",
    ]
    
    success, result, uri_used, proj_used = query_content_provider_with_fallbacks(
        uri_variants, projection_variants, "Contacts"
    )
    
    metadata = f"# Device: {device_info['manufacturer']} {device_info['model']}\n"
    metadata += f"# URI: {uri_used}\n# Projection: {proj_used}\n# Success: {success}\n\n"
    
    return metadata + result

def query_calls_live():
    """Live call log query for viewer"""
    device_info = detect_device_manufacturer()
    
    uri_variants = [
        "content://call_log/calls",
    ]
    
    projection_variants = [
        "name:number:duration:date:type",
        "name:number:duration:date",
        "",
    ]
    
    success, result, uri_used, proj_used = query_content_provider_with_fallbacks(
        uri_variants, projection_variants, "Call Logs"
    )
    
    metadata = f"# Device: {device_info['manufacturer']} {device_info['model']}\n"
    metadata += f"# URI: {uri_used}\n# Projection: {proj_used}\n# Success: {success}\n\n"
    
    return metadata + result

# -----------------------------
# Legacy compatibility wrappers
# -----------------------------
def dump_sms(dest):
    return dump_sms_enhanced(dest)

def dump_contacts(dest):
    return dump_contacts_enhanced(dest)

def dump_calls(dest):
    return dump_calls_enhanced(dest)

# -----------------------------
# Basic device helpers
# -----------------------------
def list_devices():
    return run_adb(["devices", "-l"])

def list_apps():
    return run_adb(["shell", "pm", "list", "packages", "-3"])

def list_files():
    return run_adb(["shell", "ls", "-a", "/sdcard/"])

def get_device_info():
    props = [
        ("Model", "ro.product.model"),
        ("Manufacturer", "ro.product.manufacturer"),
        ("Brand", "ro.product.brand"),
        ("Chipset", "ro.product.board"),
        ("Android Version", "ro.build.version.release"),
        ("Security Patch", "ro.build.version.security_patch"),
        ("Build Date", "ro.build.date"),
        ("SDK", "ro.build.version.sdk"),
    ]
    lines = []
    for label, prop in props:
        val = run_adb(["shell", "getprop", prop])
        lines.append(f"{label}: {val}")
    return "\n".join(lines)

def get_battery_info():
    return run_adb(["shell", "dumpsys", "battery"])

# -----------------------------
# Screenshot and pull
# -----------------------------
def get_screenshot(dest):
    if not dest:
        return "Destination not provided."
    name = f"screenshot_{fname_timestamp()}.png"
    remote = f"/sdcard/{name}"
    out = run_adb(["shell", "screencap", "-p", remote])
    pull_out = run_adb(["pull", remote, os.path.join(dest, name)], timeout=120)
    return f"Screenshot saved: {os.path.join(dest, name)}"

def pull_item(remote, dest):
    if not dest:
        return "Destination not provided."
    out = run_adb(["pull", remote, dest], timeout=180)
    return f"Pulled {remote} -> {dest}. adb: {out}"

# -----------------------------
# Copy common media with fallbacks
# -----------------------------
def copy_whatsapp(dest):
    candidates = [
        "/sdcard/Android/media/com.whatsapp/WhatsApp",
        "/sdcard/WhatsApp",
        "/storage/emulated/0/WhatsApp",
        "/storage/emulated/0/Android/media/com.whatsapp/WhatsApp",
    ]
    for p in candidates:
        ls = run_adb(["shell", "ls", p])
        if "No such" not in ls and "denied" not in ls.lower():
            return run_adb(["pull", p, dest], timeout=240)
    return "WhatsApp folder not found or inaccessible."

def copy_screenshots(dest):
    candidates = [
        "/sdcard/Pictures/Screenshots",
        "/sdcard/DCIM/Screenshots",
        "/storage/emulated/0/Pictures/Screenshots",
        "/storage/emulated/0/DCIM/Screenshots",
        "/sdcard/Screenshots",
    ]
    for p in candidates:
        ls = run_adb(["shell", "ls", p])
        if "No such" not in ls and "denied" not in ls.lower():
            return run_adb(["pull", p, dest], timeout=240)
    return "Screenshots folder not found."

def copy_camera(dest):
    candidates = [
        "/sdcard/DCIM/Camera",
        "/storage/emulated/0/DCIM/Camera",
        "/sdcard/DCIM/100ANDRO",
    ]
    for p in candidates:
        ls = run_adb(["shell", "ls", p])
        if "No such" not in ls and "denied" not in ls.lower():
            return run_adb(["pull", p, dest], timeout=240)
    return "Camera folder not found."

# -----------------------------
# App forensics helpers
# -----------------------------
def analyze_app(pkg):
    out = run_adb(["shell", "dumpsys", "package", pkg])
    if "Unable to find" in out or "Error" in out:
        return f"Could not analyze package: {pkg}\n{out}"
    perms = sorted(set(re.findall(r"android\.permission\.[A-Za-z0-9_]+", out)))
    perms_text = "\n".join(perms) if perms else "No permissions found."
    return f"Analysis for {pkg}:\n\n{out[:4000]}\n\nPermissions:\n{perms_text}"

def pull_apk(pkg, dest):
    if not dest:
        return "Destination cancelled."
    path_out = run_adb(["shell", "pm", "path", pkg])
    if not path_out or "package:" not in path_out:
        return f"Unable to get APK path for {pkg}\n{path_out}"
    m = re.search(r"package:(/.*?\.apk)", path_out)
    apk = m.group(1) if m else path_out.replace("package:", "").strip()
    out = run_adb(["pull", apk, dest], timeout=180)
    return f"APK pulled: {apk} -> {dest}. adb: {out}"

def generate_app_report(pkg, dest):
    if not dest:
        return "Destination cancelled."
    info = analyze_app(pkg)
    report_path = os.path.join(dest, f"{pkg}_report_{fname_timestamp()}.txt")
    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"Mobilytix App Report\nGenerated: {timestamp()}\n\n")
            f.write(info)
        return f"Report saved -> {report_path}"
    except Exception as e:
        return f"Failed to generate report: {e}"

# -----------------------------
# Safe filesystem helpers
# -----------------------------
def is_directory(path):
    out = run_adb(["shell", f"[ -d \"{path}\" ] && echo DIR || echo FILE"])
    return "DIR" in out

def list_directory(path):
    out = run_adb(["shell", "ls", "-1", path])
    if not out or "No such" in out or "denied" in out.lower():
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]

def brute_scan_fs(root="/sdcard"):
    """
    Brute-force scanner that works on modern Android (no ls -R).
    Returns list of dicts: {"path": fullpath, "is_dir": bool}
    """
    discovered = []
    stack = [root.rstrip("/")]
    visited = set()

    while stack:
        current = stack.pop()
        if current in visited:
            continue
        visited.add(current)

        entries = list_directory(current)
        if not entries:
            continue

        for name in entries:
            full = f"{current}/{name}".replace("//", "/")
            if " -> " in name or name.startswith("."):
                if is_directory(full):
                    discovered.append({"path": full, "is_dir": True})
                    stack.append(full)
                continue

            if is_directory(full):
                discovered.append({"path": full, "is_dir": True})
                stack.append(full)
            else:
                discovered.append({"path": full, "is_dir": False})

    return discovered

# -----------------------------
# Pull using brute scan
# -----------------------------
def brute_extract_folder(remote_root, dest_root):
    """
    Use brute_scan_fs to discover files and pull them.
    Returns manifest list.
    """
    remote_root = remote_root.rstrip("/")
    dest_root = os.path.abspath(dest_root)
    os.makedirs(dest_root, exist_ok=True)

    fs_items = brute_scan_fs(remote_root)
    manifest = []

    for entry in fs_items:
        if entry.get("is_dir"):
            continue
        remote = entry.get("path")
        local = os.path.join(dest_root, remote.lstrip("/"))
        os.makedirs(os.path.dirname(local), exist_ok=True)
        adb_out = run_adb(["pull", remote, local], timeout=240)

        size = os.path.getsize(local) if os.path.exists(local) else 0
        mtime = os.path.getmtime(local) if os.path.exists(local) else 0
        hashes = compute_hashes(local) if os.path.exists(local) else {"md5": None, "sha1": None, "sha256": None}

        manifest.append({
            "remote_path": remote,
            "local_path": local,
            "size": size,
            "mtime": mtime,
            "hashes": hashes,
            "adb_result": adb_out
        })

    return manifest

# -----------------------------
# Hashing
# -----------------------------
def compute_hashes(path, chunk_size=4*1024*1024):
    try:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}
    except Exception:
        return {"md5": None, "sha1": None, "sha256": None}

# -----------------------------
# Safe folder pull (legacy)
# -----------------------------
def pull_folder_with_metadata(remote_folder, local_root):
    """
    Legacy compatibility function used by GUI. 
    Attempts to pull direct children and returns manifest list.
    """
    local_root = os.path.abspath(local_root)
    os.makedirs(local_root, exist_ok=True)

    ls_output = run_adb(["shell", "ls", "-1", remote_folder])
    if not ls_output or "No such" in ls_output or "denied" in ls_output.lower():
        return "No files found or permission denied."

    manifest = []
    for item in ls_output.splitlines():
        item = item.strip()
        if not item:
            continue
        remote = f"{remote_folder.rstrip('/')}/{item}"
        local_path = os.path.join(local_root, remote.lstrip("/"))
        os.makedirs(os.path.dirname(local_path), exist_ok=True)

        adb_res = run_adb(["pull", remote, local_path], timeout=240)
        size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
        mtime = os.path.getmtime(local_path) if os.path.exists(local_path) else 0
        hashes = compute_hashes(local_path) if os.path.exists(local_path) else {"md5": None, "sha1": None, "sha256": None}

        manifest.append({
            "remote_path": remote,
            "local_path": local_path,
            "size": size,
            "mtime": mtime,
            "hashes": hashes,
            "adb_result": adb_res
        })
    return manifest

# -----------------------------
# ADB backup
# -----------------------------
def perform_adb_backup(dest):
    ab_path = os.path.join(dest, "full_backup.ab")
    cmd = f'adb backup -all -f "{ab_path}"'
    os.system(cmd)
    if not os.path.exists(ab_path) or os.path.getsize(ab_path) == 0:
        return None
    try:
        import zlib
        with open(ab_path, "rb") as f:
            f.read(24)
            data = f.read()
        decompressed = zlib.decompress(data)
        tar_path = ab_path.replace(".ab", ".tar")
        with open(tar_path, "wb") as out:
            out.write(decompressed)
        return tar_path
    except Exception:
        return ab_path

# -----------------------------
# Local scan to manifest
# -----------------------------
def scan_local_tree_for_manifest(local_root):
    manifest = []
    for root, dirs, files in os.walk(local_root):
        for file in files:
            local_path = os.path.join(root, file)
            rel = os.path.relpath(local_path, local_root)
            remote_sim = "/" + rel.replace("\\", "/")
            size = os.path.getsize(local_path)
            mtime = os.path.getmtime(local_path)
            hashes = compute_hashes(local_path)
            manifest.append({
                "remote_path": remote_sim,
                "local_path": local_path,
                "size": size,
                "mtime": mtime,
                "hashes": hashes,
                "adb_result": "local-scan"
            })
    return manifest

# -----------------------------
# Full device extraction orchestration
# -----------------------------
PUBLIC_FOLDERS = [
    "/sdcard/DCIM",
    "/sdcard/Pictures",
    "/sdcard/Movies",
    "/sdcard/Music",
    "/sdcard/Download",
    "/sdcard/Documents",
    "/sdcard/WhatsApp",
    "/sdcard/Android/media"
]

def perform_full_extraction(dest):
    dest = os.path.abspath(dest)
    os.makedirs(dest, exist_ok=True)
    manifest = []

    for folder in PUBLIC_FOLDERS:
        try:
            entries = pull_folder_with_metadata(folder, dest)
            if isinstance(entries, list):
                manifest.extend(entries)
        except Exception:
            pass

    try:
        sms_file = os.path.join(dest, f"sms_{fname_timestamp()}.txt")
        open(sms_file, "w", encoding="utf-8").write(query_sms_live())
        manifest.append({"remote_path": "sms-dump", "local_path": sms_file, "size": os.path.getsize(sms_file), "mtime": os.path.getmtime(sms_file), "hashes": compute_hashes(sms_file), "adb_result": "content-provider"})
    except Exception:
        pass
    try:
        contacts_file = os.path.join(dest, f"contacts_{fname_timestamp()}.txt")
        open(contacts_file, "w", encoding="utf-8").write(query_contacts_live())
        manifest.append({"remote_path": "contacts-dump", "local_path": contacts_file, "size": os.path.getsize(contacts_file), "mtime": os.path.getmtime(contacts_file), "hashes": compute_hashes(contacts_file), "adb_result": "content-provider"})
    except Exception:
        pass
    try:
        calls_file = os.path.join(dest, f"calls_{fname_timestamp()}.txt")
        open(calls_file, "w", encoding="utf-8").write(query_calls_live())
        manifest.append({"remote_path": "calls-dump", "local_path": calls_file, "size": os.path.getsize(calls_file), "mtime": os.path.getmtime(calls_file), "hashes": compute_hashes(calls_file), "adb_result": "content-provider"})
    except Exception:
        pass

    try:
        backup = perform_adb_backup(dest)
        if backup:
            manifest.append({"remote_path": "adb-backup", "local_path": backup, "size": os.path.getsize(backup), "mtime": os.path.getmtime(backup), "hashes": compute_hashes(backup), "adb_result": "adb-backup"})
    except Exception:
        pass

    try:
        brute_manifest = brute_extract_folder("/sdcard", os.path.join(dest, "sdcard"))
        if isinstance(brute_manifest, list):
            manifest.extend(brute_manifest)
    except Exception:
        pass

    try:
        manifest.extend(scan_local_tree_for_manifest(dest))
    except Exception:
        pass

    return manifest

# -----------------------------
# BIN archive writer
# -----------------------------
MAGIC = b"MOBIN001"

def archive_to_bin(manifest, output_bin):
    manifest_json = json.dumps({"generated": timestamp(), "entries": manifest}, indent=2).encode("utf-8")
    try:
        with open(output_bin, "wb") as out:
            out.write(MAGIC)
            out.write(struct.pack("<Q", len(manifest_json)))
            out.write(manifest_json)
            for entry in manifest:
                loc = entry.get("local_path")
                if loc and os.path.exists(loc):
                    with open(loc, "rb") as f:
                        while chunk := f.read(4*1024*1024):
                            out.write(chunk)
        return f"BIN created -> {output_bin}"
    except Exception as e:
        return f"BIN creation failed: {e}"
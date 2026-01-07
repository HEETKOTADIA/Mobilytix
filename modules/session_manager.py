import os
import json
from pathlib import Path
from datetime import datetime

class SessionManager:
    def __init__(self, base_dir="forensics_sessions"):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(exist_ok=True)
        self.current_session = None
        self.operation_counter = 0
    
    def get_device_serial(self):
        """Get device serial number"""
        from modules.adb_utils import run_adb
        serial = run_adb(["get-serialno"]).strip()
        if not serial or serial == "unknown":
            serial = "UNKNOWN_DEVICE"
        return serial
    
    def start_session(self, device_info=None):
        """Start or resume a session for current device"""
        serial = self.get_device_serial()
        date_str = datetime.now().strftime("%Y-%m-%d")
        session_id = f"device_{serial}_{date_str}"
        
        session_dir = self.base_dir / session_id
        session_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        for subdir in ["sms_logs", "contacts_logs", "call_logs", "device_info_logs", "other_logs"]:
            (session_dir / subdir).mkdir(exist_ok=True)
        
        metadata_path = session_dir / "session_metadata.json"
        
        if metadata_path.exists():
            # Resume existing session
            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
            metadata["session_last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.operation_counter = len(metadata.get("operations_log", []))
        else:
            # Create new session
            metadata = {
                "session_id": session_id,
                "device": device_info or {},
                "session_created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "session_last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "operations_log": []
            }
            self.operation_counter = 0
        
        self.current_session = {
            "metadata": metadata,
            "session_dir": session_dir,
            "metadata_path": metadata_path
        }
        
        self._save_metadata()
        return session_dir
    
    def get_next_operation_id(self):
        """Generate unique operation ID"""
        self.operation_counter += 1
        return f"op_{self.operation_counter:04d}"
    
    def log_operation(self, operation_type, status, log_file=None, record_count=None):
        """Add operation to session log"""
        if not self.current_session:
            return
        
        operation_entry = {
            "operation_id": self.get_next_operation_id(),
            "operation_type": operation_type,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": status,
        }
        
        if log_file:
            operation_entry["log_file"] = str(log_file)
        if record_count is not None:
            operation_entry["record_count"] = record_count
        
        self.current_session["metadata"]["operations_log"].append(operation_entry)
        self.current_session["metadata"]["session_last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._save_metadata()
        
        return operation_entry["operation_id"]
    
    def _save_metadata(self):
        """Save session metadata to disk"""
        if not self.current_session:
            return
        
        with open(self.current_session["metadata_path"], "w", encoding="utf-8") as f:
            json.dump(self.current_session["metadata"], f, indent=2, ensure_ascii=False)
    
    def get_session_dir(self):
        """Get current session directory"""
        if self.current_session:
            return self.current_session["session_dir"]
        return None
    
    def list_all_sessions(self):
        """List all available sessions"""
        sessions = []
        for session_dir in self.base_dir.iterdir():
            if session_dir.is_dir():
                metadata_path = session_dir / "session_metadata.json"
                if metadata_path.exists():
                    with open(metadata_path, "r", encoding="utf-8") as f:
                        metadata = json.load(f)
                    sessions.append({
                        "session_id": metadata.get("session_id"),
                        "device": metadata.get("device", {}),
                        "created": metadata.get("session_created"),
                        "updated": metadata.get("session_last_updated"),
                        "operation_count": len(metadata.get("operations_log", [])),
                        "path": str(session_dir)
                    })
        return sorted(sessions, key=lambda x: x.get("updated", ""), reverse=True)
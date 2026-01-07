import json
from datetime import datetime
from pathlib import Path

class DataLogger:
    def __init__(self, session_manager):
        self.session_manager = session_manager
    
    def log_sms_data(self, raw_text, parsed_data, extraction_info):
        """Log SMS data with full details"""
        session_dir = self.session_manager.get_session_dir()
        if not session_dir:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = session_dir / "sms_logs" / f"sms_{timestamp}.json"
        
        # Calculate metadata
        metadata = self._calculate_sms_metadata(parsed_data)
        
        log_data = {
            "log_type": "sms_data",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device_serial": self.session_manager.get_device_serial(),
            "extraction_method": extraction_info,
            "status": "success",
            "record_count": len(parsed_data),
            "data": parsed_data,
            "metadata": metadata,
            "raw_output": raw_text[:5000]  # First 5000 chars of raw output
        }
        
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)
        
        # Log operation in session
        operation_id = self.session_manager.log_operation(
            operation_type="view_sms",
            status="success",
            log_file=f"sms_logs/{log_file.name}",
            record_count=len(parsed_data)
        )
        
        return str(log_file)
    
    def log_contacts_data(self, raw_text, parsed_data, extraction_info):
        """Log contacts data with full details"""
        session_dir = self.session_manager.get_session_dir()
        if not session_dir:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = session_dir / "contacts_logs" / f"contacts_{timestamp}.json"
        
        metadata = {
            "total_contacts": len(parsed_data),
            "contacts_with_numbers": len([c for c in parsed_data if c.get("number")]),
            "contacts_without_numbers": len([c for c in parsed_data if not c.get("number")])
        }
        
        log_data = {
            "log_type": "contacts_data",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device_serial": self.session_manager.get_device_serial(),
            "extraction_method": extraction_info,
            "status": "success",
            "record_count": len(parsed_data),
            "data": parsed_data,
            "metadata": metadata,
            "raw_output": raw_text[:5000]
        }
        
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)
        
        operation_id = self.session_manager.log_operation(
            operation_type="view_contacts",
            status="success",
            log_file=f"contacts_logs/{log_file.name}",
            record_count=len(parsed_data)
        )
        
        return str(log_file)
    
    def log_calls_data(self, raw_text, parsed_data, extraction_info):
        """Log call logs with full details"""
        session_dir = self.session_manager.get_session_dir()
        if not session_dir:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = session_dir / "call_logs" / f"calls_{timestamp}.json"
        
        metadata = self._calculate_call_metadata(parsed_data)
        
        log_data = {
            "log_type": "call_logs_data",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device_serial": self.session_manager.get_device_serial(),
            "extraction_method": extraction_info,
            "status": "success",
            "record_count": len(parsed_data),
            "data": parsed_data,
            "metadata": metadata,
            "raw_output": raw_text[:5000]
        }
        
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)
        
        operation_id = self.session_manager.log_operation(
            operation_type="view_calls",
            status="success",
            log_file=f"call_logs/{log_file.name}",
            record_count=len(parsed_data)
        )
        
        return str(log_file)
    
    def log_device_info(self, device_info_text, device_info_dict):
        """Log device information"""
        session_dir = self.session_manager.get_session_dir()
        if not session_dir:
            return None
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = session_dir / "device_info_logs" / f"device_info_{timestamp}.json"
        
        log_data = {
            "log_type": "device_info",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "device_serial": self.session_manager.get_device_serial(),
            "status": "success",
            "data": device_info_dict,
            "raw_output": device_info_text
        }
        
        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)
        
        operation_id = self.session_manager.log_operation(
            operation_type="device_info",
            status="success",
            log_file=f"device_info_logs/{log_file.name}"
        )
        
        return str(log_file)
    
    def _calculate_sms_metadata(self, parsed_data):
        """Calculate SMS statistics"""
        if not parsed_data:
            return {}
        
        dates = [d.get("date_epoch_ms") for d in parsed_data if d.get("date_epoch_ms")]
        unique_contacts = set(d.get("address") for d in parsed_data if d.get("address"))
        
        metadata = {
            "unique_contacts": len(unique_contacts),
            "total_messages": len(parsed_data)
        }
        
        if dates:
            try:
                dates_int = [int(d) for d in dates if d]
                if dates_int:
                    from modules.adb_utils import epoch_ms_to_str
                    metadata["date_range"] = {
                        "earliest": epoch_ms_to_str(min(dates_int)),
                        "latest": epoch_ms_to_str(max(dates_int))
                    }
            except:
                pass
        
        return metadata
    
    def _calculate_call_metadata(self, parsed_data):
        """Calculate call log statistics"""
        if not parsed_data:
            return {}
        
        dates = [d.get("date_epoch_ms") for d in parsed_data if d.get("date_epoch_ms")]
        unique_numbers = set(d.get("number") for d in parsed_data if d.get("number"))
        
        total_duration = 0
        for call in parsed_data:
            try:
                total_duration += int(call.get("duration_seconds", 0))
            except:
                pass
        
        metadata = {
            "total_calls": len(parsed_data),
            "unique_numbers": len(unique_numbers),
            "total_talk_time_seconds": total_duration
        }
        
        if dates:
            try:
                dates_int = [int(d) for d in dates if d]
                if dates_int:
                    from modules.adb_utils import epoch_ms_to_str
                    metadata["date_range"] = {
                        "earliest": epoch_ms_to_str(min(dates_int)),
                        "latest": epoch_ms_to_str(max(dates_int))
                    }
            except:
                pass
        
        return metadata
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

class TimelineBuilder:
    def __init__(self, session_dir):
        self.session_dir = Path(session_dir)
    
    def build_timeline(self):
        """Aggregate all data into unified timeline"""
        events = []
        
        # Load SMS data
        sms_events = self._load_sms_events()
        events.extend(sms_events)
        
        # Load call data
        call_events = self._load_call_events()
        events.extend(call_events)
        
        # Sort by timestamp
        events.sort(key=lambda x: x.get("epoch_ms", 0))
        
        # Calculate statistics
        statistics = self._calculate_statistics(events)
        
        timeline_data = {
            "timeline_id": f"timeline_{self.session_dir.name}",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "statistics": statistics,
            "events": events
        }
        
        # Save timeline data
        timeline_path = self.session_dir / "timeline_data.json"
        with open(timeline_path, "w", encoding="utf-8") as f:
            json.dump(timeline_data, f, indent=2, ensure_ascii=False)
        
        return timeline_data, str(timeline_path)
    
    def _load_sms_events(self):
        """Load and convert SMS logs to timeline events"""
        events = []
        sms_dir = self.session_dir / "sms_logs"
        
        if not sms_dir.exists():
            return events
        
        for log_file in sms_dir.glob("*.json"):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    log_data = json.load(f)
                
                for sms in log_data.get("data", []):
                    try:
                        epoch_ms = int(sms.get("date_epoch_ms", 0))
                    except:
                        epoch_ms = 0
                    
                    event = {
                        "event_id": f"sms_{sms.get('address', 'unknown')}_{epoch_ms}",
                        "timestamp": sms.get("date", "Unknown"),
                        "epoch_ms": epoch_ms,
                        "event_type": "sms",
                        "contact_number": sms.get("address", "Unknown"),
                        "details": {
                            "body": sms.get("body", "")[:100]  # First 100 chars
                        }
                    }
                    events.append(event)
            except Exception as e:
                continue
        
        return events
    
    def _load_call_events(self):
        """Load and convert call logs to timeline events"""
        events = []
        call_dir = self.session_dir / "call_logs"
        
        if not call_dir.exists():
            return events
        
        for log_file in call_dir.glob("*.json"):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    log_data = json.load(f)
                
                for call in log_data.get("data", []):
                    try:
                        epoch_ms = int(call.get("date_epoch_ms", 0))
                    except:
                        epoch_ms = 0
                    
                    try:
                        duration = int(call.get("duration_seconds", 0))
                    except:
                        duration = 0
                    
                    event = {
                        "event_id": f"call_{call.get('number', 'unknown')}_{epoch_ms}",
                        "timestamp": call.get("date", "Unknown"),
                        "epoch_ms": epoch_ms,
                        "event_type": "call",
                        "contact_number": call.get("number", "Unknown"),
                        "contact_name": call.get("name", "Unknown"),
                        "details": {
                            "duration_seconds": duration,
                            "duration_formatted": f"{duration // 60}m {duration % 60}s"
                        }
                    }
                    events.append(event)
            except Exception as e:
                continue
        
        return events
    
    def _calculate_statistics(self, events):
        """Calculate timeline statistics"""
        if not events:
            return {}
        
        # Filter out events with valid timestamps
        valid_events = [e for e in events if e.get("epoch_ms", 0) > 0]
        
        if not valid_events:
            return {"total_events": len(events)}
        
        # Basic counts
        event_type_counts = defaultdict(int)
        for event in events:
            event_type_counts[event.get("event_type", "unknown")] += 1
        
        # Date range
        epochs = [e.get("epoch_ms", 0) for e in valid_events]
        min_epoch = min(epochs)
        max_epoch = max(epochs)
        
        from modules.adb_utils import epoch_ms_to_str
        
        # Top contacts by event count
        contact_counts = defaultdict(int)
        for event in events:
            contact = event.get("contact_number", "Unknown")
            if contact != "Unknown":
                contact_counts[contact] += 1
        
        top_contacts = [
            {
                "contact_number": contact,
                "event_count": count,
                "contact_name": self._find_contact_name(events, contact)
            }
            for contact, count in sorted(contact_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
        
        # Activity by hour
        activity_by_hour = defaultdict(int)
        for event in valid_events:
            try:
                dt = datetime.fromtimestamp(event.get("epoch_ms", 0) / 1000.0)
                hour = dt.hour
                activity_by_hour[f"{hour:02d}"] = activity_by_hour.get(f"{hour:02d}", 0) + 1
            except:
                pass
        
        # Ensure all hours are present
        for h in range(24):
            hour_key = f"{h:02d}"
            if hour_key not in activity_by_hour:
                activity_by_hour[hour_key] = 0
        
        statistics = {
            "total_events": len(events),
            "date_range": {
                "earliest": epoch_ms_to_str(min_epoch),
                "earliest_epoch_ms": min_epoch,
                "latest": epoch_ms_to_str(max_epoch),
                "latest_epoch_ms": max_epoch,
                "span_days": (max_epoch - min_epoch) // (1000 * 60 * 60 * 24)
            },
            "event_type_counts": dict(event_type_counts),
            "top_contacts": top_contacts,
            "activity_by_hour": dict(sorted(activity_by_hour.items()))
        }
        
        return statistics
    
    def _find_contact_name(self, events, contact_number):
        """Try to find contact name from events"""
        for event in events:
            if event.get("contact_number") == contact_number:
                name = event.get("contact_name")
                if name and name != "Unknown":
                    return name
        return "Unknown"
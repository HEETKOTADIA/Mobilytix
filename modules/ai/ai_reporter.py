# modules/ai/ai_reporter.py

from groq import Groq
from modules.ai.ai_embedding import embed_text
from pathlib import Path
import chromadb
from collections import Counter

def shrink_text(text: str, max_chars: int = 800):
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]..."

class ForensicReporter:
    def __init__(self, api_key: str, session_path: str | Path):
        self.client = Groq(api_key=api_key)
        self.session_path = Path(session_path)

        db_path = self.session_path / "vector_store"
        self.chroma = chromadb.PersistentClient(path=str(db_path))
        self.collection = self.chroma.get_or_create_collection("forensics")

    def _gather_statistics(self):
        """Gather key statistics for report generation"""
        stats = {
            "device_info": "",
            "call_stats": "",
            "sms_stats": "",
            "contact_stats": "",
            "top_contacts": ""
        }
        
        # Get device info
        device_results = self.collection.get(where={"type": "device_info"})
        if device_results["documents"]:
            stats["device_info"] = "\n".join(device_results["documents"][:3])
        
        # Call statistics
        call_results = self.collection.get(where={"type": "call"})
        if call_results["documents"]:
            total_calls = len(call_results["documents"])
            
            # Calculate durations
            durations = []
            call_numbers = []
            for meta in call_results["metadatas"]:
                try:
                    dur = float(meta.get("duration_seconds", 0))
                    durations.append(dur)
                    call_numbers.append(meta.get("number", "Unknown"))
                except:
                    pass
            
            total_duration = sum(durations)
            avg_duration = total_duration / len(durations) if durations else 0
            longest_call = max(durations) if durations else 0
            
            # Most frequent contacts
            freq_contacts = Counter(call_numbers).most_common(5)
            
            stats["call_stats"] = f"""
Total Calls: {total_calls}
Total Call Duration: {total_duration:.0f} seconds ({total_duration/60:.1f} minutes)
Average Call Duration: {avg_duration:.1f} seconds
Longest Call: {longest_call:.0f} seconds ({longest_call/60:.1f} minutes)
"""
            
            stats["top_contacts"] = "Top 5 Most Called Numbers:\n"
            for i, (num, count) in enumerate(freq_contacts, 1):
                stats["top_contacts"] += f"{i}. {num} - {count} calls\n"
        
        # SMS statistics
        sms_results = self.collection.get(where={"type": "sms"})
        if sms_results["documents"]:
            total_sms = len(sms_results["documents"])
            
            sms_addresses = []
            sms_lengths = []
            for meta in sms_results["metadatas"]:
                sms_addresses.append(meta.get("address", "Unknown"))
                try:
                    length = int(meta.get("body_length", 0))
                    sms_lengths.append(length)
                except:
                    pass
            
            avg_length = sum(sms_lengths) / len(sms_lengths) if sms_lengths else 0
            longest_sms = max(sms_lengths) if sms_lengths else 0
            
            freq_sms = Counter(sms_addresses).most_common(5)
            
            stats["sms_stats"] = f"""
Total SMS Messages: {total_sms}
Average Message Length: {avg_length:.0f} characters
Longest Message: {longest_sms} characters

Top 5 Most Messaged Contacts:
"""
            for i, (addr, count) in enumerate(freq_sms, 1):
                stats["sms_stats"] += f"{i}. {addr} - {count} messages\n"
        
        # Contact statistics
        contact_results = self.collection.get(where={"type": "contact"})
        if contact_results["documents"]:
            total_contacts = len(contact_results["documents"])
            stats["contact_stats"] = f"Total Contacts: {total_contacts}"
        
        return stats

    def generate_report(self):
        # Gather structured statistics
        stats = self._gather_statistics()
        
        # Also get semantic samples for context
        q_embed = embed_text("summary of all forensic data")
        results = self.collection.query(
            query_embeddings=[q_embed],
            n_results=50  # Reduced from 200 for better performance
        )

        raw_docs = results["documents"][0]
        docs = [shrink_text(doc, 600) for doc in raw_docs]
        sample_context = "\n".join(docs[:20])  # Use top 20 samples

        # Build comprehensive context
        full_context = f"""
=== DEVICE INFORMATION ===
{stats['device_info']}

=== CALL STATISTICS ===
{stats['call_stats']}

{stats['top_contacts']}

=== SMS STATISTICS ===
{stats['sms_stats']}

=== CONTACT INFORMATION ===
{stats['contact_stats']}

=== SAMPLE DATA ===
{sample_context}
"""

        prompt = f"""
Generate a professional, comprehensive digital forensic report.

REQUIRED SECTIONS:
1. Executive Summary
   - Brief overview of the investigation
   - Key findings at a glance

2. Device Overview
   - Device model, OS, identifiers
   - Collection date and method

3. Communication Patterns Analysis
   - Overall communication behavior
   - Peak activity times/periods
   - Communication frequency trends

4. Call Log Analysis
   - Total calls and duration statistics
   - Most frequent contacts
   - Call patterns and anomalies
   - Longest/shortest calls

5. SMS Message Analysis
   - Total messages and volume
   - Most frequent contacts
   - Message content themes (if visible)
   - Notable patterns

6. Contact Database Review
   - Total contacts stored
   - Contact organization
   - Notable entries

7. Suspicious or Notable Indicators
   - Unusual patterns
   - Red flags or concerns
   - Deleted or hidden data indicators
   - Timing anomalies

8. Conclusions and Recommendations
   - Summary of findings
   - Suggested follow-up actions
   - Areas requiring additional investigation

FORENSIC DATA:
{full_context}

INSTRUCTIONS:
- Be professional and objective
- Use specific numbers and statistics from the data
- Highlight patterns and anomalies
- Keep each section concise but informative
- Base ALL conclusions on actual data provided
- Use forensic terminology appropriately

Generate the complete forensic report now:
"""

        resp = self.client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3  # Lower temperature for more factual output
        )

        return resp.choices[0].message.content
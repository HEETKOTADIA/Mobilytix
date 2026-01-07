import json
from pathlib import Path
from datetime import datetime
import plotly.graph_objects as go
from plotly.subplots import make_subplots

class TimelineVisualizer:
    def __init__(self, timeline_data_path):
        self.timeline_path = Path(timeline_data_path)
        with open(self.timeline_path, "r", encoding="utf-8") as f:
            self.timeline_data = json.load(f)
    
    def generate_html(self, output_path=None):
        """Generate interactive HTML timeline"""
        if not output_path:
            output_path = self.timeline_path.parent / "timeline.html"
        
        # Create figure with subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Communication Timeline', 'Activity by Hour', 'Event Type Distribution', 'Top Contacts'),
            specs=[[{"colspan": 2}, None],
                   [{"type": "bar"}, {"type": "pie"}]],
            vertical_spacing=0.15,
            horizontal_spacing=0.1
        )
        
        # 1. Main Timeline (Scatter plot)
        self._add_timeline_trace(fig)
        
        # 2. Activity by Hour (Bar chart)
        self._add_hourly_activity(fig)
        
        # 3. Event Type Distribution (Pie chart)
        self._add_event_distribution(fig)
        
        # Update layout
        fig.update_layout(
            title={
                'text': f"Forensic Timeline Analysis<br><sub>{self.timeline_data.get('timeline_id', 'Unknown')}</sub>",
                'x': 0.5,
                'xanchor': 'center',
                'font': {'size': 24, 'color': '#fff'}
            },
            height=1000,
            showlegend=True,
            hovermode='closest',
            template='plotly_dark',
            paper_bgcolor='#0F0F0F',
            plot_bgcolor='#1E1E1E',
            font=dict(color='#ddd')
        )
        
        # Save HTML
        fig.write_html(str(output_path))
        return str(output_path)
    
    def _add_timeline_trace(self, fig):
        """Add main timeline scatter plot"""
        events = self.timeline_data.get("events", [])
        
        if not events:
            return
        
        # Separate by event type
        sms_events = [e for e in events if e.get("event_type") == "sms"]
        call_events = [e for e in events if e.get("event_type") == "call"]
        
        # SMS trace
        if sms_events:
            sms_dates = [datetime.fromtimestamp(e.get("epoch_ms", 0) / 1000.0) for e in sms_events]
            sms_y = [1] * len(sms_events)  # Fixed y-position for SMS
            sms_text = [
                f"SMS<br>Contact: {e.get('contact_number', 'Unknown')}<br>"
                f"Time: {e.get('timestamp', 'Unknown')}<br>"
                f"Message: {e.get('details', {}).get('body', '')[:50]}..."
                for e in sms_events
            ]
            
            fig.add_trace(
                go.Scatter(
                    x=sms_dates,
                    y=sms_y,
                    mode='markers',
                    name='SMS',
                    marker=dict(size=8, color='#00D9FF', symbol='circle'),
                    text=sms_text,
                    hovertemplate='%{text}<extra></extra>'
                ),
                row=1, col=1
            )
        
        # Call trace
        if call_events:
            call_dates = [datetime.fromtimestamp(e.get("epoch_ms", 0) / 1000.0) for e in call_events]
            call_y = [2] * len(call_events)  # Fixed y-position for calls
            call_text = [
                f"Call<br>Contact: {e.get('contact_name', e.get('contact_number', 'Unknown'))}<br>"
                f"Time: {e.get('timestamp', 'Unknown')}<br>"
                f"Duration: {e.get('details', {}).get('duration_formatted', 'N/A')}"
                for e in call_events
            ]
            
            fig.add_trace(
                go.Scatter(
                    x=call_dates,
                    y=call_y,
                    mode='markers',
                    name='Calls',
                    marker=dict(size=8, color='#FF6B6B', symbol='diamond'),
                    text=call_text,
                    hovertemplate='%{text}<extra></extra>'
                ),
                row=1, col=1
            )
        
        # Update y-axis to show event types
        fig.update_yaxes(
            tickvals=[1, 2],
            ticktext=['SMS', 'Calls'],
            row=1, col=1
        )
    
    def _add_hourly_activity(self, fig):
        """Add hourly activity bar chart"""
        stats = self.timeline_data.get("statistics", {})
        activity_by_hour = stats.get("activity_by_hour", {})
        
        hours = sorted(activity_by_hour.keys())
        counts = [activity_by_hour[h] for h in hours]
        
        fig.add_trace(
            go.Bar(
                x=hours,
                y=counts,
                name='Activity',
                marker=dict(color='#00D9FF'),
                showlegend=False
            ),
            row=2, col=1
        )
        
        fig.update_xaxes(title_text="Hour of Day", row=2, col=1)
        fig.update_yaxes(title_text="Event Count", row=2, col=1)
    
    def _add_event_distribution(self, fig):
        """Add event type pie chart"""
        stats = self.timeline_data.get("statistics", {})
        event_counts = stats.get("event_type_counts", {})
        
        labels = list(event_counts.keys())
        values = list(event_counts.values())
        
        colors = {'sms': '#00D9FF', 'call': '#FF6B6B', 'unknown': '#888'}
        color_list = [colors.get(label, '#888') for label in labels]
        
        fig.add_trace(
            go.Pie(
                labels=labels,
                values=values,
                marker=dict(colors=color_list),
                showlegend=False
            ),
            row=2, col=2
        )
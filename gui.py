import os
import webbrowser
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QFileDialog, QTextEdit, QInputDialog, QTableWidget,
    QTableWidgetItem, QLineEdit, QHeaderView, QScrollArea, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl

from modules.adb_utils import (
    timestamp, fname_timestamp, list_devices, list_apps, list_files,
    get_device_info, get_battery_info, get_screenshot, pull_item,
    copy_whatsapp, copy_screenshots, copy_camera, 
    dump_sms_enhanced, dump_contacts_enhanced, dump_calls_enhanced,
    query_sms_live, query_contacts_live, query_calls_live,
    analyze_app, pull_apk, generate_app_report,
    pull_folder_with_metadata, archive_to_bin, run_adb,
    perform_full_extraction, brute_extract_folder, detect_device_manufacturer
)

from modules.parsers import (
    parse_sms_text, parse_contacts_text, parse_calls_text,
    manifest_to_table_rows
)

from modules.workers import Worker

# Import new modules
from modules.session_manager import SessionManager
from modules.data_logger import DataLogger
from modules.timeline_builder import TimelineBuilder
from modules.timeline_visualizer import TimelineVisualizer


class MobilytixGUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Mobilytix – Android Forensics Suite")
        self.setMinimumSize(1300, 780)
        self.setStyleSheet("background-color: #0F0F0F; color: white;")

        self.workers = []
        self.current_rows = []
        self._last_manifest = None
        # AI forensic state
        self.ai_session_path = None
        self.ai_api_key = None

        # Initialize session manager and logger
        self.session_manager = SessionManager()
        self.data_logger = DataLogger(self.session_manager)
        

        main_layout = QHBoxLayout(self)

        # =====================================================================
        #                           SIDEBAR (SCROLL)
        # =====================================================================
        sidebar_container = QWidget()
        sidebar = QVBoxLayout(sidebar_container)
        sidebar.setAlignment(Qt.AlignmentFlag.AlignTop)
        sidebar.setSpacing(12)

        def make_btn(text, handler):
            b = QPushButton(text)
            b.setFixedHeight(40)
            b.setStyleSheet(
                "background:#1E1E1E; border:1px solid #444; "
                "color:white; font-size:14px; text-align:left; padding-left:8px;"
            )
            b.clicked.connect(handler)
            return b

        # ---------------- DEVICE INFO ----------------
        lbl_device = QLabel("DEVICE INFO")
        lbl_device.setFont(QFont("Segoe UI", 12))
        sidebar.addWidget(lbl_device)

        sidebar.addWidget(make_btn("List Devices", lambda: self.run_plain(list_devices)))
        sidebar.addWidget(make_btn("Device Info", self.ui_device_info))
        sidebar.addWidget(make_btn("Battery Info", lambda: self.run_plain(get_battery_info)))
        sidebar.addWidget(make_btn("Detect Manufacturer", self.ui_detect_manufacturer))
        sidebar.addWidget(make_btn("Grant ADB Permissions", self.ui_grant_permissions))

        sidebar.addSpacing(16)

        # ---------------- FILES & APPS ----------------
        lbl_files = QLabel("FILES & APPS")
        lbl_files.setFont(QFont("Segoe UI", 12))
        sidebar.addWidget(lbl_files)

        sidebar.addWidget(make_btn("List Apps", lambda: self.run_plain(list_apps)))
        sidebar.addWidget(make_btn("List /sdcard/", lambda: self.run_plain(list_files)))
        sidebar.addWidget(make_btn("Pull File", self.ui_pull))
        sidebar.addWidget(make_btn("Screenshot", self.ui_screenshot))

        sidebar.addSpacing(16)

        # ---------------- EXTRACTION ----------------
        lbl_extract = QLabel("EXTRACTION")
        lbl_extract.setFont(QFont("Segoe UI", 12))
        sidebar.addWidget(lbl_extract)
    
        sidebar.addWidget(make_btn("Copy WhatsApp", self.ui_whatsapp))
        sidebar.addWidget(make_btn("Copy Screenshots", self.ui_screenshots))
        sidebar.addWidget(make_btn("Copy Camera", self.ui_camera))
        sidebar.addWidget(make_btn("Dump SMS", self.ui_dump_sms))
        sidebar.addWidget(make_btn("Dump Contacts", self.ui_dump_contacts))
        sidebar.addWidget(make_btn("Dump Calls", self.ui_dump_calls))
        sidebar.addWidget(make_btn("Full Device Extraction", self.ui_full_device_extraction))
        sidebar.addWidget(make_btn("Extract Full Filesystem", self.ui_extract_full_fs))
        sidebar.addWidget(make_btn("Extract Folder", self.ui_extract_folder))
        sidebar.addWidget(make_btn("Create BIN from Last Extract", self.ui_create_bin_from_last))

        sidebar.addSpacing(16)

        # ---------------- APP FORENSICS ----------------
        lbl_forensics = QLabel("APP FORENSICS")
        lbl_forensics.setFont(QFont("Segoe UI", 12))
        sidebar.addWidget(lbl_forensics)

        sidebar.addWidget(make_btn("Analyze App", self.ui_analyze))
        sidebar.addWidget(make_btn("Pull APK", self.ui_pull_apk))
        sidebar.addWidget(make_btn("Generate Report", self.ui_report))

        sidebar.addSpacing(16)

        # ---------------- DATA VIEWER ----------------
        lbl_viewer = QLabel("DATA VIEWER")
        lbl_viewer.setFont(QFont("Segoe UI", 12))
        sidebar.addWidget(lbl_viewer)

        sidebar.addWidget(make_btn("View SMS", self.ui_view_sms))
        sidebar.addWidget(make_btn("View Contacts", self.ui_view_contacts))
        sidebar.addWidget(make_btn("View Call Logs", self.ui_view_calls))
        sidebar.addWidget(make_btn("Load Dump File", self.ui_load_file))
        
        sidebar.addSpacing(16)

        # ---------------- TIMELINE ----------------
        lbl_timeline = QLabel("TIMELINE")
        lbl_timeline.setFont(QFont("Segoe UI", 12))
        sidebar.addWidget(lbl_timeline)

        sidebar.addWidget(make_btn("Generate Timeline", self.ui_generate_timeline))
        sidebar.addWidget(make_btn("View Timeline", self.ui_view_timeline))
        sidebar.addWidget(make_btn("View Sessions", self.ui_view_sessions))

        sidebar.addSpacing(16)

        # ---------------- AI FORENSICS ----------------
        lbl_ai = QLabel("AI FORENSICS")
        lbl_ai.setFont(QFont("Segoe UI", 12))
        sidebar.addWidget(lbl_ai)

        sidebar.addWidget(make_btn("Select Session Folder", self.ui_select_session_folder))
        sidebar.addWidget(make_btn("Set Groq API Key", self.ui_set_api_key))
        sidebar.addWidget(make_btn("Index Session", self.ui_index_session))
        sidebar.addWidget(make_btn("Ask AI", self.ui_query_ai))
        sidebar.addWidget(make_btn("Generate AI Report", self.ui_generate_ai_report))
        sidebar.addWidget(make_btn("Download Report as PDF", self.ui_save_pdf))


        # Scroll setup
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(sidebar_container)
        scroll.setStyleSheet("background:#0F0F0F; border:none;")

        main_layout.addWidget(scroll, 2)

        # =====================================================================
        #                         RIGHT PANEL (CONSOLE + TABLE)
        # =====================================================================
        right_layout = QVBoxLayout()
        right_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # ----- Console -----
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet(
            "background:#111; color:#ddd; font-family:Consolas; font-size:13px;"
        )
        self.console.setFixedHeight(300)

        right_layout.addWidget(self.console)
        # ----- AI MARKDOWN OUTPUT VIEW -----
        self.md_output = QTextEdit()
        self.md_output.setReadOnly(True)
        self.md_output.setStyleSheet(
            "background:#111; color:white; font-family:Segoe UI; font-size:14px; padding:10px;"
        )
        self.md_output.hide()  # Only visible when AI output is shown
        right_layout.addWidget(self.md_output)

        # ----- Timeline HTML Viewer -----
        self.timeline_view = QWebEngineView()
        self.timeline_view.hide()
        right_layout.addWidget(self.timeline_view, 1)




        self._initialize_session()
        # ----- Search Bar -----
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Filter table (press Enter)...")
        self.search_input.returnPressed.connect(self.filter_table)

        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_search)

        search_layout.addWidget(self.search_input)
        search_layout.addWidget(clear_btn)

        right_layout.addLayout(search_layout)

        # ----- Table -----
        self.table = QTableWidget(0, 1)
        self.table.setStyleSheet("background:#111; color:#ddd;")
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)

        right_layout.addWidget(self.table)

        main_layout.addLayout(right_layout, 6)

    # =====================================================================
    #                          SESSION MANAGEMENT
    # =====================================================================
    def _initialize_session(self):
        """Initialize session on startup"""
        try:
            device_info = detect_device_manufacturer()
            session_dir = self.session_manager.start_session(device_info)
            self._append_console(f"✓ Session initialized: {session_dir.name}")
        except Exception as e:
            self._append_console(f"⚠ Session initialization warning: {e}")

    # =====================================================================
    #                          WORKER UTILITIES
    # =====================================================================
    def run_plain(self, fn):
        self._append_console("Running...")
        worker = Worker(fn)
        self.workers.append(worker)

        def finished(res):
            self._append_console(str(res))
            if worker in self.workers:
                self.workers.remove(worker)

        worker.finished.connect(finished)
        worker.start()

    def run_with_callback(self, fn, callback):
        self._append_console("Running...")
        worker = Worker(fn)
        self.workers.append(worker)

        def finished(res):
            self._append_console("Result received.")
            try:
                callback(res)
            except Exception as e:
                self._append_console(f"Callback error: {e}")
                import traceback
                self._append_console(traceback.format_exc())

            if worker in self.workers:
                self.workers.remove(worker)

        worker.finished.connect(finished)
        worker.start()
    
    def ui_grant_permissions(self):
        from modules.adb_utils import grant_adb_permissions
        self.run_plain(grant_adb_permissions)
    
    def _append_console(self, text):
        self.console.append(f"[{timestamp()}] {text}")

    def display_markdown_output(self, md_text):
        """Display Markdown-rendered output in the Raw Output section."""
        self.table.hide()            # Hide table
        self.timeline_view.hide()

        self.md_output.show()        # Show markdown viewer

        try:
            self.md_output.setMarkdown(md_text)
        except Exception:
            # Fallback if markdown fails
            self.md_output.setPlainText(md_text)

        self._append_console("✓ Output rendered in Raw Output section")

    def choose_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Destination")
        return folder if folder else None

    # =====================================================================
    #                      BASIC OPERATIONS
    # =====================================================================
    def ui_device_info(self):
        """Get device info and log it"""
        def fn():
            info_text = get_device_info()
            device_dict = detect_device_manufacturer()
            
            # Log device info
            try:
                log_file = self.data_logger.log_device_info(info_text, device_dict)
                return f"{info_text}\n\n✓ Logged to: {log_file}"
            except Exception as e:
                return f"{info_text}\n\n⚠ Logging failed: {e}"
        
        self.run_plain(fn)
    
    def ui_detect_manufacturer(self):
        def detect():
            info = detect_device_manufacturer()
            output = "Device Detection:\n"
            output += f"Manufacturer: {info['manufacturer']}\n"
            output += f"Brand: {info['brand']}\n"
            output += f"Model: {info['model']}\n"
            output += f"SDK: {info['sdk']}\n\n"
            output += "Device Type Detection:\n"
            if info['is_xiaomi']:
                output += "✓ Xiaomi/MIUI device detected\n"
            if info['is_samsung']:
                output += "✓ Samsung device detected\n"
            if info['is_oneplus']:
                output += "✓ OnePlus device detected\n"
            if info['is_oppo']:
                output += "✓ OPPO/Realme device detected\n"
            if info['is_motorola']:
                output += "✓ Motorola device detected\n"
            if info['is_google']:
                output += "✓ Google Pixel device detected\n"
            return output
        
        self.run_plain(detect)

    def ui_pull(self):
        remote, ok = QInputDialog.getText(self, "Remote Path", "Enter remote path:")
        if ok and remote:
            d = self.choose_folder()
            if d:
                self.run_plain(lambda: pull_item(remote, d))

    def ui_screenshot(self):
        d = self.choose_folder()
        if d:
            self.run_plain(lambda: get_screenshot(d))

    def ui_whatsapp(self):
        d = self.choose_folder()
        if d:
            self.run_plain(lambda: copy_whatsapp(d))

    def ui_screenshots(self):
        d = self.choose_folder()
        if d:
            self.run_plain(lambda: copy_screenshots(d))

    def ui_camera(self):
        d = self.choose_folder()
        if d:
            self.run_plain(lambda: copy_camera(d))

    def ui_dump_sms(self):
        d = self.choose_folder()
        if d:
            self.run_plain(lambda: dump_sms_enhanced(d))

    def ui_dump_contacts(self):
        d = self.choose_folder()
        if d:
            self.run_plain(lambda: dump_contacts_enhanced(d))

    def ui_dump_calls(self):
        d = self.choose_folder()
        if d:
            self.run_plain(lambda: dump_calls_enhanced(d))

    # =====================================================================
    #                      APP FORENSICS
    # =====================================================================
    def ui_analyze(self):
        pkg, ok = QInputDialog.getText(self, "Package Name", "Package name:")
        if ok and pkg:
            self.run_plain(lambda: analyze_app(pkg))

    def ui_pull_apk(self):
        pkg, ok = QInputDialog.getText(self, "Package Name", "Package name:")
        if ok and pkg:
            d = self.choose_folder()
            if d:
                self.run_plain(lambda: pull_apk(pkg, d))

    def ui_report(self):
        pkg, ok = QInputDialog.getText(self, "Package Name", "Package name:")
        if ok and pkg:
            d = self.choose_folder()
            if d:
                self.run_plain(lambda: generate_app_report(pkg, d))

    # =====================================================================
    #                  EXTRACTION FEATURES
    # =====================================================================
    def ui_extract_full_fs(self):
        d = self.choose_folder()
        if not d:
            return

        def fn():
            return brute_extract_folder("/sdcard", d)

        def cb(manifest):
            if not isinstance(manifest, list):
                self._append_console("Filesystem extraction failed or limited permissions.")
                return
            self._last_manifest = manifest
            headers, rows = manifest_to_table_rows(manifest)
            self.populate_table(headers, rows)
            self._append_console(f"Extracted {len(manifest)} files.")

        self.run_with_callback(fn, cb)

    def ui_extract_folder(self):
        remote, ok = QInputDialog.getText(self, "Remote Folder", "Remote folder (e.g. /sdcard/DCIM):")
        if not ok or not remote:
            return

        d = self.choose_folder()
        if not d:
            return

        def fn():
            return brute_extract_folder(remote, d)

        def cb(manifest):
            if not isinstance(manifest, list):
                self._append_console("No files found or permission denied.")
                return
            self._last_manifest = manifest
            headers, rows = manifest_to_table_rows(manifest)
            self.populate_table(headers, rows)

        self.run_with_callback(fn, cb)

    def ui_create_bin_from_last(self):
        if not self._last_manifest:
            self._append_console("No previous extraction.")
            return

        d = self.choose_folder()
        if not d:
            return

        out_path = os.path.join(d, f"mobilytix_dump_{fname_timestamp()}.bin")
        self.run_plain(lambda: archive_to_bin(self._last_manifest, out_path))

    def ui_full_device_extraction(self):
        d = self.choose_folder()
        if not d:
            return

        def fn():
            return perform_full_extraction(d)

        def cb(res):
            if isinstance(res, str):
                self._append_console(res)
                return
            if not isinstance(res, list):
                self._append_console("Extraction failed.")
                return

            self._last_manifest = res
            headers, rows = manifest_to_table_rows(res)
            self.populate_table(headers, rows)
            self._append_console(f"Full device extraction: {len(res)} items.")

        self.run_with_callback(fn, cb)

    # =====================================================================
    #                     VIEWER HANDLERS (WITH LOGGING)
    # =====================================================================
    def ui_view_sms(self):
        """View SMS with automatic logging"""
        def fn():
            raw = query_sms_live()
            parsed = parse_sms_text(raw)
            
            # Extract metadata from raw output
            extraction_info = self._extract_metadata_from_raw(raw)
            
            # Log the data
            try:
                log_file = self.data_logger.log_sms_data(raw, parsed, extraction_info)
                return (raw, parsed, log_file)
            except Exception as e:
                return (raw, parsed, None)
        
        self.run_with_callback(fn, self._on_sms_callback)
    
    def _on_sms_callback(self, result):
        """Handle SMS result with logging info"""
        raw, parsed, log_file = result
        self._on_sms_text(raw)
        if log_file:
            self._append_console(f"✓ SMS data logged to: {log_file}")

    def ui_view_contacts(self):
        """View contacts with automatic logging"""
        def fn():
            raw = query_contacts_live()
            parsed = parse_contacts_text(raw)
            extraction_info = self._extract_metadata_from_raw(raw)
            
            try:
                log_file = self.data_logger.log_contacts_data(raw, parsed, extraction_info)
                return (raw, parsed, log_file)
            except Exception as e:
                return (raw, parsed, None)
        
        self.run_with_callback(fn, self._on_contacts_callback)
    
    def _on_contacts_callback(self, result):
        """Handle contacts result with logging info"""
        raw, parsed, log_file = result
        self._on_contacts_text(raw)
        if log_file:
            self._append_console(f"✓ Contacts data logged to: {log_file}")

    def ui_view_calls(self):
        """View calls with automatic logging"""
        def fn():
            raw = query_calls_live()
            parsed = parse_calls_text(raw)
            extraction_info = self._extract_metadata_from_raw(raw)
            
            try:
                log_file = self.data_logger.log_calls_data(raw, parsed, extraction_info)
                return (raw, parsed, log_file)
            except Exception as e:
                return (raw, parsed, None)
        
        self.run_with_callback(fn, self._on_calls_callback)
    
    def _on_calls_callback(self, result):
        """Handle calls result with logging info"""
        raw, parsed, log_file = result
        self._on_calls_text(raw)
        if log_file:
            self._append_console(f"✓ Call logs logged to: {log_file}")

    def _extract_metadata_from_raw(self, raw_text):
        """Extract URI and projection info from raw output"""
        import re
        info = {}
        
        uri_match = re.search(r'# URI(?:\s+used)?:\s*(.+)', raw_text)
        if uri_match:
            info['uri_used'] = uri_match.group(1).strip()
        
        proj_match = re.search(r'# Projection:\s*(.+)', raw_text)
        if proj_match:
            info['projection_used'] = proj_match.group(1).strip()
        
        return info

    def ui_load_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Dump File", "", "Text files (*.txt);;All files (*.*)")
        if not path:
            return

        try:
            raw = open(path, "r", encoding="utf-8").read()
        except Exception as e:
            self._append_console(f"Error reading file: {e}")
            return

        # Auto-detect format based on content
        if "address=" in raw and "body=" in raw:
            self._on_sms_text(raw)
        elif "display_name=" in raw or "contact" in raw.lower():
            self._on_contacts_text(raw)
        elif "duration=" in raw and "date=" in raw:
            self._on_calls_text(raw)
        else:
            self._append_console("Unknown format, showing raw data")
            self.populate_table(["Raw"], [[ln] for ln in raw.splitlines()[:100]])

    # =====================================================================
    #                   PARSED CALLBACKS
    # =====================================================================
    def _on_sms_text(self, raw):
        """Handle SMS data with enhanced error reporting"""
        try:
            rows = parse_sms_text(raw)
            
            if not rows:
                self._append_console("⚠ No SMS data could be parsed. Showing raw output.")
                raw_lines = raw.splitlines()[:50]
                self.populate_table(["Raw Output"], [[ln] for ln in raw_lines])
                return
            
            self.current_rows = rows
            table = [[r["address"], r["date"], r["body"]] for r in rows]
            self.populate_table(["Address", "Date", "Body"], table)
            self._append_console(f"✓ Successfully parsed {len(rows)} SMS messages")
            
        except Exception as e:
            self._append_console(f"Error parsing SMS: {e}")

    def _on_contacts_text(self, raw):
        """Handle contacts data with enhanced error reporting"""
        try:
            rows = parse_contacts_text(raw)
            
            if not rows:
                self._append_console("⚠ No contacts data could be parsed. Showing raw output.")
                raw_lines = raw.splitlines()[:50]
                self.populate_table(["Raw Output"], [[ln] for ln in raw_lines])
                return
            
            self.current_rows = rows
            table = [[r["name"], r["number"]] for r in rows]
            self.populate_table(["Name", "Number"], table)
            self._append_console(f"✓ Successfully parsed {len(rows)} contacts")
            
        except Exception as e:
            self._append_console(f"Error parsing contacts: {e}")

    def _on_calls_text(self, raw):
        """Handle call log data with enhanced error reporting"""
        try:
            rows = parse_calls_text(raw)
            
            if not rows:
                self._append_console("⚠ No call log data could be parsed. Showing raw output.")
                raw_lines = raw.splitlines()[:50]
                self.populate_table(["Raw Output"], [[ln] for ln in raw_lines])
                return
            
            self.current_rows = rows
            table = [[r["name"], r["number"], r["duration_seconds"], r["date"]] for r in rows]
            self.populate_table(["Name", "Number", "Duration(s)", "Date"], table)
            self._append_console(f"✓ Successfully parsed {len(rows)} call log entries")
            
        except Exception as e:
            self._append_console(f"Error parsing call logs: {e}")

    # =====================================================================
    #                   TIMELINE FEATURES
    # =====================================================================

    def ui_generate_timeline(self):
        """Generate timeline from current session data (AI session first, then device session)."""
        from pathlib import Path

        session_dir = None

        # Priority 1: use the AI session folder selected by the user
        if self.ai_session_path:
            session_dir = Path(self.ai_session_path)

        # Priority 2: fall back to the SessionManager's current session
        elif self.session_manager.get_session_dir():
            session_dir = Path(self.session_manager.get_session_dir())

        if not session_dir:
            QMessageBox.warning(
                self,
                "No Session",
                "No session folder selected or active. Select a session folder or create a new session."
            )
            return

        def fn():
            builder = TimelineBuilder(session_dir)
            timeline_data, timeline_path = builder.build_timeline()

            # Generate visualization
            visualizer = TimelineVisualizer(timeline_path)
            html_path = visualizer.generate_html()

            return f"Timeline generated!\nData: {timeline_path}\nVisualization: {html_path}"

        self.run_plain(fn)



    def ui_view_timeline(self):
        """View the timeline HTML in browser"""
        session_dir = None
        from pathlib import Path

        # Priority 1: AI session folder selected manually
        if self.ai_session_path:
            session_dir = self.ai_session_path

        # Priority 2: Device session manager (old behavior)
        elif self.session_manager.get_session_dir():
            session_dir = Path(self.session_manager.get_session_dir()).resolve()
        # No session at all
        else:
            QMessageBox.warning(self, "No Session", "No session folder selected or active.")
            return

        if not session_dir:
            QMessageBox.warning(self, "No Session", "No active session found.")
            return
        
        print(Path(session_dir))
        timeline_html = Path(session_dir) / "timeline.html"

        if not timeline_html.exists():
            QMessageBox.warning(self, "Timeline Not Found", "Timeline not generated yet. Click 'Generate Timeline' first.")
            return
        
        self.display_timeline_html(timeline_html)

    
    def ui_view_sessions(self):
        """View all available sessions"""
        sessions = self.session_manager.list_all_sessions()
        
        if not sessions:
            self._append_console("No sessions found.")
            return
        
        headers = ["Session ID", "Device", "Created", "Updated", "Operations"]
        rows = []
        for s in sessions:
            device = s.get("device", {})
            device_str = f"{device.get('manufacturer', 'Unknown')} {device.get('model', 'Unknown')}"
            rows.append([
                s.get("session_id", ""),
                device_str,
                s.get("created", ""),
                s.get("updated", ""),
                str(s.get("operation_count", 0))
            ])
        
        self.populate_table(headers, rows)
        self._append_console(f"Found {len(sessions)} session(s)")

    def display_timeline_html(self, html_path):
        """Render full-featured timeline via WebEngine."""
        try:
            html_path = str(html_path)

            # Hide other views
            self.table.hide()
            self.md_output.hide()

            # Load HTML in WebEngine
            self.timeline_view.show()
            self.timeline_view.load(QUrl.fromLocalFile(html_path))

            self._append_console("✓ Timeline displayed inside application (WebEngine)")

        except Exception as e:
            self._append_console(f"Error displaying timeline: {e}")




    # =====================================================================
    #                   TABLE MANAGEMENT
    # =====================================================================
    def populate_table(self, headers, rows):
        self.timeline_view.hide()
        self.md_output.hide()  # optional: also hide markdown when table is shown
        self.table.show()      # <-- FIX: ensure table becomes visible again!
        self.table.clear()
        self.table.setColumnCount(len(headers))
        self.table.setRowCount(len(rows))
        self.table.setHorizontalHeaderLabels(headers)

        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                item = QTableWidgetItem(str(val))
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
                self.table.setItem(r, c, item)

        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.resizeRowsToContents()

    def filter_table(self):
        term = self.search_input.text().lower().strip()
        if not term or not self.current_rows:
            return

        keys = set(self.current_rows[0].keys()) if self.current_rows else set()
        filtered = []

        if "address" in keys:
            for r in self.current_rows:
                if term in r.get("address", "").lower() or term in r.get("body", "").lower():
                    filtered.append([r["address"], r["date"], r["body"]])
            headers = ["Address", "Date", "Body"]

        elif "duration_seconds" in keys:
            for r in self.current_rows:
                if term in r.get("name", "").lower() or term in r.get("number", "").lower():
                    filtered.append([r["name"], r["number"], r["duration_seconds"], r["date"]])
            headers = ["Name", "Number", "Duration(s)", "Date"]

        else:
            for r in self.current_rows:
                if term in r.get("name", "").lower() or term in r.get("number", "").lower():
                    filtered.append([r["name"], r["number"]])
            headers = ["Name", "Number"]

        self.populate_table(headers, filtered)
        self._append_console(f"Filter applied: {len(filtered)} results")

    def clear_search(self):
        self.search_input.setText("")
        if not self.current_rows:
            return

        keys = set(self.current_rows[0].keys()) if self.current_rows else set()
        
        if "address" in keys:
            rows = [[r["address"], r["date"], r["body"]] for r in self.current_rows]
            self.populate_table(["Address", "Date", "Body"], rows)
        elif "duration_seconds" in keys:
            rows = [[r["name"], r["number"], r["duration_seconds"], r["date"]] for r in self.current_rows]
            self.populate_table(["Name", "Number", "Duration(s)", "Date"], rows)
        else:
            rows = [[r["name"], r["number"]] for r in self.current_rows]
            self.populate_table(["Name", "Number"], rows)

    def ui_select_session_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select AI Session Folder")
        if folder:
            self.ai_session_path = folder
            self._append_console(f"✓ AI session folder set: {folder}")
        
    def ui_set_api_key(self):
        key, ok = QInputDialog.getText(self, "Groq API Key", "Enter API key:")
        if ok and key:
            self.ai_api_key = key
            self._append_console("✓ AI API key saved")

    def ui_index_session(self):
        if not self.ai_session_path:
            self._append_console("⚠ Set AI session folder first.")
            return

        from modules.ai.ai_indexer import SessionIndexer

        def fn():
            indexer = SessionIndexer(self.ai_session_path)
            indexer.index_all()
            return "✓ AI Indexing completed."

        self.run_plain(fn)

    def ui_query_ai(self):
        if not self.ai_api_key or not self.ai_session_path:
            self._append_console("⚠ Missing AI session path or API key.")
            return

        question, ok = QInputDialog.getText(self, "Ask AI", "Enter your question:")
        if not ok or not question:
            return

        from modules.ai.ai_query import AIQueryEngine

        def fn():
            engine = AIQueryEngine(self.ai_api_key, self.ai_session_path)
            answer = engine.query(question)
            return answer

        def cb(answer):
            self.display_markdown_output(answer)

        self.run_with_callback(fn, cb)


    def ui_generate_ai_report(self):
        if not self.ai_api_key or not self.ai_session_path:
            self._append_console("⚠ Missing AI session path or API key.")
            return

        from modules.ai.ai_reporter import ForensicReporter

        def fn():
            reporter = ForensicReporter(self.ai_api_key, self.ai_session_path)
            report = reporter.generate_report()
            return report

        def cb(report):
            self.display_markdown_output(report)

        self.run_with_callback(fn, cb)

    def ui_save_pdf(self):
        """Save the current markdown output as a PDF file."""
        md_text = self.md_output.toPlainText().strip()

        if not md_text:
            QMessageBox.warning(self, "No Report", "No report content available to save.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save PDF Report",
            "Mobilytix_Report.pdf",
            "PDF Files (*.pdf)"
        )

        if not path:
            return

        try:
            self._save_pdf_from_markdown(md_text, path)
            self._append_console(f"✓ PDF saved to: {path}")
            QMessageBox.information(self, "Success", "PDF report saved successfully.")
        except Exception as e:
            self._append_console(f"PDF Error: {e}")
            QMessageBox.warning(self, "Error", str(e))

    def _save_pdf_from_markdown(self, md_text, output_path):
        """Generate a clean, formal forensic-style PDF from markdown text."""
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from datetime import datetime

        # -----------------------------
        # PDF Document Setup
        # -----------------------------
        doc = SimpleDocTemplate(
            output_path,
            pagesize=LETTER,
            leftMargin=0.8 * inch,
            rightMargin=0.8 * inch,
            topMargin=1 * inch,
            bottomMargin=0.8 * inch
        )

        styles = getSampleStyleSheet()

        # Base body style
        body = ParagraphStyle(
            "Body",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=colors.black
        )

        # Section title style
        section_title = ParagraphStyle(
            "SectionTitle",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            spaceAfter=12,
            textColor=colors.HexColor("#003366")
        )

        # Metadata style
        meta_style = ParagraphStyle(
            "Meta",
            parent=styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=9,
            leading=12,
            textColor=colors.gray
        )

        story = []

        # -----------------------------
        # HEADER BAR
        # -----------------------------
        story.append(
            Paragraph(
                "<font color='#FFFFFF'><b>Mobilytix Forensic Report</b></font>",
                ParagraphStyle(
                    "Header",
                    fontName="Helvetica-Bold",
                    fontSize=16,
                    textColor=colors.white,
                    backColor=colors.HexColor("#003366"),
                    leftIndent=0,
                    alignment=0,
                    spaceAfter=12,
                    leading=20,
                    borderPadding=(6, 6, 6, 6),
                )
            )
        )

        # -----------------------------
        # METADATA BLOCK
        # -----------------------------
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        metadata = [
            ["Generated On:", now],
            ["Generated By:", "Mobilytix Forensic Engine"],
            ["Session:", self.ai_session_path or "Unknown"],
        ]

        table = Table(metadata, colWidths=[1.6 * inch, 4.8 * inch])
        table.setStyle(
            TableStyle([
                ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#333333")),
                ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                ("ALIGN", (1, 0), (1, -1), "LEFT"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(table)
        story.append(Spacer(1, 0.25 * inch))

        # -----------------------------
        # MARKDOWN → TEXT CONVERSION
        # -----------------------------
        # Simple markdown cleanup
        lines = md_text.replace("**", "").split("\n")

        for line in lines:
            stripped = line.strip()

            if not stripped:
                story.append(Spacer(1, 0.20 * inch))
                continue

            # Detect headers
            if stripped.startswith("# "):
                story.append(Paragraph(stripped[2:], section_title))
            elif stripped.startswith("## "):
                story.append(Paragraph(stripped[3:], section_title))
            else:
                story.append(Paragraph(stripped, body))

            story.append(Spacer(1, 0.12 * inch))

        # -----------------------------
        # FOOTER (drawn on every page)
        # -----------------------------
        def footer(canvas, doc):
            canvas.saveState()
            canvas.setFont("Helvetica", 9)
            canvas.setFillColor(colors.gray)
            canvas.drawRightString(
                7.5 * inch, 0.55 * inch,
                f"Mobilytix Forensic Report – Page {doc.page}"
            )
            canvas.restoreState()

        # -----------------------------
        # BUILD FINAL DOCUMENT
        # -----------------------------
        doc.build(story, onLaterPages=footer, onFirstPage=footer)

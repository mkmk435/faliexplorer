# Vulnerability Report System Setup

## Overview
The vulnerability reporting system has been implemented with automatic deduplication, structured JSON reports, and a Python Flask web server for viewing reports.

## Features

### 1. **Deduplication Logic**
- Automatically prevents duplicate vulnerabilities from being recorded
- A vulnerability is considered a duplicate if it has:
  - Same vulnerability type
  - Same access type
  - Same IOCTL code
- When a duplicate is detected, it's skipped and logged as informational

### 2. **Report Organization**
- All reports are saved in the `reports/` directory
- Each driver analyzed gets its own report file named `{driver_name}_report.json`
- Example: Analyzing `HEVD.sys` creates `reports/HEVD_report.json`

### 3. **Report Structure**
Each JSON report contains:
```json
{
  "driver_name": "HEVD",
  "generated_at": "2026-05-09T...",
  "total_vulnerabilities": 5,
  "vulnerabilities": [
    {
      "timestamp": "2026-05-09T...",
      "vulnerability_type": "Stack Overflow",
      "access_type": "Write",
      "ioctl": "0x22200f",
      "rip": "0x...",
      "additional_info": {...},
      "address_info": {...}
    }
  ]
}
```

## Usage

### 1. **Running Analysis**
When you run your analysis, the system automatically:
1. Detects the driver being analyzed
2. Extracts the driver filename
3. Initializes the report file at `reports/{driver_name}_report.json`
4. Records vulnerabilities with deduplication

Example command:
```bash
python main.py driver.sys
# Creates: reports/driver_report.json
```

### 2. **Viewing Reports with Web Server**

#### Option A: Start the Report Viewer Server
```bash
python report_viewer_server.py
```
This starts a web server at `http://127.0.0.1:5000`

#### Option B: Custom Host/Port
```bash
python report_viewer_server.py --host 0.0.0.0 --port 8080
```

#### Option C: Debug Mode
```bash
python report_viewer_server.py --debug
```

### 3. **Web Server Features**
- **File Upload Interface**: Upload single JSON reports or entire directories
- **Statistics Dashboard**: Total vulnerabilities, breakdown by type and access type
- **Filters**: Filter by vulnerability type, access type, or search by IOCTL/RIP
- **Detailed View**: Expandable sections for additional information
- **Multi-report Support**: Load and compare multiple reports simultaneously
- **Timestamps**: Each vulnerability is timestamped for tracking
- **Export Ready**: JSON format makes it easy to export and process further

## Installation

### Install Dependencies
```bash
pip install -r requirements.txt
```

## File Structure
```
faliexplorer/
├── main.py
├── utils.py
├── report_viewer_server.py          # Python Flask web server (NEW)
├── report_viewer.html               # Old HTML viewer (deprecated)
├── requirements.txt                  # Updated with Flask
├── REPORT_SETUP.md
├── reports/                          # Auto-created, contains all JSON reports
│   ├── HEVD_report.json
│   ├── Driver1_report.json
│   └── ...
├── templates/                        # Auto-created by server
│   ├── base.html
│   └── index.html
├── static/                           # Auto-created by server
└── [other files]
```

## Modified Files

### `utils.py`
- Added `json` and `datetime` imports
- Added global variables:
  - `current_driver_file`: Tracks the current driver being analyzed
  - `REPORT_DIR`: Points to `reports/` directory
  - `REPORT_FILE`: Dynamically set based on driver name
  - `vulnerabilities_list`: Stores all found vulnerabilities
- Added functions:
  - `set_current_driver(driver_path)`: Initialize report for a new driver
  - `_is_vulnerability_duplicate()`: Check for duplicate vulnerabilities
  - `_serialize_for_json()`: Convert complex objects to JSON-serializable format
  - `_write_json_report()`: Write reports to JSON file in reports directory
- Updated `print_vuln()`: Now checks for duplicates and writes to report

### `main.py`
- Added `utils.set_current_driver(driver)` call at the start of driver analysis
- Ensures report is initialized with correct driver name

### `report_viewer_server.py` (NEW)
- Flask web application with full report viewing capabilities
- RESTful API endpoints for loading and managing reports
- HTML templates with modern UI
- Support for single file and directory uploads
- Real-time filtering and search
- Statistics dashboard

### `requirements.txt`
- Added `flask==2.3.3` dependency

## Important Notes

1. **Reports Directory**: The `reports/` directory is automatically created when the first vulnerability is found
2. **Overwrite Mode**: Each run completely overwrites the report for that driver (previous run's data is lost)
3. **Web Server**: The Flask server automatically creates `templates/` and `static/` directories on first run
4. **Browser Compatibility**: The web interface works best in modern browsers (Chrome, Firefox, Edge, Safari)
5. **Directory Selection**: On Windows/WSL, use the WebKitDirectory attribute to select directories (may need to grant folder access)
6. **JSON Format**: Reports are plain JSON for easy parsing and processing with other tools

## Example Workflow

```bash
# Install dependencies
pip install -r requirements.txt

# Run analysis on first driver
python main.py driver1.sys
# Creates: reports/driver1_report.json

# Run analysis on another driver
python main.py driver2.sys
# Creates: reports/driver2_report.json

# Start the web server
python report_viewer_server.py

# Open browser to http://127.0.0.1:5000
# Upload single reports or load entire reports directory to compare
# Now you can switch between driver1 and driver2 reports using tabs
```

## Troubleshooting

### "Vulnerability report updated: None"
- Make sure `set_current_driver()` is called before `print_vuln()`
- Check that `main.py` has the updated line calling `utils.set_current_driver(driver)`

### Reports not appearing
- Check that the `reports/` directory was created
- Verify that `print_vuln()` is being called during your analysis
- Check console output for any error messages

### Web server won't start
- Make sure Flask is installed: `pip install flask`
- Check that ports 5000 (default) are not in use
- Try different host/port: `python report_viewer_server.py --host 0.0.0.0 --port 8080`

### Templates not found
- The server automatically creates templates on first run
- Make sure you have write permissions in the current directory
- Delete `templates/` and `static/` directories and restart server

### Upload not working
- Check browser console (F12) for JavaScript errors
- Make sure you're using a modern browser
- Try uploading smaller files first
- Check server console for error messages
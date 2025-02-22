# Piranha

## Overview
The **APT Threat Correlation Report Generator** is a cybersecurity tool designed to analyze **MITRE ATT&CK techniques** and correlate them with relevant **Indicators of Compromise (IOCs)**. The tool provides cybersecurity analysts with actionable intelligence by **extracting, filtering, and exporting APT techniques and related data into Excel reports.**

## Features
- **Supports Enterprise, Mobile, and ICS ATT&CK datasets**
- **Correlates APT techniques with relevant IOCs** (registry keys, process injections, network indicators, etc.)
- **Exports reports in Excel format (`.xlsx`)** for easy analysis
- **Provides real-time logging** to track tool execution and errors (`logs/APT_Report.log`)
- **Filters results based on user-selected tactics**
- **GUI interface with dataset and tactic selection options**

## Installation
### Prerequisites
Ensure you have **Python 3.12 or later** installed. The tool also requires the following dependencies:

```sh
pip install pandas openpyxl tkinter
```

### Running the Tool
1. Clone or download the repository.
2. Place the **MITRE ATT&CK JSON datasets** (`enterprise-attack.json`, `mobile-attack.json`, `ics-attack.json`) in the tool's directory.
3. Run the tool:
   ```sh
   python piranha.py
   ```

## Usage
1. **Select the MITRE ATT&CK dataset(s)** you want to analyze.
2. **Choose the APT groups** from the available list.
3. **Select specific tactics** (e.g., Execution, Privilege Escalation, Persistence).
4. **Click "Generate Report"** to process the data.
5. **Export results to an Excel file** for further analysis.

## Logging
All actions and errors are logged in:
```sh
logs/APT_Report.log
```
This helps in debugging and tracking execution history.

## Compiling to `.exe`
To create a standalone executable:
```sh
pyinstaller --onefile --windowed --icon=images/pin.ico --add-data "enterprise-attack.json;." --add-data "mobile-attack.json;." --add-data "ics-attack.json;." pirahna.py
```
This will generate `piranha.exe` in the `dist/` folder.

## Troubleshooting
### **Excel Export Fails in Compiled Version**
- Ensure `openpyxl` is installed (`pip install openpyxl`).
- Compile using `--hidden-import=openpyxl`.

### **No Data is Displayed in the Report**
- Verify that the MITRE JSON files are correctly placed in the same directory as the script.
- Check the `logs/APT_Report.log` file for any errors.

## License
This tool is distributed under the **MIT License**.

## Contributors
- **William Smail** - Lead Developer


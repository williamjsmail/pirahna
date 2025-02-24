PIRANHA - APT Threat Intelligence & IOC Correlation Tool
Overview
PIRANHA is a cyber threat intelligence tool designed to map MITRE ATT&CK techniques used by Advanced Persistent Threats (APTs) to relevant Indicators of Compromise (IOCs). This tool automatically analyzes descriptions of APT tactics and techniques, extracts meaningful keywords, and generates custom threat reports with detection tools and IOCs.

🚀 Features
✅ APT Technique Mapping - Retrieve techniques used by APT groups from MITRE ATT&CK datasets.
✅ APT-Specific Descriptions - Uses APT-specific JSON data for more accurate descriptions.
✅ Keyword-Based IOC Mapping - Maps keywords in descriptions to pre-defined IOCs.
✅ Multi-Dataset Support - Supports Enterprise, Mobile, and ICS ATT&CK datasets.
✅ Dynamic Keyword Management - Add new keywords, IOCs, and detection tools manually.
✅ Export Reports - Generate Excel reports with categorized threat intelligence data.
✅ Fully Scrollable UI - Navigate easily through large datasets with a scrollable interface.

📁 Installation
1. Clone the Repository
bash
Copy
Edit
git clone https://github.com/your-repo/PIRANHA.git
cd PIRANHA
2. Install Dependencies
Ensure you have Python 3.8+ installed, then run:

bash
Copy
Edit
pip install -r requirements.txt
3. Prepare Required Files
Place MITRE ATT&CK JSON files in the files/ directory:
enterprise-attack.json
mobile-attack.json
ics-attack.json
Place APT-specific JSON files inside files/APT/
Place IOC keyword mappings inside files/TCODE_IOC_MAPPING.json
4. Run PIRANHA
bash
Copy
Edit
python piranha.py
📊 How to Use PIRANHA
1️⃣ Select APT Groups - Choose one or more APTs from the list.
2️⃣ Select Tactics - Choose MITRE ATT&CK tactics (e.g., Persistence, Defense Evasion).
3️⃣ Select Dataset(s) - Pick Enterprise, Mobile, or ICS ATT&CK datasets.
4️⃣ Enable/Disable Descriptions - Toggle APT-specific technique descriptions.
5️⃣ Generate Report - Click “Generate Report” to display results.
6️⃣ Export to Excel - Click “Export to Excel” to save the report.

🛠 Managing Keywords & IOCs
Click "Manage Keywords" to add custom keywords and IOCs.
Ensure uniqueness - The tool prevents duplicate keywords.
Edits are persistent - Changes are saved in KEYWORD_IOC_MAPPING.json.

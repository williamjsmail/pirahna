import os
import json
import logging
import pandas as pd
import re
from collections import defaultdict

# Setup logging

log_dir = os.path.join(os.path.expanduser("~"), "Documents", "PiranhaLogs")
try:
    os.makedirs(log_dir, exist_ok=True)
except Exception as e:
    log_dir = os.getcwd()  # Fallback: Use current working directory
    print(f"Warning: Could not create log directory. Using {log_dir}. Error: {e}")
log_file = os.path.join(log_dir, "APT_Report.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_file, mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# Directories
APT_JSON_DIR = os.path.join(os.path.dirname(__file__), "files", "APT")
KEYWORD_IOC_FILE = os.path.join(os.path.dirname(__file__), "files", "KEYWORD_IOC_MAPPING.json")

# Load keyword-to-IOC mappings dynamically
def load_keyword_ioc_mapping():
    if os.path.exists(KEYWORD_IOC_FILE):
        try:
            with open(KEYWORD_IOC_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logging.error(f"JSON Error in {KEYWORD_IOC_FILE}: {e}")
    logging.warning("No valid keyword-to-IOC mapping found. Using empty dictionary.")
    return {}

KEYWORD_IOC_MAPPING = load_keyword_ioc_mapping()

# Load APT-specific JSON (for Enterprise, ICS, and Mobile)
def load_apt_json(apt_name, selected_datasets):
    apt_variants = [apt_name]  # Default: Enterprise dataset
    
    # Append dataset-specific variants (e.g., APT28-ICS, APT28-MOBILE)
    if selected_datasets.get("mobile"):
        apt_variants.append(f"{apt_name}-MOBILE")
    if selected_datasets.get("ics"):
        apt_variants.append(f"{apt_name}-ICS")

    for apt_variant in apt_variants:
        apt_json_file = os.path.join(APT_JSON_DIR, f"{apt_variant}.json")
        
        if os.path.exists(apt_json_file):
            try:
                with open(apt_json_file, "r", encoding="utf-8") as f:
                    logging.info(f"Loaded APT JSON: {apt_variant}.json")
                    return json.load(f)
            except json.JSONDecodeError as e:
                logging.error(f"JSON Error in {apt_json_file}: {e}")
    
    logging.warning(f"No JSON file found for {apt_name} across selected datasets. Using global IOC mapping.")
    return {}

# Load MITRE ATT&CK data
def load_mitre_data(selected_datasets):
    dataset_files = {
        "enterprise": "enterprise-attack.json",
        "mobile": "mobile-attack.json",
        "ics": "ics-attack.json"
    }

    combined_data = {"objects": []}
    dataset_mapping = {}

    for dataset, selected in selected_datasets.items():
        if selected:
            json_path = os.path.join(os.path.dirname(__file__), dataset_files[dataset])
            if os.path.exists(json_path):
                logging.info(f"Loading {dataset_files[dataset]}")
                with open(json_path, "r", encoding="utf-8") as file:
                    data = json.load(file)
                    for obj in data["objects"]:
                        combined_data["objects"].append(obj)
                        if obj["type"] == "attack-pattern" and "external_references" in obj:
                            t_code = obj["external_references"][0]["external_id"]
                            dataset_mapping[t_code] = dataset
            else:
                logging.error(f"{dataset_files[dataset]} not found!")

    return combined_data if combined_data["objects"] else None, dataset_mapping

# Extract APT groups
def get_apt_groups(mitre_data):
    return {obj["name"]: obj["id"] for obj in mitre_data["objects"] if obj["type"] == "intrusion-set"}

# Extract techniques used by an APT
def get_apt_techniques(mitre_data, apt_id):
    return [obj["target_ref"] for obj in mitre_data["objects"] if obj["type"] == "relationship" and obj["relationship_type"] == "uses" and obj["source_ref"] == apt_id]

# Extract relevant tactics and descriptions
def get_tactics_for_apt(mitre_data, apt_techniques, selected_tactics):
    techniques = {tactic: [] for tactic in selected_tactics}
    tcode_descriptions = {}

    for obj in mitre_data["objects"]:
        if obj["type"] == "attack-pattern" and obj["id"] in apt_techniques:
            t_code = obj["external_references"][0]["external_id"]
            description = obj.get("description", "No description available.")

            if "kill_chain_phases" in obj:
                for phase in obj["kill_chain_phases"]:
                    if phase["phase_name"] in selected_tactics:
                        techniques[phase["phase_name"]].append(t_code)
                        tcode_descriptions[t_code] = description

    return techniques, tcode_descriptions

# Enhanced APT Report Generation with Dataset Selection
def get_apt_report(selected_apts, selected_tactics, include_desc, selected_datasets):
    mitre_data, dataset_mapping = load_mitre_data(selected_datasets)
    if not mitre_data:
        return None

    apt_groups = get_apt_groups(mitre_data)
    output_data = []

    logging.info(f"Searching for APTs: {selected_apts}")
    logging.info(f"Filtering by tactics: {selected_tactics}")
    logging.info(f"Include T-Code Descriptions: {include_desc}")

    for apt in selected_apts:
        apt_data = load_apt_json(apt, selected_datasets)
        if not apt_data:
            logging.warning(f"⚠️ No JSON file found for {apt}, skipping.")
            continue

        apt_id = apt_groups.get(apt)
        apt_techniques = get_apt_techniques(mitre_data, apt_id) if apt_id else []
        techniques, tcode_descriptions = get_tactics_for_apt(mitre_data, apt_techniques, selected_tactics)

        if not any(techniques.values()):
            output_data.append([apt, "No Mapped Techniques", "", "Unknown Dataset", "", "", ""])
            continue

        first_row = True
        for category, t_codes in techniques.items():
            for t_code in t_codes:
                dataset_source = dataset_mapping.get(t_code, "Unknown Dataset")

                # **APT-Specific Description**
                tcode_description = next(
                    (t["comment"] for t in apt_data.get("techniques", []) if t["techniqueID"] == t_code),
                    "No description available."
                ) if include_desc else ""

                # **Match IOCs Based on Keywords in Description**
                matched_iocs = []
                matched_tools = []

                for keyword, ioc_data in KEYWORD_IOC_MAPPING.items():
                    if re.search(rf"\b{keyword}\b(?!://)", tcode_description, re.IGNORECASE):
                        
                        if isinstance(ioc_data["ioc"], list):
                            matched_iocs.extend(ioc_data["ioc"])  # Extend with multiple IOCs
                        else:
                            matched_iocs.append(ioc_data["ioc"])  # Add single IOC

                        # 🔹 Ensure tools are also correctly added
                        matched_tools.extend(ioc_data["tools"])

                # **Ensure At Least One IOC Exists**
                ioc_string = ", ".join(matched_iocs) if matched_iocs else "No IOCs Found"
                tool_string = ", ".join(set(matched_tools)) if matched_tools else "Unknown Tool"

                row = [
                    apt if first_row else "",
                    category,
                    t_code,
                    dataset_source,
                    tcode_description,
                    ioc_string,
                    tool_string 
                ]
                first_row = False
                output_data.append(row)

    return output_data


def save_to_excel(output_data, file_path, include_desc):
    if not output_data:
        logging.warning("No data to save!")
        return

    columns = ["APT", "Category", "T-Code", "Dataset Source", "IOC", "Detection Tool"]
    if include_desc:
        columns.insert(4, "T-Code Description")

    expected_columns = len(columns)

   
    corrected_data = []
    for row in output_data:
        if len(row) < expected_columns:
            row.extend([""] * (expected_columns - len(row))) 
        elif len(row) > expected_columns:
            row = row[:expected_columns] 
        corrected_data.append(row)

    try:
        df = pd.DataFrame(corrected_data, columns=columns)
        df.to_excel(file_path, index=False, engine='openpyxl')
        logging.info(f"Report successfully saved to {file_path}")
    except Exception as e:
        logging.error(f"Error saving report: {e}")

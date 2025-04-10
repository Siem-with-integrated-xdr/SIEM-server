import json
import xmltodict
from pathlib import Path

# Path to your XML file
xml_path = Path(__file__).parent / "event.xml"
json_path = Path(__file__).parent / "event_converted.json"

# Read and convert
with open(xml_path, "r", encoding="utf-8") as f:
    xml_content = f.read()

# Parse to dict
json_data = xmltodict.parse(xml_content)

# Optional: add a log_type wrapper if you'd like
data_to_save = {
    "log_type": "event",
    "payload": json_data
}

# Write to JSON file
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(data_to_save, f, indent=2)

print(f"Saved converted JSON to {json_path}")

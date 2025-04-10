import json
import xmltodict
from kafka import KafkaProducer
from pathlib import Path

# Path to the XML file relative to this script's directory
script_dir = Path(__file__).resolve().parent
file_path = script_dir /  "event.xml"

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

def infer_log_type(filepath: str, xml_data: dict):
    # First try filename
    name = Path(filepath).stem.lower()
    if "event" in name:
        return "event", None
    elif "network" in name:
        return "network", None
    elif "ethernet" in name:
        # Optionally check content too
        subtype = xml_data.get("ethernet_packet", {}).get("type")
        return "ethernet", subtype or "generic"
    return "unknown", None

def send_xml_file(filepath: str, topic: str):
    raw_xml = Path(filepath).read_text()
    parsed_xml = xmltodict.parse(raw_xml)
    
    log_type, subtype = infer_log_type(filepath, parsed_xml)
    
    wrapped = {
        "log_type": log_type,
        "subtype": subtype,
        "timestamp": None,  # optionally extract this
        "source": "XDR-agent-1",  # or dynamically from machine
        "payload": parsed_xml
    }

    producer.send(topic, value=wrapped)
    
    producer.flush()
    print(f"Sent {filepath} to topic '{topic}' with log_type='{log_type}'")

# Example usage
send_xml_file(file_path, "siem-logs")

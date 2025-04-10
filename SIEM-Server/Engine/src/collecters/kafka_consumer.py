# Engine/src/collectors/kafka_consumer.py
import json
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch

# Connect to Elasticsearch
es = Elasticsearch("http://localhost:9200")

# Connect to Kafka
consumer = KafkaConsumer(
    'siem-logs',
    bootstrap_servers='localhost:9092',
    auto_offset_reset='earliest',
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)
def flatten_event_data(event: dict) -> dict:
    """
    Flatten 'EventData.Data' array into a dictionary for easy querying.
    Result goes into a new key called 'EventDataFlat'.
    """
    try:
        data_entries = event["payload"]["Event"].get("EventData", {}).get("Data", [])
        
        # Ensure it's a list even if there's only one item
        if isinstance(data_entries, dict):
            data_entries = [data_entries]

        flat_data = {
            entry["@Name"]: entry.get("#text", "") for entry in data_entries if "@Name" in entry
        }

        event["payload"]["Event"]["EventDataFlat"] = flat_data
        return event

    except Exception as e:
        print(f"[!] Failed to flatten EventData: {e}")
        return event


def store_to_elasticsearch(doc: dict, index_name: str = "siem-logs"):
    flat_doc = flatten_event_data(doc)
    es.index(index=index_name, document=flat_doc)

# Consume messages
for message in consumer:
    document = message.value
    
    # Step 1: Flatten EventData
    if document.get("log_type") == "event":
        document = flatten_event_data(document)

    # Step 2: Sanitize + Store
    store_to_elasticsearch(document)

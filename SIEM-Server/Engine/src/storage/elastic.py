from elasticsearch import Elasticsearch

es = Elasticsearch("http://localhost:9200")

res = es.search(index="siem-logs", size=5)
for hit in res["hits"]["hits"]:
    print(hit["_source"])

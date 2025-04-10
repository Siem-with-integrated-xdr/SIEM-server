This is the SIEM's engine, the dirctory structure is as follow:

```
   src-
      |-Collecters : Holds the kafka's consumer, and any log parsers/log normalizers
      |
      |-Analysis- : Monitoring of the logs/ static and logical rule sets
      |          |
      |          |- rules -
      |                   |- process- : logic rules for process, will add .py files and inside it is a function with the rule
      |                             |-<rule>.py
      |                             |- __init__.py: a module of all the logic rules
      |          |-correlation.py : the data correlation engine
      |          |-rule_engine.py : the main logic of log monitoring runs through here, it check all the rules for each log
      |
      |-Config- :configations of the whole siem
      |       |-config.py : non sensitve configation to be checked from the rules
      |-storage- : elasticsearch initilzation
      |
      |api : api for the front end to connect to
```

**TO BE DONE**
 - complete at least %80 of the correlation and rule engine
 - design the elasticsearch indices

*then*
- write the api
- measure the throughput and efficency, and opmitimze where needed to match the throughput of the logs incoming from agents


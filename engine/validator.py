import yaml, json, jsonschema

with open('config.yaml', 'r') as configs:
    configurations = yaml.safe_load(configs) 
class Validator:
    def __init__(self):
        self.rules_path = configurations['rules']['attack']

    def validate_rules(self) -> bool:
        with open(self.rules_path) as f:
           schema = json.load(f)

        for line in schema :
            with open(line) as f:
                rule = yaml.safe_load(f)
                jsonschema.validate(rule, schema)
                print('Règle valide.')

from datetime import datetime

omit_parameters = [
    'detect_protocol',
    'authenticate',
    'bypass_cache'
]

class ProxyGroup:
    # Here _condition could be ('name', '<NAME OF THE CONDITION GROUP>' or ('expression', '<CONDITION EXPRESSION>')
    def __init__(self, _line_number, _name, _rules, _condition=None):
        self.line_number = _line_number
        self.name = _name
        self.rules = _rules
        self.condition = _condition

    def __str__(self):
        nl = '\n\t'
        rules = nl.join(map(str, self.rules))
        return f'{self.line_number} Proxy rule group {self.name} {" with condition named " + self.condition if self.condition else ""}{nl}{rules}'

    def add_rule(self, _line_number, rule):
        self.rules.append(rule)

class ConditionGroupUnparsed:
    def __init__(self, _line_number, _name, _parts, _condition=None):
        self.line_number = _line_number
        self.name = _name
        self.parts = _parts
        self.condition = _condition


class ConditionUnparsed:
    def __init__(self, _line_number, _parameters, _condition=None):
        self.line_number = _line_number
        self.parameters = _parameters
        self.condition = _condition

class Rule:
    def __init__(self, _line_number, _type, _parameters, _comment, _condition=None):
        self.line_number = _line_number
        self.type = _type
        self.parameters = dict(list(filter(lambda x: x[0] not in omit_parameters, _parameters)))
        self.comment = _comment
        self.condition = _condition

    def __str__(self):
        condition_string = f'{"condition = " + self.condition if self.condition else ""}'
        comment_string = f'{" // " + self.comment if self.comment else ""}'
        return f'{self.line_number} Proxy rule {condition_string}{self.parameters}{comment_string}'

    def get_parameter(self, _parameter_name):
        return self.parameters.get(_parameter_name)

    # Rule is expired if last date in range is less than current date
    def is_expired(self):
        if date := self.get_parameter('date'):
            (_, until) = date
            now = datetime.now()
            now_string = f'{now.year}{now.month:02}{now.day:02}'
            now_integer = int(now_string)
            return until < now_integer
        else:
            False

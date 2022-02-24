from datetime import datetime
from typing import Tuple, Type, List

omit_parameters = [
    'detect_protocol',
    'authenticate',
    'bypass_cache',
    'limit_bandwidth.server.inbound',
    'server.certificate.validate',
]


def user_mapper(username):
    slash_position = username.find('\\')
    return username[slash_position + 1:]


parameter_mappers = {
    'user': user_mapper,
}


def url_port_applier(port_numbers, destinations):
    result = {}
    for port in port_numbers:
        for parameter_name, value_list in destinations.items():
            new_values = []
            for value in value_list:
                new_value = f'{value}:{port}'
                new_values.append(new_value)
            result[parameter_name] = result.get(
                parameter_name, []) + new_values

    return result


rule_mapper = {
    'url.port': (['url.address', 'url.domain'], url_port_applier)
}


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

    def is_empty(self):
        return not bool(self.rules)

    def combine_similar(self):
        if len(self.rules) < 2:
            return

        input_rules: List[Rule] = self.rules
        ouput_rules = []

        while len(input_rules) > 0:
            a = input_rules[0]
            tail = list(enumerate(input_rules[1:]))

            new_rule = a
            indexes_to_remove = []
            for (n, b) in tail:
                if a.type == b.type:
                    a_parameter_names = a.parameters.keys()
                    b_parameter_names = b.parameters.keys()
                    common_parameters = a_parameter_names & b_parameter_names
                    have_uncommon_parameters = not (
                        a_parameter_names == common_parameters and b_parameter_names == common_parameters)

                    common_parameters.discard('client.address')

                    all_destination_parameters_are_equal = all(
                        [set(a.get_parameter(p)) == set(b.get_parameter(p)) for p in common_parameters])

                    if (a.is_same_source(b)
                            or (not have_uncommon_parameters and all_destination_parameters_are_equal)):
                        new_rule = new_rule + (a + b)
                        indexes_to_remove.append(n + 1)

            ouput_rules.append(new_rule)

            for index in reversed(indexes_to_remove):
                del input_rules[index]

            del input_rules[0]

        self.rules = ouput_rules


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
        _parameters = dict(_parameters)
        _parameters = dict(
            [(k, v) for k, v in _parameters.items() if k not in omit_parameters])

        mapped_parameters = {}
        for k, v in _parameters.items():
            if f := parameter_mappers.get(k):
                mapped_parameters[k] = list(map(f, v))
            else:
                mapped_parameters[k] = v

        _parameters = mapped_parameters

        for parameter_name, (target_list, f) in rule_mapper.items():
            if parameter_values := _parameters.get(parameter_name):
                parameters_in = dict(
                    [(k, v) for k, v in _parameters.items() if k in target_list])
                parameters_out = f(parameter_values, parameters_in)
                for k, v in parameters_out.items():
                    _parameters[k] = v
                del _parameters[parameter_name]

        self.line_number = _line_number
        self.type = _type
        self.parameters = _parameters
        self.comment = _comment
        self.condition = _condition

    def __str__(self):
        condition_string = f'{"condition = " + self.condition if self.condition else ""}'
        comment_string = f'{" // " + self.comment if self.comment else ""}'
        return f'{sorted(self.line_number)} Proxy rule {condition_string}{self.parameters}{comment_string}'

    def __add__(self, other):
        return self.combine(other)

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

    def combine(self, other: 'Rule'):
        line_number = self.line_number | other.line_number
        type = self.type
        comment = f'{self.comment} {other.comment}'
        condition = self.condition
        parameters = {}
        left_parameter_names = self.parameters.keys()
        right_parameter_names = other.parameters.keys()
        shared_parameters = left_parameter_names & right_parameter_names
        for name in shared_parameters:
            parameters[name] = list(set(
                self.parameters[name] + other.parameters[name]))

        unshared_parameters = (left_parameter_names - right_parameter_names) | (
            right_parameter_names - left_parameter_names)

        for name in unshared_parameters:
            parameters[name] = (self.parameters.get(
                name) or other.parameters.get(name))

        return Rule(line_number, type, parameters.items(), comment, condition)

    def is_same_source(self, other: 'Rule'):
        if a_source := self.get_parameter('client.address'):
            if b_source := other.get_parameter('client.address'):
                return set(a_source) == set(b_source)
        else:
            if a_source := self.get_parameter('user'):
                if b_source := other.get_parameter('user'):
                    return set(a_source) == set(b_source)

        return False

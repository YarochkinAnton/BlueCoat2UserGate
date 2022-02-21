import enum
import re
import sys
import parsec as p
import parsers


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


def parse_proxy_group_header(_line_number, line):
    parse_result = p.parse(
        parsers.proxy_group_header_parser(_line_number), line, 0)
    return dict((('line_number', _line_number), *parse_result))


class Rule:
    def __init__(self, _line_number, _type, _parameters, _condition=None):
        self.line_number = _line_number
        self.type = _type
        self.parameters = _parameters
        self.condition = _condition

    def __str__(self):
        parameters = ', '.join(
            map(lambda x: f'{x[0]} = {x[1]}', self.parameters))
        return f'{self.line_number} Proxy rule {"condition = " + self.condition if self.condition else ""}{parameters}'


def parse_rule(_line_number, _line):
    parsed_rule = p.parse(rule_parser(), _line, 0)
    return dict(parsed_rule)


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


class ParserState(enum.Enum):
    Init = enum.auto()
    ProxyGroup = enum.auto()
    ConditionGroup = enum.auto()


class LineType(enum.Enum):
    IDGAF = enum.auto()
    Empty = enum.auto()
    ProxyHeader = enum.auto()
    Comment = enum.auto()
    ConditionHeader = enum.auto()
    End = enum.auto()


rule_type_regex = r'(ALLOW|DENY|FORCE_DENY)'


def line_type(line):
    if re.match(r'^<P(roxy|ROXY)', line):
        return LineType.ProxyHeader
    elif re.match(r'^\s*\n?$', line):
        return LineType.Empty
    elif re.match(r'^\s*;', line):
        return LineType.Comment
    elif re.match(r'^define( | [\w.]* )condition', line):
        return LineType.ConditionHeader
    elif re.match(r'^end', line):
        return LineType.End
    else:
        return LineType.IDGAF


def parse_rule_group_name(line):
    name_begin_pos = line.find('"')
    name_end_pos = line.find('"', name_begin_pos + 1)
    return line[name_begin_pos + 1:name_end_pos]


def word_parser():
    # Can have brackets, upward slashes and spaces if enclosed inside quotes
    return p.regex(r'([\w\/\(\)\\\-]+|"[\w\/\(\)\s\\\-]+")')


def regex_parser():
    return p.regex(r'[\w\.]+\.regex') + (p.string('=') >> p.regex(r'"[\w\d\.\$\\\+]+"'))


def key_name_parser():
    return p.regex(r'[\w\.\-_]+')


def value_parser():
    return p.regex(r'([\w\.\-\\/\(\)]+|"[\w\.\-\\/\s\(\)]+")')


def key_value_parser():
    list_value = ip_parser() ^ hostname_parser() ^ word_parser()
    list_separator = p.regex('\s*,\s*')
    values = generic_list_parser(
        list_value, list_separator) ^ list_value ^ ip_range_parser() ^ permission_parser()
    return key_name_parser() + (p.one_of('=') >> values)


def rule_parser():
    parameters = [
        p.desc(parsers.condition_parser(), 'Condition parser failed'),
        p.desc(parsers.date_parameter_parser(), 'Date parser failed'),
        p.desc(parsers.user_parameter_parser(), 'User parser failed'),
        p.desc(parsers.category_parameter_parser(), 'Category parser failed'),
        parsers.client_address_parameter_parser(),
        parsers.client_host_parameter_parser(),
        parsers.url_domain_parameter_parser(),
        parsers.url_address_parameter_parser(),
        parsers.proxy_port_parameter_parser(),
        parsers.setting_parser(),
    ]
    parameters2 = [
        parsers.setting_parser(),
        parsers.proxy_port_parameter_parser()
    ]
    parameters_parser = p.parsecmap(p.sepBy1(
        parsers.try_parser(parameters), p.many1(p.spaces())), lambda x: ('parameters', x))
    result = p.spaces() >> (parsers.rule_type_parser() +
                            (p.spaces() >> parameters_parser))
    return result
    '''
parameter = condition_parser() ^ date_range_parser(
) ^ user_parser() ^ key_value_parser() ^ setting_parser()
parameters = p.parsecmap(
    p.sepBy1(parameter, p.spaces()), lambda x: ('parameters', x))
return p.parsecmap(p.spaces() >> (rule_type_parser() + (p.spaces() >> parameters) ^ rule_type_parser()), lambda x: (*x[0], *x[1:]))
    '''


def parse_condition_group_name(line):
    name_begin_pos = line.rfind(' ')
    return line[name_begin_pos + 1:-1]


def clear_comments(line):
    pos = line.rfind(';')
    return line[:pos]


if __name__ == '__main__':
    filename = sys.argv[1]

    input_file = open(filename, encoding='utf-8')

    fw_objects = []

    parser_state = ParserState.Init

    for (number, line) in enumerate(input_file.readlines(), start=1):
        line = clear_comments(line)
        type_of_line = line_type(line)

        if type_of_line == LineType.Comment:
            continue
        elif type_of_line == LineType.Empty:
            continue
        elif type_of_line == LineType.ProxyHeader:
            parsed_header = parse_proxy_group_header(number, line)
            fw_objects.append(ProxyGroup(
                number, parsed_header['name'], [], parsed_header.get('condition')))
            parser_state = ParserState.ProxyGroup
            continue
        elif type_of_line == LineType.ConditionHeader:
            parser_state = ParserState.Init
            continue
        elif type_of_line == LineType.IDGAF:
            if parser_state == ParserState.ProxyGroup:
                parsed_rule = None
                try:
                    parsed_rule = parse_rule(number, line)
                except:
                    print("Stopped at", number)
                    exit(1)
                rule = Rule(number, parsed_rule['type'], parsed_rule['parameters'] if parsed_rule.get(
                    'parameters') else [], parsed_rule.get('condition'))
                # print(rule)
                fw_objects[-1].add_rule(number, rule)

    for fw_obj in fw_objects:
        print(fw_obj)

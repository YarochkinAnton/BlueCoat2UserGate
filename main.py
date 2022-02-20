import enum
import re
import sys
import parsec as p

class ProxyGroup:
    # Here _condition could be ('name', '<NAME OF THE CONDITION GROUP>' or ('expression', '<CONDITION EXPRESSION>')
    def __init__(self, _line_number, _name, _rules, _condition = None):
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
    parse_result = p.parse(proxy_group_header_parser(_line_number), line, 0)
    return dict((('line_number', _line_number), *parse_result))
    
def proxy_group_header_parser(_line_number):
    # <Proxy>
    # <Proxy "FUBAR">
    # <Proxy "FUBAR"> condition=MY.CONDITION
    tag_regex = r'<P(roxy|ROXY)'
    # Any letter, dash, upward slash, downward slash, space
    name_regex = r'"[\w_\-\/\\\s]+"'
    condition_regex = r'condition=[\w\.]+'
    unnamed = p.result(p.regex(tag_regex) << p.string('>'), (('name', f'PROXY_GROUP_AT_{_line_number}'),))
    named = p.parsecmap(p.regex(tag_regex) >> p.space() >> p.regex(name_regex) << p.string('>'), lambda name: (('name', name),))
    named_with_condition = p.parsecmap(named + (p.space() >> condition_parser()), lambda x: (*x[0], x[1]))
    return named_with_condition ^ named ^ unnamed

class Rule:
    def __init__(self, _line_number, _type, _parameters, _condition = None):
        self.line_number = _line_number
        self.type = _type
        self.parameters = _parameters
        self.condition = _condition

    def __str__(self):
        parameters = ', '.join(map(lambda x: f'{x[0]} = {x[1]}', self.parameters))
        return f'{self.line_number} Proxy rule {"condition = " + self.condition if self.condition else ""}{parameters}'

def parse_rule(_line_number, _line):
    parsed_rule = p.parse(rule_parser(), _line, 0)
    return dict(parsed_rule)

class ConditionGroupUnparsed:
    def __init__(self, _line_number, _name, _parts, _condtion = None):
        self.line_number = _line_number
        self.name = _name
        self.parts = _parts
        self.condition = _condition

class ConditionUnparsed:
    def __init__(self, _line_number, _parameters, _condition = None):
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

def hostname_parser():
    # Can have any letter, dots and dashes
    return p.regex(r'[\w\.\-\d]+')

def ip_parser():
    # Can have subnet mask in short form at the end consisting of one ore two digits
    return p.regex(r'\d+\.\d+\.\d+\.\d+(\/\d\d?)?')

def ip_range_parser():
    # Ip addresses separated by dash
    return p.parsecmap(p.string('"') >> ip_parser() + (p.string('-') >> ip_parser() << p.string('"')), lambda ip_pair: ('range', *ip_pair))

def word_parser():
    # Can have brackets, upward slashes and spaces if enclosed inside quotes
    return p.regex(r'([\w\/\(\)\\\-]+|"[\w\/\(\)\s\\\-]+")')

def condition_name_parser():
    return p.regex(r'[\w\.\d]+')

def condition_parser():
    return p.string('condition') + (p.string('=') >> ((p.result(p.string('!'), 'not') + condition_name_parser()) ^ condition_name_parser()))

def regex_parser():
    return p.regex(r'[\w\.]+\.regex') + (p.string('=') >> p.regex(r'"[\w\d\.\$\\\+]+"'))

def generic_list_parser(_value_parser, _separator_parser):
    return p.string('(') >> p.spaces() >> p.sepBy1(_value_parser, _separator_parser) << p.spaces() << p.string(')')

def key_name_parser():
    return p.regex(r'[\w\.\-_]+')

def value_parser():
    return p.regex(r'([\w\.\-\\/\(\)]+|"[\w\.\-\\/\s\(\)]+")')

def key_value_parser():
    list_value = ip_parser() ^ hostname_parser() ^ word_parser() 
    list_separator = p.regex('\s*,\s*')
    values = generic_list_parser(list_value, list_separator) ^ list_value ^ ip_range_parser() ^ permission_parser()
    return key_name_parser() + (p.one_of('=') >> values)

def setting_parser():
    name = p.regex(r'[\w_]+')
    value = p.string('yes') ^ p.string('none') ^ p.string('no') ^ p.regex(r'"[\w\d\-\.]+"')
    return name + (p.one_of('(') >> value << p.one_of(')'))

def date_range_parser():
    return p.string('date') + (p.string('=') >> p.regex(r'\d\d\d\d\d\d\d\d\.\.\d\d\d\d\d\d\d\d'))

def username_parser():
    name_regex = r'\w\\'
    return p.regex(r'([' + name_regex + ']+|"[' + name_regex + ']")')

def user_parser():
    return p.string('user') + (p.string('=') >> (generic_list_parser(username_parser(), p.regex(r',\s*')) ^ username_parser()))

def permission_parser():
    permission = p.regex(r'(READ|WRITE)')
    separator = p.string('||')
    return generic_list_parser(permission, separator)

def rule_type_parser():
    return p.parsecmap(p.regex(rule_type_regex), lambda x: (('type', x),))

def rule_parser():
    parameter = condition_parser() ^ date_range_parser() ^ user_parser() ^ key_value_parser() ^ setting_parser()
    parameters = p.parsecmap(p.sepBy1(parameter, p.spaces()), lambda x: ('parameters', x))
    return p.parsecmap(p.spaces() >> (rule_type_parser() + (p.spaces() >> parameters) ^ rule_type_parser()), lambda x: (*x[0], *x[1:])) 

def parse_condition_group_name(line):
    name_begin_pos = line.rfind(' ')
    return line[name_begin_pos + 1:-1]

def clear_comments(line):
    pos = line.rfind(';')
    return line[:pos]

filename = sys.argv[1]

input_file = open(filename)

fw_objects = []

parser_state = ParserState.Init

for (number, line) in enumerate(input_file.readlines(), start=1):
    line = clear_comments(line)
    type_of_line = line_type(line)
    print(number, type_of_line,)

    if type_of_line == LineType.Comment:
        continue
    elif type_of_line == LineType.Empty:
        continue
    elif type_of_line == LineType.ProxyHeader:
        parsed_header = parse_proxy_group_header(number, line)
        fw_objects.append(ProxyGroup(number, parsed_header['name'], [], parsed_header.get('condition')))
        parser_state = ParserState.ProxyGroup
        continue
    elif type_of_line == LineType.ConditionHeader:
        parser_state = ParserState.Init
        continue
    elif type_of_line == LineType.IDGAF:
        if parser_state == ParserState.ProxyGroup:
            parsed_rule = parse_rule(number, line)
            print(parsed_rule)
            rule = Rule(number, parsed_rule['type'], parsed_rule['parameters'] if parsed_rule.get('parameters') else [], parsed_rule.get('condition'))
            print(rule)
            fw_objects[-1].add_rule(number, rule)

'''
    print(number, type_of_line, end=" ")
    
    if type_of_line == LineType.idgaf:
        print(bytes(line, 'utf-8'))
    elif type_of_line == LineType.ProxyHeader:
        name = parse_rule_group_name(line)
        print("Группа правил под названием", name)
    elif type_of_line == LineType.BeginCondition:
        name = parse_condition_group_name(line)
        print("Группа условий под названием", name)
    elif type_of_line == LineType.ProxyRule:
        print(parsec.parse(rule_parser(), line, 0))
    elif type_of_line == LineType.ConditionRule:
        parameters = regex_parser() ^ condition_parser() ^ key_value_parser() ^ setting_parser()
        pcondition = parsec.regex(r'\s+') >> parsec.sepBy1(parameters, parsec.space())
        print(parsec.parse(pcondition, line, 0))
    else:
        print('')
        '''

for fw_obj in fw_objects:
    print(fw_obj)

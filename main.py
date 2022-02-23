import enum
import re
import sys
import parsec as p
import parsers
import bluecoat
import filters
import anal
import extract


def parse_proxy_group_header(_line_number, line):
    parse_result = p.parse(
        parsers.proxy_group_header_parser(_line_number), line, 0)
    return dict((('line_number', _line_number), *parse_result))


def parse_rule(_line_number, _line):
    parsed_rule = p.parse(rule_parser(), _line, 0)
    return dict(parsed_rule)


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


def rule_parser():
    parameters = [
        p.desc(parsers.condition_parser(), 'Condition parser failed'),
        p.desc(parsers.date_parameter_parser(), 'Date parser failed'),
        p.desc(parsers.user_parameter_parser(), 'User parser failed'),
        parsers.category_parameter_parser(),
        parsers.client_address_parameter_parser(),
        parsers.client_host_parameter_parser(),
        parsers.url_domain_parameter_parser(),
        parsers.url_address_parameter_parser(),
        parsers.proxy_port_parameter_parser(),
        parsers.setting_parser(),
        parsers.url_extension_parameter_parser(),
    ]
    parameters_parser = p.parsecmap(p.sepBy1(
        parsers.try_parser(parameters), p.spaces()), lambda x: ('parameters', x))
    result = p.spaces() >> (parsers.rule_type_parser() +
                            (p.spaces() >> parameters_parser << p.regex('$')))
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


def extract_comment(line):
    pos = line.find(';')
    result = ("",)
    if pos == -1:
        result = (line, "")
    else:
        result = (line[:pos], filter_newline(line[pos + 1:]))

    result = (result[0].rstrip(), result[1])
    return result


def filter_newline(line):
    return line[:-1]


if __name__ == '__main__':
    filename = sys.argv[1]

    # server or user
    # For different aggregation naming logic
    rule_category = sys.argv[2]

    input_file = open(filename, encoding='utf-8')

    fw_objects = []

    parser_state = parsers.ParserState.Init

    for (number, line) in enumerate(input_file.readlines(), start=1):
        # try:
        (line, comment) = extract_comment(line)
        type_of_line = line_type(line)

        if type_of_line == LineType.Comment:
            continue
        elif type_of_line == LineType.Empty:
            continue
        elif type_of_line == LineType.ProxyHeader:
            parsed_header = parse_proxy_group_header(number, line)
            fw_objects.append(bluecoat.ProxyGroup(
                number, parsed_header['name'], [], parsed_header.get('condition')))
            parser_state = parsers.ParserState.ProxyGroup
            continue
        elif type_of_line == LineType.ConditionHeader:
            parser_state = parsers.ParserState.Init
            continue
        elif type_of_line == LineType.IDGAF:
            if parser_state == parsers.ParserState.ProxyGroup:
                parsed_rule = None
                parsed_rule = parse_rule(number, line)
                rule = bluecoat.Rule(number, parsed_rule['type'], parsed_rule['parameters'] if parsed_rule.get(
                    'parameters') else [], comment, parsed_rule.get('condition'))
                # print(rule)
                fw_objects[-1].add_rule(number, rule)
        # except Exception as e:
        # print(e)
        # print("Stopped at", number)
        # exit(1)

    initial_count = sum([len(group.rules) for group in fw_objects])
    attribute_set = anal.get_parameter_set(fw_objects)

    (fw_objects, filtered_out_lines) = filters.filter_rules(
        fw_objects, rule_category)

    fw_objects = filters.filter_groups(fw_objects, rule_category)

    count_after_filtering = sum(
        [len(group.rules) for group in fw_objects])
    for fw_obj in fw_objects:
        print(fw_obj)
        fw_obj.combine_similar()
        print(fw_obj)

    count_after_reduction = sum([len(group.rules) for group in fw_objects])

    print("Filtered out", filtered_out_lines)
    print("Initial: ", initial_count)
    print("After filtering: ", count_after_filtering)
    print("After reduction: ", count_after_reduction)
    print("Initial attribute set: ", attribute_set)
    attribute_set = anal.get_parameter_set(fw_objects)
    print("Filtered attribute set: ", attribute_set)
    print("Users: ", set(extract.collect_parameter_all(fw_objects, 'user')))

    extract.extractors[rule_category](fw_objects)

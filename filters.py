import bluecoat
import sys
from datetime import datetime

# Returns filtered object as first element of the tuple, and list of line numbers as second
# Containing line numbers of filtered out rules


def filter_rules(_fw_objects, _type):
    filtered_out = []
    if filters := rule_filter_map[_type]:
        for object in _fw_objects:
            filtered_rules = []
            for rule in object.rules:
                # If every filter is returned True meaning everything is OK
                if all([f(rule) for f in filters]):
                    filtered_rules.append(rule)
                else:
                    filtered_out.append(rule.line_number)
            object.rules = filtered_rules
        return (_fw_objects, filtered_out)
    else:
        sys.exit("Uknown rule category")


def filter_groups(_fw_objects, _type):
    return list(filter(lambda obj: all([f(obj)
                                        for f in group_filter_map[_type]]), _fw_objects))


# Common filters
# For each filtered out rule we need to return line number from source file


# We need to filter rules with conditions
# Return False if condition parameter is present
def condition_filter(_rule):
    return _rule.get_parameter('condition') == None

# Return True if rule is not expired


def date_filter(_rule):
    return not _rule.is_expired()


def category_filter(_rule):
    return _rule.get_parameter('category') == None


def empty_group_filter(_group):
    return not _group.is_empty()


def proxy_filter(_rule):
    return _rule.get_parameter('proxy.port') == None


def url_extension_filter(_rule):
    return _rule.get_parameter('url.extension') == None


def proxy_port_filter(_rule):
    return _rule.get_parameter('proxy.port') == None


common_rule_filters = [
    condition_filter,
    date_filter,
    category_filter,
    url_extension_filter,
    proxy_port_filter,
]

server_rule_filters = [

] + common_rule_filters

user_rule_filters = [

] + common_rule_filters

rule_filter_map = {
    'server': server_rule_filters,
    'user': user_rule_filters,
}

common_group_rules = [

]

server_group_rules = [
    empty_group_filter,
] + common_group_rules

user_group_rules = [

] + common_group_rules

group_filter_map = {
    'server': server_group_rules,
    'user': user_group_rules
}

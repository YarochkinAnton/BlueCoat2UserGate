from tkinter.ttk import Separator
import parsec as p


def generic_list_parser(_value_parser, _separator_parser):
    # Lists in BlueCoat enclosed in brackets
    # between brackets and list values and between values themselves can be zero or more spaces
    result = (p.string('(') >> p.spaces()
              >> p.sepBy1(_value_parser, _separator_parser)
              << p.spaces() << p.string(')'))
    return result


def maybe_list_parser(_value_parser):
    separator = p.spaces() + p.string(',') + p.spaces()
    result = (generic_list_parser(_value_parser, separator) ^ _value_parser)
    return result


def generic_parameter_parser(_parameter_name_parser, _value_parser):
    # Parses parameter with by name and one or more values
    result = (_parameter_name_parser
              + (p.string('=') >> maybe_list_parser(_value_parser)))
    return result


def hostname_parser():
    # Can have any letter, dots, dashes and digits
    return p.regex(r'[\w\.\-\d]+')


def ip_parser():
    # Can have subnet mask in short form at the end consisting of one ore two digits
    # x.x.x.x or x.x.x.x/y or x.x.x.x/yy
    return p.regex(r'\d+\.\d+\.\d+\.\d+(\/\d\d?)?')


def ip_range_parser():
    # Ip addresses separated by dash
    # "a.a.a.a-b.b.b.b"
    # Returns ("range", (IP, IP))
    data_parser = (p.string('"')
                   >> ip_parser() + (p.string('-') >> ip_parser()
                                     << p.string('"')))
    result = p.parsecmap(data_parser, lambda ip_pair: ('range', ip_pair))
    return result


def date_range_parser():
    # Date ranges look like this
    # yyyymmdd..yyyymmdd
    result = p.regex(r'\d\d\d\d\d\d\d\d\.\.\d\d\d\d\d\d\d\d')
    return result


def date_parameter_parser():
    result = generic_parameter_parser(p.string('date'), date_range_parser())
    return result


def setting_parser():
    # Settings look like this
    # setting_name1(yes)
    # setting_name2(no)
    # setting_name3(none)
    name = p.regex(r'[\w_]+')
    value = p.string('yes') ^ p.string('none') ^ p.string(
        'no') ^ p.regex(r'"[\w\d\-\.]+"')
    return name + (p.string('(') >> value << p.string(')'))


rule_type_regex = r'(ALLOW|DENY|FORCE_DENY)'


def rule_type_parser():
    # Rules for proxy groups can begin with:
    # ALLOW
    # DENY
    # FORCE_DENY
    # Returns eg ('type', 'ALLOW')
    return p.parsecmap(p.regex(rule_type_regex), lambda x: ('type', x))


def quoted_parser(_value_parser):
    quote = p.string('"')
    result = quote >> _value_parser << quote
    return result


def maybe_quoted_parser(_value_parser):
    result = quoted_parser(_value_parser) ^ _value_parser
    return result


def username_parser():
    # Usernames come in forms:
    # DOMAIN\USER
    # "DOMAIN\USER"
    # Names can contain letters, digits, underscores
    name_regex = r'\w+\\[\w\d_]+'
    result = maybe_quoted_parser(p.regex(name_regex))
    return result


def port_parser():
    result = p.many1(p.digit())
    return result


def user_parameter_parser():
    # Including lists of users
    result = generic_parameter_parser(p.string('user'), username_parser())
    return result


def category_name_parser():
    # Examples
    # "Technology/Internet"
    # "Search Engines/Portals"
    # "Mixed Content/Potentialy Adult"
    category_name = p.regex(r'[\w\s]+/[\w\s]+')
    result = quoted_parser(category_name)
    return result


def category_parameter_parser():
    result = generic_parameter_parser(
        p.regex(r'\w.category'), category_name_parser())
    return result


def client_address_parameter_parser():
    client_address_value = ip_range_parser() ^ ip_parser()
    result = generic_parameter_parser(
        p.string('client.address'), client_address_value)
    return result


def client_host_parameter_parser():
    result = generic_parameter_parser(
        p.string('client.host'), hostname_parser())
    return result


def url_domain_parameter_parser():
    result = generic_parameter_parser(
        p.string('url.domain'), hostname_parser())
    return result


def url_address_parameter_parser():
    result = generic_parameter_parser(p.string('url.address'), ip_parser())
    return result


def proxy_port_parameter_parser():
    result = generic_parameter_parser(p.string('proxy.port'), port_parser())
    return result


def condition_name_parser():
    return p.regex(r'[\w\.\d]+')


def condition_parser():
    # p.string('condition') + (p.string('=') >> ((p.result(p.string('!'), 'not') + condition_name_parser()) ^ condition_name_parser()))
    mark_parser = p.string('!')
    mark_name = 'not'
    result = (p.string('condition') + (p.string('=')
                                       >> maybe_mark_parser(mark_parser, mark_name, condition_name_parser())))
    return result


def maybe_mark_parser(_mark_parser, _mark_name, _value_parser):
    result = (p.result(_mark_parser, _mark_name) +
              _value_parser) ^ _value_parser
    return result


def permission_parser():
    permission = p.regex(r'(READ|WRITE)')
    separator = p.string('||')
    return generic_list_parser(permission, separator)
    return result


def proxy_group_header_parser(_line_number):
    # <Proxy>
    # <Proxy "FUBAR">
    # <Proxy "FUBAR"> condition=MY.CONDITION
    tag_regex = r'<P(roxy|ROXY)'
    # Any letter, dash, upward slash, downward slash, space
    name_regex = r'"[\w_\-\/\\\s]+"'
    condition_regex = r'condition=[\w\.]+'
    unnamed = p.result(p.regex(tag_regex) << p.string(
        '>'), (('name', f'PROXY_GROUP_AT_{_line_number}'),))
    named = p.parsecmap(p.regex(tag_regex) >> p.space() >> p.regex(
        name_regex) << p.string('>'), lambda name: (('name', name),))
    named_with_condition = p.parsecmap(
        named + (p.space() >> condition_parser()), lambda x: (*x[0], x[1]))
    return named_with_condition ^ named ^ unnamed


def permission_parser():
    permission = p.regex(r'(READ|WRITE)')
    separator = p.string('||')
    return generic_list_parser(permission, separator)


def try_parser(_parser_list):
    # result = _parser_list[0]
    # [result := result ^ _parser for _parser in _parser_list[1:]]
    result = _parser_list[0]
    for x in _parser_list[1:]:
        result = result ^ x
    return result

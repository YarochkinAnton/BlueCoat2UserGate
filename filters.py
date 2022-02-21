import bluecoat
import sys
from datetime import datetime

# Returns filtered object as first element of the tuple, and list of line numbers as second
# Containing line numbers of filtered out rules
def filter_rules(_fw_objects, _type):
	filtered_out = []
	if filters := filter_map[_type]:
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

# Common filters
# For each filtered out rule we need to return line number from source file



# We need to filter rules with conditions
# Return False if condition parameter is present
def condition_filter(_rule):
	return _rule.get_parameter('condition') == None

# Return True if rule is not expired
def date_filter(_rule):
	return not _rule.is_expired()



common_filters = [
	condition_filter,
	date_filter,
]

server_filters = [
	
] + common_filters

user_filters = [

] + common_filters

filter_map = {
	'server': server_filters,
	'user': user_filters,
}
class IPList:
	def __init__(self, _name, _description, _list):
		self.name = _name
		self.description = _description
		self.list = _list

class URLList:
	def __init__(self, _name, _description, _list):
		self.name = _name
		self.description = _description
		self.list = _list

class Rule:
	# id => _id will be calculated depending on number of rules and existing IDs
	# position -> readonly
	# action => _action depends on rule type of BlueCoat source rule
	# enabled -> default to true
	# active -> default to true
	# name => _name for users will be generated from aggregated line numbers of source rules
	# name => _name for servers depends on proxy group header from source rules
	# description => _descriptions will include aggregated comments
	# scenario_rule_id -> default = false
	# src_zones -> default "Trusted" => should fetch UID from system
	# src_zones_negate -> default = false
	# dst_zones -> default "Untrusted" => should fetch UID from system
	# dst_zones_negate -> default = false
	# src_ips (["list_id", ID]) => _source_address_list_id will be linked from list created previously
	# ... we should commit rules only after ip lists and url lists creation
	# src_ips_neage -> default = false
	# dst_ips (["list_id", ID]) => _destination_address_list_id same as src_ips in terms of providing ID value and commitment order
	# users (["user", USER_GUID], ["group", GROUP_ID]) => same as ip lists in terms of proving ID values and commitment order
	# ... except for user GUID
	# TODO: FIND OUT HOW TO GET USER GUID
	# services => should get it from system
	# service_negate -> default = false
	# apps -> default = []
	# log -> default = false
	# limit -> default = false
	# limit_value -> default = 3/h
	# ttl -> readonly
	# time_restrictions -> default = []
	def __init__(self, _id, _action, _name, _description,  _source_address_list_id, _destination_address_list_id, _users, _services):
		x = 42
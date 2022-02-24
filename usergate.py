import api


class IPList:
    def __init__(self, _name, _description, _list):
        self.name = _name
        self.description = _description
        self.list = _list
        self.id = None

    def __str__(self):
        return f'IPList {{ name: {self.name}, description: {self.description}, {self.list} }}'

    def __repr__(self):
        return f'IPList {{ name: {self.name}, description: {self.description}, {self.list} }}'

    def commit(self, client):
        id = client.create_list(self.name, self.description, "network")
        self.id = id
        for item in self.list:
            client.add_list_item(self.id, item)

        print(f'Commited {self.name}')
        return id


class URLList:
    def __init__(self, _name, _description, _list):
        self.name = _name
        self.description = _description
        self.list = _list
        self.id = None

    def __str__(self):
        return f'URLList {{ name: {self.name}, description: {self.description}, {self.list} }}'

    def __repr__(self):
        return f'URLList {{ name: {self.name}, description: {self.description}, {self.list} }}'

    def commit(self, client):
        id = client.create_list(self.name, self.description, "url")
        self.id = id
        for item in self.list:
            client.add_list_item(self.id, item)

        print(f'Commited {self.name}')
        return id


class Rule:
    '''
    id	UID<Integer>	rule identifier

    position	Integer	readonly rule position in complete rules list, starting with 1

action	String	rule action, allowed values are: accept, drop, warning

name	String	required human readable rule name

public_name	String	human readable rule name (public name)

descripton	String	detailed rule description, could be empty

enabled	Boolean	rule status: enabled/disabled

active	Boolean	readonly contains true if current rule at this moment is matched by time set in time_restrictions

enable_kav_check	Boolean	if true then check content by Kaspersky antivirus

enable_md5_check	Boolean	if true then check content by Cloud Antivirus

enable_custom_redirect	Boolean	if true then custom_redirect field should be used instead of internal blocking page

blockpage_template_id	UID<Integer>	identifier of response page template of type "blockpage" that should be used for rendering block page, -1 should be set if you want to use default template

custom_redirect	String	URL that user should be redirected to if rule is triggered

users	List	list of users, each item must be onee of the following types: ["user", USER_GUID], ["group", GROUP_ID], ["special", "known_user"], ["special", "unknown_user"] empty list means "any user"

morph_categories	List<UID>	list of identifiers of morphology categories

url_categories	List<UID>	list of identifiers of URL categories that should be used for matching, each items must be on of the following types: ["list_id", LIST_ID] or ["category_id", CATEGORY_ID]

url_categories_negate	Boolean

dst_ips	List<ExtendedIpAddress>	list of destination ip addresses

dst_ips_negate	Boolean	

src_zones	List<UID>	list of zone identifiers associated with this rule

src_zones_negate	Boolean	

dst_zones	List<UID>	identifiers of destination zone, at least one zone required

dst_zones_negate	Boolean	

src_ips	List<ExtendedIpAddress>	list of source ip addresses

src_ips_negate	Boolean	

content_types	List<UID>	list of content types (named lists of type mime)

content_types_negate	Boolean	

urls	List<UID>	list of identifiers of nlists of type url

urls_negate	Boolean	

time_restrictions	List<UID> list of identifiers of time restrictions, if empty then rules has no time restrictions.

http_methods	List<String>	list of HTTP methods that should be used in matching, it may also contains arbitrary method names, not just standard HTTP ones

user_agents	List	list of user agents, each item must be one of the following types: ["ua", USER_AGENT_STRING], ["list_id", ID], where USER_AGENT_STRING is a literal User-Agent string and ID is a named list identifier that contains User-Agent strings

referers	List<UID>	list of identifiers of nlists of type url

position_layer	String	readonly rule position, possible values are: pre, post, local
    '''
    # +id => _id will be calculated depending on number of rules and existing IDs
    # -position -> readonly
    # +action => _action depends on rule type of BlueCoat source rule
    # +name => _name for users will be generated from aggregated line numbers of source rules
    # +name => _name for servers depends on proxy group header from source rules
    # +public_name => same as name
    # +description => _descriptions will include aggregated comments
    # +enabled -> default to true
    # +active -> default to true
    # +enable_kav_check -> default = false
    # +enable_md5_check -> default = false
    # +enable_custom_redirect -> default = false
    # +blockpage_template_id -> default = -1
    # +custom_redirect -> defaul ''
    # +users (["user", USER_GUID], ["group", GROUP_ID]) => same as ip lists in terms of proving ID values and commitment order
    # ... except for user GUID
    # +morph_categories -> default = []
    # +url_categories -> default = [] WILL CHANGE PROBABLY
    # +url_categories_neage -> defaul = false
    # +dst_ips (["list_id", ID]) => _destination_address_list_id same as src_ips in terms of providing ID value and commitment order
    # +dst_ips_negate -> default = false
    # +src_zones -> default "Trusted" => should fetch UID from system
    # +src_zones_negate -> default = false
    # +dst_zones -> default "Untrusted" => should fetch UID from system
    # +dst_zones_negate -> default = false
    # +src_ips (["list_id", ID]) => _source_address_list_id will be linked from list created previously
    # ... we should commit rules only after ip lists and url lists creation
    # +src_ips_neage -> default = false
    # +content_types -> default = []
    # +content_types_negate -> default = false
    # +urls => will be gathered based on url used in bluecoat rules after aggregation
    # +urls_negate -> default = false
    # +time_restrictions -> default = []
    # +http_methods -> default = []
    # +user_agents -> default = []
    # +referers -> default = []

    def __init__(self, _action, _name, _description, _users, _dst_ip_list_ids, _src_ip_list_ids, _url_list_ids):
        self.action = _action
        self.name = _name
        self.description = _description
        self.users = _users
        self.dst_ip_list_id_list = _dst_ip_list_ids
        self.src_ip_list_id_list = _src_ip_list_ids
        self.url_list_ids = _url_list_ids

    def commit(self, client: api.Client):
        users = [["user", user_id] for user_id in self.users]
        dst_ip_list_ids = [["list_id", dst_ip_list_id]
                           for dst_ip_list_id in self.dst_ip_list_id_list]
        src_ip_list_ids = [["list_id", src_ip_list_id]
                           for src_ip_list_id in self.src_ip_list_id_list]
        dst_url_list_ids = self.url_list_ids

        return client.add_rule(self.action, self.name, self.description,
                               users, dst_ip_list_ids, src_ip_list_ids, dst_url_list_ids)

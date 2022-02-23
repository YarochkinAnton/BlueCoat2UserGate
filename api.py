from random import randint
import uuid
import requests
import xml.etree.ElementTree as ElementTree
import inspect
import misc


headers = {
    'Content-Type': 'text/xml'
}


class Client:
    def __init__(self, _url, _username, _password):
        self.url = _url
        self.username = _username
        self.password = _password
        self.auth_token = None

    def auth(self):
        payload = f'''
        <?xml version="1.0"?>
        <methodCall>
            <methodName>v2.core.login</methodName>
            <params>
                <param>
                    <value><string>{self.username}</string></value>
                </param>
                <param>
                    <value><string>{self.password}</string></value>
                </param>
            </params>
        </methodCall>
        '''
        payload = inspect.cleandoc(payload)
        response = requests.post(self.url, data=payload, headers=headers)
        xml_tree = ElementTree.fromstring(response.content)
        auth_token = xml_tree.findtext(
            './params[1]/param/value/struct/member[name="auth_token"]/value/string')
        self.auth_token = auth_token

    def get_zones(self, authenticate=False):
        if authenticate:
            self.auth()
        data = f'''
        <?xml version="1.0"?>
        <methodCall>
            <methodName>v1.netmanager.zones.list</methodName>
            <params>
                <param>
                    <value><string>{self.auth_token}</string></value>
                </param>
            </params>
        </methodCall>
        '''
        data = inspect.cleandoc(data)
        response = requests.post(self.url, data, headers)
        xml_tree = ElementTree.fromstring(response.content)
        xml_zones = xml_tree.findall('./params/param/value/array/data/value')
        zones = []
        for xml_zone in xml_zones:
            members = {}
            for xml_member in xml_zone.findall('./struct/member'):
                name = xml_member.findtext('./name')
                value = xml_member.findtext('./value/*')
                members[name] = value
            zones.append(members)
            members['id'] = int(members['id'])

        return zones

    # _type => string -> "url", "network"
    def get_named_lists(self, _type, authenticate=False):
        if authenticate:
            self.auth()
        auth_token = self.auth()
        data = f'''
        <?xml version="1.0"?>
        <methodCall>
            <methodName>v2.nlists.list</methodName>
            <params>
                <param>
                    <value><string>{self.auth_token}</string></value>
                </param>
                <param>
                    <value><string>{_type}</string></value>
                </param>
                <param>
                    <value><int>1</int></value>
                </param>
                <param>
                    <value><int>10000</int></value>
                </param>
                <param>
                    <value></value>
                </param>
            </params>
        </methodCall>
        '''
        data = inspect.cleandoc(data)
        response = requests.post(self.url, data, headers)
        xml_tree = ElementTree.fromstring(response.content)
        xml_list_items = xml_tree.findall(
            './params/param/value/struct/member[name="items"]./value/array/data/value')
        lists = []
        for xml_list_item in xml_list_items:
            members = {}
            for xml_member in xml_list_item.findall('./struct/member'):
                name = xml_member.findtext('./name')
                value = xml_member.findtext('./value/*')
                if name == 'id':
                    members[name] = int(value)
                else:
                    members[name] = value
            xml_attributes = xml_list_item.findall(
                './struct/member[name="attributes"]./value/array/data/value')
            for xml_attribute in xml_attributes:
                name = xml_attribute.findtext('./struct/member/name')
                value = xml_attribute.findtext('./struct/member/value/*')
                members['attributes'][name] = value
            lists.append(members)

        return lists

    # _id => string -> list ID
    def get_list_info(self, _id, authenticate=False):
        if authenticate:
            self.auth()
        auth_token = self.auth()
        data = f'''
        <?xml version="1.0"?>
        <methodCall>
            <methodName>v2.nlists.list.list</methodName>
            <params>
                <param>
                    <value><string>{self.auth_token}</string></value>
                </param>
                <param>
                    <value><int>{_id}</int></value>
                </param>
                <param>
                    <value><int>1</int></value>
                </param>
                <param>
                    <value><int>100</int></value>
                </param>
                <param>
                    <value><string></string></value>
                </param>
                <param>
                    <value><array><data></data></array></value>
                </param>
            </params>
        </methodCall>
        '''
        data = inspect.cleandoc(data)
        response = requests.post(self.url, data, headers)
        xml_tree = ElementTree.fromstring(response.content)
        xml_items = xml_tree.findall(
            '.params/param/value/struct/member[name="items"]/./value/array/data/value')
        result = []
        for xml_item in xml_items:
            members = {}
            for xml_member in xml_item.findall('.struct/member'):
                name = xml_member.findtext('./name')
                value = xml_member.findtext('./value/*')
                members[name] = value
            result.append(members)

        return result

    def add_list_item(self, _id, _item, authenticate=False):
        if authenticate:
            self.auth()
        item_id = randint(1, 10000)
        data = f'''
        <?xml version="1.0"?>
        <methodCall>
            <methodName>v2.nlists.list.add</methodName>
            <params>
                <param>
                    <value><string>{self.auth_token}</string></value>
                </param>
                <param>
                    <value><int>{_id}</int></value>
                </param>
                <param>
                    <value>
                        <struct>
                            <member>
                                <name>id</name>
                                <value><int>{item_id}</int></value>
                            </member>
                            <member>
                                <name>value</name>
                                <value><string>{_item}</string></value>
                            </member>
                        </struct>
                    </value>
                </param>
            </params>
        </methodCall>
        '''
        data = inspect.cleandoc(data)
        response = requests.post(self.url, data, headers)
        return response.content

    # Return UID of newly created list
    def create_list(self, _name, _description, _type, authenticate=False):
        if authenticate:
            self.auth()
        list_id = randint(1, 10000)
        list_guid = str(uuid.uuid4())
        data = f'''
        <?xml version="1.0"?>
        <methodCall>
            <methodName>v2.nlists.add</methodName>
            <params>
                <param>
                    <value><string>{self.auth_token}</string></value>
                </param>
                <param>
                    <value>
                        <struct>
                            <member>
                                <name>id</name>
                                <value><int>{list_id}</int></value>
                            </member>
                            <member>
                                <name>guid</name>
                                <value><string>{list_guid}</string></value>
                            </member>
                            <member>
                                <name>type</name>
                                <value><string>{_type}</string></value>
                            </member>
                            <member>
                                <name>name</name>
                                <value><string>{_name}</string></value>
                            </member>
                            <member>
                                <name>description</name>
                                <value><string>{_description}</string></value>
                            </member>
                            <member>
                                <name>url</name>
                                <value><string></string></value>
                            </member>
                            <member>
                                <name>attributes</name>
                                <value>
                                    <struct>
                                        <member>
                                            <name>threat_level</name>
                                            <value><int>1</int></value>
                                        </member>
                                    </struct>
                                </value>
                            </member>
                        </struct>
                    </value>
                </param>
            </params>
        </methodCall>
        '''
        data = inspect.cleandoc(data)
        response = requests.post(self.url, data, headers)
        xml_tree = ElementTree.fromstring(response.content)
        uid = xml_tree.findtext('./params/param/value/int')
        return int(uid)

    def list_ldap_servers(self, authenticate=False):
        if authenticate:
            self.auth()
        data = f'''
        <?xml version="1.0"?>
        <methodCall>
            <methodName>v1.auth.ldap.servers.list</methodName>
            <params>
                <param>
                    <value><string>{self.auth_token}</string></value>
                </param>
                <param>
                    <value>
                        <struct>
                            <member>
                                <name>enabled</name>
                                <value><boolean>1</boolean></value>
                            </member>
                        </struct>
                    </value>
                </param>
            </params>
        </methodCall>
        '''
        data = inspect.cleandoc(data)
        response = requests.post(self.url, data, headers)
        xml_tree = ElementTree.fromstring(response.content)
        xml_ldap_servers = xml_tree.findall(
            './params/param/value/array/data/value')
        servers = []
        for xml_ldap_server in xml_ldap_servers:
            members = {
                'id': xml_ldap_server.findtext('./struct/member[name="id"]/./value/int'),
                'name': xml_ldap_server.findtext('./struct/member[name="name"]/./value/string')
            }
            servers.append(members)

        return servers

    def get_user(self, _server_name, _pattern="*", authenticate=False):
        if authenticate:
            self.auth()
        ldap_server_id = next(
            filter(lambda x: x['name'] == _server_name, self.list_ldap_servers()))['id']
        data = f'''
        <?xml version="1.0"?>
        <methodCall>
            <methodName>v1.ldap.users.list</methodName>
            <params>
                <param>
                    <value><string>{self.auth_token}</string></value>
                </param>
                <param>
                    <value><int>{ldap_server_id}</int></value>
                </param>
                <param>
                    <value><string>{_pattern}</string></value>
                </param>
            </params>
        </methodCall>
        '''
        data = inspect.cleandoc(data)
        response = requests.post(self.url, data, headers)
        xml_tree = ElementTree.fromstring(response.content)
        xml_user_list = xml_tree.findall(
            './params/param/value/array/data/value')
        users = []
        for xml_user in xml_user_list:
            members = {
                'guid': xml_user.findtext('./struct/member[name="guid"]/./value/string'),
                'name': xml_user.findtext('./struct/member[name="name"]/./value/string'),
                'ldap_dn': xml_user.findtext('./struct/member[name="ldap_dn"]/./value/string')
            }
            xml_login_names = xml_user.findall(
                './struct/member[name="login"]/./value/array/data/value')
            login_names = []
            for xml_login_name in xml_login_names:
                login_name = xml_login_name.findtext('./string')
                login_names.append(login_name)

            members['login'] = login_names
            users.append(members)

        return users

    # _action
    def add_rule(self, _action, _name, _description, _users, _dst_ip_list_id_list, _src_ip_list_id_list, _url_list_id_list, authenticate=False):
        if authenticate:
            self.auth()
        zones = self.get_zones()
        src_zone_id = next(
            filter(lambda x: x['name'] == 'Trusted', zones))['id']
        dst_zone_id = next(
            filter(lambda x: x['name'] == 'Untrusted', zones))['id']
        data = f'''
        <?xml version="1.0"?>
        <methodCall>
            <methodName>v1.content.rule.add</methodName>
            <params>
                <param>
                    <value><string>{self.auth_token}</string></value>
                </param>
                <param>
                    <value>
                        <struct>
                            <member>
                                <name>id</name>
                                <value><int>{randint(1, 10000)}</int></value>
                            </member>
                            <member>
                                <name>action</name>
                                <value><string>{_action}</string></value>
                            </member>
							<member>
								<name>name</name>
								<value><string>{_name}</string></value>
							</member>
							<member>
								<name>public_name</name>
								<value><string>{_name}</string></value>
							</member>
							<member>
								<name>description</name>
								<value><string>{_description}</string></value>
							</member>
							<member>
								<name>enabled</name>
								<value><boolean>1</boolean></value>
							</member>
							<member>
								<name>enable_kav_check</name>
								<value><boolean>0</boolean></value>
							</member>
							<member>
								<name>enable_md5_check</name>
								<value><boolean>0</boolean></value>
							</member>
							<member>
								<name>enable_custom_redirect</name>
								<value><boolean>0</boolean></value>
							</member>
							<member>
								<name>blockpage_template_id</name>
								<value><int>-1</int></value>
							</member>
							<member>
								<name>custom_redirect</name>
								<value><string></string></value>
							</member>
                            <member>
                                <name>users</name>
                                <value>{misc.list_to_xml_array(_users)}</value>
                            </member>
                            <member>
                                <name>morph_categories</name>
                                <value><array><data></data></array></value>
                            </member>
                            <member>
                                <name>url_categories</name>
                                <value><array><data></data></array></value>
                            </member>
							<member>
								<name>url_categories_negate</name>
								<value><boolean>0</boolean></value>
							</member>
                            <member>
                                <name>dst_ips</name>
                                <value>{misc.list_to_xml_array(_dst_ip_list_id_list)}</value>
                            </member>
							<member>
								<name>dst_ips_negate</name>
								<value><boolean>0</boolean></value>
							</member>
							<member>
								<name>src_zones</name>
								<value>{misc.list_to_xml_array([src_zone_id])}</value>
							</member>
							<member>
								<name>src_zones_negate</name>
								<value><boolean>0</boolean></value>
							</member>
							<member>
								<name>dst_zones</name>
								<value>{misc.list_to_xml_array([dst_zone_id])}</value>
							</member>
							<member>
								<name>dst_zones_negate</name>
								<value><boolean>0</boolean></value>
							</member>
							<member>
								<name>src_ips</name>
								<value>{misc.list_to_xml_array(_src_ip_list_id_list)}</value>
							</member>
							<member>
								<name>src_ips_negate</name>
								<value><boolean>0</boolean></value>
							</member>
							<member>
								<name>content_types</name>
								<value>{misc.list_to_xml_array([])}</value>
							</member>
							<member>
								<name>content_types_negate</name>
								<value><boolean>0</boolean></value>
							</member>
                            <member>
                                <name>urls</name>
                                <value>{misc.list_to_xml_array(_url_list_id_list)}</value>
                            </member>
                            <member>
								<name>urls_negate</name>
								<value><boolean>0</boolean></value>
                            </member>
                            <member>
                                <name>time_restrictions</name>
                                <value>{misc.list_to_xml_array([])}</value>
                            </member>
                            <member>
                                <name>http_methods</name>
                                <value>{misc.list_to_xml_array([])}</value>
                            </member>
                            <member>
                                <name>user_agents</name>
                                <value>{misc.list_to_xml_array([])}</value>
                            </member>
                            <member>
                                <name>referers</name>
                                <value>{misc.list_to_xml_array([])}</value>
                            </member>
                        </struct>
                    </value>
                </param>
            </params>
        </methodCall>
        '''
        print(data)
        data = inspect.cleandoc(data)
        response = requests.post(self.url, data, headers)
        print(response.content)
        xml_tree = ElementTree.fromstring(response.content)
        return int(xml_tree.findtext('./params/param/value/int'))

    def get_rules(self, authenticate=False):
        if authenticate:
            self.auth()
        data = f'''
        <?xml version="1.0"?>
        <methodCall>
            <methodName>v1.content.rules.list</methodName>
            <params>
                <param>
                    <value><string>{self.auth_token}</string></value>
                </param>
                <param>
                    <value><int>1</int></value>
                </param>
                <param>
                    <value><string>1000</string></value>
                </param>
                '''\
                '''
                <param>
                    <value>
                        <struct>
                        </struct>
                    </value>
                </param>
            </params>
        </methodCall>
        '''
        data = inspect.cleandoc(data)
        response = requests.post(self.url, data, headers)
        xml_tree = ElementTree.fromstring(response.content)
        return response.content

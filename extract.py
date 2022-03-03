import bluecoat
import usergate
from typing import Any, List, Union, Tuple, Dict
import os
import api
from multiprocessing.pool import ThreadPool
import MC_lib


def collect_parameter_all(_fw_objects, parameter_name):
    parameter_values = []
    for object in _fw_objects:
        for rule in object.rules:
            x = rule.parameters.get(parameter_name, [])
            parameter_values += x

    return parameter_values


def fetch_user_id(client: api.Client, server_name, username):
    found_user_ids = client.get_user(server_name, username)
    print(found_user_ids)
    assert(len(found_user_ids) > 0)
    return (username, found_user_ids[0]['guid'])


def populate_users(client: api.Client, pool: ThreadPool, server_name, user_list):
    users = dict(pool.map(lambda u: fetch_user_id(
        client, server_name, u), user_list))
    return users


def fetch_url_id(client: api.Client, existring_url_lists, named_url_list: Tuple[str, usergate.URLList]):
    (name, url_list) = named_url_list
    if id := existring_url_lists.get(name):
        return (name, id)
    else:
        return (name, url_list.commit(client))


def populate_url_lists(client: api.Client, pool: ThreadPool, url_lists):
    existing_urls = dict(map(lambda x: (
        x['name'], x['id']), client.get_named_lists('url')))
    return pool.map_async(lambda url_list: fetch_url_id(client, existing_urls, url_list), url_lists.items())


def fetch_ip_list_id(client: api.Client, existing_ip_lists, named_ip_list: Tuple[str, usergate.URLList]):
    (name, ip_list) = named_ip_list
    if id := existing_ip_lists.get(name):
        return (name, id)
    else:
        return (name, ip_list.commit(client))


def populate_ip_lists(client: api.Client, pool: ThreadPool, ip_lists: dict):
    assert(isinstance(ip_lists, dict))
    new_ip_lists = {
        'src': {},
        'dst': {},
    }
    existing_ip_lists = dict(
        map(lambda x: (x['name'], x['id']), client.get_named_lists('network')))
    for direction, named_ip_lists in ip_lists.items():
        new_ip_lists[direction] = pool.map_async(lambda ip_list: fetch_ip_list_id(
            client, existing_ip_lists, ip_list), named_ip_lists.items())
    return new_ip_lists


def extractor_mc(_fw_objects: List[bluecoat.ProxyGroup], rule_category: str) -> List[Union[usergate.IPList, usergate.URLList, usergate.Rule]]:
    '''
    Paramteres
    ----------
    rule_category: str
        'server' or 'user'
    '''
    assert(rule_category != '')
    # Weather updates for MC variant
    # Firstly we should go through list of url lists
    #   add list name of lists
    #   go through each url inside inner list
    #       add that list to named list
    server_ip = os.environ.get('FW_ADDRESS')
    username = os.environ.get('FW_USERNAME')
    password = os.environ.get('FW_PASSWORD')
    ldap_server_name = os.environ.get('FW_LDAP_SERVER_NAME')
    prefix = os.environ.get('FW_PREFIX')
    template_name = f'template_{rule_category}'

    server = MC_lib.mc(server_ip=server_ip, login=username,
                       prefix=prefix, password=password)
    server.start()
    server.mctemplate_add(name=template_name,
                          description='Template for server rules exported and comined from BlueCoat')

    (url_lists, ip_lists) = gather_lists(_fw_objects)

    for (url_list_name, url_list) in url_lists.items():
        server.template_list_url_add(
            template_name, url_list_name, description='')
        for url in url_list:
            server.template_url_in_list_add(url_list_name, url)

        for (ip_list_name, ip_list) in ip_lists.items():
            server.template_group_ip_address_add(
                template_name, ip_list_name, description='', threat_level='very_low')
            for ip in ip_list:
                server.template_ip_address_in_group_add(ip_list_name, ip)

    for object in _fw_objects:
        name_prefix = object.name

        for rule in object.rules:
            local_user = None
            if users := rule.parameters.get('user', None):
                local_user = ", ".join(users)

            src_ips = None
            if rule.parameters.get('client.address', None):
                src_ips = f'SRC {name_prefix} {str(rule.line_number)}'

            dst_ips = None
            if rule.parameters.get('url.address', None):
                dst_ips = f'DST {name_prefix} {str(rule.line_number)}'

            urls = None
            if rule.parameters.get('url.domain', None):
                urls = f'{name_prefix} {str(rule.line_number)}'

            server.template_content_filtering_rule_add(
                template=template_name,
                name=f'{name_prefix} {rule.line_number}',
                public_name='',
                enabled=True,
                action=action_map[rule.type],
                description=f'{rule.comment}',
                position=1,
                enable_custom_redirect=False,
                blockpage_template=-1,
                special_user=None,
                local_user=local_user,
                local_group=None,
                ldap_server=ldap_server_name,
                url_categories=None,
                group_categories=None,
                referer_categories=None,
                src_ips=src_ips,
                dst_ips=dst_ips,
                morph_lists=None,
                urls=urls,
                referers=None,
                src_zones='Trusted',
                dst_zones='Untrusted',
                time_restrictions=None,
                content_types=None,
                http_methods=None,
                custom_redirect=None,
                enable_kav_check=False,
                enable_md5_check=False,
                rule_log=True,
                src_zones_negate=False,
                dst_zones_negate=False,
                user_agents=None,
                src_ips_negate=False,
                dst_ips_negate=False,
                url_categories_negate=False,
                urls_negate=False,
                referer_negate=False,
                content_types_negate=False,
                user_agents_negate=False,
                scenario_rule_name=None,
                position_layer='pre',
                active=True,
                rownumber=1,
                devices=None,
                devices_invert=False,
                users_negate=False
            )

            action_map = {
                'ALLOW': 'accept',
                'DENY': 'drop',
            }


def gather_lists(_fw_objects: List[bluecoat.ProxyGroup]) \
        -> Tuple[Dict[str, List[usergate.URLList]], Dict[str, List[usergate.IPList]]]:

    url_lists: Dict[str, List[usergate.URLList]] = {}
    ip_lists: Dict[str, List[usergate.IPList]] = {}

    for object in _fw_objects:

        name_prefix = object.name

        for rule in object.rules:
            if source_addresses := rule.get_parameter('client.address'):
                ip_list_name = f'SRC {name_prefix} {str(rule.line_number)}'
                ip_lists[ip_list_name] = source_addresses

            if url_domains := rule.get_parameter('url.domain'):
                url_list_name = f'{name_prefix} {str(rule.line_number)}'
                url_lists[url_list_name] = url_domains

            if destination_addresses := rule.get_parameter('url.address'):
                ip_list_name = f'DST {name_prefix} {str(rule.line_number)}'
                ip_lists[ip_list_name] = destination_addresses

    return (url_lists, ip_lists)


def server_extractor(_fw_objects: List[bluecoat.ProxyGroup]) -> List[Union[usergate.IPList, usergate.URLList, usergate.Rule]]:
    pool = ThreadPool(processes=8)
    url = os.environ.get('RPC_URL')
    username = os.environ.get('FW_USERNAME')
    password = os.environ.get('FW_PASSWORD')
    ldap_server_name = os.environ.get('FW_LDAP_SERVER_NAME')

    client = api.Client(url, username, password)
    client.auth()

    users = collect_parameter_all(_fw_objects, 'user')

    def handle_users(client: api.Client, username_list):
        username_to_guid = {}
        for username in username_list:
            user_guid = next(filter(lambda u: username in u['name'], client.get_user(
                ldap_server_name, username)))['guid']

            print(user_guid)
            username_to_guid[username] = user_guid

        return username_to_guid

    user_list_thread = pool.apply_async(
        populate_users, (client, pool, ldap_server_name, users))

    url_lists = {}
    ip_lists = {
        'src': {},
        'dst': {}
    }
    for object in _fw_objects:
        name_prefix = object.name
        for rule in object.rules:
            if source_addresses := rule.get_parameter('client.address'):
                ip_list_name = f'SRC {name_prefix} {str(rule.line_number)}'
                ip_lists['src'][ip_list_name] = usergate.IPList(
                    ip_list_name, '', source_addresses)
            if url_domains := rule.get_parameter('url.domain'):
                url_list_name = f'{name_prefix} {str(rule.line_number)}'
                url_lists[url_list_name] = usergate.URLList(
                    url_list_name, '', url_domains)
            if destination_addresses := rule.get_parameter('url.address'):
                ip_list_name = f'DST {name_prefix} {str(rule.line_number)}'
                ip_lists['dst'][ip_list_name] = usergate.IPList(
                    ip_list_name, '', destination_addresses)

    def handle_ip_lists(client, ip_lists):
        existing_ip_lists_names = dict(
            map(lambda x: (x['name'], x['id']), client.get_named_lists('network')))

        for k, v in ip_lists.items():
            for (name, l) in v.items():
                if id := existing_ip_lists_names.get(name):
                    ip_lists[k][name] = id

            for (name, l) in v.items():
                if not isinstance(l, int):
                    ip_lists[k][name] = l.commit(client)

        return ip_lists

    def handle_url_lists(client, url_lists):
        existing_url_lists_names = dict(
            map(lambda x: (x['name'], x['id']), client.get_named_lists('url')))

        for (name, l) in url_lists.items():
            if id := existing_url_lists_names.get(name):
                url_lists[name] = id

        for (name, l) in url_lists.items():
            if not isinstance(l, int):
                url_lists[name] = l.commit(client)

        return url_lists

    ip_thread = pool.apply_async(
        handle_ip_lists, (client, ip_lists))

    url_thread = pool.apply_async(
        handle_url_lists, (client, url_lists))

    users = user_list_thread.get()
    ip_lists = ip_thread.get()
    url_lists = url_thread.get()

    for direction, lists in ip_lists.items():
        for (n, l) in lists.items():
            print(n, l)

    print(url_lists)
    print(users)

    usergate_rules = []

    for object in _fw_objects:
        name_prefix = object.name
        for rule in object.rules:
            src_list_id = [ip_lists['src'].get(
                f'SRC {name_prefix} {rule.line_number}', [])]
            user_ids = [users[username]
                        for username in rule.parameters.get('user', [])]
            dst_ip_list_id = []
            if rule.parameters.get('url.address', []):
                dst_ip_list_id = [ip_lists['dst']
                                  [f'DST {name_prefix} {rule.line_number}']]
            dst_url_list_id = []
            if rule.parameters.get('url.domain', []):
                dst_url_list_id = [
                    url_lists[f'{name_prefix} {rule.line_number}']]

            action_map = {
                'ALLOW': 'accept',
                'DENY': 'drop',
            }

            usergate_rule = usergate.Rule(
                action_map[rule.type], f'{name_prefix} {rule.line_number}', rule.comment, user_ids, dst_ip_list_id, src_list_id, dst_url_list_id)
            usergate_rules.append(usergate_rule)

    existing_rules = list(map(lambda r: r['name'], client.get_rules()))

    usergate_rules = list(
        filter(lambda r: r.name not in existing_rules, usergate_rules))

    client.auth()
    uids = pool.map(lambda r: r.commit(client), usergate_rules)
    print(uids)


def user_extractor(_fw_objects):
    pool = ThreadPool(processes=8)
    url = os.environ.get('RPC_URL')
    username = os.environ.get('FW_USERNAME')
    password = os.environ.get('FW_PASSWORD')
    ldap_server_name = os.environ.get('FW_LDAP_SERVER_NAME')

    client = api.Client(url, username, password)
    client.auth()

    users = collect_parameter_all(_fw_objects, 'user')
    print(users)

    users = populate_users(client, pool, ldap_server_name, users)
    print(users)

    url_lists = {}
    ip_lists = {
        'src': {},
        'dst': {}
    }
    for object in _fw_objects:
        name_prefix = object.name
        for rule in object.rules:
            if source_addresses := rule.get_parameter('client.address'):
                ip_list_name = f'SRC {name_prefix} {str(rule.line_number)}'
                ip_lists['src'][ip_list_name] = usergate.IPList(
                    ip_list_name, '', source_addresses)
            if source_hosts := rule.get_parameter('client.host'):
                url_list_name = f'HOST {name_prefix} {str(rule.line_number)}'
                url_lists[url_list_name] = usergate.URLList(
                    url_list_name, '', source_hosts)
            if url_domains := rule.get_parameter('url.domain'):
                url_list_name = f'{name_prefix} {str(rule.line_number)}'
                url_lists[url_list_name] = usergate.URLList(
                    url_list_name, '', url_domains)
            if destination_addresses := rule.get_parameter('url.address'):
                ip_list_name = f'DST {name_prefix} {str(rule.line_number)}'
                ip_lists['dst'][ip_list_name] = usergate.IPList(
                    ip_list_name, '', destination_addresses)

    url_lists = populate_url_lists(client, pool, url_lists)

    for (n, l) in dict(url_lists.get()).items():
        print(n, l)

    ip_lists = populate_ip_lists(client, pool, ip_lists)

    ip_lists = dict(
        list(
            map(lambda name_lists: (name_lists[0], dict(
                name_lists[1].get())), ip_lists.items())
        )
    )

    print(ip_lists)

    usergate_rules = []

    for object in _fw_objects:
        name_prefix = object.name
        for rule in object.rules:
            src_list_id = [ip_lists['src'].get(
                f'SRC {name_prefix} {rule.line_number}', [])]
            user_ids = [users[username]
                        for username in rule.parameters.get('user', [])]
            dst_ip_list_id = []
            if rule.parameters.get('url.address', []):
                dst_ip_list_id = [ip_lists['dst']
                                  [f'DST {name_prefix} {rule.line_number}']]
            dst_url_list_id = []
            if rule.parameters.get('url.domain', []):
                dst_url_list_id = [
                    url_lists[f'{name_prefix} {rule.line_number}']]

            action_map = {
                'ALLOW': 'accept',
                'DENY': 'drop',
            }

            usergate_rule = usergate.Rule(
                action_map[rule.type], f'{name_prefix} {rule.line_number}', rule.comment, user_ids, dst_ip_list_id, src_list_id, dst_url_list_id)
            usergate_rules.append(usergate_rule)

    existing_rules = list(map(lambda r: r['name'], client.get_rules()))

    usergate_rules = list(
        filter(lambda r: r.name not in existing_rules, usergate_rules))

    client.auth()
    uids = pool.map(lambda r: r.commit(client), usergate_rules)
    print(uids)


extractors = {
    'server': server_extractor,
    'user': user_extractor,
}

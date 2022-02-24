import bluecoat
import usergate
from typing import Any, List, Union
import os
import api
import threading
from multiprocessing.pool import ThreadPool


def collect_parameter_all(_fw_objects, parameter_name):
    parameter_values = []
    for object in _fw_objects:
        for rule in object.rules:
            x = rule.parameters.get(parameter_name, [])
            parameter_values += x

    return parameter_values


def server_extractor(_fw_objects: List[bluecoat.ProxyGroup]) -> List[Union[usergate.IPList, usergate.URLList, usergate.Rule]]:
    pool = ThreadPool(processes=3)
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
            fetched_user = client.get_user(ldap_server_name, username)
            user_guid = next(filter(lambda u: username in u['name'], client.get_user(
                ldap_server_name, username)))['guid']

            print(user_guid)
            username_to_guid[username] = user_guid

        return username_to_guid

    user_list_thread = pool.apply_async(
        handle_users, (client, users))

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

    # for (name, l) in ip_lists.items():
    #     print(name, l)

    # for (name, l) in url_lists.items():
    #     print(name, l)

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

    client.auth()
    for usergate_rule in usergate_rules:
        uid = usergate_rule.commit(client)
        print(uid)


def user_extractor(_fw_objects):
    x = 42


extractors = {
    'server': server_extractor,
    'user': user_extractor,
}

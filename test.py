import sys
import api
import usergate
import os

url = ''
username = ''
password = ''


def test_fetching_rules():
    client = api.Client(url, username, password)

    rules = client.get_rules(authenticate=True)
    print(rules)


def ldap_server_list_test():

    client = api.Client(url, username, password)
    ldap_servers = client.list_ldap_servers()

    ldap_server_name = 'Example AD DC'
    users = client.list_ldap_users(ldap_server_name, ldap_username)
    print(users)


def test_get_zones():

    client = api.Client(url, username, password)

    zones = client.get_zones()
    print(zones)


def addition_test():
    ips = [
        "192.168.0.1",
        "10.0.1.0/24"
    ]

    client = api.Client(url, username, password)
    named_lists = client.get_named_lists('network')
    print(named_lists)
    list_name = 'Private IPs'
    private_ips_list = next(
        filter(lambda x: x['name'] == list_name, named_lists))
    private_ips_list_id = private_ips_list['id']
    print(client.get_list_info(private_ips_list_id))
    for item in ips:
        result = client.add_list_item(private_ips_list_id, item)
        print(result)

    print(client.get_list_info(private_ips_list_id))


def test_ip_list():
    ips = [
        "192.168.0.1",
        "10.0.1.0/24"
    ]

    client = api.Client(url, username, password)

    ip_list = usergate.IPList("Test API list", "Created with Python", ips)
    ip_list.commit(client)


def test_get_list_info():
    client = api.Client(url, username, password)
    info = client.get_named_lists("network")
    print(info)


if __name__ == '__main__':
    url = os.environ['RPC_URL']
    username = os.environ['FW_USERNAME']
    password = os.environ['FW_PASSWORD']
    # test_get_list_info()
    # test_ip_list()
    # ldap_server_list_test()
    test_fetching_rules()

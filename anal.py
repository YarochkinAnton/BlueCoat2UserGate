import bluecoat
from typing import List


def get_parameter_set(_fw_objects: List[bluecoat.ProxyGroup]):
    parameter_set = set()

    for object in _fw_objects:
        for rule in object.rules:
            parameter_set |= set(rule.parameters.keys())

    return parameter_set


def list_users(_fw_objects: List[bluecoat.ProxyGroup]):
    users = []
    for object in _fw_objects:
        for rule in object.rules:
            user = rule.get_parameter('user')
            users.append(user)

    users = list(filter(lambda x: x != None, users))
    return users

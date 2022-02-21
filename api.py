import requests
import xml.etree.ElementTree as ElementTree
import inspect


headers = {
    'Content-Type': 'text/xml'
}


class Client:
    def __init__(self, _url, _username, _password):
        self.url = _url
        self.username = _username
        self.password = _password

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
        return auth_token

import base64


class Utils:

    @staticmethod
    def b64decode(text):
        text = text.replace('.', '+').replace('-', '/').replace('*', '=')
        return base64.b64decode(text)

    @staticmethod
    def b64encode(text):
        # Convert to bytes if necessary.
        if isinstance(text, str):
            text = text.encode()
        text = base64.b64encode(text).decode()
        return text.replace('+', '.').replace('/', '-').replace('=', '*')

    @staticmethod
    def dict_to_query(_dict):
        query = ''
        idx = 0
        for key in _dict.keys():
            if idx != 0:
                query += '&'
            query += str(key) + '=' + str(_dict[key])
            idx += 1
        return query

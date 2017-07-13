from acme import client


class NotInitializedError(Exception):
    pass


class LazyClient(object):
    client = None

    def init(self, directory_url, account_key_callback):
        self.__directory_url = directory_url
        self.__account_key_callback = account_key_callback

    @property
    def account_key(self):
        return self.__account_key_callback()

    @property
    def acme(self):
        if not self.client:
            self.client = client.Client(self.__directory_url, self.account_key)
        return self.client

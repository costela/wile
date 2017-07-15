from acme import client


class NotInitializedError(Exception):
    pass


class LazyClient(object):
    __client = None
    __account_key = None

    def init(self, directory_url, account_key_callback):
        self.__directory_url = directory_url
        self.__account_key_callback = account_key_callback

    @property
    def account_key(self):
        if not self.__account_key:
            self.__account_key = self.__account_key_callback()
        return self.__account_key_callback()

    @property
    def acme(self):
        if not self.__client:
            self.__client = client.Client(self.__directory_url, self.account_key)
        return self.__client

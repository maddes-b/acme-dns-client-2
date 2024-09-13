#!/bin/false
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: nil; py-indent-offset: 4 -*-

"""
Module for acme-dns Clients to handle configuration and domain accounts incl. server API

License: GPLv2 - https://www.gnu.org/licenses/gpl-2.0.html

Targeted Python Version: 3.5 (Debian 9 "Stretch"), taking Python 3.12 into account
- only function parameter annotations; no variable annotations (=3.6+)
- use collections.OrderedDict() to keep keys in order of addition

Authors:
- Matthias "Maddes" Bücher <maddes@maddes.net>
"""


__version__ = "0.10.2"
__author__ = "Matthias \"Maddes\" Bücher"
__license__ = "GPLv2"
__copyright__ = "Copyright (C) 2024 Matthias \"Maddes\" Bücher"
__homepage__ = "https://github.com/maddes-b/acme-dns-client-2"
__contact__ = __homepage__


### python standard modules
import collections
import datetime
import os
import typing
import urllib.parse

### 3rd-party modules
## https://pypi.org/project/dnspython/
import dns.exception
import dns.rdatatype
import dns.resolver
## https://pypi.org/project/json5/
import json5 as json ### SPEEDUP: switch to standard 'json' module, but then avoid comments and extra commas in both JSON files
## https://pypi.org/project/requests/
import requests

### Check for json5 otherwise fallback to json arguments
JSON5_DUMP_KWARGS = {"quote_keys": True, "trailing_commas": False}
JSON5_TEST = {"Test1": "1", "Test2": 2}
try:
    RESULT = json.dumps(JSON5_TEST, indent=4, **JSON5_DUMP_KWARGS)
except TypeError as e: ### fallback to  for json.dump()
    JSON5_DUMP_KWARGS = {}
    RESULT = json.dumps(JSON5_TEST, indent=4, **JSON5_DUMP_KWARGS)
del JSON5_TEST, RESULT


### ----------------------------------------
### --- Class Configuration
### ----------------------------------------
class Configuration:
    """
    Handles configuration for acme-dns clients

    Defines default configuration and loads settings from a JSON configuration file.
    Configuration is kept in dictionary `.settings`.
    Provides constants (all uppercase) for default values plus attribute names of settings.
    Use `ATTR_...` constants to access each setting.
    """

    ### Constants for default values
    DEFAULT_DIR_CONFIG = "/etc/acme-dns-client"
    DEFAULT_FILE_CONFIG = "config.json"
    DEFAULT_FILE_DOMAIN_ACCOUNTS = "domain_accounts.json"
    DEFAULT_NAME_SERVERS = (
        ### Cloudflare's DNS servers (as of 2024-08)
        ### https://developers.cloudflare.com/1.1.1.1/ip-addresses/
        "1.1.1.1",
        "2606:4700:4700::1111",
        "1.0.0.1",
        "2606:4700:4700::1001",
        ### Quad9's DNS Servers (as of 2024-08)
        ### https://www.quad9.net/service/service-addresses-and-features
        "9.9.9.9",
        "2620:fe::fe",
        "149.112.112.112",
        "2620:fe::9",
        ### Google's DNS Servers (as of 2024-08)
        ### https://developers.google.com/speed/public-dns/docs/using
        ### https://dns.google/
        #"8.8.8.8",
        #"2001:4860:4860::8888",
        #"8.8.4.4",
        #"2001:4860:4860::8844",
        ### OpenDNS's DNS Servers (as of 2024-08)
        ### https://www.opendns.com/setupguide/
        ### https://support.opendns.com/hc/en-us/articles/227986667-Does-OpenDNS-Support-IPv6
        #"208.67.222.222",
        #"2620:119:35::35",
        #"2620:119:53::53",
        #"208.67.220.220",
    )
    DEFAULT_URL_PATH_CHANGE = "change"
    DEFAULT_URL_PATH_CLEAN = "clean"
    DEFAULT_URL_PATH_DEREGISTER = "deregister"
    DEFAULT_URL_PATH_REGISTER = "register"
    DEFAULT_URL_PATH_UPDATE = "update"

    ### Constants of setting attribute names in configuration
    ATTR_PATH_CONFIG = "configpath"
    ATTR_PATH_ACCOUNTS = "accountspath"
    ATTR_IPS_NAME_SERVERS = "nameservers"
    ATTR_URL_DEFAULT_SERVER = "default_server"
    ATTR_URL_DEFAULT_PATH_CHANGE = "default_server_path_change"
    ATTR_URL_DEFAULT_PATH_CLEAN = "default_server_path_clean"
    ATTR_URL_DEFAULT_PATH_DEREGISTER = "default_server_path_deregister"
    ATTR_URL_DEFAULT_PATH_REGISTER = "default_server_path_register"
    ATTR_URL_DEFAULT_PATH_UPDATE = "default_server_path_update"

    def __init__(self, configpath:str, accountspath:typing.Union[str,None]=None) -> None:
        """
        Constructor stores given arguments separately to rebuild defaults at any time.
        Creates ordered dictionary for configuration settings and loads further configuration from the given JSON file.
        """

        ### keep given arguments separately
        self._jsonpath = configpath
        self._accountspath = accountspath

        ### create dictionary for settings
        self.settings = collections.OrderedDict()

        ### load configuration from JSON file, sets defaults first
        self._loadFromFile()
    # --- /Configuration.__init__()

    def _resetWithDefaults(self) -> None:
        """
        Clears configuration and sets default settings.
        Honors settings given explicitly on class object instantiation.
        """

        self.settings.clear()
        self.settings[self.ATTR_PATH_CONFIG] = self._jsonpath
        if self._accountspath is not None:
            self.settings[self.ATTR_PATH_ACCOUNTS] = self._accountspath
        else:
            self.settings[self.ATTR_PATH_ACCOUNTS] = os.path.join(self.DEFAULT_DIR_CONFIG, self.DEFAULT_FILE_DOMAIN_ACCOUNTS)
        self.settings[self.ATTR_URL_DEFAULT_SERVER] = None
        self.settings[self.ATTR_URL_DEFAULT_PATH_CHANGE] = self.DEFAULT_URL_PATH_CHANGE
        self.settings[self.ATTR_URL_DEFAULT_PATH_CLEAN] = self.DEFAULT_URL_PATH_CLEAN
        self.settings[self.ATTR_URL_DEFAULT_PATH_DEREGISTER] = self.DEFAULT_URL_PATH_DEREGISTER
        self.settings[self.ATTR_URL_DEFAULT_PATH_REGISTER] = self.DEFAULT_URL_PATH_REGISTER
        self.settings[self.ATTR_URL_DEFAULT_PATH_UPDATE] = self.DEFAULT_URL_PATH_UPDATE
        self.settings[self.ATTR_IPS_NAME_SERVERS] = list(self.DEFAULT_NAME_SERVERS)
    # --- /Configuration._resetWithDefaults()

    def _loadFromFile(self) -> None:
        """
        First initializes configuration with defaults.
        Then loads configuration from JSON file.
        Additional unknown settings of JSON file are ignored.

        Special configuration settings CANNOT be overwritten by the configuration file:
        - the configuration file path itself
        - the domain accounts file path, if given explicitly on class object instantiation
        """

        ### clear configuration and set defaults
        self._resetWithDefaults()

        filedata = None
        with open(self._jsonpath, mode="rt") as file:
            filedata = json.load(file)

        for key, fileconfigdata in filedata.items():
            ### do not overwrite some specific keys
            if key == self.ATTR_PATH_CONFIG:
                continue
            if key == self.ATTR_PATH_ACCOUNTS \
            and self._accountspath is not None:
                continue

            ### overwrite if known setting
            if key in self.settings:
                ### special cases
                if key == self.ATTR_URL_DEFAULT_SERVER:
                    if fileconfigdata and not fileconfigdata.endswith("/"):
                        fileconfigdata = "/".join((fileconfigdata, ""))

                self.settings[key] = fileconfigdata
    # --- /Configuration._loadFromFile()

### ----------------------------------------
### --- /Class Configuration
### ----------------------------------------


### ----------------------------------------
### --- Class DomainAccounts
### ----------------------------------------
class DomainAccounts:
    """
    Handles domain accounts for acme-dns clients

    Defines an ordered dictionary and load domain accounts from a JSON file.
    As domain key the domain name of the  to be authorized target domain is used.

    Provides constants (all uppercase) for default values plus attribute names of settings.
    Use `ATTR_...` constants to access each domain account field.
    """

    ### attributes of API
    ATTR_FULLDOMAIN = "fulldomain"
    ATTR_SUBDOMAIN = "subdomain"
    ATTR_USERNAME = "username"
    ATTR_PASSWORD = "password"
    ATTR_ALLOW_FROM = "allowfrom"

    ### additional attributes of clients
    ATTR_SERVER_URL = "server_url"
    ATTR_SERVER_URL_PATH_CHANGE = "server_path_change"
    ATTR_SERVER_URL_PATH_CLEAN = "server_path_clean"
    ATTR_SERVER_URL_PATH_DEREGISTER = "server_path_deregister"
    ATTR_SERVER_URL_PATH_REGISTER = "server_path_register"
    ATTR_SERVER_URL_PATH_UPDATE = "server_path_update"
    ATTR_ADDED_ON = "added_on"
    ATTR_ADDED_VIA = "added_via"

    ### virtual attributes of client
    ATTR_KEY = "key"
    ATTR_DOMAIN_CHALLENGE = "challengedomain"
    ATTR_DOMAIN_CNAME_ENTRY = "cnameentry"
    ATTR_DOMAIN_CNAME_RECORD = "cnamerecord"

    ### misc constants
    DOMAIN_CHALLENGE_PREFIX = "_acme-challenge."
    DOMAIN_CHALLENGE_PREFIX_LEN = len(DOMAIN_CHALLENGE_PREFIX)
    TOKEN_DUMMY = "-DUMMY-DUMMY-DUMMY-DUMMY-DUMMY-DUMMY-DUMMY-"

    def __init__(self, config:Configuration) -> None:
        """
        Constructor creates ordered dictionary for domain acounts and loads accounts from the configured JSON file.
        """

        ### keep given arguments separately
        self._jsonpath = config.settings[config.ATTR_PATH_ACCOUNTS]

        ### create dictionary for domain accounts
        self.domains = collections.OrderedDict()

        ### load from domain accounts file
        self._loadFromFile(config=config)
    # --- /DomainAccounts.__init__()

    def _loadFromFile(self, config:Configuration) -> None:
        """
        First clears domain accounts.
        Then loads domain accounts from JSON file sorted by domain name.

        If data is missing for a domain account, then it is enhanced with the configured defaults.
        This can happen if the domain accounts are from an older version or other client.

        Additional unknown data entries are kept to avoid issues with other versions and/or other client implementations.
        """

        self.domains.clear()

        filedata = None
        with open(self._jsonpath, mode="rt") as file:
            filedata = json.load(file)

        default_server = config.settings[config.ATTR_URL_DEFAULT_SERVER]
        for key, fileaccdata in sorted(filedata.items()):
            accdata = collections.OrderedDict()
            #
            accdata[self.ATTR_FULLDOMAIN] = fileaccdata.pop(self.ATTR_FULLDOMAIN)
            accdata[self.ATTR_SUBDOMAIN] = fileaccdata.pop(self.ATTR_SUBDOMAIN)
            accdata[self.ATTR_USERNAME] = fileaccdata.pop(self.ATTR_USERNAME)
            accdata[self.ATTR_PASSWORD] = fileaccdata.pop(self.ATTR_PASSWORD)
            server_url = fileaccdata.pop(self.ATTR_SERVER_URL)
            if server_url and not server_url.endswith("/"):
                server_url = "/".join((server_url, ""))
            accdata[self.ATTR_SERVER_URL] = server_url
            #
            try:
                path = fileaccdata.pop(self.ATTR_SERVER_URL_PATH_CHANGE)
            except KeyError as e:
                if server_url == default_server:
                    path = config.settings[config.ATTR_URL_DEFAULT_PATH_CHANGE]
                else:
                    path = config.DEFAULT_URL_PATH_CHANGE
            accdata[self.ATTR_SERVER_URL_PATH_CHANGE] = path.lstrip("/")
            #
            try:
                path = fileaccdata.pop(self.ATTR_SERVER_URL_PATH_CLEAN)
            except KeyError as e:
                if server_url == default_server:
                    path = config.settings[config.ATTR_URL_DEFAULT_PATH_CLEAN]
                else:
                    path = config.DEFAULT_URL_PATH_CLEAN
            accdata[self.ATTR_SERVER_URL_PATH_CLEAN] = path.lstrip("/")
            #
            try:
                path = fileaccdata.pop(self.ATTR_SERVER_URL_PATH_DEREGISTER)
            except KeyError as e:
                if server_url == default_server:
                    path = config.settings[config.ATTR_URL_DEFAULT_PATH_DEREGISTER]
                else:
                    path = config.DEFAULT_URL_PATH_DEREGISTER
            accdata[self.ATTR_SERVER_URL_PATH_DEREGISTER] = path.lstrip("/")
            #
            try:
                path = fileaccdata.pop(self.ATTR_SERVER_URL_PATH_REGISTER)
            except KeyError as e:
                if server_url == default_server:
                    path = config.settings[config.ATTR_URL_DEFAULT_PATH_REGISTER]
                else:
                    path = config.DEFAULT_URL_PATH_REGISTER
            accdata[self.ATTR_SERVER_URL_PATH_REGISTER] = path.lstrip("/")
            #
            try:
                path = fileaccdata.pop(self.ATTR_SERVER_URL_PATH_UPDATE)
            except KeyError as e:
                if server_url == default_server:
                    path = config.settings[config.ATTR_URL_DEFAULT_PATH_UPDATE]
                else:
                    path = config.DEFAULT_URL_PATH_UPDATE
            accdata[self.ATTR_SERVER_URL_PATH_UPDATE] = path.lstrip("/")
            #
            try:
                accdata[self.ATTR_ADDED_ON] = fileaccdata.pop(self.ATTR_ADDED_ON)
            except KeyError as e:
                pass
            #
            try:
                accdata[self.ATTR_ADDED_VIA] = fileaccdata.pop(self.ATTR_ADDED_VIA)
            except KeyError as e:
                pass

            ### keep additional data from other sources or future versions
            accdata.update(fileaccdata)

            self.domains[key] = accdata
    # --- /DomainAccounts._loadFromFile()

    @classmethod
    def sanitizeDomain(cls, key:str) -> str:
        """
        Removes unwanted prefixes until all are removed and the normal domain is left:
        - '*.' from wildcard certificate domains
        - '_acme-challenge.' from challenge domains

        Allow usage from ACME clients that may not provide the base domain as-is.
        """

        while True:
            if key.startswith("*."):
                key = key[2:]
                continue
            if key.startswith(cls.DOMAIN_CHALLENGE_PREFIX):
                key = key[cls.DOMAIN_CHALLENGE_PREFIX_LEN:]
                continue
            break

        return key
    # --- /DomainAccounts.sanitizeDomain()

    @classmethod
    def _enhanceEntry(cls, key:str, accdata:dict) -> None:
        """
        Enhance domain account with additional data for processing and display.
        - domain name as 'key' of domain account
        - DNS related data (CNAME entry and its components)

        DO NOT use for account data that will be saved to domain accounts file.
        """

        accdata[cls.ATTR_KEY] = key

        accdata.update(cls._determineRelatedDomains(accdata=accdata))
    # --- /DomainAccounts._enhanceEntry()

    @classmethod
    def _determineRelatedDomains(cls, accdata:dict) -> dict:
        """
        Determines DNS related data for domain account and returns them as a dictionary.
        """

        result = collections.OrderedDict()
        result[cls.ATTR_DOMAIN_CHALLENGE] = "{prefix:s}{domain:s}.".format(prefix=cls.DOMAIN_CHALLENGE_PREFIX, domain=accdata[cls.ATTR_KEY])
        result[cls.ATTR_DOMAIN_CNAME_ENTRY] = "{domain:s}.".format(domain=accdata[cls.ATTR_FULLDOMAIN])
        result[cls.ATTR_DOMAIN_CNAME_RECORD] = "{prefix:s}{domain1:s}. IN CNAME {domain2:s}.".format(prefix=cls.DOMAIN_CHALLENGE_PREFIX, domain1=accdata[cls.ATTR_KEY], domain2=accdata[cls.ATTR_FULLDOMAIN])

        return result
    # --- /DomainAccounts._determineRelatedDomains()

    def save(self) -> None:
        """
        Save domain accounts to JSON file sorted by domain name.
        """

        ### sort accounts by domain name for saving
        filedata = collections.OrderedDict()
        for key, accdata in sorted(self.domains.items()):
            filedata[key] = accdata

        ### convert sorted domain accounts to JSON string
        filedata = json.dumps(filedata, indent=4, **JSON5_DUMP_KWARGS)

        ### write JSON string
        with open(self._jsonpath, mode="wt") as file:
            file.write(filedata)
    # --- /DomainAccounts.save()

    def get(self, key:str) -> typing.Union[dict,None]:
        """
        Gets domain account for a domain key.

        Result is enhanced with additional data for processing and display.
        DO NOT use for account data that will be saved to domain accounts file.
        """

        try:
            accdata = collections.OrderedDict(self.domains[key])
        except KeyError as e:
            return None

        self._enhanceEntry(key=key, accdata=accdata)

        return accdata
    # --- /DomainAccounts.get()

    def add(self, key:str, fulldomain:str, subdomain:str,
            username:str, password:str,
            server_url:str,
            server_path_change:str,
            server_path_clean:str,
            server_path_deregister:str,
            server_path_register:str,
            server_path_update:str,
            allowfrom:typing.Union[list,None]=None) -> typing.Union[dict,None]:
        """
        Adds domain account for domain key.
        The domain key is sanitized down to the normal domain.
        Useful to add already existing domain registration from another client and/or machine.

        Result is enhanced with additional data for processing and display.
        DO NOT use result for account data that will be saved to domain accounts file.

        Only one domain account is needed for normal and wildcard certificate entries.
        """

        key = self.sanitizeDomain(key=key)

        if key in self.domains:
            return None

        accdata = collections.OrderedDict()
        #
        accdata[self.ATTR_FULLDOMAIN] = fulldomain
        accdata[self.ATTR_SUBDOMAIN] = subdomain
        accdata[self.ATTR_USERNAME] = username
        accdata[self.ATTR_PASSWORD] = password
        if server_url and not server_url.endswith("/"):
            server_url = "/".join((server_url, ""))
        accdata[self.ATTR_SERVER_URL] = server_url
        #
        accdata[self.ATTR_SERVER_URL_PATH_CHANGE] = server_path_change.lstrip("/")
        accdata[self.ATTR_SERVER_URL_PATH_CLEAN] = server_path_clean.lstrip("/")
        accdata[self.ATTR_SERVER_URL_PATH_DEREGISTER] = server_path_deregister.lstrip("/")
        accdata[self.ATTR_SERVER_URL_PATH_REGISTER] = server_path_register.lstrip("/")
        accdata[self.ATTR_SERVER_URL_PATH_UPDATE] = server_path_update.lstrip("/")
        #
        accdata[self.ATTR_ADDED_ON] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        accdata[self.ATTR_ADDED_VIA] = "add"
        #
        if allowfrom:
            accdata[self.ATTR_ALLOW_FROM] = allowfrom
        else:
            accdata[self.ATTR_ALLOW_FROM] = []

        self.domains[key] = collections.OrderedDict(accdata)

        self._enhanceEntry(key=key, accdata=accdata)

        return accdata
    # --- /DomainAccounts.add()

    def remove(self, key:str) -> bool:
        """
        Removes domain account for a domain key.
        """

        try:
            del self.domains[key]
        except KeyError as e:
            return False

        return True
    # --- /DomainAccounts.remove()

    def rename(self, key_from:str, key_to:str) -> typing.Tuple[typing.Union[dict,None],str]:
        """
        Renames domain key for a domain account.

        Result is enhanced with additional data for processing and display.
        DO NOT use result for account data that will be saved to domain accounts file.
        """

        if key_to in self.domains:
            return None, "Domain account for \"{domain:s}\" already exists".format(domain=key_to)

        try:
            accdata = collections.OrderedDict(self.domains[key_from])
        except KeyError as e:
            return None, "Domain account for \"{domain:s}\" does not exist".format(domain=key_from)

        self.domains[key_to] = collections.OrderedDict(accdata)
        del self.domains[key_from]

        self._enhanceEntry(key=key_to, accdata=accdata)

        return accdata, "Domain renamed"
    # --- /DomainAccounts.get()

    @classmethod
    def _setApiHeaders(cls, accdata:typing.Union[dict,None]) -> dict:
        """
        Creates HTTP headers for acme-dns server API.
        If account data is present, then header entries for username and password will be created.
        """

        api_headers = {}
        api_headers["Content-Type"] = "application/json; charset=utf8"

        if accdata:
            api_headers["X-Api-User"] = accdata[cls.ATTR_USERNAME]
            api_headers["X-Api-Key"] = accdata[cls.ATTR_PASSWORD]

        return api_headers
    # --- /DomainAccounts._setApiHeaders()

    @classmethod
    def _setApiData(cls, accdata:typing.Union[dict,None]) -> dict:
        """
        Creates HTTP POST data for acme-dns server API.
        If account data is present, then entry for subdomain will be created.
        """

        api_data = {}

        if accdata:
            api_data[cls.ATTR_SUBDOMAIN] = accdata[cls.ATTR_SUBDOMAIN]

        return api_data
    # --- /DomainAccounts._setApiData()

    def register(self, key:str,
                 server_url:str,
                 server_path_change:str,
                 server_path_clean:str,
                 server_path_deregister:str,
                 server_path_register:str,
                 server_path_update:str,
                 allowfrom:typing.Union[list,None]=None) -> typing.Tuple[typing.Union[dict,None],str,int]:
        """
        Registers a new domain account for domain key via acme-dns server API.
        The domain key is sanitized down to the normal domain.

        Result is enhanced with additional data for processing and display.
        DO NOT use result for account data that will be saved to domain accounts file.

        Only one domain account is needed for normal and wildcard certificate entries.
        """

        key = self.sanitizeDomain(key=key)

        if key in self.domains:
            return None, "Domain account for \"{domain:s}\" already exists".format(domain=key), -1

        request_headers = self._setApiHeaders(accdata=None)

        request_data = self._setApiData(accdata=None)
        if allowfrom:
            request_data[self.ATTR_ALLOW_FROM] = allowfrom

        ### convert request data into JSON format; post() json parameter = requests 2.4.2+
        request_data = json.dumps(request_data, **JSON5_DUMP_KWARGS)

        ### sanitize arguments
        if server_url and not server_url.endswith("/"):
            server_url = "/".join((server_url, ""))
        server_path_register = server_path_register.lstrip("/")

        request_url = urllib.parse.urljoin(server_url, server_path_register)
        request_response = requests.post(
            url=request_url,
            headers=request_headers,
            data=request_data,
        )

        message = ""

        if request_response.status_code != requests.codes.CREATED:
            message = "{code:d} Error: \"{reason:s}\" for URL \"{url}\"".format(code=request_response.status_code, reason=request_response.reason, url=request_response.url)
            #
            try:
                text = request_response.json()
                text = json.dumps(text, indent=4, **JSON5_DUMP_KWARGS)
            except requests.JSONDecodeError as e:
                text = request_response.text.rstrip("\n")
            message = "\n".join((message, text))
            #
            return None, message, request_response.status_code

        apiaccdata = request_response.json()

        accdata = collections.OrderedDict()
        #
        accdata[self.ATTR_FULLDOMAIN] = apiaccdata.pop(self.ATTR_FULLDOMAIN)
        accdata[self.ATTR_SUBDOMAIN] = apiaccdata.pop(self.ATTR_SUBDOMAIN)
        accdata[self.ATTR_USERNAME] = apiaccdata.pop(self.ATTR_USERNAME)
        accdata[self.ATTR_PASSWORD] = apiaccdata.pop(self.ATTR_PASSWORD)
        accdata[self.ATTR_SERVER_URL] = server_url
        #
        try:
            accdata[self.ATTR_SERVER_URL_PATH_CHANGE] = apiaccdata.pop(self.ATTR_SERVER_URL_PATH_CHANGE).lstrip("/")
        except KeyError as e:
            accdata[self.ATTR_SERVER_URL_PATH_CHANGE] = server_path_change.lstrip("/")
        #
        try:
            accdata[self.ATTR_SERVER_URL_PATH_CLEAN] = apiaccdata.pop(self.ATTR_SERVER_URL_PATH_CLEAN).lstrip("/")
        except KeyError as e:
            accdata[self.ATTR_SERVER_URL_PATH_CLEAN] = server_path_clean.lstrip("/")
        #
        try:
            accdata[self.ATTR_SERVER_URL_PATH_DEREGISTER] = apiaccdata.pop(self.ATTR_SERVER_URL_PATH_DEREGISTER).lstrip("/")
        except KeyError as e:
            accdata[self.ATTR_SERVER_URL_PATH_DEREGISTER] = server_path_deregister.lstrip("/")
        #
        accdata[self.ATTR_SERVER_URL_PATH_REGISTER] = server_path_register
        #
        try:
            accdata[self.ATTR_SERVER_URL_PATH_UPDATE] = apiaccdata.pop(self.ATTR_SERVER_URL_PATH_UPDATE).lstrip("/")
        except KeyError as e:
            accdata[self.ATTR_SERVER_URL_PATH_UPDATE] = server_path_update.lstrip("/")
        #
        accdata[self.ATTR_ADDED_ON] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        accdata[self.ATTR_ADDED_VIA] = "register"

        ### keep additional data
        accdata.update(apiaccdata)

        self.domains[key] = collections.OrderedDict(accdata)

        self._enhanceEntry(key=key, accdata=accdata)

        return accdata, message, request_response.status_code
    # --- /DomainAccounts.register()

    @classmethod
    def update(cls, accdata:dict, token:str) -> typing.Tuple[bool,str,int]:
        """
        Updates challenge token for domain account on the related acme-dns server with given token.

        acme-dns server holds two (2) rolling TXT challenge tokens, so no need to clean up TXT records.
        """

        if not accdata:
            return False, "Missing domain account data", -1

        request_headers = cls._setApiHeaders(accdata=accdata)

        request_data = cls._setApiData(accdata=accdata)
        request_data["txt"] = token

        ### convert request data into JSON format; post() json parameter = requests 2.4.2+
        request_data = json.dumps(request_data, **JSON5_DUMP_KWARGS)

        request_url = urllib.parse.urljoin(accdata[cls.ATTR_SERVER_URL], accdata[cls.ATTR_SERVER_URL_PATH_UPDATE])
        request_response = requests.post(
            url=request_url,
            headers=request_headers,
            data=request_data,
        )

        message = ""

        if request_response.status_code != requests.codes.OK:
            message = "{code:d} Error: \"{reason:s}\" for URL \"{url}\"".format(code=request_response.status_code, reason=request_response.reason, url=request_response.url)
            #
            try:
                text = request_response.json()
                text = json.dumps(text, indent=4, **JSON5_DUMP_KWARGS)
            except requests.JSONDecodeError as e:
                text = request_response.text.rstrip("\n")
            message = "\n".join((message, text))
            #
            return False, message, request_response.status_code

        return True, message, request_response.status_code
    # --- /DomainAccounts.update()

    @classmethod
    def deregister(cls, accdata:dict) -> typing.Tuple[bool,str,int]:
        """
        [FUTURE] possible functionality
        Deregisters domain account on the related acme-dns server.
        """

        if not accdata:
            return False, "Missing domain account data", -1

        request_headers = cls._setApiHeaders(accdata=accdata)

        request_data = cls._setApiData(accdata=accdata)

        ### convert request data into JSON format; post() json parameter = requests 2.4.2+
        request_data = json.dumps(request_data, **JSON5_DUMP_KWARGS)

        request_url = urllib.parse.urljoin(accdata[cls.ATTR_SERVER_URL], accdata[cls.ATTR_SERVER_URL_PATH_DEREGISTER])
        request_response = requests.post(
            url=request_url,
            headers=request_headers,
            data=request_data,
        )

        message = ""

        if request_response.status_code != requests.codes.OK:
            message = "{code:d} Error: \"{reason:s}\" for URL \"{url}\"".format(code=request_response.status_code, reason=request_response.reason, url=request_response.url)
            #
            try:
                text = request_response.json()
                text = json.dumps(text, indent=4, **JSON5_DUMP_KWARGS)
            except requests.JSONDecodeError as e:
                text = request_response.text.rstrip("\n")
            message = "\n".join((message, text))
            #
            return False, message, request_response.status_code

        return True, message, request_response.status_code
    # --- /DomainAccounts.deregister()

    @classmethod
    def clean(cls, accdata:dict, token:str) -> typing.Tuple[bool,str,int]:
        """
        [FUTURE] possible functionality
        Cleans challenge token for domain account on the related acme-dns server.
        """

        if not accdata:
            return False, "Missing domain account data", -1

        request_headers = cls._setApiHeaders(accdata=accdata)

        request_data = cls._setApiData(accdata=accdata)
        request_data["txt"] = token

        ### convert request data into JSON format; post() json parameter = requests 2.4.2+
        request_data = json.dumps(request_data, **JSON5_DUMP_KWARGS)

        request_url = urllib.parse.urljoin(accdata[cls.ATTR_SERVER_URL], accdata[cls.ATTR_SERVER_URL_PATH_CLEAN])
        request_response = requests.post(
            url=request_url,
            headers=request_headers,
            data=request_data,
        )

        message = ""

        if request_response.status_code != requests.codes.OK:
            message = "{code:d} Error: \"{reason:s}\" for URL \"{url}\"".format(code=request_response.status_code, reason=request_response.reason, url=request_response.url)
            #
            try:
                text = request_response.json()
                text = json.dumps(text, indent=4, **JSON5_DUMP_KWARGS)
            except requests.JSONDecodeError as e:
                text = request_response.text.rstrip("\n")
            message = "\n".join((message, text))
            #
            return False, message, request_response.status_code

        return True, message, request_response.status_code
    # --- /DomainAccounts.clean()

    def change(self, accdata:dict, allowfrom:typing.Union[list,None]=None) -> typing.Tuple[typing.Union[dict,None],str,int]:
        """
        [FUTURE] possible functionality
        Changes domain account data on the related acme-dns server.

        Change values of None are not send to the server and therefore not changed.
        e.g. if "allowfrom" shall be cleared out, then set an empty list []

        Result is enhanced with additional data for processing and display.
        DO NOT use result for account data that will be saved to domain accounts file.
        """

        if not accdata:
            return None, "Missing domain account data", -1

        request_headers = self._setApiHeaders(accdata=accdata)

        request_data = self._setApiData(accdata=accdata)

        ### set to be changed fields
        Change = False

        if allowfrom is not None:
            request_data[self.ATTR_ALLOW_FROM] = allowfrom
            Change = True

        if not Change:
            return None, "Nothing to change", 0

        ### convert request data into JSON format; post() json parameter = requests 2.4.2+
        request_data = json.dumps(request_data, **JSON5_DUMP_KWARGS)

        request_url = urllib.parse.urljoin(accdata[self.ATTR_SERVER_URL], accdata[self.ATTR_SERVER_URL_PATH_CHANGE])
        request_response = requests.post(
            url=request_url,
            headers=request_headers,
            data=request_data,
        )

        message = ""

        if request_response.status_code != requests.codes.OK:
            message = "{code:d} Error: \"{reason:s}\" for URL \"{url}\"".format(code=request_response.status_code, reason=request_response.reason, url=request_response.url)
            #
            try:
                text = request_response.json()
                text = json.dumps(text, indent=4, **JSON5_DUMP_KWARGS)
            except requests.JSONDecodeError as e:
                text = request_response.text.rstrip("\n")
            message = "\n".join((message, text))
            #
            return None, message, request_response.status_code

        apiaccdata = request_response.json()
        ### remove fixed entries
        del apiaccdata[self.ATTR_FULLDOMAIN]
        del apiaccdata[self.ATTR_SUBDOMAIN]
        del apiaccdata[self.ATTR_USERNAME]
        del apiaccdata[self.ATTR_PASSWORD]

        key = accdata[self.ATTR_KEY]
        accdata = collections.OrderedDict(self.domains[key])
        try:
            del accdata[self.ATTR_ALLOW_FROM]
        except KeyError as e:
            pass

        ### update additional data
        accdata.update(apiaccdata)

        self.domains[key] = collections.OrderedDict(accdata)

        self._enhanceEntry(key=key, accdata=accdata)

        return accdata, message, request_response.status_code
    # --- /DomainAccounts.change()

    @classmethod
    def _check_cname(cls, accdata:dict, resolve_func:typing.Callable[...,dns.resolver.Answer]) -> typing.Tuple[bool,str]:
        try:
            ### https://dnspython.readthedocs.io/en/stable/resolver-class.html#dns.resolver.Resolver.resolve
            dns_answers = resolve_func(qname=accdata[cls.ATTR_DOMAIN_CHALLENGE], rdtype=dns.rdatatype.CNAME)
        except dns.exception.DNSException as e:
            return False, "CNAME missing (DNS)\n{record:s}".format(record=accdata[cls.ATTR_DOMAIN_CNAME_RECORD])

        ### https://dnspython.readthedocs.io/en/stable/resolver-class.html#dns.resolver.Answer
        ### https://dnspython.readthedocs.io/en/stable/rdata-set-classes.html#dns.rrset.RRset
        for answer in dns_answers:
            if answer.to_text() == accdata[cls.ATTR_DOMAIN_CNAME_ENTRY]:
                return True, "Correct CNAME found (DNS)"

        return False, "INCORRECT CNAME found (DNS). Expected\n{record:s}".format(record=accdata[cls.ATTR_DOMAIN_CNAME_RECORD])
    # --- /DomainAccounts._check_cname()

    @classmethod
    def _check_txt(cls, accdata:dict, resolve_func:typing.Callable[...,dns.resolver.Answer]) -> typing.Tuple[bool,str]:
        try:
            ### https://dnspython.readthedocs.io/en/stable/resolver-class.html#dns.resolver.Resolver.resolve
            dns_answers = resolve_func(qname=accdata[cls.ATTR_DOMAIN_CHALLENGE], rdtype=dns.rdatatype.TXT)
        except dns.exception.DNSException as e:
            return False, "TXT missing (acme-dns: either DNS (NS, A/AAAA or glue record) or setup (domain not updated once yet? deregistered?)"

        return True, "TXT available (acme-dns)"
    # --- /DomainAccounts._check_txt()

    @classmethod
    def check(cls, accdata:dict, nameservers:list) -> typing.Tuple[bool,str]:
        """
        Checks DNS setup for domain account
        - correct CNAME entry of challenge domain to acme-dns fulldomain
        - TXT records are served for the challenge domain
        """

        if not accdata:
            return False, "Missing domain account data"

        dns_resolver = dns.resolver.Resolver()
        dns_resolver.nameservers = nameservers
        if "resolve" in dir(dns_resolver):
            resolve_func = dns_resolver.resolve
        else:
            ### Workaround for dnspython 1.6 with Python 3.5
            resolve_func = dns_resolver.query

        message = ""
        sep = ", "

        ### check CNAME record of challenge domain
        subresult = cls._check_cname(accdata=accdata, resolve_func=resolve_func)
        message = subresult[1]

        if subresult[0]:
            ### check TXT record for challenge domain
            subresult = cls._check_txt(accdata=accdata, resolve_func=resolve_func)
            message = sep.join((message, subresult[1]))

        ### final result
        result = subresult[0]

        return result, message
    # --- /DomainAccounts.check()

### ----------------------------------------
### --- /Class DomainAccounts
### ----------------------------------------

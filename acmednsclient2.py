#!/bin/false
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: nil; py-indent-offset: 4 -*-

"""
Module for acme-dns Clients

License: GPLv2 - https://www.gnu.org/licenses/gpl-2.0.html

Targeted Python Version: 3.5 (Debian 9 "Stretch"), taking Python 3.12 into account
- only function parameter annotations; no variable annotations (=3.6+)
- use collections.OrderedDict() to keep keys in order of addition

Authors:
- Matthias "Maddes" Bücher <maddes@maddes.net>
"""
### TODO: complete docstrings


__version__ = "0.8.0"
__author__ = "Matthias \"Maddes\" Bücher"
__license__ = "GPLv2"
__copyright__ = "Copyright (C) 2024 Matthias \"Maddes\" Bücher"
__homepage__ = "https://github.com/maddes-b/acme-dns-client-2"
__contact__ = __homepage__


### python standard modules
import collections
import datetime
import json
import os
import typing

### 3rd-party modules
## https://pypi.org/project/dnspython/
import dns.exception
import dns.rdatatype
import dns.resolver
## https://pypi.org/project/requests/
import requests


### ----------------------------------------
### --- Class Configuration
### ----------------------------------------
class Configuration:
    """
    Handles configuration for acme-dns-client-2

    Defines default configuration and loads settings from a JSON configuration file.
    Configuration is kept in dictionary `.settings`. Use ATTR_ constants to access the settings.

    Provides constants (all uppercase) for default values plus attribute names of settings.
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

    ### Constants of setting attribute names in configuration
    ATTR_PATH_CONFIG = "configpath"
    ATTR_PATH_ACCOUNTS = "accountspath"
    ATTR_IPS_NAME_SERVERS = "nameservers"
    ATTR_URL_DEFAULT_SERVER = "default_server"

    def __init__(self, configpath:str, accountspath:typing.Union[str,None]=None) -> None:
        """
        Stores given arguments separately to rebuild defaults at any time.
        Creates dictionary for configuration settings and loads further configuration from the given JSON file.
        """

        ### keep given arguments separately
        self._jsonpath = configpath
        self._accountspath = accountspath

        ### create dictionary for settings
        self.settings = collections.OrderedDict()

        ### load configuration from JSON file if available, sets defaults first
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
        self.settings[self.ATTR_IPS_NAME_SERVERS] = list(self.DEFAULT_NAME_SERVERS)
    # --- /Configuration._resetWithDefaults()

    def _loadFromFile(self) -> None:
        """
        First initializes configuration with defaults.
        Then loads configuration from JSON file if available.

        Special configuration settings CANNOT be overwritten by the configuration file:
        - the configuration file path itself
        - the domains accounts file path if given explicitly on class object instantiation

        Additional unknown settings are kept to avoid issues with other client implementations and/or other versions.
        """

        ### clear configuration and set defaults
        self._resetWithDefaults()

        ### check if JSON file exists
        if not os.path.exists(self._jsonpath):
            return

        filedata = None
        with open(self._jsonpath, mode="r") as fd:
            filedata = json.load(fd)

        for key, fileconfigdata in filedata.items():
            ### do not overwrite some specific keys
            if key == self.ATTR_PATH_CONFIG:
                continue
            if key == self.ATTR_PATH_ACCOUNTS \
            and self._accountspath is not None:
                continue

            if key in self.settings:
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
    key = to be authorized target domain
    (full|sub)domain = CNAMEd acme-dns domain
    server_url = base URL of acme-dns API
    """

    ### attributes of API
    ATTR_FULLDOMAIN = "fulldomain"
    ATTR_SUBDOMAIN = "subdomain"
    ATTR_USERNAME = "username"
    ATTR_PASSWORD = "password"
    ATTR_ALLOW_FROM = "allowfrom"

    ### additional attributes of clients
    ATTR_SERVER_URL = "server_url"
    ATTR_ADDED_ON = "added_on"
    ATTR_ADDED_VIA = "added_via"

    ### virtual attributes of client
    ATTR_KEY = "key"
    ATTR_DOMAIN_CHALLENGE = "challengedomain"
    ATTR_DOMAIN_CNAME_ENTRY = "cnameentry"
    ATTR_DOMAIN_CNAME_RECORD = "cnamerecord"

    ### misc constants
    DOMAIN_CHALLENGE_PREFIX = "_acme-challenge."
    TOKEN_DUMMY = "-DUMMY-DUMMY-DUMMY-DUMMY-DUMMY-DUMMY-DUMMY-"

    def __init__(self, accountspath:str) -> None:
        """
        Creates dictionary for domain acounts and loads accounts from the given JSON file.
        """

        ### keep given arguments separately
        self._jsonpath = accountspath

        ### create dictionary for domain accounts
        self.domains = collections.OrderedDict()

        ### load from domain accounts file if available
        self._loadFromFile()
    # --- /DomainAccounts.__init__()

    def _loadFromFile(self) -> None:
        """
        First clears domain accounts.
        Then loads account domains from JSON file if available.

        Additional unknown data entries are kept to avoid issues with other client implementations and/or other versions.
        """

        self.domains.clear()

        if not os.path.exists(self._jsonpath):
            return

        filedata = None
        with open(self._jsonpath, mode="r") as fd:
            filedata = json.load(fd)

        for key, fileaccdata in sorted(filedata.items()):
            accdata = collections.OrderedDict()
            #
            accdata[self.ATTR_FULLDOMAIN] = fileaccdata.pop(self.ATTR_FULLDOMAIN)
            accdata[self.ATTR_SUBDOMAIN] = fileaccdata.pop(self.ATTR_SUBDOMAIN)
            accdata[self.ATTR_USERNAME] = fileaccdata.pop(self.ATTR_USERNAME)
            accdata[self.ATTR_PASSWORD] = fileaccdata.pop(self.ATTR_PASSWORD)
            accdata[self.ATTR_SERVER_URL] = fileaccdata.pop(self.ATTR_SERVER_URL)
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

            self.domains[key] = collections.OrderedDict(accdata)
    # --- /DomainAccounts._loadFromFile()

    @classmethod
    def sanitizeDomain(cls, key:str) -> str:
        """
        Removes unwanted prefixes, until all removed and the normal domain is left:
        - '*.' from wildcard certificate domains
        - '_acme-challenge.' from challenge domains

        Allow usage from ACME clients that may not provide the base domain as-is.
        """

        while True:
            if key.startswith("*."):
                key = key[2:]
                continue
            if key.startswith(cls.DOMAIN_CHALLENGE_PREFIX):
                key = key[len(cls.DOMAIN_CHALLENGE_PREFIX):]
                continue
            break

        return key
    # --- /DomainAccounts.sanitizeDomain()

    @classmethod
    def _enhanceEntry(cls, key:str, accdata:dict) -> None:
        """
        Enhance a domain account with additional data for processing and display.
        - DNS related data (CNAME entry and its components)
        - Domain as key of domain account

        DO NOT use for account data that will be saved to domain accounts file.
        """

        accdata[cls.ATTR_KEY] = key

        accdata.update(cls._determineRelatedDomains(accdata))
    # --- /DomainAccounts._enhanceEntry()

    @classmethod
    def _determineRelatedDomains(cls, accdata:dict) -> dict:
        """
        Determines DNS related data for a domain and returns them as a dictionary.
        """

        result = collections.OrderedDict()
        result[cls.ATTR_DOMAIN_CHALLENGE] = "{prefix:s}{domain:s}.".format(prefix=cls.DOMAIN_CHALLENGE_PREFIX, domain=accdata[cls.ATTR_KEY])
        result[cls.ATTR_DOMAIN_CNAME_ENTRY] = "{domain:s}.".format(domain=accdata[cls.ATTR_FULLDOMAIN])
        result[cls.ATTR_DOMAIN_CNAME_RECORD] = "{prefix:s}{domain1:s}. IN CNAME {domain2:s}.".format(prefix=cls.DOMAIN_CHALLENGE_PREFIX, domain1=accdata[cls.ATTR_KEY], domain2=accdata[cls.ATTR_FULLDOMAIN])

        return result
    # --- /DomainAccounts._determineRelatedDomains()

    def save(self) -> None:
        """
        Save domains accounts to JSON file.

        Directory and file are created if they do not exist
        """

        ### Check directory and create it if it doesn't exist
        jsondir = os.path.dirname(self._jsonpath)
        if not os.path.exists(jsondir):
            os.makedirs(jsondir, mode=0o0777, exist_ok=False)

        ### sort accounts on domain key for saving
        filedata = collections.OrderedDict()
        for key, accdata in sorted(self.domains.items()):
            filedata[key] = accdata

        ### write sorted domain accounts
        with os.fdopen(os.open(self._jsonpath, flags=os.O_WRONLY|os.O_TRUNC|os.O_CREAT, mode=0o0600), mode="w") as fd:
            json.dump(filedata, fd, indent=4)
    # --- /DomainAccounts.save()

    def get(self, key:str) -> typing.Union[dict,None]:
        """
        Gets domain account data for a domain key.

        Result is enhanced with additional data for processing and display.
        DO NOT use for account data that will be saved to domain accounts file.
        """

        try:
            accdata = collections.OrderedDict(self.domains[key])
        except KeyError as e:
            return None

        self._enhanceEntry(key, accdata)

        return accdata
    # --- /DomainAccounts.get()

    def add(self, key:str, fulldomain:str, subdomain:str, username:str, password:str, server_url:str, allowfrom:typing.Union[list,None]=None) -> typing.Union[dict,None]:
        """
        Adds domain account data for a domain key.
        The domain key is sanitized down to the base domain.
        Only one domain account is needed for normal and wildcard certificate entries.

        Useful to add already existing domain registration from another client and/or machine.
        """

        key = self.sanitizeDomain(key)

        if key in self.domains:
            return None

        accdata = collections.OrderedDict()
        #
        accdata[self.ATTR_FULLDOMAIN] = fulldomain
        accdata[self.ATTR_SUBDOMAIN] = subdomain
        accdata[self.ATTR_USERNAME] = username
        accdata[self.ATTR_PASSWORD] = password
        accdata[self.ATTR_SERVER_URL] = server_url
        #
        accdata[self.ATTR_ADDED_ON] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        accdata[self.ATTR_ADDED_VIA] = "add"
        #
        if allowfrom:
            accdata[self.ATTR_ALLOW_FROM] = allowfrom

        self.domains[key] = collections.OrderedDict(accdata)

        self._enhanceEntry(key, accdata)

        return accdata
    # --- /DomainAccounts.add()

    def remove(self, key:str) -> bool:
        try:
            del self.domains[key]
        except KeyError as e:
            return False

        return True
    # --- /DomainAccounts.remove()

    def rename(self, key_from:str, key_to:str) -> typing.Union[dict,None]:
        """
        Rename domain key for a domain account.
        WARNING! Overwrites existing target domain if available.

        Result is enhanced with additional data for processing and display.
        DO NOT use for account data that will be saved to domain accounts file.
        """

        try:
            accdata = collections.OrderedDict(self.domains[key_from])
            self.domains[key_to] = collections.OrderedDict(accdata)
            del self.domains[key_from]
        except KeyError as e:
            return None

        self._enhanceEntry(key_to, accdata)

        return accdata
    # --- /DomainAccounts.get()

    @classmethod
    def _setApiHeaders(cls, accdata:typing.Union[dict,None]) -> dict:
        api_headers = {}
        api_headers["Content-Type"] = "application/json; charset=utf8"

        if accdata:
            api_headers["X-Api-User"] = accdata[cls.ATTR_USERNAME]
            api_headers["X-Api-Key"] = accdata[cls.ATTR_PASSWORD]

        return api_headers
    # --- /DomainAccounts._setApiHeaders()

    @classmethod
    def _setApiData(cls, accdata:typing.Union[dict,None]) -> dict:
        api_data = {}

        if accdata:
            api_data[cls.ATTR_SUBDOMAIN] = accdata[cls.ATTR_SUBDOMAIN]

        return api_data
    # --- /DomainAccounts._setApiData()

    def register(self, key:str, server_url:str, allowfrom:typing.Union[list,None]=None) -> typing.Tuple[typing.Union[dict,None],str,int]:
        key = self.sanitizeDomain(key)

        if key in self.domains:
            return None, "Domain account data already exist", -1

        request_headers = self._setApiHeaders(None)

        request_data = self._setApiData(None)
        if allowfrom:
            request_data[self.ATTR_ALLOW_FROM] = allowfrom

        request_response = requests.post(
            url="{server_url:s}/register".format(server_url=server_url),
            headers=request_headers,
            data=json.dumps(request_data), ### json parameter = requests 2.4.2+
        )

        message = ""

        if request_response.status_code != requests.codes.CREATED:
            message = "{code:d} Error: \"{reason:s}\" for URL \"{url}\"".format(code=request_response.status_code, reason=request_response.reason, url=request_response.url)
            #
            try:
                text = json.dumps(request_response.json(), indent=4)
            except:
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
        accdata[self.ATTR_ADDED_ON] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        accdata[self.ATTR_ADDED_VIA] = "register"

        ### keep additional data
        accdata.update(apiaccdata)

        self.domains[key] = collections.OrderedDict(accdata)

        self._enhanceEntry(key, accdata)

        return accdata, message, request_response.status_code
    # --- /DomainAccounts.register()

    @classmethod
    def update(cls, accdata:dict, token:str) -> typing.Tuple[bool,str,int]:
        if not accdata:
            return False, "Missing domain account data", -1

        request_headers = cls._setApiHeaders(accdata)

        request_data = cls._setApiData(accdata)
        request_data["txt"] = token

        request_response = requests.post(
            url="{server_url:s}/update".format(server_url=accdata[cls.ATTR_SERVER_URL]),
            headers=request_headers,
            data=json.dumps(request_data), ### json parameter = requests 2.4.2+
        )

        message = ""

        if request_response.status_code != requests.codes.OK:
            message = "{code:d} Error: \"{reason:s}\" for URL \"{url}\"".format(code=request_response.status_code, reason=request_response.reason, url=request_response.url)
            #
            try:
                text = json.dumps(request_response.json(), indent=4)
            except:
                text = request_response.text.rstrip("\n")
            message = "\n".join((message, text))
            #
            return False, message, request_response.status_code

        return True, message, request_response.status_code
    # --- /DomainAccounts.update()

    @classmethod
    def deregister(cls, accdata:dict) -> typing.Tuple[bool,str,int]:
        if not accdata:
            return False, "Missing domain account data", -1

        request_headers = cls._setApiHeaders(accdata)

        request_data = cls._setApiData(accdata)

        request_response = requests.post(
            url="{server_url:s}/deregister".format(server_url=accdata[cls.ATTR_SERVER_URL]),
            headers=request_headers,
            data=json.dumps(request_data), ### json parameter = requests 2.4.2+
        )

        message = ""

        if request_response.status_code != requests.codes.OK:
            message = "{code:d} Error: \"{reason:s}\" for URL \"{url}\"".format(code=request_response.status_code, reason=request_response.reason, url=request_response.url)
            #
            if request_response.status_code == requests.codes.NOT_FOUND:
                text = "NOT SUPPORTED by server. OK."
            else:
                try:
                    text = json.dumps(request_response.json(), indent=4)
                except:
                    text = request_response.text.rstrip("\n")
            message = "\n".join((message, text))
            #
            return False, message, request_response.status_code

        return True, message, request_response.status_code
    # --- /DomainAccounts.deregister()

    @classmethod
    def clean(cls, accdata:dict, token:str) -> typing.Tuple[bool,str,int]:
        if not accdata:
            return False, "Missing domain account data", -1

        request_headers = cls._setApiHeaders(accdata)

        request_data = cls._setApiData(accdata)
        request_data["txt"] = token

        request_response = requests.post(
            url="{server_url:s}/clean".format(server_url=accdata[cls.ATTR_SERVER_URL]),
            headers=request_headers,
            data=json.dumps(request_data), ### json parameter = requests 2.4.2+
        )

        message = ""

        if request_response.status_code != requests.codes.OK:
            message = "{code:d} Error: \"{reason:s}\" for URL \"{url}\"".format(code=request_response.status_code, reason=request_response.reason, url=request_response.url)
            #
            if request_response.status_code == requests.codes.NOT_FOUND:
                text = "NOT SUPPORTED by server. OK."
            else:
                try:
                    text = json.dumps(request_response.json(), indent=4)
                except:
                    text = request_response.text.rstrip("\n")
            message = "\n".join((message, text))
            #
            return False, message, request_response.status_code

        return True, message, request_response.status_code
    # --- /DomainAccounts.clean()

    def change(self, accdata:dict, allowfrom:typing.Union[list,None]) -> typing.Tuple[typing.Union[dict,None],str,int]:
        if not accdata:
            return None, "Missing domain account data", -1

        request_headers = self._setApiHeaders(accdata)

        request_data = self._setApiData(accdata)
        if allowfrom:
            request_data[self.ATTR_ALLOW_FROM] = allowfrom
        else:
            request_data[self.ATTR_ALLOW_FROM] = None ### explicit clear

        request_response = requests.post(
            url="{server_url:s}/change".format(server_url=accdata[self.ATTR_SERVER_URL]),
            headers=request_headers,
            data=json.dumps(request_data), ### json parameter = requests 2.4.2+
        )

        message = ""

        if request_response.status_code != requests.codes.OK:
            message = "{code:d} Error: \"{reason:s}\" for URL \"{url}\"".format(code=request_response.status_code, reason=request_response.reason, url=request_response.url)
            #
            if request_response.status_code == requests.codes.NOT_FOUND:
                text = "NOT SUPPORTED by server. OK."
            else:
                try:
                    text = json.dumps(request_response.json(), indent=4)
                except:
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

        self._enhanceEntry(key, accdata)

        return accdata, message, request_response.status_code
    # --- /DomainAccounts.change()

    @classmethod
    def _check_cname(cls, accdata:dict, dns_resolver:dns.resolver.Resolver, resolve_func) -> typing.Tuple[bool,str]:
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
    # --- /DomainAccounts.check()

    @classmethod
    def _check_txt(cls, accdata:dict, dns_resolver:dns.resolver.Resolver, resolve_func) -> typing.Tuple[bool,str]:
        try:
            ### https://dnspython.readthedocs.io/en/stable/resolver-class.html#dns.resolver.Resolver.resolve
            dns_answers = resolve_func(qname=accdata[cls.ATTR_DOMAIN_CHALLENGE], rdtype=dns.rdatatype.TXT)
        except dns.exception.DNSException as e:
            return False, "TXT missing (acme-dns: either DNS (NS, A/AAAA or glue record) or setup (domain not updated once yet? deregistered?)"

        return True, "TXT available (acme-dns)"
    # --- /DomainAccounts.check()

    @classmethod
    def check(cls, accdata:dict, nameservers:list) -> typing.Tuple[bool,str]:
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
        subresult = cls._check_cname(accdata, dns_resolver, resolve_func)
        message = subresult[1]

        if subresult[0]:
            ### check TXT record for challenge domain
            subresult = cls._check_txt(accdata, dns_resolver, resolve_func)
            message = sep.join((message, subresult[1]))

        ### final result
        result = subresult[0]

        return result, message
    # --- /DomainAccounts.check()

### ----------------------------------------
### --- /Class DomainAccounts
### ----------------------------------------

#!/usr/bin/env python
# -*- coding: utf-8; tab-width: 4; indent-tabs-mode: nil; py-indent-offset: 4 -*-

"""
acme-dns-client-2 for acme-dns servers - normally executed via related .sh file (due to Virtual Enviroment with required modules)
- the client script can be used directly to register a domains, check the DNS
  and acme-dns setup, and more. Execute with `[command] --help` for more details.
- default configuration can be displayed via `config` command
- the client script can be used as a manual authorization hook for dns-01
  challenges via `certbot` command.

License: GPLv2 - https://www.gnu.org/licenses/gpl-2.0.html

Targeted Python Version: 3.5 (Debian 9 "Stretch"), taking Python 3.12 into account
- only function parameter annotations; no variable annotations (=3.6+)

Authors:
- Matthias "Maddes" Bücher <maddes@maddes.net>
"""
### TODO: complete docstrings


__version__ = "0.9.0"
__author__ = "Matthias \"Maddes\" Bücher"
__license__ = "GPLv2"
__copyright__ = "Copyright (C) 2024 Matthias \"Maddes\" Bücher"
__homepage__ = "https://github.com/maddes-b/acme-dns-client-2"
__contact__ = __homepage__


### python standard modules
import argparse
import json
import os
import sys

### fix script name for argparse output
try:
    sys.argv[0] = os.environ["SCRIPT_PATH"]
except KeyError as e:
    pass
### allow local imports from script directory
sys.path.append(os.path.dirname(sys.argv[0]))

### local modules
import acmednsclient2


### ----------------------------------------
### --- Class Command
### ----------------------------------------
class Command:
    ADD = "add"
    CERTBOT = "certbot"
    CHANGE = "change"
    CHECK = "check"
    CLEAN = "clean"
    CONFIG = "config"
    DEREGISTER = "deregister"
    LIST = "list"
    REGISTER = "register"
    REMOVE = "remove"
    RENAME = "rename"
    SHOW = "show"
    UPDATE = "update"
    VERSION = "version"

### ----------------------------------------
### --- /Class Command
### ----------------------------------------


### ----------------------------------------
### --- ArgParse Setup
### --- https://docs.python.org/3/library/argparse.html
### ----------------------------------------
def createArgParser() -> argparse.ArgumentParser:
    ### Create description and epilog
    description = "\
%(prog)s v{version:s} (module v{version2:s})\n{copyright:s}\n{homepage:s}\n\
Client for acme-dns servers. Client can be used with certbot and acme.sh.".format(version=__version__, version2=acmednsclient2.__version__, copyright=__copyright__, homepage=__homepage__)
    epilog = "\
First register the domain on the acme-dns server via the `register` command. \
Existing registrations can also be imported into the config via the `add` command.\n\
Then setup the DNS records and verify the setup with the `check` command.\n\
Finally use this script as a certbot plugin via `--manual --preferred-challenges dns --manual-auth-hook '/path/to/{script:s} certbot'` to retrieve a certificate with certbot's `certonly` command.\n\
For acme.sh copy the wrapper script 'dns_acmednsclient2.sh' to '/path/to/acme.sh/dnsapi/' and use it via `--dns dns_acmednsclient2`.".format(script=os.path.basename(sys.argv[0]).replace(".py", ".sh"))

    Future = False

    ### Build Arg Parser
    parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawTextHelpFormatter)
    ### path to config file
    parser.add_argument("--config", action="store", default=os.path.join(acmednsclient2.Configuration.DEFAULT_DIR_CONFIG, acmednsclient2.Configuration.DEFAULT_FILE_CONFIG), help="path to configuration file")
    ### path to domain accounts file
    parser.add_argument("--accounts", action="store", default=None, help="path to domain accounts file")
    ### verbosity
    parser.add_argument("--verbose", "-v", action="count", default=0, help="increase verbosity")
    ### commands
    subparsers = parser.add_subparsers(title="commands", description=None, dest="command", help="Use `<command> --help` for details", metavar="command")
    #
    parser_add = subparsers.add_parser(Command.ADD, help="add an already registered domain (to client only)")
    parser_add.add_argument("--domain", "-d", action="store", required=True, help="domain to add")
    parser_add.add_argument("--fulldomain", "-f", action="store", required=True, help="related auth domain in full")
    parser_add.add_argument("--username", "-u", action="store", required=True, help="username of auth domain")
    parser_add.add_argument("--password", "-p", action="store", required=True, help="password of auth domain")
    parser_add.add_argument("--server", "-s", action="store", required=True, help="base URL of server with acme-dns API to register with")
    parser_add.add_argument("--allow", "-a", action="append", required=False, help="ip to allow updates from, can be specified multiple times (for completeness only)")
    parser_add.add_argument("--force", action="store_true", required=False, help="force addition if domain already registered (data loss)")
    #
    parser_certbot = subparsers.add_parser(Command.CERTBOT, help="run as manual-auth-hook with certbot")
    #
    if Future: ### possible future acme-dns functionality (security concerns?)
        parser_change = subparsers.add_parser(Command.CHANGE, help="change details of a registered domain (if supported by server)")
        parser_change.add_argument("--domain", "-d", action="store", required=True, help="domain to change details of")
        group = parser_change.add_mutually_exclusive_group(required=True)
        group.add_argument("--allow", "-a", action="append", help="ip to allow updates from, can be specified multiple times")
        group.add_argument("--allow-clear", action="store_true", help="clear allow from")
        group.add_argument("--allow-keep", action="store_true", help="keep allow from")
    #
    parser_check = subparsers.add_parser(Command.CHECK, help="check DNS setup of a registered domain")
    parser_check.add_argument("--domain", "-d", action="store", required=True, help="domain to check")
    #
    if Future: ### possible future acme-dns functionality
        parser_clean = subparsers.add_parser(Command.CLEAN, help="clean challenge token of a registered domain (if supported by server)")
        parser_clean.add_argument("--domain", "-d", action="store", required=True, help="domain to update")
        parser_clean.add_argument("--token", "-t", action="store", required=True, help="token to clean")
    #
    parser_config = subparsers.add_parser(Command.CONFIG, help="list configuration")
    #
    if Future: ### possible future acme-dns functionality (security concerns?)
        parser_deregister = subparsers.add_parser(Command.DEREGISTER, help="deregister a domain (if supported by server)")
        parser_deregister.add_argument("--domain", "-d", action="store", required=True, help="domain to deregister")
    #
    parser_list = subparsers.add_parser(Command.LIST, help="list registered domains")
    #
    parser_register = subparsers.add_parser(Command.REGISTER, help="register a domain")
    parser_register.add_argument("--domain", "-d", action="store", required=True, help="domain to register")
    parser_register.add_argument("--server", "-s", action="store", required=False, help="base URL of server with acme-dns API to register with")
    parser_register.add_argument("--allow", "-a", action="append", required=False, help="ip to allow updates from; can be specified multiple times")
    parser_register.add_argument("--force", action="store_true", required=False, help="force registeration if domain already registered (data loss)")
    #
    parser_remove = subparsers.add_parser(Command.REMOVE, help="remove a registered domain (from client only)")
    parser_remove.add_argument("--domain", "-d", action="store", required=True, help="domain to remove")
    #
    parser_rename = subparsers.add_parser(Command.RENAME, help="rename a registered domain")
    parser_rename.add_argument("--domain", "-d", action="store", required=True, help="domain to rename")
    parser_rename.add_argument("--new", "-n", action="store", required=True, help="new domain name")
    parser_rename.add_argument("--force", action="store_true", required=False, help="force rename if new domain name already exists (data loss)")
    #
    parser_show = subparsers.add_parser(Command.SHOW, help="show data for a registered domain")
    parser_show.add_argument("--domain", "-d", action="store", required=True, help="domain to show")
    #
    parser_update = subparsers.add_parser(Command.UPDATE, help="update challenge token of a registered domain")
    parser_update.add_argument("--domain", "-d", action="store", required=True, help="domain to update")
    group = parser_update.add_mutually_exclusive_group(required=True)
    group.add_argument("--token", "-t", action="store", help="new challenge token")
    group.add_argument("--dummy", action="store_true", help="use dummy challenge token")
    #
    parser_version = subparsers.add_parser(Command.VERSION, help="show program version")

    return parser
# --- /createArgParser()

### ----------------------------------------
### --- /ArgParse Setup
### ----------------------------------------


### ----------------------------------------
### --- Main
### ----------------------------------------
if __name__ == "__main__":
    ### Parse arguments from the command line
    Parser = createArgParser()
    Arguments = Parser.parse_args()
    if not Arguments.command:
        ### no functionality chosen
        Parser.print_help()
        sys.exit(1)

    ### Read configuration
    if not (Arguments.config and Arguments.config.strip()):
        print("Empty/whitespace-only configuration file specified. Specified via --config", file=sys.stderr)
        sys.exit(1)
    if Arguments.accounts is not None \
    and not (Arguments.accounts and Arguments.accounts.strip()):
        print("Empty/whitespace-only accounts file specified. Specified via --accounts", file=sys.stderr)
        sys.exit(1)
    #
    Config = acmednsclient2.Configuration(Arguments.config, Arguments.accounts)

    ### Read domain accounts
    Accounts = acmednsclient2.DomainAccounts(Config.settings[Config.ATTR_PATH_ACCOUNTS])

    ### Process command...
    ### show version
    if Arguments.command == Command.VERSION:
        if Arguments.verbose >= 1:
            print("{version:s} - Command Line Tool".format(version=__version__))
            print("{version:s} - Python Module".format(version=acmednsclient2.__version__))
        else:
            print(__version__)
        sys.exit(0)
    ### list configuration
    elif Arguments.command == Command.CONFIG:
        print(json.dumps(Config.settings, indent=4))
        sys.exit(0)
    ### list registered domains
    elif Arguments.command == Command.LIST:
        if not Accounts.domains:
            if Arguments.verbose >= 1:
                print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
                print("No domains registered", file=sys.stderr)
        else:
            if Arguments.verbose >= 1:
                print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]))
            for Key in Accounts.domains.keys():
                print("{domain:s}".format(domain=Key))
        sys.exit(0)
    ### show data for a registered domain
    elif Arguments.command == Command.SHOW:
        Key = Arguments.domain

        Data = Accounts.get(Key)
        if not Data:
            print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
            print("Domain \"{domain:s}\" not found".format(domain=Key), file=sys.stderr)
            Key_Clean = Accounts.sanitizeDomain(Key.strip())
            if Key_Clean != Key \
            and Key_Clean in Accounts.domains:
                print("Did you mean domain \"{domain:s}\"?".format(domain=Key_Clean), file=sys.stderr)
            sys.exit(1)

        if Arguments.verbose >= 1:
            print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]))
        print(json.dumps(Data, indent=4))
        sys.exit(0)
    ### add an already registered domain (to client only)
    ### register a domain
    elif Arguments.command == Command.ADD \
    or Arguments.command == Command.REGISTER:
        Key = None
        if Arguments.domain is not None:
            Key = Accounts.sanitizeDomain(Arguments.domain.strip())

        Server = None
        if Arguments.server is not None:
            Server = Arguments.server.strip()
            Server_Message = "Specified via --server"
        elif Config.settings[Config.ATTR_URL_DEFAULT_SERVER]:
            Server = Config.settings[Config.ATTR_URL_DEFAULT_SERVER].strip()
            Server_Message = "Specified via config file"
        else:
            Server_Message = "Specify via --server"

        if not Key \
        or not Server:
            if not Key:
                print("Empty/whitespace-only domain not allowed. Specified via --domain", file=sys.stderr)
            if not Server:
                print("Empty/whitespace-only server not allowed. {message:s}".format(message=Server_Message), file=sys.stderr)
            sys.exit(1)

        if Arguments.command == Command.ADD \
        and ( \
            not (Arguments.fulldomain and Arguments.fulldomain.strip()) \
            or not (Arguments.username and Arguments.username.strip()) \
            or not (Arguments.password and Arguments.password.strip()) \
        ):
            print("Empty/whitespace-only arguments not allowed", file=sys.stderr)
            sys.exit(1)

        if Arguments.force:
            Accounts.remove(Key)
        else:
            Data = Accounts.get(Key)
            if Data:
                print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
                print("Domain \"{domain:s}\" already exists".format(domain=Key), file=sys.stderr)
                if Arguments.verbose >= 1:
                    print(json.dumps(Data, indent=4), file=sys.stderr)
                sys.exit(1)

        if Arguments.command == Command.ADD:
            Subdomain = Arguments.fulldomain.split(".")[0]
            Data = Accounts.add(Key, Arguments.fulldomain, Subdomain, Arguments.username, Arguments.password, Server, allowfrom=Arguments.allow)
            if not Data:
                print("Domain \"{domain:s}\" could not be added".format(domain=Key), file=sys.stderr)
                sys.exit(1)
        elif Arguments.command == Command.REGISTER:
            Data, Message, Code = Accounts.register(Key, Server, allowfrom=Arguments.allow)
            if not Data:
                print("Domain \"{domain:s}\" could not be registered via {server:s}".format(domain=Key, server=Server), file=sys.stderr)
                print("Check server URL, acme-dns server and related DNS setup (NS, A/AAAA or glue records)", file=sys.stderr)
                print("{message:s}".format(message=Message), file=sys.stderr)
                sys.exit(1)
        else:
            ### AARRGGHH! chosen command not implemented
            print("ABORT! Command \"{command:s}\" not implemented!\nCheck out {homepage:s} for a newer version and/or related bug reports.".format(command=Arguments.command, homepage=__homepage__), file=sys.stderr)
            sys.exit(1)

        Accounts.save()
        print("Data added to {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]))
        print(json.dumps(Data, indent=4))
        print("Update DNS setup with the following CNAME record", file=sys.stderr)
        print(Data[Accounts.ATTR_DOMAIN_CNAME_RECORD], file=sys.stderr)
        print("Then use command `check` to verify. Maybe in conjuction with `watch -n 15 -- {prog:s} check ...`".format(prog=sys.argv[0]), file=sys.stderr)

        ### Add the first TXT record to a newly registered domain for checking the setup
        if Arguments.command == Command.REGISTER:
            result = Accounts.update(Data, Accounts.TOKEN_DUMMY)
            if not result[0]:
                print("Domain \"{domain:s}\" could not be updated with dummy token".format(domain=Key), file=sys.stderr)
                print("{message:s}".format(message=result[1]), file=sys.stderr)
                sys.exit(1)

        sys.exit(0)
    ### remove a registered domain (from client only)
    ### deregister a domain
    elif Arguments.command == Command.REMOVE \
    or Arguments.command == Command.DEREGISTER:
        Key = Arguments.domain

        Data = Accounts.get(Key)
        if not Data:
            print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
            print("Domain \"{domain:s}\" not found".format(domain=Key), file=sys.stderr)
            Key_Clean = Accounts.sanitizeDomain(Key.strip())
            if Key_Clean != Key \
            and Key_Clean in Accounts.domains:
                print("Did you mean domain \"{domain:s}\"?".format(domain=Key_Clean), file=sys.stderr)
            sys.exit(1)

        if Arguments.command == Command.DEREGISTER:
            result = Accounts.deregister(Data)
            if not result[0]:
                print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
                print("Domain \"{domain:s}\" could not be deregistered".format(domain=Key), file=sys.stderr)
                print("{message:s}".format(message=result[1]), file=sys.stderr)
                if result[2] == 404: ### URL not found, not supported by server
                    sys.exit(0)
                else:
                    sys.exit(1)

        if not Accounts.remove(Key):
            print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
            print("Domain \"{domain:s}\" not found".format(domain=Key), file=sys.stderr)
            sys.exit(1)

        Accounts.save()
        sys.exit(0)
    ### rename a registered domain
    elif Arguments.command == Command.RENAME:
        Key = Arguments.domain

        New = None
        if Arguments.new is not None:
            New = Accounts.sanitizeDomain(Arguments.new.strip())
        if not New:
            print("Empty/whitespace-only new domain not allowed. Specified via --new", file=sys.stderr)
            sys.exit(1)

        Error = False
        Message = None

        if Key not in Accounts.domains:
            Error = True
            Text = "Old domain \"{domain:s}\" not found".format(domain=Key)
            #
            Key_Clean = Accounts.sanitizeDomain(Key.strip())
            if Key_Clean != Key \
            and Key_Clean in Accounts.domains:
                Text = "\n".join((Text, "Did you mean domain \"{domain:s}\"?".format(domain=Key_Clean)))
            #
            if Message:
                Message = "\n".join((Message, Text))
            else:
                Message = Text

        if not Arguments.force \
        and New in Accounts.domains:
            Error = True
            Text = "New domain \"{domain:s}\" already exists".format(domain=New)
            #
            if Message:
                Message = "\n".join((Message, Text))
            else:
                Message = Text

        if Error:
            print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
            print("{message:s}".format(message=Message), file=sys.stderr)
            sys.exit(1)

        Data = Accounts.rename(Key, New)
        if not Data:
            print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
            print("Domain \"{domain:s}\" could not be renamed".format(domain=Key), file=sys.stderr)
            sys.exit(1)

        Accounts.save()
        sys.exit(0)
    ### update challenge token of a registered domain
    ### clean challenge token of a registered domain
    ### run as manual-auth-hook with certbot
    elif Arguments.command == Command.UPDATE \
    or Arguments.command == Command.CLEAN \
    or Arguments.command == Command.CERTBOT:
        Key = None
        if Arguments.command == Command.CERTBOT:
            Key = Accounts.sanitizeDomain(os.environ["CERTBOT_DOMAIN"])
            Key_Message = "Specified via env CERTBOT_DOMAIN"
        elif Arguments.domain is not None:
            Key = Accounts.sanitizeDomain(Arguments.domain.strip())
            Key_Message = "Specified via --domain"
        else:
            Key_Message = "Specify via --domain"

        Token = None
        if Arguments.command == Command.CERTBOT:
            Token = os.environ["CERTBOT_VALIDATION"]
            Token_Message = "Specified via env CERTBOT_VALIDATION"
        elif Arguments.command == Command.UPDATE \
        and Arguments.dummy:
            Token = Accounts.TOKEN_DUMMY
            Token_Message = "Specified via --dummy"
        elif Arguments.token is not None:
            Token = Arguments.token.strip()
            Token_Message = "Specified via --token"
        else:
            Token_Message = "Specify via --token/--dummy"

        if not Key \
        or not Token:
            if not Key:
                print("Empty/whitespace-only domain not allowed. {message:s}".format(message=Key_Message), file=sys.stderr)
            if not Token:
                print("Empty/whitespace-only token not allowed. {message:s}".format(message=Token_Message), file=sys.stderr)
            sys.exit(1)

        Data = Accounts.get(Key)
        if not Data:
            print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
            print("Domain \"{domain:s}\" not found".format(domain=Key), file=sys.stderr)
            sys.exit(1)

        if Arguments.command == Command.CLEAN:
            result = Accounts.clean(Data, Token)
            if not result[0]:
                print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
                print("Domain \"{domain:s}\" Token \"{token:s}\" could not be cleaned".format(domain=Key, token=Token), file=sys.stderr)
                print("{message:s}".format(message=result[1]), file=sys.stderr)
                sys.exit(0) ### no error as acme-dns keeps only the last 2 txt records (normal/wildcard)
        else:
            result = Accounts.update(Data, Token)
            if not result[0]:
                print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
                print("Domain \"{domain:s}\" could not be updated".format(domain=Key), file=sys.stderr)
                print("{message:s}".format(message=result[1]), file=sys.stderr)
                sys.exit(1)

        sys.exit(0)
    ### check DNS setup of a registered domain
    elif Arguments.command == Command.CHECK:
        Key = None
        if Arguments.domain is not None:
            Key = Accounts.sanitizeDomain(Arguments.domain.strip())
            Key_Message = "Specified via --domain"
        else:
            Key_Message = "Specify via --domain"

        if not Key:
            print("Empty/whitespace-only domain not allowed. {message:s}".format(message=Key_Message), file=sys.stderr)

        Data = Accounts.get(Key)
        if not Data:
            print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
            print("Domain \"{domain:s}\" not found".format(domain=Key), file=sys.stderr)
            sys.exit(1)

        result = Accounts.check(Data, Config.settings[Config.ATTR_IPS_NAME_SERVERS])
        if not result[0]:
            print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
            print("Domain \"{domain:s}\" DNS check has FAILED: {message:s}".format(domain=Key, message=result[1]), file=sys.stderr)
            sys.exit(1)

        print("Domain \"{domain:s}\" DNS check was SUCCESSFUL: {message:s}".format(domain=Key, message=result[1]), file=sys.stderr)
        sys.exit(0)
    ### change details of a registered domain
    elif Arguments.command == Command.CHANGE:
        Key = None
        if Arguments.domain is not None:
            Key = Accounts.sanitizeDomain(Arguments.domain.strip())
            Key_Message = "Specified via --domain"
        else:
            Key_Message = "Specify via --domain"

        if not Key:
            print("Empty/whitespace-only domain not allowed. {message:s}".format(message=Key_Message), file=sys.stderr)
            sys.exit(1)

        Data = Accounts.get(Key)
        if not Data:
            print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
            print("Domain \"{domain:s}\" not found".format(domain=Key), file=sys.stderr)
            sys.exit(1)

        Allow_From = None
        if not Arguments.allow_clear:
            if Arguments.allow_keep:
                try:
                    Allow_From = Data[Accounts.ATTR_ALLOW_FROM]
                except KeyError as e:
                    pass
            else:
                Allow_From = Arguments.allow
            if not Allow_From:
                Allow_From = None

        result = Accounts.change(Data, allowfrom=Allow_From)
        if not result[0]:
            print("Data from {path:s}".format(path=Config.settings[Config.ATTR_PATH_ACCOUNTS]), file=sys.stderr)
            print("Domain \"{domain:s}\" details could not be changed".format(domain=Key), file=sys.stderr)
            print("{message:s}".format(message=result[1]), file=sys.stderr)
            sys.exit(1)

        Accounts.save()
        sys.exit(0)
    ### AARRGGHH! chosen command not implemented
    else:
        print("ABORT! Command \"{command:s}\" not implemented!\nCheck out {homepage:s} for a newer version and/or related bug reports.".format(command=Arguments.command, homepage=__homepage__), file=sys.stderr)
        sys.exit(1)

### ----------------------------------------
### --- /Main
### ----------------------------------------

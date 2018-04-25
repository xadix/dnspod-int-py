#!/usr/bin/env python2

import logging
import argparse
import sys
import urlparse
import urllib
import copy
import httplib
import requests
import posixpath
import tabulate
import json
import os.path
#import . as dnspod
from .. import dnspod

class DnspodException(Exception):
    def __init__(self, message, data):
        self._message = message
        self.data = data

    def __str__(self):
        return self._message

class Records(object):

    def __init__(self,base,domain_id):
        self.base = base
        self.domain_id = domain_id

    def list(self):
        result = self.base._dispatch("Record.List", {"domain_id": self.domain_id})
        return { "domain": result["domain"], "info": result["info"], "records": result["records"] }
    
    def create(self, **kwargs):
        query = { "domain_id": self.domain_id }
        query["sub_domain"] = kwargs["name"]
        query["record_type"] = kwargs["type"]
        query["value"] = kwargs["value"]
        query["record_line"] = kwargs["line"]
        if "mx_priority" in kwargs and kwargs["mx_priority"] is not None: query["mx"] = kwargs["mx_priority"]
        if "ttl" in kwargs and kwargs["ttl"] is not None: query["ttl"] = kwargs["ttl"]
        result = self.base._dispatch("Record.Create", query)
        return result

    def get_id(self, **kwargs):
        result = self.list()
        for record in result["records"]:
            if record["name"] == kwargs["name"] and record["line"].lower() == kwargs["line"].lower() and record["type"] == kwargs["type"]: return record["id"]
        return None
    
    def get(self, **kwargs):
        result = self.list()
        for record in result["records"]:
            if record["name"] == kwargs["name"] and record["line"].lower() == kwargs["line"].lower() and record["type"] == kwargs["type"]: return record
        return None

    def remove(self, **kwargs):
        if "record_id" not in kwargs:
            record_id = self.get_id(**kwargs)
        else:
            record_id = kwargs["record_id"]
        result = self.base._dispatch("Record.Remove", { "domain_id": self.domain_id, "record_id": record_id })
        return result

    def modify(self, **kwargs):
        if "record_id" not in kwargs:
            lookup = { "name": kwargs["match_name"], "type": kwargs["match_type"], "line": kwargs["match_line"] }
            record_id = self.get_id(**lookup)
        else:
            record_id = kwargs["record_id"]
        query = { "domain_id": self.domain_id, "record_id": record_id }
        query["sub_domain"] = kwargs["name"]
        query["record_type"] = kwargs["type"]
        query["value"] = kwargs["value"]
        query["record_line"] = kwargs["line"]
        if "mx_priority" in kwargs and kwargs["mx_priority"] is not None: query["mx"] = kwargs["mx_priority"]
        if "ttl" in kwargs and kwargs["ttl"] is not None: query["ttl"] = kwargs["ttl"]
        result = self.base._dispatch("Record.Modify", query)
        return result

    def upsert(self, **kwargs):
        record_id = self.get_id(**kwargs)
        if record_id is not None:
            query = kwargs.copy()
            query["record_id"] = record_id
            result = self.modify(**query)
        else:
            query = kwargs.copy()
            result = self.create(**query)
        return result

class Domains(object):

    def __init__(self,base):
        self.base = base

    def remove(self, **kwargs):
        if "domain_name" in kwargs:
            domain_id = self.get_id(kwargs["domain_name"])
        else:
            domain_id = kwargs["domain_id"]
        result = self.base._dispatch("Domain.Remove", { "domain_id": domain_id })

    def create(self, domain_name):
        result = self.base._dispatch("Domain.Create", { "domain": domain_name })
        return result["domain"]

    def get_id(self, domain_name):
        result = self.list()
        for domain in result["domains"]:
            if domain["name"] == domain_name: return domain["id"]
        return None

    def get(self, domain_name):
        result = self.list()
        for domain in result["domains"]:
            if domain["name"] == domain_name: return domain
        return None

    def list(self):
        result = self.base._dispatch("Domain.List", {})
        return { "info": result["info"], "domains": result["domains"] }

    def records(self, **kwargs):
        if "domain_name" in kwargs:
            domain_id = self.get_id(kwargs["domain_name"])
        else:
            domain_id = kwargs["domain_id"]
        return Records(self.base, domain_id)

class User(object):
    def __init__(self,base):
        self.base = base

    def detail(self):
        result = self.base._dispatch("User.Detail", {})
        return result["info"]

class Base(object):
    def __init__(self, **kwargs):
        self.url = kwargs.get("url", 'https://api.dnspod.com')
        self.urlp = urlparse.urlparse(self.url)
        self.domains = Domains(self)
        self.user = User(self)
        self.user_token = None

    def _dispatch(self, path, iquery):
        query = iquery.copy()
        query["format"] = "json"
        if self.user_token is not None and "user_token" not in query:
            query["user_token"] = self.user_token
        query_string = urllib.urlencode(query)
        #query_string = "login_email={:s}&login_password={:s}&format=json".format( kwargs.get("email"), kwargs.get("password") )
        url = urlparse.urlunparse(
            ( self.urlp.scheme, self.urlp.netloc, posixpath.join( self.urlp.path, path ),
            self.urlp.params, query_string, self.urlp.fragment ) )
        logging.debug("url = %s, query_string = %s", url, query_string)
        response = requests.post(url, query_string, headers={ "Content-Type": "application/x-www-form-urlencoded" })
        logging.debug("response = %s", response)
        logging.debug("response.headers = %s", response.headers)
        logging.debug("response.text = %s", response.text)
        response_data = response.json()
        logging.debug("response_data = %s", response_data)
        if ( response_data["status"]["code"] != "1" ):
            raise DnspodException("response.text = {}".format(response.text), response_data)
        return response_data

    def auth(self, **kwargs):
        query = { "login_email": kwargs.get("email"), "login_password": kwargs.get("password") }
        response_data = self._dispatch("Auth", query)
        self.user_token = response_data["user_token"]
        return self.user_token

    def check_token(self, token):
        try:
            result = self._dispatch("User.Detail", {"user_token": token})
        except DnspodException as e:
            if e.data["status"]["code"] != "1": return False
        return True
        

def format_dlist(dlist, fmt):
    if fmt=="json":
        return json.dumps(dlist, sort_keys=True, indent=4)
    elif fmt=="table":
        if len(dlist) < 1: return ""
        headers = dlist[0].keys()
        rows = []
        for item in dlist:
            row = []
            for header in headers:
                row.append(item[header] if header in item else None)
            rows.append(row)
        return tabulate.tabulate(rows, headers)

try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client

def do_auth(base, arguments):
    cache_data = {}   
    if os.path.exists(arguments.cache):
        with open(arguments.cache) as cache_file:
            cache_data = json.load(cache_file)
            use_token = cache_data["token"]

    logging.debug("cache_data = %s", cache_data)

    use_token = None
    if False: None
    elif arguments.token is not None:
        use_token = arguments.token
    elif "XADIX_DNSPOD_TOKEN" in os.environ:
        use_token = os.environ["XADIX_DNSPOD_TOKEN"]
    elif "token" in cache_data:
        use_token = cache_data["token"]

    logging.debug("use_token=%s", use_token)
    token_ok = False
    if use_token is not None:
        token_ok = base.check_token(use_token)
    logging.debug("token_ok=%s", token_ok)

    if token_ok:
        base.user_token = use_token
    else:
        config_data = {}
        if os.path.exists(arguments.config):
            with open(arguments.config) as config_file:
                config_data = json.load(config_file)

        if False: None
        elif arguments.email is not None:
            use_email = arguments.email
        elif "XADIX_DNSPOD_EMAIL" in os.environ:
            use_email = os.environ["XADIX_DNSPOD_EMAIL"]
        elif "email" in config_data:
            use_email = config_data["email"]

        if False: None
        elif arguments.password is not None:
            use_password = arguments.password
        elif "XADIX_DNSPOD_PASSWORD" in os.environ:
            use_password = os.environ["XADIX_DNSPOD_PASSWORD"]
        elif "password" in config_data:
            use_password = config_data["password"]

        logging.debug("use_email=%s", use_email)
        logging.debug("use_password=%s", use_password)

        token = base.auth( email = arguments.email, password = arguments.password )
        cache_data["token"] = token
        if not os.path.exists(os.path.dirname(arguments.cache)):
            os.makedirs(os.path.dirname(arguments.cache), 0700)
        with open(arguments.cache, "w") as cache_file:
            json.dump(cache_data, cache_file)
        

'''
def do_auth(base, arguments):
    if arguments.token is None:
        base.auth( email = arguments.email, password = arguments.password )
    else:
        base.user_token = arguments.token

    XADIX_DNSPOD_EMAIL
    XADIX_DNSPOD_PASSWORD
    XADIX_DNSPOD_TOKEN
'''

def main():
    logging.basicConfig(level=logging.INFO, datefmt='%Y-%m-%dT%H:%M:%S', stream=sys.stderr, format="%(asctime)s %(process)d %(thread)d %(levelno)03d:%(levelname)-8s %(name)-12s %(module)s:%(lineno)s:%(funcName)s %(message)s")

    config_dir = os.path.join(os.path.expanduser("~"),".config","xadix-dnspod")

    root_parser = argparse.ArgumentParser(add_help = False, prog="xadix-dnspod")
    root_parser.add_argument("--version", action="version", version="xadix-dnspod {:s}".format(dnspod.__version__))
    root_parser.add_argument("-v", "--verbose", action="count", dest="verbosity", help="increase verbosity level")
    root_parser.add_argument("-h", "--help", action="help", help="shows this help message and exit")

    root_parser.add_argument("-e", "--email", action="store", dest="email", type=str, required=False, default=None, help="...")
    root_parser.add_argument("-p", "--password", action="store", dest="password", type=str, required=False, default=None, help="...")
    root_parser.add_argument("-t", "--token", action="store", dest="token", type=str, required=False, default=None, help="...")
    root_parser.add_argument("--cache", action="store", dest="cache", type=str, required=False, default=os.path.join(config_dir,"cache.json"), help="...")
    root_parser.add_argument("--config", action="store", dest="config", type=str, required=False, default=os.path.join(config_dir,"config.json"), help="...")
    root_parser.add_argument("-f", "--format", action="store", dest="format", type=str, required=False, default="table", help="...")

    root_subparsers = root_parser.add_subparsers(dest="subparser0", help="...")

    auth_subparser = root_subparsers.add_parser("auth")
    auth_subparser.add_argument("-e", "--email", action="store", dest="email", type=str, required=True, help="...")
    auth_subparser.add_argument("-p", "--password", action="store", dest="password", type=str, required=True, help="...")

    user_subparser = root_subparsers.add_parser("user")
    user_subparsers = user_subparser.add_subparsers(dest="subparser1", help="...")
    user_detail_subparser = user_subparsers.add_parser("detail")

    domain_subparser = root_subparsers.add_parser("domain")
    domain_subparsers = domain_subparser.add_subparsers(dest="subparser1", help="...")

    domain_list_subparser = domain_subparsers.add_parser("list")

    domain_create_subparser = domain_subparsers.add_parser("create")
    domain_create_subparser.add_argument("-d", "--domain-name", action="store", dest="domain_name", type=str, required=True, help="...")

    domain_remove_subparser = domain_subparsers.add_parser("remove")
    domain_remove_subparser.add_argument("-d", "--domain-name", action="store", dest="domain_name", type=str, required=True, help="...")

    domain_record_subparser = domain_subparsers.add_parser("record")
    domain_record_subparser.add_argument("-d", "--domain-name", action="store", dest="domain_name", type=str, required=True, help="...")
    domain_record_subparsers = domain_record_subparser.add_subparsers(dest="subparser2", help="...")

    domain_record_list_subparser = domain_record_subparsers.add_parser("list")

    domain_record_create_subparser = domain_record_subparsers.add_parser("create")
    domain_record_create_subparser.add_argument("-n", "--name", action="store", dest="record_name", type=str, required=True, help="...")
    domain_record_create_subparser.add_argument("-l", "--line", action="store", dest="record_line", type=str, required=False, default="default", help="...")
    domain_record_create_subparser.add_argument("-t", "--type", action="store", dest="record_type", type=str, required=True, help="...")
    domain_record_create_subparser.add_argument("-v", "--value", action="store", dest="record_value", type=str, required=True, help="...")
    domain_record_create_subparser.add_argument("-m", "--mx-priority", action="store", dest="record_mx_priority", type=str, required=False, help="...")
    domain_record_create_subparser.add_argument("-x", "--ttl", action="store", dest="record_ttl", type=str, required=False, help="...")

    domain_record_delete_subparser = domain_record_subparsers.add_parser("remove")
    domain_record_delete_subparser.add_argument("-n", "--name", action="store", dest="record_name", type=str, required=True, help="...")
    domain_record_delete_subparser.add_argument("-l", "--line", action="store", dest="record_line", type=str, required=False, default="default", help="...")
    domain_record_delete_subparser.add_argument("-t", "--type", action="store", dest="record_type", type=str, required=True, help="...")

    domain_record_modify_subparser = domain_record_subparsers.add_parser("modify")
    domain_record_modify_subparser.add_argument("-N", "--match-name", action="store", dest="record_match_name", type=str, required=True, help="...")
    domain_record_modify_subparser.add_argument("-L", "--match-line", action="store", dest="record_match_line", type=str, required=False, default="default", help="...")
    domain_record_modify_subparser.add_argument("-T", "--match-type", action="store", dest="record_match_type", type=str, required=True, help="...")
    domain_record_modify_subparser.add_argument("-n", "--name", action="store", dest="record_name", type=str, required=True, help="...")
    domain_record_modify_subparser.add_argument("-l", "--line", action="store", dest="record_line", type=str, required=False, default="default", help="...")
    domain_record_modify_subparser.add_argument("-t", "--type", action="store", dest="record_type", type=str, required=True, help="...")
    domain_record_modify_subparser.add_argument("-v", "--value", action="store", dest="record_value", type=str, required=True, help="...")
    domain_record_modify_subparser.add_argument("-m", "--mx-priority", action="store", dest="record_mx_priority", type=str, required=False, help="...")
    domain_record_modify_subparser.add_argument("-x", "--ttl", action="store", dest="record_ttl", type=str, required=False, help="...")

    domain_record_upsert_subparser = domain_record_subparsers.add_parser("upsert")
    domain_record_upsert_subparser.add_argument("-n", "--name", action="store", dest="record_name", type=str, required=True, help="...")
    domain_record_upsert_subparser.add_argument("-l", "--line", action="store", dest="record_line", type=str, required=False, default="default", help="...")
    domain_record_upsert_subparser.add_argument("-t", "--type", action="store", dest="record_type", type=str, required=True, help="...")
    domain_record_upsert_subparser.add_argument("-v", "--value", action="store", dest="record_value", type=str, required=True, help="...")
    domain_record_upsert_subparser.add_argument("-m", "--mx-priority", action="store", dest="record_mx_priority", type=str, required=False, help="...")
    domain_record_upsert_subparser.add_argument("-x", "--ttl", action="store", dest="record_ttl", type=str, required=False, help="...")

    '''
    argument_subparsers = argument_parser.add_subparsers(dest="subparser0", help="...")
    if True:
        argument_subparser = argument_subparsers.add_parser("auth")
        argument_subparser.add_argument("-e", "--email", action="store", dest="email", type=str, required=True, help="...")
        argument_subparser.add_argument("-p", "--password", action="store", dest="password", type=str, required=True, help="...")
    if True:
        argument_subparser = argument_subparsers.add_parser("user")
        argument_subparsers = argument_subparser.add_subparsers(dest="subparser1", help="...")
        if True:
            argument_subparser = argument_subparsers.add_parser("detail")
    if True:
        argument_subparser = argument_subparsers.add_parser("domain")
        argument_subparsers = argument_subparser.add_subparsers(dest="subparser1", help="...")
        if True:
            argument_subparser = argument_subparsers.add_parser("list")
        if True:
            argument_subparser = argument_subparsers.add_parser("create")
            argument_subparser.add_argument("-d", "--domain-name", action="store", dest="domain_name", type=str, required=True, help="...")
            #argument_subparser.add_argument("domain_name", action="store", type=str)
        if True:
            argument_subparser = argument_subparsers.add_parser("remove")
            argument_subparser.add_argument("-d", "--domain-name", action="store", dest="domain_name", type=str, required=True, help="...")
            #argument_subparser.add_argument("domain_name", action="store", type=str)
        if True:
            argument_subparser = argument_subparsers.add_parser("record")
            argument_subparser.add_argument("-d", "--domain-name", action="store", dest="domain_name", type=str, required=True, help="...")
            argument_subparsers = argument_subparser.add_subparsers(dest="subparser2", help="...")
            if True:
                argument_subparser = argument_subparsers.add_parser("list")
            if True:
                argument_subparser = argument_subparsers.add_parser("create")
                argument_subparser.add_argument("-s", "--name", action="store", dest="record_name", type=str, required=True, help="...")
                argument_subparser.add_argument("-t", "--type", action="store", dest="record_type", type=str, required=True, help="...")
                argument_subparser.add_argument("-l", "--line", action="store", dest="record_line", type=str, required=False, default="Default", help="...")
                argument_subparser.add_argument("-v", "--value", action="store", dest="record_value", type=str, required=True, help="...")
                argument_subparser.add_argument("-m", "--mx-priority", action="store", dest="record_mx_priority", type=str, required=False, help="...")
                argument_subparser.add_argument("-T", "--ttl", action="store", dest="record_ttl", type=str, required=False, help="...")
    '''     
        
    arguments = root_parser.parse_args( args = sys.argv[1:] )

    if arguments.verbosity is not None:
        root_logger = logging.getLogger("")
        new_level = ( root_logger.getEffectiveLevel() - (min(1,arguments.verbosity))*10 - min(max(0,arguments.verbosity - 1),9)*1 )
        root_logger.setLevel( new_level )
        root_logger.propagate = True
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(new_level)
        requests_log.propagate = True
        http_client.HTTPConnection.debuglevel = 1


    logging.debug("sys.argv = %s, arguments = %s, logging.level = %s", sys.argv, arguments, logging.getLogger("").getEffectiveLevel())

    base = Base()

    #do_auth(base)
    if arguments.subparser0 != "auth":
        '''
        if arguments.token is None:
            base.auth( email = arguments.email, password = arguments.password )
        else:
            base.user_token = arguments.token
        '''
        do_auth(base, arguments)

    if False: None
    elif arguments.subparser0 == "auth":
        user_token = base.auth( email = arguments.email, password = arguments.password )
        sys.stdout.write("{}\n".format(user_token))
    elif arguments.subparser0 == "user":
        if False: None
        elif arguments.subparser1 == "detail":
            result = base.user.detail()
            sys.stdout.write(format_dlist([result["user"]], arguments.format))
            sys.stdout.write("\n")
    elif arguments.subparser0 == "domain":
        if False: None
        elif arguments.subparser1 == "list":
            result = base.domains.list()
            sys.stdout.write(format_dlist(result["domains"], arguments.format))
            sys.stdout.write("\n")
        elif arguments.subparser1 == "create":
            result = base.domains.create(arguments.domain_name)
            sys.stdout.write(format_dlist([ result ], arguments.format))
            sys.stdout.write("\n")
        elif arguments.subparser1 == "remove":
            base.domains.remove(domain_name = arguments.domain_name)
        elif arguments.subparser1 == "record":
            records = base.domains.records(domain_name = arguments.domain_name)
            if False: None
            elif arguments.subparser2 == "list":
                result = records.list()
                sys.stdout.write(format_dlist(result["records"], arguments.format))
                sys.stdout.write("\n")
            elif arguments.subparser2 == "create":
                result = records.create( name = arguments.record_name, type = arguments.record_type, line = arguments.record_line,
                    value = arguments.record_value, mx_priority = arguments.record_mx_priority, ttl = arguments.record_ttl )
            elif arguments.subparser2 == "modify":
                result = records.modify( match_name = arguments.record_match_name, match_type = arguments.record_match_type, match_line = arguments.record_match_line,
                    name = arguments.record_name, type = arguments.record_type, line = arguments.record_line,
                    value = arguments.record_value, mx_priority = arguments.record_mx_priority, ttl = arguments.record_ttl )
            elif arguments.subparser2 == "remove":
                result = records.remove( name = arguments.record_name, type = arguments.record_type, line = arguments.record_line )
            elif arguments.subparser2 == "upsert":
                result = records.upsert( name = arguments.record_name, type = arguments.record_type, line = arguments.record_line,
                    value = arguments.record_value, mx_priority = arguments.record_mx_priority, ttl = arguments.record_ttl )
            

if __name__ == "__main__":
    main()

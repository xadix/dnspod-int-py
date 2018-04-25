import urlparse
import posixpath
import urllib
import requests
import logging

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

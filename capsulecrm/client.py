from urllib.parse import urlencode

import requests
import json
# Python 2/3 version compatibility
try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

from capsulecrm import exceptions


class Client(object):
    AUTHORITY_URL = 'https://api.capsulecrm.com/'
    AUTH_ENDPOINT = 'oauth/authorise?'
    TOKEN_ENDPOINT = 'oauth/token'
    REVOKE_ENDPOINT = TOKEN_ENDPOINT + '/revoke'

    RESOURCE = 'https://api.capsulecrm.com/api/'
    _VALID_VERSIONS = ['v2', ]

    def __init__(self, client_id, client_secret, api_version=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.link_next = None
        if api_version not in self._VALID_VERSIONS:
            self.api_version = self._VALID_VERSIONS[0]
        self.base_url = self.RESOURCE + self.api_version + '/'

    def authorization_url(self, redirect_uri, scope=None, state=None):
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
        }
        if scope:
            params['scope'] = ' '.join(scope),
        if state:
            params['state'] = state
        return self.AUTHORITY_URL + self.AUTH_ENDPOINT + urlencode(params)

    def exchange_code(self, code):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'grant_type': 'authorization_code',
        }
        return self._parse(requests.post(self.AUTHORITY_URL + self.TOKEN_ENDPOINT, data=data))

    def refresh_token(self, refresh_token):
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token',
        }
        return self._parse(requests.post(self.AUTHORITY_URL + self.TOKEN_ENDPOINT, data=data))

    def revoke_token(self):
        data = {
            'token': self.token
        }
        return self._parse(requests.post(self.AUTHORITY_URL + self.REVOKE_ENDPOINT, data=data))

    def set_token(self, token):
        self.token = token

    def create_tag(self, entity, name, description, datatag):
        """Returns the created tag.
        Args:
            entity: String [parties, opportunities, kases]
            name: String requerid
            description: String
            datatag: Boolean
        Returns:
            A dict.
        """
        data = {
            "tag": {
                "name": name,
                "description": description,
                "dataTag": datatag
            }
        }
        return self._post('{}/tags'.format(entity), **data)

    def list_tag(self, entity, page=None, perpage=None):
        """Returns all created tags.
        Args:
            entity: String [parties, opportunities, kases]
            page: Integer
            perpage: Integer
        Returns:
            A dict.
        """
        data = {
            'page': page,
            'perPage': perpage
        }
        return self._get('{}/tags'.format(entity), params=data)

    def create_person(self, embed):
        """Returns the created person.
        Args:
            embed: Dict { 'firstName': String required, 'lastName': String required, 'title': String,
                          'jobTitle': String (Mr, Master, Mrs, Miss, Ms, Dr, Prof), 'organisation': String,
                          'about': String,
                          'addresses': dict { 'type': String (Home, Postal, Office),
                                              'street': String,
                                              'city': String,
                                              'state': String,
                                              'country': String,
                                              'zip': String },
                          'phoneNumbers': dict { 'type': String (Home, Work, Mobile, Fax, Direct),
                                                 'number': String required },
                          'websites': dict { 'service': String required (URL, SKYPE, TWITTER, LINKED_IN, FLICKR, GITHUB,
                                                                         YOUTUBE, INSTAGRAM, PINTEREST),
                                             'address': String required,
                                             'type': String (Home, Work),
                                             'url': String required },
                          'emailAddresses': dict { 'type': String (Home, Work),
                                                   'address': String required },
                          'tags': dict { 'id': Long,
                                         'name': String required,
                                         'description': String },
                          'fields': dict { 'id': Long,
                                           'value': Multiple requerid,
                                           'definition': dict requerid { 'id': Long,
                                                                         'name': String } }
        Returns:
            A dict.
        """
        data = {
            'party': {
                'type': 'person',
            }
        }
        data['party'].update(embed)
        return self._post('/parties', **data)

    def create_organisation(self, embed):
        """Returns the created organisation.
        Args:
            embed: Dict { 'name': String required, 'about': String,
                          'addresses': dict { 'type': String (Home, Postal, Office),
                                              'street': String,
                                              'city': String,
                                              'state': String,
                                              'country': String,
                                              'zip': String },
                          'phoneNumbers': dict { 'type': String (Home, Work, Mobile, Fax, Direct),
                                                 'number': String required },
                          'websites': dict { 'service': String required (URL, SKYPE, TWITTER, LINKED_IN, FLICKR, GITHUB,
                                                                         YOUTUBE, INSTAGRAM, PINTEREST),
                                             'address': String required,
                                             'type': String (Home, Work),
                                             'url': String required },
                          'emailAddresses': dict { 'type': String (Home, Work),
                                                   'address': String required },
                          'tags': dict { 'id': Long,
                                         'name': String required,
                                         'description': String },
                          'fields': dict { 'id': Long,
                                           'value': Multiple requerid,
                                           'definition': dict requerid { 'id': Long,
                                                                         'name': String } }
        Returns:
            A dict.
        """
        data = {
            'party': {
                'type': 'organisation',
            }
        }
        data['party'].update(embed)
        return self._post('/parties', **data)

    def list_parties(self, since=None, page=None, perpage=None, embed=None):
        """Returns the all parties.
        Args:
            since: Date
            page: Integer
            perpage: Integer
            embed: dict
        Returns:
            A dict.
        """
        data = {
            'since': since,
            'page': page,
            'perPage': perpage,
            'embed': embed
        }
        return self._get('/parties', params=data)

    def create_milestone(self, name, description, probability, complete=False):
        """Returns the create milestone.
        Args:
            name: String required
            description: String
            probability: Integer
            complete: Boolean
        Returns:
            A dict.
        """
        data = {
            'milestone': {
                'name': name,
                'description': description,
                'probability': probability,
                'complete': complete
            }
        }
        return self._post('/milestones', **data)

    def list_milestone(self, page=None, perpage=None):
        """Returns the all milestones.
        Args:
            page: Integer
            perpage: Integer
        Returns:
            A dict.
        """
        data = {
            'page': page,
            'perPage': perpage
        }
        return self._get('/milestones', params=data)

    def create_oppotunity(self, embed):
        """Returns the created oppotunity.
        Args:
            embed: Dict { 'description' : String
                          'party': dict { 'id': Long required },
                          'name': String required, 'description': String,
                          'milestone': dict { 'id': Long required },
                          'value': dict { 'amount': Double required, 'currency': String },
                          'probability': Long
                        }
        Returns:
            A dict.
        """
        data = {
            'opportunity': {}
        }
        data['opportunity'].update(embed)
        return self._post('/opportunities', **data)

    def list_opportunities(self, since=None, page=None, perpage=None, embed=None):
        """Returns the all parties.
        Args:
            since: Date
            page: Integer
            perpage: Integer
            embed: dict
        Returns:
            A dict.
        """
        data = {
            'since': since,
            'page': page,
            'perPage': perpage,
            'embed': embed
        }
        return self._get('/opportunities', params=data)

    def get_current_user(self):
        return self._get('/users/current')

    def list_users(self):
        return self._get('/users')

    def list_tasks(self, page=None, perpage=None, embed=None, since=None):
        """Returns the all tasks.
        Args:
            page: Integer
            perpage: Integer
            embed: dict
        Returns:
            A dict.
        """
        data = {
            'since': since,
            'page': page,
            'perPage': perpage,
            'embed': embed
        }
        return self._get('/tasks', params=data)

    def create_task(self, embed):
        """Returns the created task.
        Args:
            embed: Dict { 'party': dict { 'id': Long required },
                          'detail': String required,
                          'description': String,
                          'dueOn': String,
                          'dueTime': dict { 'amount': Double required, 'currency': String },
                          'oportunity': dict { 'id': Long required },
                          'owner': dict { 'id': Long required },
                          'completeAt': String,
                        }
        Returns:
            A dict.
        """
        return self._post('/tasks', **{'task': embed})

    def follow_next(self):
        """
        Capsule will return 'url' in the json if there is another
        page of results from the previous request
        """
        if self.link_next:
            next_link = self.link_next.get('url', None)
            if next_link:
                return self._parse(
                    requests.get(
                        next_link,
                        headers=self._get_headers()
                    )
                )
        else:
            raise exceptions.NextLinkUnavailableError

    def _get_headers(self, content_type='application/json', headers=None):
        _headers = {
            'Authorization': 'Bearer ' + self.token
        }
        if content_type:
            _headers['Content-Type'] = content_type
        if headers:
            _headers.update(headers)
        return _headers

    def _get(self, url, headers=None, **kwargs):
        _headers = self._get_headers(
            headers=headers
        )
        if kwargs:
            filtered_params = {}
            for k, v in kwargs.get('params').items():
                if v:
                    filtered_params[k] = v
            payload = '?' + urlencode(filtered_params)
        else:
            payload = ''
        return self._parse(
            requests.get(
                self.base_url + url + payload,
                headers=_headers
            )
        )

    def _post(self, url, **kwargs):
        return self._request('POST', url, **kwargs)

    def _put(self, url, **kwargs):
        return self._request('PUT', url, **kwargs)

    def _patch(self, url, **kwargs):
        return self._request('PATCH', url, **kwargs)

    def _delete(self, url, **kwargs):
        return self._request('DELETE', url, **kwargs)

    def _request(self, method, endpoint, headers=None, **kwargs):
        _headers = self._get_headers(headers=headers)
        return self._parse(requests.request(method, self.base_url + endpoint, headers=_headers, data=json.dumps(kwargs)))

    def _parse(self, response):
        self.link_next = response.links.get('next', None)
        status_code = response.status_code
        if status_code == 204:
            return None
        if 'application/json' in response.headers['Content-Type']:
            r = response.json()
        else:
            r = response.text
        if status_code in (200, 201, 202):
            return r
        elif status_code == 400:
            raise exceptions.BadRequestError(r)
        elif status_code == 401:
            raise exceptions.AuthenticationFailedError(r)
        elif status_code == 403:
            raise exceptions.ForbiddenError(r)
        elif status_code == 422:
            raise exceptions.ValidationFailedError(r)
        else:
            raise exceptions.UnknownError(r)

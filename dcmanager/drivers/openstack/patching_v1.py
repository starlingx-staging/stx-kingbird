# Copyright 2016 Ericsson AB

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2017 Wind River Systems, Inc.
#

from oslo_log import log
import requests
from requests_toolbelt import MultipartEncoder

from dcmanager.drivers import base

LOG = log.getLogger(__name__)

# Patch states
PATCH_STATE_AVAILABLE = 'Available'
PATCH_STATE_APPLIED = 'Applied'
PATCH_STATE_PARTIAL_APPLY = 'Partial-Apply'
PATCH_STATE_PARTIAL_REMOVE = 'Partial-Remove'
PATCH_STATE_COMMITTED = 'Committed'
PATCH_STATE_UNKNOWN = 'n/a'


class PatchingClient(base.DriverBase):
    """Patching V1 driver."""

    def __init__(self, region, session):
        # Get an endpoint and token.
        self.endpoint = session.get_endpoint(service_type='patching',
                                             region_name=region,
                                             interface='internal')
        self.token = session.get_token()

    def query(self, state=None, release=None,):
        """Query patches"""
        url = self.endpoint + '/v1/query'
        if state is not None:
            url += "?show=%s" % state.lower()
        if release is not None:
            url += "&release=%s" % release
        headers = {"X-Auth-Token": self.token}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'error' in data and data["error"] != "":
                message = "query failed with error: %s" % data["error"]
                LOG.error(message)
                raise Exception(message)
            else:
                return data.get('pd', [])
        else:
            message = "query failed with RC: %d" % response.status_code
            LOG.error(message)
            raise Exception(message)

    def query_hosts(self):
        """Query hosts"""
        url = self.endpoint + '/v1/query_hosts'
        headers = {"X-Auth-Token": self.token}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'error' in data and data["error"] != "":
                message = "query_hosts failed with error: %s" % data["error"]
                LOG.error(message)
                raise Exception(message)
            else:
                return data.get('data', [])
        else:
            message = "query_hosts failed with RC: %d" % response.status_code
            LOG.error(message)
            raise Exception(message)

    def apply(self, patches):
        """Apply patches"""
        patch_str = "/".join(patches)
        url = self.endpoint + '/v1/apply/%s' % patch_str
        headers = {"X-Auth-Token": self.token}
        response = requests.post(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'error' in data and data["error"] != "":
                message = "apply failed with error: %s" % data["error"]
                LOG.error(message)
                raise Exception(message)
            else:
                return data.get('pd', [])
        else:
            message = "apply failed with RC: %d" % response.status_code
            LOG.error(message)
            raise Exception(message)

    def remove(self, patches):
        """Remove patches"""
        patch_str = "/".join(patches)
        url = self.endpoint + '/v1/remove/%s' % patch_str
        headers = {"X-Auth-Token": self.token}
        response = requests.post(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'error' in data and data["error"] != "":
                message = "remove failed with error: %s" % data["error"]
                LOG.error(message)
                raise Exception(message)
            else:
                return data.get('pd', [])
        else:
            message = "remove failed with RC: %d" % response.status_code
            LOG.error(message)
            raise Exception(message)

    def delete(self, patches):
        """Delete patches"""
        patch_str = "/".join(patches)
        url = self.endpoint + '/v1/delete/%s' % patch_str
        headers = {"X-Auth-Token": self.token}
        response = requests.post(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'error' in data and data["error"] != "":
                message = "delete failed with error: %s" % data["error"]
                LOG.error(message)
                raise Exception(message)
            else:
                return data.get('pd', [])
        else:
            message = "delete failed with RC: %d" % response.status_code
            LOG.error(message)
            raise Exception(message)

    def commit(self, patches):
        """Commit patches"""
        patch_str = "/".join(patches)
        url = self.endpoint + '/v1/commit/%s' % patch_str
        headers = {"X-Auth-Token": self.token}
        response = requests.post(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            if 'error' in data and data["error"] != "":
                message = "commit failed with error: %s" % data["error"]
                LOG.error(message)
                raise Exception(message)
            else:
                return data.get('pd', [])
        else:
            message = "commit failed with RC: %d" % response.status_code
            LOG.error(message)
            raise Exception(message)

    def upload(self, files):
        """Upload patches"""

        for file in sorted(list(set(files))):
            enc = MultipartEncoder(fields={'file': (file,
                                                    open(file, 'rb'),
                                                    )})
            url = self.endpoint + '/v1/upload'
            headers = {"X-Auth-Token": self.token,
                       'Content-Type': enc.content_type}
            response = requests.post(url,
                                     data=enc,
                                     headers=headers)

            if response.status_code == 200:
                data = response.json()
                if 'error' in data and data["error"] != "":
                    message = "upload failed with error: %s" % data["error"]
                    LOG.error(message)
                    raise Exception(message)
                else:
                    return data.get('pd', [])
            else:
                message = "upload failed with RC: %d" % response.status_code
                LOG.error(message)
                raise Exception(message)

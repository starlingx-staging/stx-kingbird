# Copyright 2017 Wind River Inc

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

'''
OpenStack Driver
'''
import collections

from oslo_concurrency import lockutils
from oslo_log import log
from oslo_utils import timeutils

from dcorch.drivers.openstack.keystone_v3 import KeystoneClient
from dcorch.drivers.openstack.sysinv_v1 import SysinvClient

# Gap, in seconds, to determine whether the given token is about to expire
STALE_TOKEN_DURATION = 60

LOG = log.getLogger(__name__)


class OpenStackDriver(object):

    @lockutils.synchronized('dcorch-openstackdriver-platform')
    def __init__(self, region_name=None):
        # Check if objects are cached and try to use those
        self.os_clients_dict = collections.defaultdict(dict)
        self._token = None

        self.region_name = region_name

        if ('keystone' in self.os_clients_dict) and self._is_token_valid():
            self.keystone_client = self.os_clients_dict['keystone']
        else:
            self.keystone_client = KeystoneClient()
            self.os_clients_dict['keystone'] = self.keystone_client
        if region_name in self.os_clients_dict and \
                self._is_token_valid():
            LOG.info('Using cached OS client objects %s' % region_name)
            self.sysinv_client = self.os_clients_dict[
                region_name]['sysinv']
        else:
            # Create new objects and cache them
            LOG.debug("Creating fresh OS Clients objects %s" % region_name)
            self.os_clients_dict[
                region_name] = collections.defaultdict(dict)

            try:
                self.sysinv_client = SysinvClient(region_name,
                                                  self.keystone_client.session)
                self.os_clients_dict[region_name][
                    'sysinv'] = self.sysinv_client
            except Exception as exception:
                LOG.error('sysinv_client region %s error: %s' %
                          (region_name, exception.message))

    @lockutils.synchronized('dcorch-openstackdriver-platform')
    def delete_region_clients(self, region_name, clear_token=False):
        LOG.warn("delete_region_clients=%s, clear_token=%s" %
                 (region_name, clear_token))
        if region_name in self.os_clients_dict:
            del self.os_clients_dict[region_name]
        if clear_token:
            self._token = None

    def _is_token_valid(self):
        try:
            keystone = self.os_clients_dict['keystone'].keystone_client
            if not self._token:
                self._token = \
                    keystone.tokens.validate(keystone.session.get_token())
                LOG.info("Get new self._token expires_at=%s" %
                         self._token['expires_at'])
                # Reset the cached dictionary
                self.os_clients_dict = collections.defaultdict(dict)
                return False

            token = keystone.tokens.validate(self._token)
            if token != self._token:
                LOG.info("updating token %s to %s" % (self._token, token))
                self._token = token
                self.os_clients_dict = collections.defaultdict(dict)
                return False

        except Exception as exception:
            LOG.info('_is_token_valid handle: %s', exception.message)
            # Reset the cached dictionary
            self.os_clients_dict = collections.defaultdict(dict)
            self._token = None
            return False

        expiry_time = timeutils.normalize_time(timeutils.parse_isotime(
            self._token['expires_at']))
        if timeutils.is_soon(expiry_time, STALE_TOKEN_DURATION):
            LOG.info('The cached keystone token will expire soon %s' %
                     self._token['expires_at'])
            # Reset the cached dictionary
            self.os_clients_dict = collections.defaultdict(dict)
            self._token = None
            return False
        else:
            return True

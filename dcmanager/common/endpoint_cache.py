# Copyright 2015 Huawei Technologies Co., Ltd.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2017 Wind River Systems, Inc.
#

import collections

from keystoneauth1 import loading
from keystoneauth1 import session

from keystoneclient.v3 import client as keystone_client

from oslo_config import cfg


class EndpointCache(object):
    def __init__(self):
        self.endpoint_map = collections.defaultdict(dict)
        self.admin_session = None
        self.keystone_client = None
        self._update_endpoints()

    @staticmethod
    def _get_endpoint_from_keystone(self):
        proj_domain_name = cfg.CONF.keystone_authtoken.project_domain_name
        loader = loading.get_plugin_loader(
            cfg.CONF.keystone_authtoken.auth_type)
        auth = loader.load_from_options(
            auth_url=cfg.CONF.keystone_authtoken.auth_uri,
            username=cfg.CONF.keystone_authtoken.username,
            user_domain_name=cfg.CONF.keystone_authtoken.user_domain_name,
            password=cfg.CONF.keystone_authtoken.password,
            project_name=cfg.CONF.keystone_authtoken.project_name,
            project_domain_name=proj_domain_name
        )
        self.admin_session = session.Session(auth=auth)
        cli = keystone_client.Client(session=self.admin_session)
        self.keystone_client = cli

        service_id_name_map = {}
        for service in cli.services.list():
            service_dict = service.to_dict()
            service_id_name_map[service_dict['id']] = service_dict['name']

        region_service_endpoint_map = {}
        for endpoint in cli.endpoints.list():
            endpoint_dict = endpoint.to_dict()
            if endpoint_dict['interface'] != 'internal':
                continue
            region_id = endpoint_dict['region']
            service_id = endpoint_dict['service_id']
            url = endpoint_dict['url']
            service_name = service_id_name_map[service_id]
            if region_id not in region_service_endpoint_map:
                region_service_endpoint_map[region_id] = {}
            region_service_endpoint_map[region_id][service_name] = url
        return region_service_endpoint_map

    def _get_endpoint(self, region, service, retry):
        if service not in self.endpoint_map[region]:
            if retry:
                self.update_endpoints()
                return self._get_endpoint(region, service, False)
            else:
                return ''
        else:
            return self.endpoint_map[region][service]

    def _update_endpoints(self):
        endpoint_map = EndpointCache._get_endpoint_from_keystone(self)

        for region in endpoint_map:
            for service in endpoint_map[region]:
                self.endpoint_map[region][
                    service] = endpoint_map[region][service]

    def get_endpoint(self, region, service):
        """Get service endpoint url.

        :param region: region the service belongs to
        :param service: service type
        :return: url of the service
        """
        return self._get_endpoint(region, service, True)

    def update_endpoints(self):
        """Update endpoint cache from Keystone.

        :return: None
        """
        self._update_endpoints()

    def get_all_regions(self):
        """Get region list.

        return: List of regions
        """
        return self.endpoint_map.keys()

    def get_session_from_token(self, token, project_id):
        """Get session based on token to communicate with openstack services.

        :param token: token with which the request is triggered.
        :param project_id: UUID of the project.

        :return: session object.
        """
        loader = loading.get_plugin_loader('token')
        auth = loader.load_from_options(auth_url=cfg.CONF.cache.auth_uri,
                                        token=token, project_id=project_id)
        sess = session.Session(auth=auth)
        return sess

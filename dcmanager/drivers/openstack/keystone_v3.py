#   Copyright 2012-2013 OpenStack Foundation
#
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#
#
# Copyright (c) 2017 Wind River Systems, Inc.
#

from keystoneauth1 import exceptions as keystone_exceptions
from keystoneclient.v3.contrib import endpoint_filter
from oslo_utils import importutils

from dcmanager.common.endpoint_cache import EndpointCache
from dcmanager.common import exceptions
from dcmanager.drivers import base

# Ensure keystonemiddleware options are imported
importutils.import_module('keystonemiddleware.auth_token')


class KeystoneClient(base.DriverBase):
    '''Keystone V3 driver.'''

    def __init__(self):
        try:
            self.endpoint_cache = EndpointCache()
            self.session = self.endpoint_cache.admin_session
            self.keystone_client = self.endpoint_cache.keystone_client
            self.services_list = self.keystone_client.services.list()
            self.endpoints_list = self.keystone_client.endpoints.list()
        except exceptions.ServiceUnavailable:
            raise

    def get_enabled_projects(self):
        try:
            return [current_project.id for current_project in
                    self.keystone_client.projects.list() if
                    current_project.enabled]
        except exceptions.InternalError:
            raise

    def get_enabled_users(self):
        try:
            return [current_user.id for current_user in
                    self.keystone_client.users.list() if
                    current_user.enabled]
        except exceptions.InternalError:
            raise

    def is_service_enabled(self, service):
        try:
            for current_service in self.services_list:
                if service in current_service.type:
                    return True
            return False
        except exceptions.InternalError:
            raise

    # Returns list of regions if endpoint filter is applied for the project
    def get_filtered_region(self, project_id):
        try:
            region_list = []
            endpoint_manager = endpoint_filter.EndpointFilterManager(
                self.keystone_client)
            endpoint_lists = endpoint_manager.list_endpoints_for_project(
                project_id)
            for endpoint in endpoint_lists:
                region_list.append(endpoint.region)
            return region_list
        except exceptions.InternalError:
            raise

    def delete_endpoints(self, region_name):
        endpoints = self.keystone_client.endpoints.list(region=region_name)
        for endpoint in endpoints:
            self.keystone_client.endpoints.delete(endpoint)

    def delete_region(self, region_name):
        try:
            self.keystone_client.regions.delete(region_name)
        except keystone_exceptions.NotFound:
            pass

    def delete_users(self, region_name):
        users = self.keystone_client.users.list()
        for user in users:
            # Delete any users created specifically for this region. This
            # relies on the naming convention of <username><regionname>. For
            # example, the cinder user in subcloud1 is cindersubcloud1.
            if user.name.endswith(region_name) and user.name != region_name:
                self.keystone_client.users.delete(user)

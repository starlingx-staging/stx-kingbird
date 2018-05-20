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

import mock

from dcmanager.common import consts
from dcmanager.drivers.openstack import sysinv_v1
from dcmanager.tests import base
from dcmanager.tests import utils


class FakeInterface(object):
    def __init__(self, ifname, networktype):
        self.ifname = ifname
        self.networktype = networktype


class FakeNetwork(object):
    def __init__(self, type, pool_uuid):
        self.type = type
        self.pool_uuid = pool_uuid


class FakeAddressPool(object):
    def __init__(self, pool_uuid):
        self.pool_uuid = pool_uuid


class FakeRoute(object):
    def __init__(self, uuid, network, prefix, gateway, metric):
        self.uuid = uuid
        self.network = network
        self.prefix = prefix
        self.gateway = gateway
        self.metric = metric


class TestSysinvClient(base.DCManagerTestCase):
    def setUp(self):
        super(TestSysinvClient, self).setUp()
        self.ctx = utils.dummy_context()

    @mock.patch.object(sysinv_v1.SysinvClient, '__init__')
    def test_get_controller_hosts(self, mock_sysinvclient_init):
        controller_list = ['controller-0', 'controller-1']
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(consts.DEFAULT_REGION_NAME,
                                               None)
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.ihost.list_personality = mock.MagicMock()
        sysinv_client.sysinv_client.ihost.list_personality.return_value = \
            controller_list
        controllers = sysinv_client.get_controller_hosts()
        self.assertEqual(controller_list, controllers)

    @mock.patch.object(sysinv_v1.SysinvClient, '__init__')
    def test_get_management_interface(self, mock_sysinvclient_init):
        interface = FakeInterface('interface', 'mgmt')
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(consts.DEFAULT_REGION_NAME,
                                               None)
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.iinterface.list = mock.MagicMock()
        sysinv_client.sysinv_client.iinterface.list.return_value = [interface]
        management_interface = sysinv_client.get_management_interface(
            'hostname')
        self.assertEqual(interface, management_interface)

    @mock.patch.object(sysinv_v1.SysinvClient, '__init__')
    def test_get_management_address_pool(self, mock_sysinvclient_init):
        network = FakeNetwork('mgmt', 'uuid')
        pool = FakeAddressPool('uuid')
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(consts.DEFAULT_REGION_NAME,
                                               None)
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.network.list = mock.MagicMock()
        sysinv_client.sysinv_client.network.list.return_value = [network]
        sysinv_client.sysinv_client.address_pool.get = mock.MagicMock()
        sysinv_client.sysinv_client.address_pool.get.return_value = pool
        management_pool = sysinv_client.get_management_address_pool()
        self.assertEqual(pool, management_pool)

    @mock.patch.object(sysinv_v1.SysinvClient, '__init__')
    def test_create_route(self, mock_sysinvclient_init):
        mock_sysinvclient_init.return_value = None
        sysinv_client = sysinv_v1.SysinvClient(consts.DEFAULT_REGION_NAME,
                                               None)
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.route.create = mock.MagicMock()
        sysinv_client.create_route(
            'uuid', 'network', 'prefix', 'gateway', 'metric')
        sysinv_client.sysinv_client.route.create.assert_called_with(
            interface_uuid='uuid', network='network', prefix='prefix',
            gateway='gateway', metric='metric')

    @mock.patch.object(sysinv_v1.SysinvClient, '__init__')
    def test_delete_route(self, mock_sysinvclient_init):
        mock_sysinvclient_init.return_value = None
        route = FakeRoute('uuid', 'network', 'prefix', 'gateway', 'metric')
        sysinv_client = sysinv_v1.SysinvClient(consts.DEFAULT_REGION_NAME,
                                               None)
        sysinv_client.sysinv_client = mock.MagicMock()
        sysinv_client.sysinv_client.route.list_by_interface = mock.MagicMock()
        sysinv_client.sysinv_client.route.delete = mock.MagicMock()
        sysinv_client.sysinv_client.route.list_by_interface.return_value = \
            [route]
        sysinv_client.delete_route(
            'uuid', 'network', 'prefix', 'gateway', 'metric')
        sysinv_client.sysinv_client.route.delete.assert_called_with('uuid')

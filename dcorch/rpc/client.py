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
Client side of the DC Orchestrator RPC API.
'''

from oslo_log import log as logging

from dcorch.common import consts
from dcorch.common import messaging

LOG = logging.getLogger(__name__)


class EngineClient(object):
    """Client side of the DC orchestrator engine rpc API.

    Version History:
     1.0 - Initial version
    """

    BASE_RPC_API_VERSION = '1.0'

    def __init__(self):
        self._client = messaging.get_rpc_client(
            topic=consts.TOPIC_ORCH_ENGINE,
            version=self.BASE_RPC_API_VERSION)

    @staticmethod
    def make_msg(method, **kwargs):
        return method, kwargs

    def call(self, ctxt, msg, version=None):
        method, kwargs = msg
        if version is not None:
            client = self._client.prepare(version=version)
        else:
            client = self._client
        return client.call(ctxt, method, **kwargs)

    def cast(self, ctxt, msg, version=None):
        method, kwargs = msg
        if version is not None:
            client = self._client.prepare(version=version)
        else:
            client = self._client
        return client.cast(ctxt, method, **kwargs)

    def get_usage_for_project_and_user(self, ctxt, endpoint_type,
                                       project_id, user_id=None):
        return self.call(ctxt, self.make_msg('get_usage_for_project_and_user',
                                             endpoint_type=endpoint_type,
                                             project_id=project_id,
                                             user_id=user_id))

    def quota_sync_for_project(self, ctxt, project_id):
        return self.cast(ctxt, self.make_msg('quota_sync_for_project',
                                             project_id=project_id))

    def keypair_sync_for_user(self, ctxt, job_id, payload):
        return self.cast(
            ctxt,
            self.make_msg('keypair_sync_for_user', job_id=job_id,
                          payload=payload))

    def image_sync(self, ctxt, job_id, payload):
        return self.cast(
            ctxt,
            self.make_msg('image_sync', job_id=job_id, payload=payload))

    def add_subcloud(self, ctxt, subcloud_name, sw_version):
        return self.call(
            ctxt,
            self.make_msg('add_subcloud', subcloud_name=subcloud_name,
                          sw_version=sw_version))

    def del_subcloud(self, ctxt, subcloud_name):
        return self.call(
            ctxt,
            self.make_msg('del_subcloud', subcloud_name=subcloud_name))

    def update_subcloud_states(self, ctxt, subcloud_name, management_state,
                               availability_status):
        return self.call(
            ctxt,
            self.make_msg('update_subcloud_states',
                          subcloud_name=subcloud_name,
                          management_state=management_state,
                          availability_status=availability_status))

    def update_subcloud_version(self, ctxt, subcloud_name, sw_version):
        return self.call(
            ctxt,
            self.make_msg('update_subcloud_version',
                          subcloud_name=subcloud_name, sw_version=sw_version))

    def update_alarm_summary(self, ctxt, region_name):
        return self.cast(
            ctxt, self.make_msg('update_alarm_summary',
                                region_name=region_name))

    def get_alarm_summary(self, ctxt):
        return self.call(
            ctxt, self.make_msg('get_alarm_summary'))

    # The sync job info has been written to the DB, alert the sync engine
    # that there is work to do.
    def sync_request(self, ctxt, endpoint_type):
        return self.cast(
            ctxt, self.make_msg('sync_request', endpoint_type=endpoint_type))

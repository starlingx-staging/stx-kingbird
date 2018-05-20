# Copyright 2017 Wind River
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import threading

from cinderclient import client as cinderclient
from keystoneauth1 import exceptions as keystone_exceptions
from keystoneauth1 import loading
from keystoneauth1 import session
from keystoneclient import client as keystoneclient
from neutronclient.common import exceptions as neutronclient_exceptions
from neutronclient.neutron import client as neutronclient
from novaclient import client as novaclient
from novaclient import exceptions as novaclient_exceptions
from novaclient import utils as novaclient_utils
from requests_toolbelt import MultipartDecoder

from oslo_log import log as logging
from oslo_serialization import jsonutils

from dcmanager.common import consts as dcmanager_consts
from dcmanager.rpc import client as dcmanager_rpc_client
from dcorch.common import consts
from dcorch.common import context
from dcorch.common import exceptions
from dcorch.common import utils
from dcorch.drivers.openstack import sdk_platform as sdk
from dcorch.engine import quota_manager
from dcorch.objects import orchrequest
from dcorch.objects import resource
from dcorch.objects import subcloud_resource
from oslo_config import cfg

LOG = logging.getLogger(__name__)

STATUS_NEW = 'new'
STATUS_PROCESSING = 'processing'
STATUS_TIMEDOUT = 'timedout'
STATUS_SLEEPING = 'sleeping'
STATUS_SHUTTING_DOWN = 'shutting_down'   # is this actually needed?

# sync request states, should be in SyncRequest class
STATE_QUEUED = 'queued'
STATE_IN_PROGRESS = 'in-progress'
STATE_TIMEDOUT = 'timedout'
STATE_ABORTED = 'aborted'
STATE_FAILED = 'failed'
STATE_COMPLETED = 'completed'

# Audit findings
AUDIT_RESOURCE_MISSING = 'missing'
AUDIT_RESOURCE_EXTRA = 'extra_resource'


class SyncThread(object):
    """Manages tasks related to resource management."""

    MAX_RETRY = 2

    def __init__(self, subcloud_engine):
        super(SyncThread, self).__init__()
        self.endpoint_type = None               # endpoint type in keystone
        self.subcloud_engine = subcloud_engine  # engine that owns this obj
        self.thread = None                      # thread running sync()
        self.audit_thread = None
        self.status = STATUS_NEW                # protected by condition lock
        self.audit_status = None                # todo: needed?
        self.condition = threading.Condition()  # used to wake up the thread
        self.ctxt = context.get_admin_context()
        self.sync_handler_map = {}
        self.master_region_name = consts.CLOUD_0
        self.audit_resources = []

        self.log_extra = {
            "instance": self.subcloud_engine.subcloud.region_name + ": "}
        self.dcmanager_rpc_client = dcmanager_rpc_client.ManagerClient()
        self.sync_status = dcmanager_consts.SYNC_STATUS_UNKNOWN
        self.subcloud_managed = False

    def start(self):
        if self.status == STATUS_NEW:
            self.status = STATUS_PROCESSING
            self.thread = threading.Thread(target=self.sync)
            self.thread.start()
        else:
            LOG.error("unable to start, not in new status",
                      extra=self.log_extra)

    def shutdown(self):
        # Stop all work, optionally delete from DB
        self.condition.acquire()
        self.status = STATUS_SHUTTING_DOWN
        self.condition.notify()  # Wake the threads so they exit.
        self.condition.release()

    def should_exit(self):
        # Return whether the sync/audit threads should exit.
        # Caller must hold the condition lock.
        return self.status == STATUS_SHUTTING_DOWN

    def wake(self):
        # Called when work has been saved to the DB
        self.condition.acquire()
        self.status = STATUS_PROCESSING
        self.condition.notify()
        self.condition.release()

    def initialize(self):
        # To be overridden by endpoint implementation if there
        # are actions to be performed when a subcloud goes enabled.
        pass

    def enable(self):
        # Called when DC manager thinks this subcloud is good to go.
        self.initialize()
        self.wake()
        self.run_sync_audit()

    def get_db_subcloud_resource(self, rsrc_id):
        try:
            subcloud_rsrc = \
                subcloud_resource.SubcloudResource. \
                get_by_resource_and_subcloud(
                    self.ctxt, rsrc_id, self.subcloud_engine.subcloud.id)
            return subcloud_rsrc
        except exceptions.SubcloudResourceNotFound:
            LOG.info("{} not found in subcloud {} resource table".format(
                     rsrc_id, self.subcloud_engine.subcloud.id),
                     extra=self.log_extra)
        return None

    def persist_db_subcloud_resource(self, db_rsrc_id, subcloud_rsrc_id):
        # This function can be invoked after creating a subcloud resource.
        # Persist the subcloud resource to the DB for later
        #
        # Parameters:
        #   db_rsrc_id: the "id" field of the resource in the DB
        #   subcloud_rsrc_id: the unique identifier of the subcloud resource

        subcloud_rsrc = self.get_db_subcloud_resource(db_rsrc_id)
        if not subcloud_rsrc:
            subcloud_rsrc = subcloud_resource.SubcloudResource(
                self.ctxt, subcloud_resource_id=subcloud_rsrc_id,
                resource_id=db_rsrc_id,
                subcloud_id=self.subcloud_engine.subcloud.id)
            # There is no race condition for creation of
            # subcloud_resource as it is always done from the same thread.
            subcloud_rsrc.create()
        elif subcloud_rsrc.subcloud_resource_id != subcloud_rsrc_id:
            # May be the resource was manually deleted from the subcloud.
            # So, update the dcorch DB with the new resource id from subcloud.
            subcloud_rsrc.subcloud_resource_id = subcloud_rsrc_id
            LOG.info("Updating {}:{} [{}]".format(db_rsrc_id,
                     subcloud_rsrc.subcloud_resource_id, subcloud_rsrc_id),
                     extra=self.log_extra)
            subcloud_rsrc.save()
        else:
            LOG.info("subcloud_rsrc {}:{} [{}] is up-to-date"
                     .format(db_rsrc_id, subcloud_rsrc.subcloud_resource_id,
                             subcloud_rsrc_id),
                     extra=self.log_extra)
        return subcloud_rsrc.subcloud_resource_id

    def sync_resource(self, sync_request):
        rsrc = resource.Resource.get_by_id(self.ctxt,
                                           sync_request.orch_job.resource_id)
        handler = self.sync_handler_map[rsrc.resource_type]
        LOG.info("Invoking {} for {} [{}]".format(
            handler.func_name, rsrc.resource_type,
            sync_request.orch_job.operation_type), extra=self.log_extra)
        handler(sync_request, rsrc)

    def set_sync_status(self, sync_status):
        # Only report sync_status when managed
        subcloud_managed = self.subcloud_engine.is_managed()
        if not subcloud_managed:
            LOG.debug("set_sync_status: skip update sync update for unmanaged "
                      "subcloud {}".format(
                          self.subcloud_engine.subcloud.region_name))
            self.sync_status = dcmanager_consts.SYNC_STATUS_UNKNOWN
            self.subcloud_managed = False
            return

        if ((self.sync_status == sync_status) and
           (self.subcloud_managed != subcloud_managed)):
            return

        self.sync_status = sync_status
        self.subcloud_managed = subcloud_managed

        self.dcmanager_rpc_client.update_subcloud_endpoint_status(
            self.ctxt, self.subcloud_engine.subcloud.region_name,
            self.endpoint_type, sync_status)

    def sync(self):
        LOG.info("{}: starting sync routine".format(self.thread.name),
                 extra=self.log_extra)
        self.condition.acquire()
        self.status = STATUS_PROCESSING
        region_name = self.subcloud_engine.subcloud.region_name
        while self.status != STATUS_SHUTTING_DOWN:
            sync_requests = []
            # We want to check for pending work even if subcloud is disabled.
            if self.status in (STATUS_PROCESSING, STATUS_TIMEDOUT):
                states = [
                    consts.ORCH_REQUEST_QUEUED,
                    consts.ORCH_REQUEST_IN_PROGRESS,
                ]
                sync_requests = orchrequest.OrchRequestList.get_by_attrs(
                    self.ctxt, self.endpoint_type,
                    target_region_name=region_name,
                    states=states)
                LOG.info("Got " + str(len(sync_requests)) + " sync request(s)",
                         extra=self.log_extra)
                # todo: for each request look up sync handler based on
                # resource type (I'm assuming here we're not storing a python
                # object in the DB)

            # Update dcmanager with the current sync status.
            subcloud_enabled = self.subcloud_engine.is_enabled()
            if sync_requests:
                self.set_sync_status(dcmanager_consts.SYNC_STATUS_OUT_OF_SYNC)
            else:
                self.set_sync_status(dcmanager_consts.SYNC_STATUS_IN_SYNC)

            if (not sync_requests or not subcloud_enabled or
                    self.status == STATUS_TIMEDOUT):
                # Either there are no sync requests, or subcloud is disabled,
                # or we timed out trying to talk to it.
                # We're not going to process any sync requests, just go
                # back to sleep.
                if not subcloud_enabled:
                    LOG.info("subcloud is disabled", extra=self.log_extra)
                if self.status == STATUS_PROCESSING:
                    self.status = STATUS_SLEEPING
                LOG.debug("calling condition.wait", extra=self.log_extra)
                # no work to do, sleep till someone wakes us
                self.condition.wait()
                LOG.debug("back from condition.wait", extra=self.log_extra)
            else:
                # Subcloud is enabled and there are pending sync requests, so
                # we have work to do.
                self.condition.release()
                try:
                    for request in sync_requests:
                        if not self.subcloud_engine.is_enabled() or \
                                self.should_exit():
                            # Oops, someone disabled the endpoint while
                            # we were processing work for it.
                            raise exceptions.EndpointNotReachable()
                        request.state = consts.ORCH_REQUEST_STATE_IN_PROGRESS
                        request.save()  # save to DB
                        retry_count = 0
                        while retry_count < self.MAX_RETRY:
                            try:
                                self.sync_resource(request)
                                request.state = \
                                    consts.ORCH_REQUEST_STATE_COMPLETED
                                request.save()  # save to DB
                                break
                            except exceptions.SyncRequestTimeout:
                                request.try_count += 1
                                request.save()
                                retry_count += 1
                                if retry_count >= self.MAX_RETRY:
                                    # todo: raise "unable to sync this
                                    # subcloud/endpoint" alarm with fmapi
                                    self.condition.acquire()
                                    self.status = STATUS_TIMEDOUT
                                    self.condition.release()
                                    raise exceptions.EndpointNotReachable()
                            except exceptions.SyncRequestFailedRetry:
                                # todo: raise "unable to sync this
                                # subcloud/endpoint" alarm with fmapi
                                request.try_count += 1
                                request.state = \
                                    consts.ORCH_REQUEST_STATE_FAILED
                                request.save()
                                retry_count += 1
                                # we'll retry
                            except exceptions.SyncRequestFailed:
                                request.state = \
                                    consts.ORCH_REQUEST_STATE_FAILED
                                request.save()
                                retry_count = self.MAX_RETRY

                        # If we fall out of the retry loop we either succeeded
                        # or failed multiple times and want to move to the next
                        # request.

                except exceptions.EndpointNotReachable:
                    # Endpoint not reachable, throw away all the sync requests.
                    LOG.info("EndpointNotReachable, {} sync requests pending"
                             .format(len(sync_requests)))
                    # del sync_requests[:] #This fails due to:
                    # 'OrchRequestList' object does not support item deletion
                self.condition.acquire()
        # if we get here it's because we want this thread to exit
        self.condition.release()
        LOG.info("exiting thread for subcloud", extra=self.log_extra)

    def run_sync_audit(self):
        if not self.subcloud_engine.is_enabled() or self.should_exit():
            return
        if self.endpoint_type in cfg.CONF.disable_audit_endpoints:
            LOG.warn("Audit disabled!", extra=self.log_extra)
            return
        # This will be called periodically as well as when the subcloud is
        # enabled. We want to make a new thread to do this so the caller
        # doesn't get blocked.
        thread = threading.Thread(target=self.do_sync_audit)
        thread.start()
        LOG.debug("{}: do_sync_audit started".format(thread.name),
                  extra=self.log_extra)

    def do_sync_audit(self):
        LOG.debug("In do sync audit", extra=self.log_extra)
        # This first part just checks to see if we want to wake up the main
        # sync thread. We want to run this unconditionally.
        self.condition.acquire()
        if self.status == STATUS_TIMEDOUT:
            self.status = STATUS_PROCESSING
            self.condition.notify()

        # Now we want to look at the actual sync audit.  If there's already a
        # sync audit thread running don't make a new one.
        if self.audit_thread is None or not self.audit_thread.is_alive():
            LOG.debug("Creating sync audit thread", extra=self.log_extra)
            self.audit_thread = threading.Thread(target=self.sync_audit)
            self.audit_thread.start()
        else:
            LOG.info("Skipping sync audit thread creation, already running",
                     extra=self.log_extra)
        self.condition.release()

    def sync_audit(self):
        LOG.debug("{}: starting sync audit".format(self.audit_thread.name),
                  extra=self.log_extra)

        total_num_of_audit_jobs = 0
        for resource_type in self.audit_resources:
            if not self.subcloud_engine.is_enabled() or self.should_exit():
                LOG.info("{}: aborting sync audit, as subcloud is disabled"
                         .format(self.audit_thread.name),
                         extra=self.log_extra)
                return

            # Skip resources with outstanding sync requests
            region_name = self.subcloud_engine.subcloud.region_name
            sync_requests = []
            states = [
                consts.ORCH_REQUEST_QUEUED,
                consts.ORCH_REQUEST_IN_PROGRESS,
            ]
            sync_requests = orchrequest.OrchRequestList.get_by_attrs(
                self.ctxt, self.endpoint_type, resource_type=resource_type,
                target_region_name=region_name, states=states)
            abort_resources = [req.orch_job.source_resource_id
                               for req in sync_requests]
            if len(sync_requests) > 0:
                LOG.info("Will not audit {}. {} sync request(s) pending"
                         .format(abort_resources, len(sync_requests)),
                         extra=self.log_extra)

            num_of_audit_jobs = 0
            try:
                m_resources, db_resources, sc_resources = \
                    self.get_all_resources(resource_type)

                # todo: delete entries in db_resources with no corresponding
                # entry in m_resources?

                if sc_resources is None or m_resources is None:
                    return
                LOG.info("Audit {}: {} vs {}".format(
                    resource_type, m_resources, sc_resources),
                    extra=self.log_extra)
                LOG.debug("Auditing {}: master={} db={} sc={}".format(
                    resource_type, m_resources, db_resources, sc_resources),
                    extra=self.log_extra)
                num_of_audit_jobs += self.audit_find_missing(
                    resource_type, m_resources, db_resources, sc_resources,
                    abort_resources)
                num_of_audit_jobs += self.audit_find_extra(
                    resource_type, m_resources, db_resources, sc_resources,
                    abort_resources)
            except Exception as e:
                LOG.exception(e)

            # Extra resources in subcloud are not impacted by the audit.

            if not num_of_audit_jobs:
                LOG.info("Clean audit run for {}".format(resource_type),
                         extra=self.log_extra)
            total_num_of_audit_jobs += num_of_audit_jobs

        if not total_num_of_audit_jobs:
            # todo: if we had an "unable to sync this
            # subcloud/endpoint" alarm raised, then clear it
            pass

        LOG.debug("{}: done sync audit".format(self.audit_thread.name),
                  extra=self.log_extra)

    def audit_find_missing(self, resource_type, m_resources,
                           db_resources, sc_resources,
                           abort_resources):
        """Find missing resources in subcloud.

        - Input param db_resources is modified in this routine
          to remove entries that match the resources in
          master cloud. At the end, db_resources will have a
          list of resources that are present in dcorch DB, but
          not present in the master cloud.
        """
        num_of_audit_jobs = 0
        for m_r in m_resources:
            master_id = self.get_resource_id(resource_type, m_r)
            if master_id in abort_resources:
                LOG.info("audit_find_missing: Aborting audit for {}"
                         .format(master_id), extra=self.log_extra)
                num_of_audit_jobs += 1
                # There are pending jobs for this resource, abort audit
                continue

            missing_resource = False
            m_rsrc_db = None
            for db_resource in db_resources:
                if db_resource.master_id == master_id:
                    m_rsrc_db = db_resource
                    db_resources.remove(db_resource)
                    break

            if m_rsrc_db:
                # resource from master cloud is present in DB.

                # Contents of "m_r" may refer to other master cloud resources.
                # Make a copy with the references updated to refer to subcloud
                # resources.
                try:
                    m_r_updated = self.update_resource_refs(resource_type, m_r)
                except exceptions.SubcloudResourceNotFound:
                    # If we couldn't find the equivalent subcloud resources,
                    # we don't know what to look for in the subcloud so skip
                    # this m_r and go to the next one.
                    continue

                # Now, look for subcloud resource in DB.
                # If present: look for actual resource in the
                # subcloud and compare the resource details.
                # If not present: create resource in subcloud.
                db_sc_resource = self.get_db_subcloud_resource(m_rsrc_db.id)
                if db_sc_resource:
                    if not db_sc_resource.is_managed():
                        LOG.info("Resource {} is not managed"
                                 .format(master_id), extra=self.log_extra)
                        continue
                    sc_rsrc_present = False
                    for sc_r in sc_resources:
                        sc_id = self.get_resource_id(resource_type, sc_r)
                        if sc_id == db_sc_resource.subcloud_resource_id:
                            if self.same_resource(resource_type,
                                                  m_r_updated, sc_r):
                                LOG.info("Resource type {} {} is in-sync"
                                         .format(resource_type, master_id),
                                         extra=self.log_extra)
                                num_of_audit_jobs += self.audit_dependants(
                                    resource_type, m_r, sc_r)
                                sc_rsrc_present = True
                                break
                    if not sc_rsrc_present:
                        LOG.info(
                            "Subcloud resource {} found in master cloud & DB, "
                            "but the exact same resource not found in subcloud"
                            .format(db_sc_resource.subcloud_resource_id),
                            extra=self.log_extra)
                        # Subcloud resource is present in DB, but the check
                        # for same_resource() was negative. Either the resource
                        # disappeared from subcloud or the resource details
                        # are different from that of master cloud. Let the
                        # resource implementation decide on the audit action.
                        missing_resource = self.audit_discrepancy(
                            resource_type, m_r, sc_resources)
                else:
                    LOG.info("Subcloud res {} not found in DB, will create"
                             .format(master_id), extra=self.log_extra)
                    # Check and see if there are any subcloud resources that
                    # match the master resource, and if so set up mappings.
                    # This returns true if it finds a match.
                    if self.map_subcloud_resource(resource_type, m_r_updated,
                                                  m_rsrc_db, sc_resources):
                        continue
                    missing_resource = True

            else:  # master_resource not in resource DB
                LOG.info("{} not found in DB, will create it"
                         .format(master_id),
                         extra=self.log_extra)
                missing_resource = True

            if missing_resource:
                # Resource is missing from subcloud, take action
                num_of_audit_jobs += self.audit_action(
                    resource_type, AUDIT_RESOURCE_MISSING, m_r)
                # As the subcloud resource is missing, invoke
                # the hook for dependants with no subcloud resource.
                # Resource implementation should handle this.
                num_of_audit_jobs += self.audit_dependants(
                    resource_type, m_r, None)
        return num_of_audit_jobs

    def audit_find_extra(self, resource_type, m_resources,
                         db_resources, sc_resources, abort_resources):
        """Find extra resources in subcloud.

        - Input param db_resources is expected to be a
          list of resources that are present in dcorch DB, but
          not present in the master cloud.
        """

        num_of_audit_jobs = 0
        # At this point, db_resources contains resources present in DB,
        # but not in master cloud
        for db_resource in db_resources:
            if db_resource.master_id:
                if db_resource.master_id in abort_resources:
                    LOG.info("audit_find_extra: Aborting audit for {}"
                             .format(db_resource.master_id),
                             extra=self.log_extra)
                    num_of_audit_jobs += 1
                    # There are pending jobs for this resource, abort audit
                    continue

                LOG.debug("Extra resource ({}) in DB".format(db_resource.id),
                          extra=self.log_extra)
                subcloud_rsrc = self.get_db_subcloud_resource(db_resource.id)
                if subcloud_rsrc:
                    if not subcloud_rsrc.is_managed():
                        LOG.info("Resource {} is not managed"
                                 .format(subcloud_rsrc.subcloud_resource_id),
                                 extra=self.log_extra)
                        continue
                    LOG.info("Resource ({}) and subcloud resource ({}) "
                             "not in sync with master cloud"
                             .format(db_resource.master_id,
                                     subcloud_rsrc.subcloud_resource_id),
                             extra=self.log_extra)
                    # There is extra resource in the subcloud, take action.
                    # Note that the resource is in dcorch DB, but not
                    # actually present in the master cloud.
                    num_of_audit_jobs += self.audit_action(
                        resource_type, AUDIT_RESOURCE_EXTRA, db_resource)
                else:
                    # Resource is present in resource table, but not in
                    # subcloud_resource table. We have also established that
                    # the corresponding OpenStack resource is not present in
                    # the master cloud.
                    # There might be another subcloud with "unmanaged"
                    # subcloud resource corresponding to this resource.
                    # So, just ignore this here!
                    pass
        return num_of_audit_jobs

    def schedule_work(self, endpoint_type, resource_type,
                      source_resource_id, operation_type,
                      resource_info=None):
        LOG.info("Scheduling {} work for {}/{}".format(
                 operation_type, resource_type, source_resource_id),
                 extra=self.log_extra)
        try:
            utils.enqueue_work(
                self.ctxt, endpoint_type, resource_type,
                source_resource_id, operation_type, resource_info,
                subcloud=self.subcloud_engine.subcloud)
            self.wake()
        except Exception as e:
            LOG.info("Exception in schedule_work: {}".format(str(e)),
                     extra=self.log_extra)

    def get_resource_id(self, resource_type, resource):
        if hasattr(resource, 'master_id'):
            # If resource from DB, return master resource id
            # from master cloud
            return resource.master_id
        else:
            # Else, return id field (by default)
            return resource.id

    # Audit functions to be overridden in inherited classes
    def get_all_resources(self, resource_type):
        m_resources = None
        db_resources = None
        # Query subcloud first. If not reachable, abort audit.
        sc_resources = self.get_subcloud_resources(resource_type)
        if sc_resources is None:
            return m_resources, db_resources, sc_resources
        db_resources = self.get_db_master_resources(resource_type)
        # todo: master resources will be read by multiple threads
        # depending on the number of subclouds. Could do some kind of
        # caching for performance improvement.
        m_resources = self.get_master_resources(resource_type)
        return m_resources, db_resources, sc_resources

    def get_subcloud_resources(self, resource_type):
        return None

    def get_db_master_resources(self, resource_type):
        return list(resource.ResourceList.get_all(self.ctxt, resource_type))

    def get_master_resources(self, resource_type):
        return None

    def same_resource(self, resource_type, m_resource, sc_resource):
        return True

    def map_subcloud_resource(self, resource_type, m_r, m_rsrc_db,
                              sc_resources):
        # Child classes can override this function to map an existing subcloud
        # resource to an existing master resource.  If a mapping is created
        # the function should return True.
        #
        # It is expected that update_resource_refs() has been called on m_r.
        return False

    def update_resource_refs(self, resource_type, m_r):
        # Child classes can override this function to update any references
        # to other master resources embedded within the info of this resource.
        return m_r

    def audit_dependants(self, resource_type, m_resource, sc_resource):
        num_of_audit_jobs = 0
        if not self.subcloud_engine.is_enabled() or self.should_exit():
            return num_of_audit_jobs
        if not sc_resource:
            # Handle None value for sc_resource
            pass
        return num_of_audit_jobs

    def audit_discrepancy(self, resource_type, m_resource, sc_resources):
        # Return true to try creating the resource again
        return True

    def audit_action(self, resource_type, finding, resource):
        LOG.info("audit_action: {}/{}"
                 .format(finding, resource_type),
                 extra=self.log_extra)
        # Default actions are create & delete. Can be overridden
        # in resource implementation
        num_of_audit_jobs = 0
        # resource can be either from dcorch DB or fetched by OpenStack query
        resource_id = self.get_resource_id(resource_type, resource)
        if finding == AUDIT_RESOURCE_MISSING:
            # default action is create for a 'missing' resource
            self.schedule_work(
                self.endpoint_type, resource_type,
                resource_id,
                consts.OPERATION_TYPE_CREATE,
                self.get_resource_info(
                    resource_type, resource,
                    consts.OPERATION_TYPE_CREATE))
            num_of_audit_jobs += 1
        elif finding == AUDIT_RESOURCE_EXTRA:
            # default action is delete for an 'extra_resource'
            # resource passed in is db_resource (resource in dcorch DB)
            self.schedule_work(self.endpoint_type, resource_type,
                               resource_id,
                               consts.OPERATION_TYPE_DELETE)
            num_of_audit_jobs += 1
        return num_of_audit_jobs

    def get_resource_info(self, resource_type, resource, operation_type=None):
        return ""


class VolumeSyncThread(SyncThread):
    """Manages tasks related to resource management for cinder."""

    def __init__(self, subcloud_engine):
        super(VolumeSyncThread, self).__init__(subcloud_engine)
        self.endpoint_type = consts.ENDPOINT_TYPE_VOLUME
        self.sync_handler_map = {
            consts.RESOURCE_TYPE_VOLUME_QUOTA_SET: self.sync_volume_resource,
            consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
                self.sync_volume_resource,
        }
        self.audit_resources = [
            consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET,
            # note: no audit here for quotas, that's handled separately
        ]
        self.log_extra = {"instance": "{}/{}: ".format(
            self.subcloud_engine.subcloud.region_name,
            self.endpoint_type)}

        self.initialize()
        LOG.info("VolumeSyncThread initialized", extra=self.log_extra)

    def initialize(self):
        # Subcloud may be enabled a while after being added.
        # Keystone endpoints for the subcloud could be added in
        # between these 2 steps. Reinitialize the session to
        # get the most up-to-date service catalog.
        loader = loading.get_plugin_loader(
            cfg.CONF.keystone_authtoken.auth_type)
        auth = loader.load_from_options(
            auth_url=cfg.CONF.cache.auth_uri,
            username=cfg.CONF.cache.admin_username,
            password=cfg.CONF.cache.admin_password,
            project_name=cfg.CONF.cache.admin_tenant,
            project_domain_name=cfg.CONF.cache.admin_project_domain_name,
            user_domain_name=cfg.CONF.cache.admin_user_domain_name)
        self.admin_session = session.Session(
            auth=auth, timeout=60, additional_headers=consts.USER_HEADER)
        self.ks_client = keystoneclient.Client(
            session=self.admin_session,
            region_name=consts.VIRTUAL_MASTER_CLOUD)
        self.m_cinder_client = cinderclient.Client(
            "3.0", session=self.admin_session,
            endpoint_type=consts.KS_ENDPOINT_INTERNAL,
            region_name=consts.VIRTUAL_MASTER_CLOUD)
        self.sc_cinder_client = cinderclient.Client(
            "3.0", session=self.admin_session,
            endpoint_type=consts.KS_ENDPOINT_INTERNAL,
            region_name=self.subcloud_engine.subcloud.region_name)
        LOG.info("session and clients initialized", extra=self.log_extra)

    def sync_volume_resource(self, request, rsrc):
        # Invoke function with name format "operationtype_resourcetype".
        # For example: create_flavor()
        try:
            func_name = request.orch_job.operation_type + \
                "_" + rsrc.resource_type
            getattr(self, func_name)(request, rsrc)
        except keystone_exceptions.EndpointNotFound as e:
            # Cinder is optional in the subcloud, so this isn't considered
            # an error.
            LOG.info("sync_volume_resource: {} does not have a volume "
                     "endpoint in keystone"
                     .format(self.subcloud_engine.subcloud.region_name),
                     extra=self.log_extra)
        except AttributeError:
            LOG.error("{} not implemented for {}"
                      .format(request.orch_job.operation_type,
                              rsrc.resource_type))
            raise exceptions.SyncRequestFailed
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.error("sync_volume_resource: {} is not reachable [{}]"
                      .format(self.subcloud_engine.subcloud.region_name,
                              str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except exceptions.SyncRequestFailed:
            raise
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def put_volume_quota_set(self, request, rsrc):
        project_id = request.orch_job.source_resource_id

        # Get the new global limits from the request.
        quota_dict = jsonutils.loads(request.orch_job.resource_info)

        # Cinder doesn't do user-specific quotas
        user_id = None

        # The client code may set a tenant_id field.  If so, remove it
        # since it's not defined in the API.
        quota_dict.pop('tenant_id', None)

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Apply the limits to the subcloud.
        self.sc_cinder_client.quotas.update(project_id, **quota_dict)

        # Persist the subcloud resource. (Not really applicable for quotas.)
        self.persist_db_subcloud_resource(rsrc.id, rsrc.master_id)
        LOG.info("Updated quotas {} for tenant {} and user {}"
                 .format(quota_dict, rsrc.master_id, user_id),
                 extra=self.log_extra)

    def delete_volume_quota_set(self, request, rsrc):
        # When deleting the quota-set in the master cloud, we don't actually
        # delete it in the subcloud.  Instead we recalculate the subcloud
        # quotas based on the defaults in the master cloud.

        project_id = request.orch_job.source_resource_id
        user_id = None

        # Get the new master quotas
        quota_dict = self.m_cinder_client.quotas.get(project_id).to_dict()

        # Remove the 'id' key before doing calculations.
        quota_dict.pop('id', None)

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Apply the limits to the subcloud.
        self.sc_cinder_client.quotas.update(project_id, **quota_dict)

        # Clean up the subcloud resource entry in the DB since it's been
        # deleted in the master cloud.
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if subcloud_rsrc:
            subcloud_rsrc.delete()

    def put_quota_class_set(self, request, rsrc):
        # Only a class_id of "default" is meaningful to cinder.
        class_id = request.orch_job.source_resource_id

        # Get the new quota class limits from the request.
        quota_dict = jsonutils.loads(request.orch_job.resource_info)

        # If this is coming from the audit we need to remove the "id" field.
        quota_dict.pop('id', None)

        # The client code may set a class name.  If so, remove it since it's
        # not defined in the API.
        quota_dict.pop('class_name', None)

        # Apply the new quota class limits to the subcloud.
        self.sc_cinder_client.quota_classes.update(class_id, **quota_dict)

        # Persist the subcloud resource. (Not really applicable for quotas.)
        self.persist_db_subcloud_resource(rsrc.id, rsrc.master_id)
        LOG.info("Updated quota classes {} for class {}"
                 .format(quota_dict, rsrc.master_id),
                 extra=self.log_extra)

    # ---- Override common audit functions ----
    def get_resource_id(self, resource_type, resource):
        if resource_type == consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
            # We only care about the default class.
            return 'default'
        else:
            return super(VolumeSyncThread, self).get_resource_id(
                resource_type, resource)

    def get_resource_info(self, resource_type, resource, operation_type=None):
        if resource_type == consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
            return jsonutils.dumps(resource._info)
        else:
            return super(VolumeSyncThread, self).get_resource_info(
                resource_type, resource, operation_type)

    def get_subcloud_resources(self, resource_type):
        if resource_type == consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
            return self.get_quota_class_resources(self.sc_cinder_client)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def get_master_resources(self, resource_type):
        if resource_type == consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
            return self.get_quota_class_resources(self.m_cinder_client)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def same_resource(self, resource_type, m_resource, sc_resource):
        if resource_type == consts.RESOURCE_TYPE_VOLUME_QUOTA_CLASS_SET:
            return self.same_quota_class(m_resource, sc_resource)
        else:
            return True

    # This will only be called by the audit code.
    def create_quota_class_set(self, request, rsrc):
        self.put_quota_class_set(request, rsrc)

    def same_quota_class(self, qc1, qc2):
        # The audit code will pass in QuotaClassSet objects, we need to
        # convert them before comparing them.
        return qc1.to_dict() == qc2.to_dict()

    def get_quota_class_resources(self, nc):
        # We only care about the "default" class since it's the only one
        # that actually affects cinder.
        try:
            quota_class = nc.quota_classes.get('default')
            return [quota_class]
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_quota_class: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except keystone_exceptions.EndpointNotFound as e:
            LOG.info("get_quota_class: subcloud {} does not have a volume "
                     "endpoint in keystone"
                     .format(self.subcloud_engine.subcloud.region_name),
                     extra=self.log_extra)
            return None
        except Exception as e:
            LOG.exception(e)
            return None


class NetworkSyncThread(SyncThread):
    """Manages tasks related to resource management for neutron."""

    def __init__(self, subcloud_engine):
        super(NetworkSyncThread, self).__init__(subcloud_engine)
        self.endpoint_type = consts.ENDPOINT_TYPE_NETWORK
        self.sync_handler_map = {
            consts.RESOURCE_TYPE_NETWORK_QUOTA_SET: self.sync_network_resource,
            consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP:
                self.sync_network_resource,
            consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE:
                self.sync_network_resource,
        }
        # Security group needs to come before security group rule to ensure
        # that the group exists by the time we try to create the rules.
        self.audit_resources = [
            consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
            consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE,
            # note: no audit here for quotas, that's handled separately
        ]
        self.log_extra = {"instance": "{}/{}: ".format(
            self.subcloud_engine.subcloud.region_name, self.endpoint_type)}

        self.initialize()
        LOG.info("NetworkSyncThread initialized", extra=self.log_extra)

    def initialize(self):
        # Subcloud may be enabled a while after being added.
        # Keystone endpoints for the subcloud could be added in
        # between these 2 steps. Reinitialize the session to
        # get the most up-to-date service catalog.
        loader = loading.get_plugin_loader(
            cfg.CONF.keystone_authtoken.auth_type)
        auth = loader.load_from_options(
            auth_url=cfg.CONF.cache.auth_uri,
            username=cfg.CONF.cache.admin_username,
            password=cfg.CONF.cache.admin_password,
            project_name=cfg.CONF.cache.admin_tenant,
            project_domain_name=cfg.CONF.cache.admin_project_domain_name,
            user_domain_name=cfg.CONF.cache.admin_user_domain_name)
        self.admin_session = session.Session(
            auth=auth, timeout=60, additional_headers=consts.USER_HEADER)
        self.ks_client = keystoneclient.Client(
            session=self.admin_session,
            region_name=consts.VIRTUAL_MASTER_CLOUD)
        self.m_neutron_client = neutronclient.Client(
            "2.0", session=self.admin_session,
            endpoint_type=consts.KS_ENDPOINT_INTERNAL,
            region_name=consts.VIRTUAL_MASTER_CLOUD)
        self.sc_neutron_client = neutronclient.Client(
            "2.0", session=self.admin_session,
            endpoint_type=consts.KS_ENDPOINT_INTERNAL,
            region_name=self.subcloud_engine.subcloud.region_name)
        LOG.info("session and clients initialized", extra=self.log_extra)

    def sync_network_resource(self, request, rsrc):
        # Invoke function with name format "operationtype_resourcetype".
        # For example: create_flavor()
        try:
            func_name = request.orch_job.operation_type + \
                "_" + rsrc.resource_type
            getattr(self, func_name)(request, rsrc)
        except AttributeError:
            LOG.error("{} not implemented for {}"
                      .format(request.orch_job.operation_type,
                              rsrc.resource_type))
            raise exceptions.SyncRequestFailed
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.error("sync_network_resource: {} is not reachable [{}]"
                      .format(self.subcloud_engine.subcloud.region_name,
                              str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except exceptions.SyncRequestFailed:
            raise
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def put_network_quota_set(self, request, rsrc):
        project_id = request.orch_job.source_resource_id

        # Get the new global limits from the request.
        quota_dict = jsonutils.loads(request.orch_job.resource_info)

        # Neutron doesn't do user-specific quotas
        user_id = None

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Apply the limits to the subcloud.
        self.sc_neutron_client.update_quota(project_id, {"quota": quota_dict})

        # Persist the subcloud resource. (Not really applicable for quotas.)
        self.persist_db_subcloud_resource(rsrc.id, rsrc.master_id)
        LOG.info("Updated quotas {} for tenant {} and user {}"
                 .format(quota_dict, rsrc.master_id, user_id),
                 extra=self.log_extra)

    def delete_network_quota_set(self, request, rsrc):
        # When deleting the quota-set in the master cloud, we don't actually
        # delete it in the subcloud.  Instead we recalculate the subcloud
        # quotas based on the defaults in the master cloud.
        project_id = request.orch_job.source_resource_id
        user_id = None

        # Get the new master quotas
        quota_dict = self.m_neutron_client.show_quota(project_id)['quota']

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Apply the limits to the subcloud.
        self.sc_neutron_client.update_quota(project_id, {"quota": quota_dict})

        # Clean up the subcloud resource entry in the DB since it's been
        # deleted in the master cloud.
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if subcloud_rsrc:
            subcloud_rsrc.delete()

    def post_security_group(self, request, rsrc):
        sec_group_dict = jsonutils.loads(request.orch_job.resource_info)
        body = {"security_group": sec_group_dict}

        # Create the security group in the subcloud
        sec_group = self.sc_neutron_client.create_security_group(body)
        sec_group_id = sec_group['security_group']['id']

        # Persist the subcloud resource.
        subcloud_rsrc_id = self.persist_db_subcloud_resource(rsrc.id,
                                                             sec_group_id)
        LOG.info("Created security group {}:{} [{}]"
                 .format(rsrc.id, subcloud_rsrc_id, sec_group_dict['name']),
                 extra=self.log_extra)

    def put_security_group(self, request, rsrc):
        sec_group_dict = jsonutils.loads(request.orch_job.resource_info)
        body = {"security_group": sec_group_dict}

        sec_group_subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not sec_group_subcloud_rsrc:
            LOG.error("Unable to update security group {}:{},"
                      "cannot find equivalent security group in subcloud."
                      .format(rsrc, sec_group_dict),
                      extra=self.log_extra)
            return

        # Update the security group in the subcloud
        sec_group = self.sc_neutron_client.update_security_group(
            sec_group_subcloud_rsrc.subcloud_resource_id, body)
        sec_group = sec_group['security_group']

        LOG.info("Updated security group: {}:{} [{}]"
                 .format(rsrc.id, sec_group['id'], sec_group['name']),
                 extra=self.log_extra)

    def delete_security_group(self, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return
        try:
            self.sc_neutron_client.delete_security_group(
                subcloud_rsrc.subcloud_resource_id)
        except neutronclient_exceptions.NotFound:
            # security group already deleted in subcloud, carry on.
            LOG.info("ResourceNotFound in subcloud, may be already deleted",
                     extra=self.log_extra)
        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Security group {}:{} [{}] deleted"
                 .format(rsrc.id, subcloud_rsrc.id,
                         subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)

    def post_security_group_rule(self, request, rsrc):
        sec_group_rule_dict = jsonutils.loads(request.orch_job.resource_info)

        # Any fields with values of "None" are removed since they are defaults
        # and we can't send them to Neutron.
        for key in sec_group_rule_dict.keys():
            if sec_group_rule_dict[key] is None:
                del sec_group_rule_dict[key]

        try:
            sec_group_rule_dict = self.update_resource_refs(
                consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE,
                sec_group_rule_dict)
        except exceptions.SubcloudResourceNotFound:
            # If we couldn't find the equivalent internal resource refs,
            # we don't know what to create in the subcloud.
            raise exceptions.SyncRequestFailed

        body = {"security_group_rule": sec_group_rule_dict}

        # Create the security group in the subcloud
        try:
            rule = self.sc_neutron_client.create_security_group_rule(body)
            rule_id = rule['security_group_rule']['id']
        except neutronclient.common.exceptions.Conflict:
            # This can happen if we try to create a rule that is already there.
            # If this happens, we'll update our mapping on the next audit.
            LOG.info("Problem creating security group rule {}, neutron says"
                     "it's a duplicate.".format(sec_group_rule_dict))
            # No point in retrying.
            raise exceptions.SyncRequestFailed

        # Persist the subcloud resource.
        self.persist_db_subcloud_resource(rsrc.id, rule_id)
        LOG.info("Created security group rule {}:{}"
                 .format(rsrc.id, rule_id),
                 extra=self.log_extra)

    def delete_security_group_rule(self, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return
        try:
            self.sc_neutron_client.delete_security_group_rule(
                subcloud_rsrc.subcloud_resource_id)
        except neutronclient_exceptions.NotFound:
            # security group rule already deleted in subcloud, carry on.
            LOG.info("ResourceNotFound in subcloud, may be already deleted",
                     extra=self.log_extra)
        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Security group rule {}:{} [{}] deleted"
                 .format(rsrc.id, subcloud_rsrc.id,
                         subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)

    # ---- Override common audit functions ----

    def get_resource_id(self, resource_type, resource):
        if hasattr(resource, 'master_id'):
            # If resource from DB, return master resource id
            # from master cloud
            return resource.master_id

        # Else, it is OpenStack resource retrieved from master cloud
        if resource_type in (consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
                             consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE):
            return resource['id']

    def get_resource_info(self, resource_type, resource, operation_type=None):
        if resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP:
            if isinstance(resource, dict):
                tmp = resource.copy()
                del tmp['id']
                return jsonutils.dumps(tmp)
            else:
                return jsonutils.dumps(
                    resource._info.get(
                        consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP))
        elif resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE:
            if isinstance(resource, dict):
                tmp = resource.copy()
                del tmp['id']
                return jsonutils.dumps(tmp)
            else:
                return jsonutils.dumps(resource._info.get(
                    consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE))
        else:
            return super(NetworkSyncThread, self).get_resource_info(
                resource_type, resource, operation_type)

    def get_resources(self, resource_type, client):
        if resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP:
            return self.get_security_groups(client)
        elif resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE:
            return self.get_security_group_rules(client)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def get_subcloud_resources(self, resource_type):
        return self.get_resources(resource_type, self.sc_neutron_client)

    def get_master_resources(self, resource_type):
        return self.get_resources(resource_type, self.m_neutron_client)

    def same_resource(self, resource_type, m_resource, sc_resource):
        if resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP:
            return self.same_security_group(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE:
            return self.same_security_group_rule(m_resource, sc_resource)
        else:
            return True

    def audit_discrepancy(self, resource_type, m_resource, sc_resources):
        if resource_type in [consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
                             consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE]:
            # It could be that the group/rule details are different
            # between master cloud and subcloud now.
            # Thus, delete the resource before creating it again.
            self.schedule_work(self.endpoint_type, resource_type,
                               self.get_resource_id(resource_type, m_resource),
                               consts.OPERATION_TYPE_DELETE)
        # Return true to try creating the resource again
        return True

    def map_subcloud_resource(self, resource_type, m_r, m_rsrc_db,
                              sc_resources):
        # Map an existing subcloud resource to an existing master resource.
        # If a mapping is created the function should return True.
        # It is expected that update_resource_refs() has been called on m_r.

        # Used for security groups since there are a couple of default
        # groups (and rules) that get created in the subcloud.
        if resource_type in (consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
                             consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE):

            for sc_r in sc_resources:
                if self.same_resource(resource_type, m_r, sc_r):
                    LOG.info(
                        "Mapping resource {} to existing subcloud resource {}"
                        .format(m_r, sc_r), extra=self.log_extra)
                    self.persist_db_subcloud_resource(m_rsrc_db.id,
                                                      sc_r['id'])
                    return True
        return False

    def update_resource_refs(self, resource_type, m_r):
        # Update any references in m_r to other resources in the master cloud
        # to use the equivalent subcloud resource instead.
        m_r = m_r.copy()
        if resource_type == consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP_RULE:

            if m_r.get('security_group_id') is not None:
                # If the security group id is in the dict then it is for the
                # master region, and we need to update it with the equivalent
                # id from the subcloud.
                master_sec_group_id = m_r['security_group_id']
                sec_group_rsrc = resource.Resource.get_by_type_and_master_id(
                    self.ctxt, consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
                    master_sec_group_id)
                sec_group_subcloud_rsrc = self.get_db_subcloud_resource(
                    sec_group_rsrc.id)
                if sec_group_subcloud_rsrc:
                    m_r['security_group_id'] = \
                        sec_group_subcloud_rsrc.subcloud_resource_id
                else:
                    LOG.error(
                        "Unable to update security group id in {},"
                        "cannot find equivalent security group in subcloud."
                        .format(m_r), extra=self.log_extra)
                    raise exceptions.SubcloudResourceNotFound(
                        resource=sec_group_rsrc.id)

            if m_r.get('remote_group_id') is not None:
                # If the remote group id is in the dict then it is for the
                # master region, and we need to update it with the equivalent
                # id from the subcloud.
                master_remote_group_id = m_r['remote_group_id']
                remote_group_rsrc = \
                    resource.Resource.get_by_type_and_master_id(
                        self.ctxt, consts.RESOURCE_TYPE_NETWORK_SECURITY_GROUP,
                        master_remote_group_id)
                remote_group_subcloud_rsrc = self.get_db_subcloud_resource(
                    remote_group_rsrc.id)
                if remote_group_subcloud_rsrc:
                    m_r['remote_group_id'] = \
                        remote_group_subcloud_rsrc.subcloud_resource_id
                else:
                    LOG.error(
                        "Unable to update remote group id in {},"
                        "cannot find equivalent remote group in subcloud."
                        .format(m_r), extra=self.log_extra)
                    raise exceptions.SubcloudResourceNotFound(
                        resource=sec_group_rsrc.id)
        return m_r

    # This will only be called by the audit code.
    def create_security_group(self, request, rsrc):
        self.post_security_group(request, rsrc)

    # This will only be called by the audit code.
    def create_security_group_rule(self, request, rsrc):
        self.post_security_group_rule(request, rsrc)

    def same_security_group(self, qc1, qc2):
        return (qc1['description'] == qc2['description'] and
                qc1['tenant_id'] == qc2['tenant_id'] and
                qc1['name'] == qc2['name'])

    def same_security_group_rule(self, qc1, qc2):
        # Ignore id, created_at, updated_at, and revision_number
        return (qc1['description'] == qc2['description'] and
                qc1['tenant_id'] == qc2['tenant_id'] and
                qc1['project_id'] == qc2['project_id'] and
                qc1['direction'] == qc2['direction'] and
                qc1['protocol'] == qc2['protocol'] and
                qc1['ethertype'] == qc2['ethertype'] and
                qc1['remote_group_id'] == qc2['remote_group_id'] and
                qc1['security_group_id'] == qc2['security_group_id'] and
                qc1['remote_ip_prefix'] == qc2['remote_ip_prefix'] and
                qc1['port_range_min'] == qc2['port_range_min'] and
                qc1['port_range_max'] == qc2['port_range_max'])

    def get_security_groups(self, nc):
        try:
            # Only retrieve the info we care about.
            # created_at, updated_at, and revision_number can't be specified
            # when making a new group.  tags would require special handling,
            # and security_group_rules is handled separately.
            groups = nc.list_security_groups(
                retrieve_all=True,
                fields=['id', 'name', 'description', 'tenant_id'])
            groups = groups['security_groups']
            return groups
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_flavor: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_security_group_rules(self, nc):
        try:
            rules = nc.list_security_group_rules(retrieve_all=True)
            rules = rules['security_group_rules']
            for rule in rules:
                # We don't need these for comparing/creating security groups
                # and/or they're not allowed in POST calls.
                del rule['created_at']
                del rule['updated_at']
                del rule['revision_number']
                # These would have to be handled separately, not yet supported.
                rule.pop('tags', None)
                # Some rules have a blank description as an empty string, some
                # as None, depending on whether they were auto-created during
                # security group creation or added later.  Convert the empty
                # strings to None.
                if rule['description'] == '':
                    rule['description'] = None
            return rules
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_flavor: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except Exception as e:
            LOG.exception(e)
            return None


class ComputeSyncThread(SyncThread):
    """Manages tasks related to resource management for nova."""

    def __init__(self, subcloud_engine):
        super(ComputeSyncThread, self).__init__(subcloud_engine)
        self.endpoint_type = consts.ENDPOINT_TYPE_COMPUTE
        self.sync_handler_map = {
            consts.RESOURCE_TYPE_COMPUTE_FLAVOR: self.sync_compute_resource,
            consts.RESOURCE_TYPE_COMPUTE_KEYPAIR: self.sync_compute_resource,
            consts.RESOURCE_TYPE_COMPUTE_QUOTA_SET: self.sync_compute_resource,
            consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
                self.sync_compute_resource,
        }
        self.audit_resources = [
            consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET,
            consts.RESOURCE_TYPE_COMPUTE_FLAVOR,
            consts.RESOURCE_TYPE_COMPUTE_KEYPAIR,
            # note: no audit here for quotas, that's handled separately
        ]
        self.log_extra = {"instance": "{}/{}: ".format(
            self.subcloud_engine.subcloud.region_name, self.endpoint_type)}
        self.initialize()
        LOG.info("ComputeSyncThread initialized", extra=self.log_extra)

    def initialize(self):
        # Subcloud may be enabled a while after being added.
        # Keystone endpoints for the subcloud could be added in
        # between these 2 steps. Reinitialize the session to
        # get the most up-to-date service catalog.
        loader = loading.get_plugin_loader(
            cfg.CONF.keystone_authtoken.auth_type)
        auth = loader.load_from_options(
            auth_url=cfg.CONF.cache.auth_uri,
            username=cfg.CONF.cache.admin_username,
            password=cfg.CONF.cache.admin_password,
            project_name=cfg.CONF.cache.admin_tenant,
            project_domain_name=cfg.CONF.cache.admin_project_domain_name,
            user_domain_name=cfg.CONF.cache.admin_user_domain_name)
        self.admin_session = session.Session(
            auth=auth, timeout=60, additional_headers=consts.USER_HEADER)
        self.ks_client = keystoneclient.Client(
            session=self.admin_session,
            region_name=consts.VIRTUAL_MASTER_CLOUD)
        # todo: update version to 2.53 once on pike
        self.m_nova_client = novaclient.Client(
            '2.38', session=self.admin_session,
            endpoint_type=consts.KS_ENDPOINT_INTERNAL,
            region_name=consts.VIRTUAL_MASTER_CLOUD)
        self.sc_nova_client = novaclient.Client(
            '2.38', session=self.admin_session,
            endpoint_type=consts.KS_ENDPOINT_INTERNAL,
            region_name=self.subcloud_engine.subcloud.region_name)
        LOG.info("session and clients initialized", extra=self.log_extra)

    def sync_compute_resource(self, request, rsrc):
        # Invoke function with name format "operationtype_resourcetype".
        # For example: create_flavor()
        try:
            func_name = request.orch_job.operation_type + \
                "_" + rsrc.resource_type
            getattr(self, func_name)(request, rsrc)
        except AttributeError:
            LOG.error("{} not implemented for {}"
                      .format(request.orch_job.operation_type,
                              rsrc.resource_type))
            raise exceptions.SyncRequestFailed
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.error("sync_compute_resource: {} is not reachable [{}]"
                      .format(self.subcloud_engine.subcloud.region_name,
                              str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except exceptions.SyncRequestFailed:
            raise
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    # ---- Override common audit functions ----
    def get_resource_id(self, resource_type, resource):
        if hasattr(resource, 'master_id'):
            # If resource from DB, return master resource id
            # from master cloud
            return resource.master_id

        # Else, it is OpenStack resource retrieved from master cloud
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_KEYPAIR:
            # User_id field is set in _info data by audit query code.
            return utils.keypair_construct_id(
                resource.id, resource._info['keypair']['user_id'])
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
            # We only care about the default class.
            return 'default'

        # Nothing special for other resources (flavor)
        return resource.id

    def get_resource_info(self, resource_type, resource, operation_type=None):
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_FLAVOR:
            return jsonutils.dumps(resource._info)
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_KEYPAIR:
            return jsonutils.dumps(resource._info.get('keypair'))
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
            return jsonutils.dumps(resource._info)
        else:
            return super(ComputeSyncThread, self).get_resource_info(
                resource_type, resource, operation_type)

    def get_subcloud_resources(self, resource_type):
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_FLAVOR:
            return self.get_flavor_resources(self.sc_nova_client)
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
            return self.get_quota_class_resources(self.sc_nova_client)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def get_master_resources(self, resource_type):
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_FLAVOR:
            return self.get_flavor_resources(self.m_nova_client)
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
            return self.get_quota_class_resources(self.m_nova_client)
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def same_resource(self, resource_type, m_resource, sc_resource):
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_FLAVOR:
            return self.same_flavor(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_KEYPAIR:
            return self.same_keypair(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_COMPUTE_QUOTA_CLASS_SET:
            return self.same_quota_class(m_resource, sc_resource)
        else:
            return True

    def audit_discrepancy(self, resource_type, m_resource, sc_resources):
        if resource_type in [consts.RESOURCE_TYPE_COMPUTE_FLAVOR,
                             consts.RESOURCE_TYPE_COMPUTE_KEYPAIR]:
            # It could be that the flavor details are different
            # between master cloud and subcloud now.
            # Thus, delete the flavor before creating it again.
            # Dependants (ex: flavor-access) will be created again.
            self.schedule_work(self.endpoint_type, resource_type,
                               self.get_resource_id(resource_type, m_resource),
                               consts.OPERATION_TYPE_DELETE)

        # For quota classes there is no delete operation, so we just want
        # to update the existing class.  Nothing to do here.

        # Return true to try creating the resource again
        return True

    # ---- Flavor & dependants (flavor-access, extra-spec) ----
    def create_flavor(self, request, rsrc):
        flavor_dict = jsonutils.loads(request.orch_job.resource_info)
        name = flavor_dict['name']
        ram = flavor_dict['ram']
        vcpus = flavor_dict['vcpus']
        disk = flavor_dict['disk']
        kwargs = {}
        # id is always passed in by proxy
        kwargs['flavorid'] = flavor_dict['id']
        if 'OS-FLV-EXT-DATA:ephemeral' in flavor_dict:
            kwargs['ephemeral'] = flavor_dict['OS-FLV-EXT-DATA:ephemeral']
        if 'swap' in flavor_dict and flavor_dict['swap']:
            kwargs['swap'] = flavor_dict['swap']
        if 'rxtx_factor' in flavor_dict:
            kwargs['rxtx_factor'] = flavor_dict['rxtx_factor']
        if 'os-flavor-access:is_public' in flavor_dict:
            kwargs['is_public'] = flavor_dict['os-flavor-access:is_public']

        # todo: maybe we can bypass all the above and just directly call
        # self.sc_nova_client.flavors._create("/flavors", body, "flavor")
        # with "body" made from request.orch_job.resource_info.
        newflavor = None
        try:
            newflavor = self.sc_nova_client.flavors.create(
                name, ram, vcpus, disk, **kwargs)
        except novaclient_exceptions.Conflict as e:
            if "already exists" in e.message:
                # FlavorExists or FlavorIdExists.
                LOG.info("Flavor {} already exists in subcloud"
                         .format(name), extra=self.log_extra)
                # Compare the flavor details and recreate flavor if required.
                newflavor = self.recreate_flavor_if_reqd(name, ram, vcpus,
                                                         disk, kwargs)
            else:
                LOG.exception(e)
        if not newflavor:
            raise exceptions.SyncRequestFailed

        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, newflavor.id)
        LOG.info("Flavor {}:{} [{}/{}] created"
                 .format(rsrc.id, subcloud_rsrc_id, name, newflavor.id),
                 extra=self.log_extra)

    def recreate_flavor_if_reqd(self, name, ram, vcpus, disk, kwargs):
        # Both the flavor name and the flavor id must be unique.
        # If the conflict is due to same name, but different uuid,
        # we have to fetch the correct id from subcloud before
        # attempting to delete it.
        # Since the flavor details are available, compare with master cloud
        # and recreate the flavor only if required.
        newflavor = None
        try:
            master_flavor = self.m_nova_client.flavors.get(kwargs['flavorid'])
            subcloud_flavor = None
            sc_flavors = self.sc_nova_client.flavors.list(is_public=None)
            for sc_flavor in sc_flavors:
                # subcloud flavor might have the same name and/or the same id
                if name == sc_flavor.name or \
                        kwargs['flavorid'] == sc_flavor.id:
                    subcloud_flavor = sc_flavor
                    break
            if master_flavor and subcloud_flavor:
                if self.same_flavor(master_flavor, subcloud_flavor):
                    newflavor = subcloud_flavor
                else:
                    LOG.info("recreate_flavor, deleting {}:{}".format(
                             subcloud_flavor.name, subcloud_flavor.id),
                             extra=self.log_extra)
                    self.sc_nova_client.flavors.delete(subcloud_flavor.id)
                    newflavor = self.sc_nova_client.flavors.create(
                        name, ram, vcpus, disk, **kwargs)
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailed
        return newflavor

    def delete_flavor(self, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return
        try:
            self.sc_nova_client.flavors.delete(
                subcloud_rsrc.subcloud_resource_id)
        except novaclient_exceptions.NotFound:
            # Flavor already deleted in subcloud, carry on.
            LOG.info("ResourceNotFound in subcloud, may be already deleted",
                     extra=self.log_extra)
        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Flavor {}:{} [{}] deleted".format(rsrc.id, subcloud_rsrc.id,
                 subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)

    def action_flavor(self, request, rsrc):
        action_dict = jsonutils.loads(request.orch_job.resource_info)
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            LOG.error("Subcloud resource missing for {}:{}"
                      .format(rsrc, action_dict),
                      extra=self.log_extra)
            return

        switcher = {
            consts.ACTION_ADDTENANTACCESS: self.add_tenant_access,
            consts.ACTION_REMOVETENANTACCESS: self.remove_tenant_access,
            consts.ACTION_EXTRASPECS_POST: self.set_extra_specs,
            consts.ACTION_EXTRASPECS_DELETE: self.unset_extra_specs,
        }
        action = action_dict.keys()[0]
        if action not in switcher.keys():
            LOG.error("Unsupported flavor action {}".format(action),
                      extra=self.log_extra)
            return
        LOG.info("Flavor action [{}]: {}".format(action, action_dict),
                 extra=self.log_extra)
        switcher[action](rsrc, action, action_dict, subcloud_rsrc)

    def add_tenant_access(self, rsrc, action, action_dict, subcloud_rsrc):
            tenant_id = action_dict[action]['tenant']
            try:
                self.sc_nova_client.flavor_access.add_tenant_access(
                    subcloud_rsrc.subcloud_resource_id, tenant_id)
            except novaclient_exceptions.Conflict:
                LOG.info("Flavor-access already present {}:{}"
                         .format(rsrc, action_dict),
                         extra=self.log_extra)

    def remove_tenant_access(self, rsrc, action, action_dict, subcloud_rsrc):
            tenant_id = action_dict[action]['tenant']
            try:
                self.sc_nova_client.flavor_access.remove_tenant_access(
                    subcloud_rsrc.subcloud_resource_id, tenant_id)
            except novaclient_exceptions.NotFound:
                LOG.info("Flavor-access already deleted {}:{}"
                         .format(rsrc, action_dict),
                         extra=self.log_extra)

    def set_extra_specs(self, rsrc, action, action_dict, subcloud_rsrc):
            flavor = novaclient_utils.find_resource(
                self.sc_nova_client.flavors,
                subcloud_rsrc.subcloud_resource_id, is_public=None)
            flavor.set_keys(action_dict[action])
            # No need to handle "extra-spec already exists" case.
            # Nova throws no exception for that.

    def unset_extra_specs(self, rsrc, action, action_dict, subcloud_rsrc):
            flavor = novaclient_utils.find_resource(
                self.sc_nova_client.flavors,
                subcloud_rsrc.subcloud_resource_id, is_public=None)

            es_metadata = action_dict[action]
            metadata = {}
            # extra_spec keys passed in could be of format "key1"
            # or "key1;key2;key3"
            for metadatum in es_metadata.split(';'):
                if metadatum:
                    metadata[metadatum] = None

            try:
                flavor.unset_keys(metadata.keys())
            except novaclient_exceptions.NotFound:
                LOG.info("Extra-spec {} not found {}:{}"
                         .format(metadata.keys(), rsrc, action_dict),
                         extra=self.log_extra)

    def get_flavor_resources(self, nc):
        try:
            flavors = nc.flavors.list(is_public=None)
            for flavor in flavors:
                # Attach flavor access list to flavor object, so that
                # it can be audited later in audit_dependants()
                if not flavor.is_public:
                    try:
                        fa_list = nc.flavor_access.list(flavor=flavor.id)
                        flavor.attach_fa = fa_list
                    except novaclient_exceptions.NotFound:
                        # flavor/flavor_access just got deleted
                        # (after flavors.list)
                        LOG.info("Flavor/flavor_access not found [{}]"
                                 .format(flavor.id),
                                 extra=self.log_extra)
                        flavor.attach_fa = []
                else:
                    flavor.attach_fa = []

                # Attach extra_spec dict to flavor object, so that
                # it can be audited later in audit_dependants()
                flavor.attach_es = flavor.get_keys()
            return flavors
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_flavor: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def same_flavor(self, f1, f2):
        return (f1.name == f2.name and
                f1.vcpus == f2.vcpus and
                f1.ram == f2.ram and
                f1.disk == f2.disk and
                f1.swap == f2.swap and
                f1.rxtx_factor == f2.rxtx_factor and
                f1.is_public == f2.is_public and
                f1.ephemeral == f2.ephemeral)

    def audit_dependants(self, resource_type, m_flavor, sc_flavor):
        num_of_audit_jobs = 0
        if not self.subcloud_engine.is_enabled() or self.should_exit():
            return num_of_audit_jobs
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_FLAVOR:
            num_of_audit_jobs += self.audit_flavor_access(
                resource_type, m_flavor, sc_flavor)
            num_of_audit_jobs += self.audit_extra_specs(
                resource_type, m_flavor, sc_flavor)
        return num_of_audit_jobs

    def audit_flavor_access(self, resource_type, m_flavor, sc_flavor):
        num_of_audit_jobs = 0
        sc_fa_attachment = []  # Subcloud flavor-access attachment
        if sc_flavor:
            sc_fa_attachment = sc_flavor.attach_fa

        # Flavor-access needs to be audited. flavor-access details are
        # filled in m_resources and sc_resources during query.
        for m_fa in m_flavor.attach_fa:
            found = False
            for sc_fa in sc_fa_attachment:
                if m_fa.tenant_id == sc_fa.tenant_id:
                    found = True
                    sc_flavor.attach_fa.remove(sc_fa)
                    break
            if not found:
                action_dict = {
                    consts.ACTION_ADDTENANTACCESS: {"tenant": m_fa.tenant_id}}
                self.schedule_work(
                    self.endpoint_type, resource_type, m_flavor.id,
                    consts.OPERATION_TYPE_ACTION,
                    jsonutils.dumps(action_dict))
                num_of_audit_jobs += 1

        for sc_fa in sc_fa_attachment:
            action_dict = {
                consts.ACTION_REMOVETENANTACCESS: {"tenant": sc_fa.tenant_id}}
            self.schedule_work(
                self.endpoint_type, resource_type, m_flavor.id,
                consts.OPERATION_TYPE_ACTION,
                jsonutils.dumps(action_dict))
            num_of_audit_jobs += 1

        return num_of_audit_jobs

    def audit_extra_specs(self, resource_type, m_flavor, sc_flavor):
        num_of_audit_jobs = 0
        sc_es_attachment = {}  # Subcloud extra-spec attachment
        if sc_flavor:
            # sc_flavor could be None.
            sc_es_attachment = sc_flavor.attach_es

        # Extra-spec needs to be audited. Extra-spec details are
        # filled in m_resources and sc_resources during query.
        metadata = {}
        for m_key, m_value in m_flavor.attach_es.iteritems():
            found = False
            for sc_key, sc_value in sc_es_attachment.iteritems():
                if m_key == sc_key and m_value == sc_value:
                    found = True
                    sc_es_attachment.pop(sc_key)
                    break
            if not found:
                metadata.update({m_key: m_value})
        if metadata:
            action_dict = {consts.ACTION_EXTRASPECS_POST: metadata}
            self.schedule_work(
                self.endpoint_type, resource_type, m_flavor.id,
                consts.OPERATION_TYPE_ACTION, jsonutils.dumps(action_dict))
            num_of_audit_jobs += 1

        keys_to_delete = ""
        for sc_key, sc_value in sc_es_attachment.iteritems():
            keys_to_delete += sc_key + ";"
        if keys_to_delete:
            action_dict = {consts.ACTION_EXTRASPECS_DELETE: keys_to_delete}
            self.schedule_work(
                self.endpoint_type, resource_type, m_flavor.id,
                consts.OPERATION_TYPE_ACTION, jsonutils.dumps(action_dict))
            num_of_audit_jobs += 1

        return num_of_audit_jobs

    # ---- Keypair resource ----
    def create_keypair(self, request, rsrc):
        keypair_dict = jsonutils.loads(request.orch_job.resource_info)
        name, user_id = utils.keypair_deconstruct_id(rsrc.master_id)
        log_str = rsrc.master_id + ' ' + name + '/' + user_id
        kwargs = {}
        kwargs['user_id'] = user_id
        if 'public_key' in keypair_dict:
            kwargs['public_key'] = keypair_dict['public_key']
        if 'type' in keypair_dict:
            kwargs['key_type'] = keypair_dict['type']
            log_str += "/" + kwargs['key_type']
        newkeypair = None
        try:
            newkeypair = self.sc_nova_client.keypairs.create(name, **kwargs)
        except novaclient_exceptions.Conflict:
            # KeyPairExists: keypair with same name already exists.
            LOG.info("Keypair {} already exists in subcloud"
                     .format(log_str), extra=self.log_extra)
            newkeypair = self.recreate_keypair(name, kwargs)
        if not newkeypair:
            raise exceptions.SyncRequestFailed

        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, rsrc.master_id)
        LOG.info("Keypair {}:{} [{}] created".format(rsrc.id,
                 subcloud_rsrc_id, log_str),
                 extra=self.log_extra)

    def recreate_keypair(self, name, kwargs):
        newkeypair = None
        try:
            # Not worth doing additional api calls to compare the
            # master and subcloud keypairs. Delete and create again.
            # This is different from recreate_flavor_if_reqd().
            # Here for keypair, name and user_id are already available
            # and query api can be avoided.
            delete_kw = {'user_id': kwargs['user_id']}
            LOG.info("recreate_keypair, deleting {}:{}"
                     .format(name, delete_kw),
                     extra=self.log_extra)
            self.sc_nova_client.keypairs.delete(name, **delete_kw)
            newkeypair = self.sc_nova_client.keypairs.create(
                name, **kwargs)
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailed
        return newkeypair

    def delete_keypair(self, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return
        name, user_id = utils.keypair_deconstruct_id(rsrc.master_id)
        log_str = subcloud_rsrc.subcloud_resource_id + ' ' + \
            name + '/' + user_id
        kwargs = {}
        kwargs['user_id'] = user_id
        try:
            self.sc_nova_client.keypairs.delete(name, **kwargs)
        except novaclient_exceptions.NotFound:
            # Keypair already deleted in subcloud, carry on.
            LOG.info("Keypair {} not found in subcloud, may be already deleted"
                     .format(log_str), extra=self.log_extra)
        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("Keypair {}:{} [{}] deleted".format(rsrc.id, subcloud_rsrc.id,
                 log_str), extra=self.log_extra)

    def get_all_resources(self, resource_type):
        if resource_type == consts.RESOURCE_TYPE_COMPUTE_KEYPAIR:
            # Keypair has unique id (name) per user. And, there is no API to
            # retrieve all keypairs at once. So, keypair for each user is
            # retrieved individually.
            try:
                m_resources = []
                sc_resources = []
                users = self.ks_client.users.list()
                users_with_kps = set()
                for user in users:
                    user_keypairs = self.get_keypair_resources(
                        self.m_nova_client, user.id)
                    if user_keypairs:
                        m_resources.extend(user_keypairs)
                        users_with_kps.add(user.id)
                db_resources = self.get_db_master_resources(resource_type)
                # Query the subcloud for only the users-with-keypairs in the
                # master cloud
                for userid in users_with_kps:
                    sc_user_keypairs = self.get_keypair_resources(
                        self.sc_nova_client, userid)
                    if sc_user_keypairs:
                        sc_resources.extend(sc_user_keypairs)
                LOG.info("get_all_resources: users_with_kps={}"
                         .format(users_with_kps), extra=self.log_extra)
                return m_resources, db_resources, sc_resources
            except (keystone_exceptions.connection.ConnectTimeout,
                    keystone_exceptions.ConnectFailure) as e:
                LOG.info("get_all_resources: subcloud {} is not reachable [{}]"
                         .format(self.subcloud_engine.subcloud.region_name,
                                 str(e)), extra=self.log_extra)
                return None, None, None
            except Exception as e:
                LOG.exception(e)
                return None, None, None
        else:
            return super(ComputeSyncThread, self).get_all_resources(
                resource_type)

    def get_keypair_resources(self, nc, user_id):
        keypairs = nc.keypairs.list(user_id)
        for keypair in keypairs:
            keypair._info['keypair']['user_id'] = user_id
        return keypairs

    def same_keypair(self, k1, k2):
        return (k1.name == k2.name
                and k1.type == k2.type
                and k1.fingerprint == k2.fingerprint
                and (k1._info['keypair']['user_id'] ==
                     k2._info['keypair']['user_id'])
                )

    # ---- quota_set resource operations ----
    def put_compute_quota_set(self, request, rsrc):
        project_id = request.orch_job.source_resource_id

        # Get the new global limits from the request.
        quota_dict = jsonutils.loads(request.orch_job.resource_info)

        # Extract the user_id if there is one.
        user_id = quota_dict.pop('user_id', None)

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Force the update in case existing usage is higher.
        quota_dict['force'] = True

        # Apply the limits to the subcloud.
        self.sc_nova_client.quotas.update(project_id, user_id=user_id,
                                          **quota_dict)
        # Persist the subcloud resource. (Not really applicable for quotas.)
        self.persist_db_subcloud_resource(rsrc.id, rsrc.master_id)
        LOG.info("Updated quotas {} for tenant {} and user {}"
                 .format(quota_dict, rsrc.master_id, user_id),
                 extra=self.log_extra)

    def delete_compute_quota_set(self, request, rsrc):
        # There's tricky behaviour here, pay attention!

        # If you delete a quota-set for a tenant nova will automatically
        # delete all tenant/user quota-sets within that tenant.

        # If we delete a tenant/user quota-set in the master then we want to
        # delete it in the subcloud as well.  Nothing more is needed.
        #
        # If we delete a tenant quota-set in the master then we want to delete
        # it in the subcloud as well (to force deletion of all related
        # tenant/user quota-sets.  However, we then need to recalculate the
        # quota-set for that tenant in all the subclouds based on the current
        # usage and the default quotas.

        project_id = request.orch_job.source_resource_id

        # Get the request info from the request.
        req_info = jsonutils.loads(request.orch_job.resource_info)

        # Extract the user_id if there is one.
        user_id = req_info.pop('user_id', None)

        # Delete the quota set in the subcloud.  If user_id is None this will
        # also delete the quota-sets for all users within this project.
        self.sc_nova_client.quotas.delete(project_id, user_id)

        # Clean up the subcloud resource entry in the DB.
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if subcloud_rsrc:
            subcloud_rsrc.delete()

        # If we deleted a user/tenant quota-set we're done.
        if user_id is not None:
            return

        # If we deleted a tenant quota-set we need to recalculate the
        # tenant quota-set in the subcloud based on the default quotas
        # in the master cloud.

        # Get the new global quotas
        quota_resource = self.m_nova_client.quotas.get(project_id)
        quota_dict = quota_resource.to_dict()

        # Get rid of the "id" field before doing any calculations
        quota_dict.pop('id', None)

        # Calculate the new limits for this subcloud (factoring in the
        # existing usage).
        quota_dict = \
            quota_manager.QuotaManager.calculate_subcloud_project_quotas(
                project_id, user_id, quota_dict,
                self.subcloud_engine.subcloud.region_name)

        # Force the update in case existing usage is higher.
        quota_dict['force'] = True

        # Apply the limits to the subcloud.
        self.sc_nova_client.quotas.update(project_id, user_id=user_id,
                                          **quota_dict)

    # ---- quota_set resource operations ----
    def put_quota_class_set(self, request, rsrc):
        # Only a class_id of "default" is meaningful to nova.
        class_id = request.orch_job.source_resource_id

        # Get the new quota class limits from the request.
        quota_dict = jsonutils.loads(request.orch_job.resource_info)

        # If this is coming from the audit we need to remove the "id" field.
        quota_dict.pop('id', None)

        # Apply the new quota class limits to the subcloud.
        self.sc_nova_client.quota_classes.update(class_id, **quota_dict)

        # Persist the subcloud resource. (Not really applicable for quotas.)
        self.persist_db_subcloud_resource(rsrc.id, rsrc.master_id)
        LOG.info("Updated quota classes {} for class {}"
                 .format(quota_dict, rsrc.master_id),
                 extra=self.log_extra)

    # This will only be called by the audit code.
    def create_quota_class_set(self, request, rsrc):
        self.put_quota_class_set(request, rsrc)

    def same_quota_class(self, qc1, qc2):
        # The audit code will pass in QuotaClassSet objects, we need to
        # convert them before comparing them.
        return qc1.to_dict() == qc2.to_dict()

    def get_quota_class_resources(self, nc):
        # We only care about the "default" class since it's the only one
        # that actually affects nova.
        try:
            quota_class = nc.quota_classes.get('default')
            return [quota_class]
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_quota_class: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except Exception as e:
            LOG.exception(e)
            return None


class SysinvSyncThread(SyncThread):
    """Manages tasks related to distributed cloud orchestration for sysinv."""

    SYSINV_MODIFY_RESOURCES = [consts.RESOURCE_TYPE_SYSINV_DNS,
                               consts.RESOURCE_TYPE_SYSINV_NTP,
                               consts.RESOURCE_TYPE_SYSINV_REMOTE_LOGGING,
                               consts.RESOURCE_TYPE_SYSINV_USER,
                               ]

    SYSINV_ADD_DELETE_RESOURCES = [consts.RESOURCE_TYPE_SYSINV_SNMP_COMM,
                                   consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST]

    SYSINV_CREATE_RESOURCES = [consts.RESOURCE_TYPE_SYSINV_FIREWALL_RULES,
                               consts.RESOURCE_TYPE_SYSINV_CERTIFICATE]

    FIREWALL_SIG_NULL = 'NoCustomFirewallRules'
    CERTIFICATE_SIG_NULL = 'NoCertificate'
    RESOURCE_UUID_NULL = 'NoResourceUUID'

    def __init__(self, subcloud_engine):
        super(SysinvSyncThread, self).__init__(subcloud_engine)

        self.endpoint_type = consts.ENDPOINT_TYPE_PLATFORM
        self.sync_handler_map = {
            consts.RESOURCE_TYPE_SYSINV_DNS: self.sync_dns,
            consts.RESOURCE_TYPE_SYSINV_NTP: self.sync_ntp,
            consts.RESOURCE_TYPE_SYSINV_SNMP_COMM:
                self.sync_snmp_community,
            consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST:
                self.sync_snmp_trapdest,
            consts.RESOURCE_TYPE_SYSINV_REMOTE_LOGGING:
                self.sync_remotelogging,
            consts.RESOURCE_TYPE_SYSINV_FIREWALL_RULES:
                self.sync_firewallrules,
            consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
                self.sync_certificate,
            consts.RESOURCE_TYPE_SYSINV_USER: self.sync_user,
        }
        self.region_name = self.subcloud_engine.subcloud.region_name
        self.log_extra = {"instance": "{}/{}: ".format(
            self.subcloud_engine.subcloud.region_name, self.endpoint_type)}

        self.audit_resources = [
            consts.RESOURCE_TYPE_SYSINV_CERTIFICATE,
            consts.RESOURCE_TYPE_SYSINV_DNS,
            consts.RESOURCE_TYPE_SYSINV_FIREWALL_RULES,
            consts.RESOURCE_TYPE_SYSINV_NTP,
            consts.RESOURCE_TYPE_SYSINV_REMOTE_LOGGING,
            consts.RESOURCE_TYPE_SYSINV_SNMP_COMM,
            consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST,
            consts.RESOURCE_TYPE_SYSINV_USER,
        ]
        LOG.info("SysinvSyncThread initialized", extra=self.log_extra)

    def update_dns(self, nameservers):
        try:
            s_os_client = sdk.OpenStackDriver(self.region_name)
            idns = s_os_client.sysinv_client.update_dns(nameservers)
            return idns
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info("update_dns exception Timeout",
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestTimeout
        except (AttributeError, TypeError) as e:
            LOG.info("update_dns error {} region_name".format(e),
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name,
                                              clear_token=True)
            raise exceptions.SyncRequestFailedRetry
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def sync_dns(self, request, rsrc):
        # The system is created with default dns; thus there
        # is a prepopulated dns entry.
        LOG.info("sync_dns resource_info={}".format(
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        dns_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = dns_dict.get('payload')

        nameservers = None
        if type(payload) is list:
            for ipayload in payload:
                if ipayload.get('path') == '/nameservers':
                    nameservers = ipayload.get('value')
                    LOG.debug("sync_dns nameservers = {}".format(nameservers),
                              extra=self.log_extra)
                    break
        else:
            nameservers = payload.get('nameservers')
            LOG.debug("sync_dns nameservers from dict={}".format(nameservers),
                      extra=self.log_extra)

        if nameservers is None:
            LOG.info("sync_dns No nameservers update found in resource_info"
                     "{}".format(request.orch_job.resource_info),
                     extra=self.log_extra)
            nameservers = ""

        idns = self.update_dns(nameservers)

        # Ensure subcloud resource is persisted to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, idns.uuid)
        LOG.info("DNS {}:{} [{}] updated"
                 .format(rsrc.id, subcloud_rsrc_id, nameservers),
                 extra=self.log_extra)

    def update_ntp(self, ntpservers):
        try:
            s_os_client = sdk.OpenStackDriver(self.region_name)
            intp = s_os_client.sysinv_client.update_ntp(ntpservers)
            return intp
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info("update_ntp exception Timeout",
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestTimeout
        except (AttributeError, TypeError) as e:
            LOG.info("update_ntp error {} region_name".format(e),
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name,
                                              clear_token=True)
            raise exceptions.SyncRequestFailedRetry
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def sync_ntp(self, request, rsrc):
        # The system is created with default ntp; thus there
        # is a prepopulated ntp entry.
        LOG.info("sync_ntp resource_info={}".format(
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        ntp_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = ntp_dict.get('payload')

        ntpservers = None
        if type(payload) is list:
            for ipayload in payload:
                if ipayload.get('path') == '/ntpservers':
                    ntpservers = ipayload.get('value')
                    LOG.debug("sync_ntp ntpservers = {}".format(ntpservers),
                              extra=self.log_extra)
                    break
        else:
            ntpservers = payload.get('ntpservers')
            LOG.debug("sync_ntp ntpservers from dict={}".format(ntpservers),
                      extra=self.log_extra)

        if ntpservers is None:
            LOG.info("sync_ntp No ntpservers update found in resource_info"
                     "{}".format(request.orch_job.resource_info),
                     extra=self.log_extra)
            ntpservers = ""

        intp = self.update_ntp(ntpservers)

        # Ensure subcloud resource is persisted to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, intp.uuid)
        LOG.info("NTP {}:{} [{}] updated"
                 .format(rsrc.id, subcloud_rsrc_id, ntpservers),
                 extra=self.log_extra)

    def sync_snmp_trapdest(self, request, rsrc):
        switcher = {
            consts.OPERATION_TYPE_POST: self.snmp_trapdest_create,
            consts.OPERATION_TYPE_CREATE: self.snmp_trapdest_create,
            consts.OPERATION_TYPE_DELETE: self.snmp_trapdest_delete,
        }

        func = switcher[request.orch_job.operation_type]
        try:
            func(request, rsrc)
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("sync_snmp_trapdest: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def snmp_trapdest_create(self, request, rsrc):
        LOG.info("snmp_trapdest_create region {} resource_info={}".format(
                 self.subcloud_engine.subcloud.region_name,
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        resource_info_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = resource_info_dict.get('payload')
        if not payload:
            payload = resource_info_dict

        s_os_client = sdk.OpenStackDriver(self.region_name)
        try:
            itrapdest = s_os_client.sysinv_client.snmp_trapdest_create(
                payload)
            itrapdest_id = itrapdest.uuid
            ip_address = itrapdest.ip_address
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info("snmp_trapdest_create exception Timeout",
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestTimeout
        except (AttributeError, TypeError) as e:
            LOG.info("snmp_trapdest_create error {}".format(e),
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name,
                                              clear_token=True)
            raise exceptions.SyncRequestFailedRetry

        # Now persist the subcloud resource to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, ip_address)

        LOG.info("SNMP trapdest {}:{} [{}/{}] created".format(rsrc.id,
                 subcloud_rsrc_id, ip_address, itrapdest_id),
                 extra=self.log_extra)
        return itrapdest

    def snmp_trapdest_delete(self, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return
        s_os_client = sdk.OpenStackDriver(self.region_name)
        try:
            s_os_client.sysinv_client.snmp_trapdest_delete(
                subcloud_rsrc.subcloud_resource_id)
        except exceptions.TrapDestNotFound:
            # SNMP trapdest already deleted in subcloud, carry on.
            LOG.info("SNMP trapdest not in subcloud, may be already deleted",
                     extra=self.log_extra)
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info("snmp_trapdest_delete exception Timeout",
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestTimeout
        except (AttributeError, TypeError) as e:
            LOG.info("snmp_trapdest_delete error {}".format(e),
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name,
                                              clear_token=True)
            raise exceptions.SyncRequestFailedRetry

        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("SNMP trapdest {}:{} [{}] deleted".format(
                 rsrc.id, subcloud_rsrc.id,
                 subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)

    def sync_snmp_community(self, request, rsrc):
        switcher = {
            consts.OPERATION_TYPE_POST: self.snmp_community_create,
            consts.OPERATION_TYPE_CREATE: self.snmp_community_create,
            consts.OPERATION_TYPE_DELETE: self.snmp_community_delete,
        }

        func = switcher[request.orch_job.operation_type]
        try:
            func(request, rsrc)
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("sync_snmp_community: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            raise exceptions.SyncRequestTimeout
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def snmp_community_create(self, request, rsrc):
        LOG.info("snmp_community_create region {} resource_info={}".format(
                 self.subcloud_engine.subcloud.region_name,
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        resource_info_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = resource_info_dict.get('payload')
        if not payload:
            payload = resource_info_dict

        s_os_client = sdk.OpenStackDriver(self.region_name)
        try:
            icommunity = s_os_client.sysinv_client.snmp_community_create(
                payload)
            icommunity_id = icommunity.uuid
            community = icommunity.community
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info("snmp_community_create exception Timeout",
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestTimeout
        except (AttributeError, TypeError) as e:
            LOG.info("snmp_community_create error {}".format(e),
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name,
                                              clear_token=True)
            raise exceptions.SyncRequestFailedRetry

        # Now persist the subcloud resource to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, community)

        LOG.info("SNMP community {}:{} [{}/{}] created".format(rsrc.id,
                 subcloud_rsrc_id, community, icommunity_id),
                 extra=self.log_extra)
        return icommunity

    def snmp_community_delete(self, request, rsrc):
        subcloud_rsrc = self.get_db_subcloud_resource(rsrc.id)
        if not subcloud_rsrc:
            return
        s_os_client = sdk.OpenStackDriver(self.region_name)
        try:
            s_os_client.sysinv_client.snmp_community_delete(
                subcloud_rsrc.subcloud_resource_id)
        except exceptions.CommunityNotFound:
            # Community already deleted in subcloud, carry on.
            LOG.info("SNMP community not in subcloud, may be already deleted",
                     extra=self.log_extra)
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info("snmp_community_delete exception Timeout",
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestTimeout
        except (AttributeError, TypeError) as e:
            LOG.info("snmp_community_delete error {}".format(e),
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name,
                                              clear_token=True)
            raise exceptions.SyncRequestFailedRetry

        subcloud_rsrc.delete()
        # Master Resource can be deleted only when all subcloud resources
        # are deleted along with corresponding orch_job and orch_requests.
        LOG.info("SNMP community {}:{} [{}] deleted".format(
                 rsrc.id, subcloud_rsrc.id,
                 subcloud_rsrc.subcloud_resource_id),
                 extra=self.log_extra)

    def update_remotelogging(self, values):

        s_os_client = sdk.OpenStackDriver(self.region_name)
        try:
            iremotelogging = s_os_client.sysinv_client.update_remotelogging(
                values)
            return iremotelogging
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info("update_remotelogging exception Timeout",
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestTimeout
        except (AttributeError, TypeError) as e:
            LOG.info("update_remotelogging error {} region_name".format(e),
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name,
                                              clear_token=True)
            raise exceptions.SyncRequestFailedRetry
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def sync_remotelogging(self, request, rsrc):
        # The system is created with default remotelogging; thus there
        # is a prepopulated remotelogging entry.
        LOG.info("sync_remotelogging resource_info={}".format(
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        remotelogging_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = remotelogging_dict.get('payload')

        if not payload:
            LOG.info("sync_remotelogging No payload found in resource_info"
                     "{}".format(request.orch_job.resource_info),
                     extra=self.log_extra)
            return

        iremotelogging = self.update_remotelogging(payload)

        # Ensure subcloud resource is persisted to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, iremotelogging.uuid)

        LOG.info("remotelogging {}:{} [{}/{}] updated".format(rsrc.id,
                 subcloud_rsrc_id, iremotelogging.ip_address,
                 iremotelogging.uuid),
                 extra=self.log_extra)

    def update_firewallrules(self, firewall_sig, firewallrules=None):

        s_os_client = sdk.OpenStackDriver(self.region_name)
        try:
            ifirewallrules = s_os_client.sysinv_client.update_firewallrules(
                firewall_sig, firewallrules=firewallrules)
            return ifirewallrules
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info("update_firewallrules exception Timeout",
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestTimeout
        except (AttributeError, TypeError) as e:
            LOG.info("update_firewallrules error {} region_name".format(e),
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name,
                                              clear_token=True)
            raise exceptions.SyncRequestFailedRetry
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def sync_firewallrules(self, request, rsrc):
        # The system is not created with default firewallrules
        LOG.info("sync_firewallrules resource_info={}".format(
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        firewallrules_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = firewallrules_dict.get('payload')
        # payload is the contents of the POST operation

        if not payload:
            LOG.info("sync_firewallrules No payload found in resource_info"
                     "{}".format(request.orch_job.resource_info),
                     extra=self.log_extra)
            return

        if isinstance(payload, dict):
            firewall_sig = payload.get('firewall_sig')
        else:
            firewall_sig = rsrc.master_id
            LOG.info("firewall_sig from master_id={}".format(firewall_sig))

        ifirewallrules = None
        if firewall_sig:
            ifirewallrules = self.update_firewallrules(firewall_sig)
        else:
            firewall_sig = rsrc.master_id
            if firewall_sig and firewall_sig != self.FIREWALL_SIG_NULL:
                ifirewallrules = self.update_firewallrules(
                    firewall_sig,
                    firewallrules=payload)
            else:
                LOG.info("skipping firewall_sig={}".format(firewall_sig))

        ifirewallrules_sig = None
        try:
            ifirewallrules_sig = \
                ifirewallrules.get('firewallrules').get('firewall_sig')
        except Exception as e:
            LOG.warn("No ifirewallrules={} unknown e={}".format(
                ifirewallrules, e))

        # Ensure subcloud resource is persisted to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, firewall_sig)

        LOG.info("firewallrules {} {} [{}/{}] updated".format(rsrc.id,
                 subcloud_rsrc_id, ifirewallrules_sig, firewall_sig),
                 extra=self.log_extra)

    def update_certificate(self, signature, certificate=None, data=None):

        s_os_client = sdk.OpenStackDriver(self.region_name)
        try:
            icertificate = s_os_client.sysinv_client.update_certificate(
                signature, certificate=certificate, data=data)
            return icertificate
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info("update_certificate exception Timeout",
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestTimeout
        except (AttributeError, TypeError) as e:
            LOG.info("update_certificate error {} region_name".format(e),
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name,
                                              clear_token=True)
            raise exceptions.SyncRequestFailedRetry
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    @staticmethod
    def _decode_certificate_payload(certificate_dict):
        """Decode certificate from payload.

           params: certificate_dict
           returns: certificate, metadata
        """
        certificate = None
        metadata = {}
        content_disposition = 'Content-Disposition'
        try:
            content_type = certificate_dict.get('content_type')
            payload = certificate_dict.get('payload')
            multipart_data = MultipartDecoder(payload, content_type)
            for part in multipart_data.parts:
                if ('name="passphrase"' in part.headers.get(
                        content_disposition)):
                    metadata.update({'passphrase': part.content})
                elif ('name="mode"' in part.headers.get(
                        content_disposition)):
                    metadata.update({'mode': part.content})
                elif ('name="file"' in part.headers.get(
                        content_disposition)):
                    certificate = part.content
        except Exception as e:
            LOG.warn("No certificate decode e={}".format(e))

        LOG.info("_decode_certificate_payload metadata={}".format(
            metadata))
        return certificate, metadata

    def sync_certificate(self, request, rsrc):
        LOG.info("sync_certificate resource_info={}".format(
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        certificate_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = certificate_dict.get('payload')

        if not payload:
            LOG.info("sync_certificate No payload found in resource_info"
                     "{}".format(request.orch_job.resource_info),
                     extra=self.log_extra)
            return

        if isinstance(payload, dict):
            signature = payload.get('signature')
            LOG.info("signature from dict={}".format(signature))
        else:
            signature = rsrc.master_id
            LOG.info("signature from master_id={}".format(signature))

        certificate, metadata = self._decode_certificate_payload(
            certificate_dict)

        isignature = None
        signature = rsrc.master_id
        if signature and signature != self.CERTIFICATE_SIG_NULL:
            icertificate = self.update_certificate(
                signature,
                certificate=certificate,
                data=metadata)
            cert_body = icertificate.get('certificates')
            if cert_body:
                isignature = cert_body.get('signature')
        else:
            LOG.info("skipping signature={}".format(signature))

        # Ensure subcloud resource is persisted to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, signature)

        LOG.info("certificate {} {} [{}/{}] updated".format(rsrc.id,
                 subcloud_rsrc_id, isignature, signature),
                 extra=self.log_extra)

    def update_user(self, passwd_hash, root_sig, passwd_expiry_days):
        LOG.info("update_user={} {} {}".format(
                 passwd_hash, root_sig, passwd_expiry_days),
                 extra=self.log_extra)

        try:
            s_os_client = sdk.OpenStackDriver(self.region_name)
            iuser = s_os_client.sysinv_client.update_user(passwd_hash,
                                                          root_sig,
                                                          passwd_expiry_days)
            return iuser
        except (exceptions.ConnectionRefused, exceptions.NotAuthorized,
                exceptions.TimeOut):
            LOG.info("update_user exception Timeout",
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name)
            raise exceptions.SyncRequestTimeout
        except (AttributeError, TypeError) as e:
            LOG.info("update_user error {} region_name".format(e),
                     extra=self.log_extra)
            s_os_client.delete_region_clients(self.region_name,
                                              clear_token=True)
            raise exceptions.SyncRequestFailedRetry
        except Exception as e:
            LOG.exception(e)
            raise exceptions.SyncRequestFailedRetry

    def sync_user(self, request, rsrc):
        # The system is populated with user entry for wrsroot.
        LOG.info("sync_user resource_info={}".format(
                 request.orch_job.resource_info),
                 extra=self.log_extra)
        user_dict = jsonutils.loads(request.orch_job.resource_info)
        payload = user_dict.get('payload')

        passwd_hash = None
        if type(payload) is list:
            for ipayload in payload:
                if ipayload.get('path') == '/passwd_hash':
                    passwd_hash = ipayload.get('value')
                elif ipayload.get('path') == '/root_sig':
                    root_sig = ipayload.get('value')
                elif ipayload.get('path') == '/passwd_expiry_days':
                    passwd_expiry_days = ipayload.get('value')
        else:
            passwd_hash = payload.get('passwd_hash')
            root_sig = payload.get('root_sig')
            passwd_expiry_days = payload.get('passwd_expiry_days')

        LOG.info("sync_user from dict passwd_hash={} root_sig={} "
                 "passwd_expiry_days={}".format(
                     passwd_hash, root_sig, passwd_expiry_days),
                 extra=self.log_extra)

        if not passwd_hash:
            LOG.info("sync_user no user update found in resource_info"
                     "{}".format(request.orch_job.resource_info),
                     extra=self.log_extra)
            return

        iuser = self.update_user(passwd_hash, root_sig, passwd_expiry_days)

        # Ensure subcloud resource is persisted to the DB for later
        subcloud_rsrc_id = self.persist_db_subcloud_resource(
            rsrc.id, iuser.uuid)
        LOG.info("User wrsroot {}:{} [{}] updated"
                 .format(rsrc.id, subcloud_rsrc_id, passwd_hash),
                 extra=self.log_extra)

    # SysInv Audit Related
    def get_master_resources(self, resource_type):
        os_client = sdk.OpenStackDriver(consts.CLOUD_0)
        if resource_type == consts.RESOURCE_TYPE_SYSINV_DNS:
            return [self.get_dns_resource(os_client)]
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_NTP:
            return [self.get_ntp_resource(os_client)]
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_COMM:
            return self.get_snmp_community_resources(os_client)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST:
            return self.get_snmp_trapdest_resources(os_client)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_REMOTE_LOGGING:
            return [self.get_remotelogging_resource(os_client)]
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_FIREWALL_RULES:
            return [self.get_firewallrules_resource(os_client)]
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
            return self.get_certificates_resources(os_client)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_USER:
            return [self.get_user_resource(os_client)]
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def get_subcloud_resources(self, resource_type):
        os_client = sdk.OpenStackDriver(self.region_name)
        if resource_type == consts.RESOURCE_TYPE_SYSINV_DNS:
            return [self.get_dns_resource(os_client)]
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_NTP:
            return [self.get_ntp_resource(os_client)]
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_COMM:
            return self.get_snmp_community_resources(os_client)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST:
            return self.get_snmp_trapdest_resources(os_client)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_REMOTE_LOGGING:
            return [self.get_remotelogging_resource(os_client)]
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_FIREWALL_RULES:
            return [self.get_firewallrules_resource(os_client)]
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
            return self.get_certificates_resources(os_client)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_USER:
            return [self.get_user_resource(os_client)]
        else:
            LOG.error("Wrong resource type {}".format(resource_type),
                      extra=self.log_extra)
            return None

    def get_dns_resource(self, os_client):
        try:
            idns = os_client.sysinv_client.get_dns()
            return idns
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_dns: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            os_client.delete_region_clients(self.region_name)
            return None
        except (AttributeError, TypeError) as e:
            LOG.info("get_dns_resources error {}".format(e),
                     extra=self.log_extra)
            os_client.delete_region_clients(self.region_name, clear_token=True)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_ntp_resource(self, os_client):
        try:
            intp = os_client.sysinv_client.get_ntp()
            return intp
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_ntp: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            os_client.delete_region_clients(self.region_name)
            return None
        except (AttributeError, TypeError) as e:
            LOG.info("get_ntp_resources error {}".format(e),
                     extra=self.log_extra)
            os_client.delete_region_clients(self.region_name, clear_token=True)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_snmp_trapdest_resources(self, os_client):
        try:
            itrapdests = os_client.sysinv_client.snmp_trapdest_list()
            return itrapdests
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("snmp_trapdest_list: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except (AttributeError, TypeError) as e:
            LOG.info("get_snmp_trapdest_resources error {}".format(e),
                     extra=self.log_extra)
            os_client.delete_region_clients(self.region_name, clear_token=True)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_snmp_community_resources(self, os_client):
        try:
            icommunitys = os_client.sysinv_client.snmp_community_list()
            return icommunitys
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("snmp_community_list: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            return None
        except (AttributeError, TypeError) as e:
            LOG.info("get_snmp_community_resources error {}".format(e),
                     extra=self.log_extra)
            os_client.delete_region_clients(self.region_name, clear_token=True)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_remotelogging_resource(self, os_client):
        try:
            iremotelogging = os_client.sysinv_client.get_remotelogging()
            return iremotelogging
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_remotelogging: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            os_client.delete_region_clients(self.region_name)
            return None
        except (AttributeError, TypeError) as e:
            LOG.info("get_remotelogging_resource error {}".format(e),
                     extra=self.log_extra)
            os_client.delete_region_clients(self.region_name, clear_token=True)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_firewallrules_resource(self, os_client):
        try:
            ifirewallrules = os_client.sysinv_client.get_firewallrules()
            return ifirewallrules
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_firewallrules: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            os_client.delete_region_clients(self.region_name)
            return None
        except (AttributeError, TypeError) as e:
            LOG.info("get_firewallrules_resource error {}".format(e),
                     extra=self.log_extra)
            os_client.delete_region_clients(self.region_name, clear_token=True)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_certificates_resources(self, os_client):
        try:
            return os_client.sysinv_client.get_certificates()
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_certificates: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            os_client.delete_region_clients(self.region_name)
            return None
        except (AttributeError, TypeError) as e:
            LOG.info("get_certificates_resources error {}".format(e),
                     extra=self.log_extra)
            os_client.delete_region_clients(self.region_name, clear_token=True)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_user_resource(self, os_client):
        try:
            iuser = os_client.sysinv_client.get_user()
            return iuser
        except (keystone_exceptions.connection.ConnectTimeout,
                keystone_exceptions.ConnectFailure) as e:
            LOG.info("get_user: subcloud {} is not reachable [{}]"
                     .format(self.subcloud_engine.subcloud.region_name,
                             str(e)), extra=self.log_extra)
            # None will force skip of audit
            os_client.delete_region_clients(self.region_name)
            return None
        except (AttributeError, TypeError) as e:
            LOG.info("get_user_resources error {}".format(e),
                     extra=self.log_extra)
            os_client.delete_region_clients(self.region_name, clear_token=True)
            return None
        except Exception as e:
            LOG.exception(e)
            return None

    def get_resource_id(self, resource_type, resource):
        if resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_COMM:
            LOG.debug("get_resource_id for community {}".format(resource))
            return resource.community
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST:
            if hasattr(resource, 'ip_address') and \
               hasattr(resource, 'community'):
                LOG.debug("get_resource_id resource={} has ip_address and "
                          "community".format(resource),
                          extra=self.log_extra)
                return resource.ip_address
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_FIREWALL_RULES:
            if hasattr(resource, 'firewall_sig'):
                LOG.info("get_resource_id firewall_sig={}".format(
                    resource.firewall_sig))
                if resource.firewall_sig is None:
                    return self.FIREWALL_SIG_NULL  # master_id cannot be None
                return resource.firewall_sig
            elif hasattr(resource, 'master_id'):
                LOG.info("get_resource_id master_id firewall_sig={}".format(
                    resource.master_id))
                if resource.master_id is None:
                    return self.FIREWALL_SIG_NULL  # master_id cannot be None
                return resource.master_id
            else:
                LOG.error("no get_resource_id for firewall")
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
            if hasattr(resource, 'signature'):
                LOG.info("get_resource_id signature={}".format(
                    resource.signature))
                if resource.signature is None:
                    return self.CERTIFICATE_SIG_NULL
                return resource.signature
            elif hasattr(resource, 'master_id'):
                LOG.info("get_resource_id master_id signature={}".format(
                    resource.master_id))
                if resource.master_id is None:
                    # master_id cannot be None
                    return self.CERTIFICATE_SIG_NULL
                return resource.master_id
            else:
                LOG.error("no get_resource_id for certificate")
                return self.CERTIFICATE_SIG_NULL
        else:
            if hasattr(resource, 'uuid'):
                LOG.info("get_resource_id {} uuid={}".format(
                    resource_type, resource.uuid))
                return resource.uuid
            else:
                LOG.info("get_resource_id {} NO uuid resource_type={}".format(
                    resource_type))
                return self.RESOURCE_UUID_NULL  # master_id cannot be None

    def same_dns(self, i1, i2):
        LOG.debug("same_dns i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        same_nameservers = True
        if i1.nameservers != i2.nameservers:
            if not i1.nameservers and not i2.nameservers:
                # To catch equivalent nameservers None vs ""
                same_nameservers = True
            else:
                same_nameservers = False
        return same_nameservers

    def same_ntp(self, i1, i2):
        LOG.debug("same_ntp i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        same_ntpservers = True
        if i1.ntpservers != i2.ntpservers:
            if not i1.ntpservers and not i2.ntpservers:
                # To catch equivalent ntpservers None vs ""
                same_ntpservers = True
            else:
                same_ntpservers = False
        return same_ntpservers

    def same_snmp_trapdest(self, i1, i2):
        LOG.debug("same_snmp_trapdest i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        return (i1.ip_address == i2.ip_address and
                i1.community == i2.community)

    def same_snmp_community(self, i1, i2):
        LOG.debug("same_snmp_community i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        if i1.community and (i1.community != i2.community):
            if i1.signature == self.RESOURCE_UUID_NULL:
                LOG.info("Master Resource SNMP Community NULL UUID")
                return True
            return False
        return True

    def same_remotelogging(self, i1, i2):
        LOG.debug("same_remotelogging i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)

        same_ip_address = True
        if i1.ip_address and (i1.ip_address != i2.ip_address):
            same_ip_address = False

        return (same_ip_address and
                i1.enabled == i2.enabled and
                i1.transport == i2.transport and
                i1.port == i2.port)

    def same_firewallrules(self, i1, i2):
        LOG.debug("same_firewallrules i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        same = True
        if i1.firewall_sig and (i1.firewall_sig != i2.firewall_sig):
            if i1.firewall_sig == self.FIREWALL_SIG_NULL:
                return True
            LOG.info("same_firewallrules differ i1={}, i2={}".format(i1, i2),
                     extra=self.log_extra)
            same = False

        return same

    def same_certificate(self, i1, i2):
        LOG.debug("same_certificate i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        same = True
        if i1.signature and (i1.signature != i2.signature):
            if i1.signature == self.CERTIFICATE_SIG_NULL:
                return True
            same = False
        if ((i1.expiry_date and i1.expiry_date != i2.expiry_date) or
           (i1.start_date and i1.start_date != i2.start_date)):
            same = False

        if not same:
            LOG.info("same_certificate differs i1={}, i2={}".format(i1, i2),
                     extra=self.log_extra)

        return same

    def same_user(self, i1, i2):
        LOG.debug("same_user i1={}, i2={}".format(i1, i2),
                  extra=self.log_extra)
        same_user = True
        if (i1.passwd_hash != i2.passwd_hash or
           i1.passwd_expiry_days != i2.passwd_expiry_days):
            same_user = False
        return same_user

    def same_resource(self, resource_type, m_resource, sc_resource):
        if resource_type == consts.RESOURCE_TYPE_SYSINV_DNS:
            return self.same_dns(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_NTP:
            return self.same_ntp(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_COMM:
            return self.same_snmp_community(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST:
            return self.same_snmp_trapdest(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_REMOTE_LOGGING:
            return self.same_remotelogging(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_FIREWALL_RULES:
            return self.same_firewallrules(m_resource, sc_resource)
        elif resource_type == consts.RESOURCE_TYPE_SYSINV_CERTIFICATE:
            return self.same_certificate(m_resource, sc_resource)
        if resource_type == consts.RESOURCE_TYPE_SYSINV_USER:
            return self.same_user(m_resource, sc_resource)
        else:
            LOG.warn("same_resource() unexpected resource_type {}".format(
                resource_type),
                extra=self.log_extra)

    def audit_discrepancy(self, resource_type, m_resource, sc_resources):
        # Return true to try the audit_action
        if resource_type in self.SYSINV_ADD_DELETE_RESOURCES:
            # It could be that the details are different
            # between master cloud and subcloud now.
            # Thus, delete the resource before creating it again.
            master_id = self.get_resource_id(resource_type, m_resource)
            self.schedule_work(self.endpoint_type, resource_type,
                               master_id,
                               consts.OPERATION_TYPE_DELETE)
            return True
        elif (resource_type in self.SYSINV_MODIFY_RESOURCES or
              resource_type in self.SYSINV_CREATE_RESOURCES):
            # The resource differs, signal to perform the audit_action
            return True

        LOG.info("audit_discrepancy default action".format(resource_type),
                 extra=self.log_extra)
        return False

    def audit_action(self, resource_type, finding, resource):
        if resource_type in self.SYSINV_MODIFY_RESOURCES:
            LOG.info("audit_action: {}/{}"
                     .format(finding, resource_type),
                     extra=self.log_extra)
            num_of_audit_jobs = 0
            if finding == AUDIT_RESOURCE_MISSING:
                # The missing resource should be created by underlying subcloud
                # thus action is to update for a 'missing' resource
                # should not get here since audit discrepency will handle this
                resource_id = self.get_resource_id(resource_type, resource)
                self.schedule_work(self.endpoint_type, resource_type,
                                   resource_id,
                                   consts.OPERATION_TYPE_PATCH,
                                   self.get_resource_info(
                                       resource_type, resource))
                num_of_audit_jobs += 1
            else:
                LOG.warn("unexpected finding {} resource_type {}".format(
                         finding, resource_type),
                         extra=self.log_extra)
            return num_of_audit_jobs
        elif resource_type in self.SYSINV_CREATE_RESOURCES:
            LOG.info("audit_action: {}/{}"
                     .format(finding, resource_type),
                     extra=self.log_extra)
            # Default actions are create & delete. Can be overridden
            # in resource implementation
            num_of_audit_jobs = 0
            # resource can be either from dcorch DB or
            # fetched by OpenStack query
            resource_id = self.get_resource_id(resource_type, resource)
            if finding == AUDIT_RESOURCE_MISSING:
                # default action is create for a 'missing' resource
                if resource_id == self.FIREWALL_SIG_NULL:
                    LOG.info("No custom firewall resource to sync")
                    return num_of_audit_jobs
                elif resource_id == self.CERTIFICATE_SIG_NULL:
                    LOG.info("No certificate resource to sync")
                    return num_of_audit_jobs
                elif resource_id == self.RESOURCE_UUID_NULL:
                    LOG.info("No resource to sync")
                    return num_of_audit_jobs

                self.schedule_work(
                    self.endpoint_type, resource_type,
                    resource_id,
                    consts.OPERATION_TYPE_CREATE,
                    self.get_resource_info(
                        resource_type, resource,
                        consts.OPERATION_TYPE_CREATE))
                num_of_audit_jobs += 1
            return num_of_audit_jobs
        else:  # use default audit_action
            return super(SysinvSyncThread, self).audit_action(
                resource_type,
                finding,
                resource)

    def get_resource_info(self, resource_type,
                          resource, operation_type=None):
        payload_resources = [consts.RESOURCE_TYPE_SYSINV_DNS,
                             consts.RESOURCE_TYPE_SYSINV_NTP,
                             consts.RESOURCE_TYPE_SYSINV_SNMP_COMM,
                             consts.RESOURCE_TYPE_SYSINV_SNMP_TRAPDEST,
                             consts.RESOURCE_TYPE_SYSINV_REMOTE_LOGGING,
                             consts.RESOURCE_TYPE_SYSINV_FIREWALL_RULES,
                             consts.RESOURCE_TYPE_SYSINV_CERTIFICATE,
                             consts.RESOURCE_TYPE_SYSINV_USER,
                             ]
        if resource_type in payload_resources:
            if 'payload' not in resource._info:
                dumps = jsonutils.dumps({"payload": resource._info})
            else:
                dumps = jsonutils.dumps(resource._info)
            LOG.info("get_resource_info resource_type={} dumps={}".format(
                resource_type, dumps),
                extra=self.log_extra)
            return dumps
        else:
            LOG.warn("get_resource_info unsupported resource {}".format(
                resource_type),
                extra=self.log_extra)
            return super(SysinvSyncThread, self).get_resource_info(
                resource_type, resource, operation_type)

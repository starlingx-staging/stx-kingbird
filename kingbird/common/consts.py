# Copyright (c) 2016 Ericsson AB.

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

NOVA_QUOTA_FIELDS = ("metadata_items",
                     "cores",
                     "instances",
                     "ram",
                     "key_pairs",
                     "floating_ips",
                     "fixed_ips",
                     "security_groups",
                     "security_group_rules",)

CINDER_QUOTA_FIELDS = ("volumes",
                       "snapshots",
                       "gigabytes",
                       "backups",)

NEUTRON_QUOTA_FIELDS = ("network",
                        "subnet",
                        "port",
                        "router",
                        "floatingip",
                        "security_group",
                        "security_group_rule",
                        )

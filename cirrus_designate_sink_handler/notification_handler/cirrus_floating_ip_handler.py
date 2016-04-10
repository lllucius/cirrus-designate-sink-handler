# Copyright 2012 Bouvet ASA
# Copyright 2015 Time Warner Cable
#
# Author: Endre Karlson <endre.karlson@bouvet.no>
# Author: Clayton O'Neill <clayton.oneill@twcable.com>
# Updated by: Leland Lucius <github@homerow.net>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or ageeed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import re
import time

import designate.exceptions
from designate.notification_handler.base import BaseAddressHandler
from designate.objects import Record
from designate.objects import FloatingIP
from designate.context import DesignateContext
from keystoneclient.v2_0 import client as keystone_c
from neutronclient.v2_0 import client as neutron_c
from novaclient.v2 import client as nova_c
from oslo_log import log as logging
from oslo_config import cfg

LOG = logging.getLogger(__name__)

cfg.CONF.register_group(cfg.OptGroup(
    name='handler:cirrus_floatingip',
    title='Configuration for Cirrus Notification Handler'
))

cfg.CONF.register_opts([
    cfg.ListOpt('notification-topics', default=['notifications_designate']),
    cfg.StrOpt('control-exchange', default='neutron'),
    cfg.StrOpt('region-name', default=None),
    cfg.StrOpt('keystone-username', default=None),
    cfg.StrOpt('keystone-password', default=None),
    cfg.StrOpt('keystone-auth-uri', default=None),
    cfg.StrOpt('domain-id', default=None),
    cfg.IntOpt('pending_delete_retries', default=60),
    cfg.IntOpt('pending_delete_interval', default=1),
    cfg.StrOpt('default-regex', default='\(default\)$'),
    cfg.BoolOpt('require-default-regex', default=False),
    cfg.StrOpt('format', default='%(instance_short_name)s.%(domain)s'),
    cfg.StrOpt('format-fallback',
               default='%(instance_short_name)s-%(octet0)s-%(octet1)s-%(octet2)s-%(octet3)s.%(domain)s'),
], group='handler:cirrus_floatingip')

class CirrusRecordExists(Exception):
    pass

class CirrusFloatingIPHandler(BaseAddressHandler):
    """Handler for Neutron notifications."""
    __plugin_name__ = 'cirrus_floatingip'
    __plugin_type__ = 'handler'

    def get_exchange_topics(self):
        exchange = cfg.CONF[self.name].control_exchange
        topics = [topic for topic in cfg.CONF[self.name].notification_topics]

        return (exchange, topics)

    def get_event_types(self):
        return [
            'port.update.end',
            'port.delete.end',
            'floatingip.update.end',
            'floatingip.delete.end',
        ]

    def _get_ip_data(self, addr_dict):
        data = super(CirrusFloatingIPHandler, self)._get_ip_data(addr_dict)
        return data

    def _get_keystone_client(self, tenant_id):
        return keystone_c.Client(auth_url=cfg.CONF[self.name].keystone_auth_uri,
                                 username=cfg.CONF[self.name].keystone_username,
                                 password=cfg.CONF[self.name].keystone_password,
                                 region_name=cfg.CONF[self.name].region_name,
                                 tenant_id=tenant_id)

    def _get_neutron_client(self, keystone_client):
        endpoint = keystone_client.service_catalog.url_for(service_type='network',
                                                           endpoint_type='internalURL')
        return neutron_c.Client(token=keystone_client.auth_token,
                                tenant_id=keystone_client.auth_tenant_id,
                                endpoint_url=endpoint)

    def _get_nova_client(self, keystone_client):
        endpoint = keystone_client.service_catalog.url_for(service_type='compute',
                                                           endpoint_type='internalURL')
        return nova_c.Client(auth_token=keystone_client.auth_token,
                             tenant_id=keystone_client.auth_tenant_id,
                             bypass_url=endpoint)
 
    # RFC 952/1123 allow only A-Z, a-z, 0-9, and -
    # We'll swap all other special characters with '-',
    # this may lead to a collision but at least has a possibility
    # to work.
    # Additionally each section of a domain name may only be
    # 63 characters long, so we'll truncate that too.
    def _scrub_instance_name(self, name=''):
        scrubbed = ''
        for char in name:
            if char.isalnum() or char == '.' or char == '-':
                scrubbed += char
            else:
                scrubbed += '-'
            if len(scrubbed) == 63:
                return scrubbed
        return scrubbed

    def _get_instance_info(self, keystone_client, port_id):
        """Returns information about the instance associated with the neutron `port_id` given.

        Given a Neutron `port_id`, it will retrieve the device_id associated with
        the port which should be the instance UUID.  It will then retrieve and
        return the instance name and UUID for the instance.  Note that the
        `port_id` must the one associated with the instance, not the floating IP.
        Neutron floating ip notifications will contain the instance's port_id.

        """

        neutron_client = self._get_neutron_client(keystone_client)
        port_details = neutron_client.show_port(port_id)

        instance_id = port_details['port']['device_id']
        if instance_id is None or instance_id == '':
            LOG.debug('device_id not yet available on %s' % port_id)
            return None;

        LOG.debug('Instance id for port id %s is %s' % (port_id, instance_id))

        nova_client = self._get_nova_client(keystone_client)
        server = nova_client.servers.get(instance_id)

        LOG.debug('Instance name for id %s is %s' % (server.id, server.name))

        instance_info = {
            'client': nova_client,
            'server': server,
            'id': instance_id,
            'original_name': server.name,
            'scrubbed_name': self._scrub_instance_name(server.name)
        }
        if instance_info['original_name'] != instance_info['scrubbed_name']:
            LOG.warn('Instance name for id %s contains characters that cannot be used'
                     ' for a valid DNS record. It was scrubbed from %s to %s'
                     % (instance_id, instance_info['original_name'], instance_info['scrubbed_name']))
            instance_info['name'] = instance_info['scrubbed_name']
        else:
            instance_info['name'] = instance_info['original_name']

        LOG.debug('instance info: %s' % instance_info)

        return instance_info

    def _pick_tenant_domain(self, tenant_id, metadata={}):
        """Pick the appropriate domain to create floating ip records in

        If no appropriate domains can be found, it will return `None`.  If a single
        domain is found, it will be returned.  If multiple domains are found, then
        it will look for one where the description matches the regex given, and
        return the first match found.
        """
        tenant_context = DesignateContext(tenant=tenant_id)
 
        tenant_domains = self.central_api.find_domains(tenant_context)
        if len(tenant_domains) == 1 and not cfg.CONF[self.name].require_default_regex:
            return tenant_domains[0]

        for domain in tenant_domains:
            if domain.description is not None:
                if re.search(cfg.CONF[self.name].default_regex, domain.description):
                    return domain

        # Fallback to default domain if available
        domain_id = cfg.CONF[self.name].domain_id
        if domain_id is not None:
            domain = self.get_domain(domain_id)
            return domain

        return None

    def _create(self, context, addresses, name_format, extra, domain_id,
                managed_extra, resource_type, resource_id):
        """
        Create a a record from addresses
        :param addresses: Address objects like
                          {'version': 4, 'ip': '10.0.0.1'}
        :param extra: Extra data to use when formatting the record
        :param resource_type: The managed resource type
        :param resource_id: The managed resource ID
        """

        data = extra.copy()
        LOG.debug('Event data: %s' % data)

        names = []
        for addr in addresses:
            event_data = data.copy()
            event_data.update(self._get_ip_data(addr))

            recordset_values = {
                'domain_id': domain_id,
                'name': name_format % event_data,
                'type': 'A' if addr['version'] == 4 else 'AAAA'
            }

            for x in range(0, cfg.CONF[self.name].pending_delete_retries):
                recordset = self._find_or_create_recordset(context, **recordset_values)
                if len(recordset.records) == 0:
                    break

                # If there is any existing A records for this name, then we don't
                # want to create additional ones, we throw an exception so the
                # caller can retry if appropriate.
                for record in recordset.records:
                    if record['status'] != 'PENDING':
                        raise CirrusRecordExists('Name already has an A record')

                time.sleep(cfg.CONF[self.name].pending_delete_interval)

            record_values = {
                'data': addr['address'],
                'managed': True,
                'managed_plugin_name': self.get_plugin_name(),
                'managed_plugin_type': self.get_plugin_type(),
                'managed_extra': managed_extra,
                'managed_resource_type': resource_type,
                'managed_resource_id': resource_id
            }

            LOG.debug('Creating record in %s / %s with values %r' %
                      (domain_id, recordset['id'], record_values))
            self.central_api.create_record(context,
                                           domain_id,
                                           recordset['id'],
                                           Record(**record_values),
                                           )
            values = {
                'ptrdname': recordset_values['name'],
                'description': None
            }
            self.central_api.update_floatingip(context,
                                               cfg.CONF[self.name].region_name,
                                               resource_id,
                                               FloatingIP(**values))
            names.append({'name': recordset_values['name'],
                          'addr': addr['address']})
        return names

    def _associate(self, keystone_client, payload, floatingip):
        """Associate a new A record with a Floating IP

        Try to create an A record using the format specified in the config.  If
        a record with that name already exists, then it will try to create a
        record using the format specified for fallback.  The data passed in as
        the `extra` dict will be used along with the appropriate format to
        generate the FQDN to associate with the A record.

        When creating the record, we store the floating IP uuid in the
        resource_id field and store the port id in the managed_extra field.
        We'll need the port id in case the instance is deleted without the
        floating IP being disassociated first.
        """

        fip = floatingip['floating_ip_address']
        fid = floatingip['id']
        port_id = floatingip['port_id']

        # Create an object from the original context so we can use it with the
        # RPC API calls.  We want this limited to the single tenant so we can
        # use it to find their domains.
        domain = self._pick_tenant_domain(keystone_client.tenant_id)
        if domain is None:
            LOG.warn('No domains found for tenant %s(%s), ignoring Floating IP update for %s' %
                     (keystone_client.tenant_name, keystone_client.tenant_id, fip))
            return

        LOG.info('Using domain %s(%s) for tenant %s(%s)' %
                 (domain.name, domain.id,
                  keystone_client.tenant_name, keystone_client.tenant_id))

        instance_info = self._get_instance_info(keystone_client, port_id)
        if instance_info is None:
            LOG.info('Could not determine instance information for portid %s' % port_id)
            return

        # We need a context that will allow us to manipulate records that are
        # flagged as managed, so we can't use the context that was provided
        # with the notification.
        elevated_context = DesignateContext(tenant=keystone_client.tenant_id).elevated()
        elevated_context.all_tenants = True
        elevated_context.edit_managed_records = True

        extra = payload.copy()
        extra.update({'instance_name': instance_info['name'],
                      'instance_short_name': instance_info['name'].partition('.')[0],
                      'project': keystone_client.tenant_name,
                      'domain': domain.name})

        addresses = [{
            'version': 4,
            'address': fip,
        }]
        names = None
        try:
            names = self._create(context=elevated_context,
                                 addresses=addresses,
                                 name_format=cfg.CONF[self.name].format,
                                 extra=extra,
                                 domain_id=domain.id,
                                 managed_extra='portid:%s' % port_id,
                                 resource_type='a:floatingip',
                                 resource_id=fid)
        except (designate.exceptions.DuplicateRecord, CirrusRecordExists):
            LOG.warn('Could not create record for %s using default format, '
                     'trying fallback format' % (extra['instance_name']))
            names = self._create(context=elevated_context,
                                 addresses=addresses,
                                 name_format=cfg.CONF[self.name].format_fallback,
                                 extra=extra,
                                 domain_id=domain.id,
                                 managed_extra='portid:%s' % port_id,
                                 resource_type='a:floatingip',
                                 resource_id=fid)
        if names is not None:
            client = instance_info['client']
            for name in names:
                LOG.info('Created %s to point at %s' % (name['name'], name['addr']))
                client.servers.set_meta_item(instance_info['server'],
                                             'hostname-%s' % name['addr'],
                                             name['name'])

    def _disassociate(self, tenant_id, floatingip_id=None, port_id=None):
        """Remove A and associated PTR records

        Searches for managed A records based on floatingip_id or port_id
        and deletes them along with any associated PTR records.
        """

        # We need a context that will allow us to manipulate records that are
        # flagged as managed, so we can't use the context that was provided
        # with the notification.
        elevated_context = DesignateContext(tenant=tenant_id).elevated()
        elevated_context.all_tenants = True
        elevated_context.edit_managed_records = True

        criterion = {
            'managed': 1,
            'managed_resource_type': 'a:floatingip',
            'managed_plugin_name': self.get_plugin_name(),
            'managed_plugin_type': self.get_plugin_type(),
        }

        if floatingip_id is not None:
            criterion['managed_resource_id'] = floatingip_id
        elif port_id is not None:
            criterion['managed_extra'] = port_id
        else:
            LOG.warn('floatingip_id or port_id needed for _find_and_delete()')
            return

        records = self.central_api.find_records(elevated_context, criterion=criterion)

        LOG.debug('Found %d records to delete' % len(records))

        for record in records:
            LOG.debug('Deleting record %s with IP %s from %s' % (record['id'], record['data'], record['domain_id']))

            values = {
                'ptrdname': None
            }
            try:
                self.central_api.update_floatingip(elevated_context,
                                                   record['managed_resource_region'],
                                                   record['managed_resource_id'],
                                                   FloatingIP(**values))
            except:
                pass

            try:
                LOG.info('domain %s recordid %s id %s' % (
                                               record['domain_id'],
                                               record['recordset_id'],
                                               record['id']))
                self.central_api.delete_record(elevated_context,
                                               record['domain_id'],
                                               record['recordset_id'],
                                               record['id'])
            except designate.exceptions.DomainNotFound:
                pass

    def process_port_delete_end(self, context, payload):
        """Process the floatingip.delete.end event

        When an instance with an associated floatingip is deleted without first
        disassociating that floatingip, we never get a floatingip update event.
        We just get notified that the underlying port was deleted.  So, just
        disassociate all floatingips assigned to the port since the port will
        no longer exist.
        """

        tenant_id = context['tenant_id']

        self._disassociate(tenant_id, port_id=payload['port_id'])

    def process_port_update_end(self, context, payload):
        tenant_id = payload['port']['tenant_id']

        # If tenant_id is blank, then a non-floatingip change was made to the port,
        # so we ignore it
        if tenant_id == '':
            return

        port_id = payload['port']['id']

        keystone_client = self._get_keystone_client(tenant_id)
        neutron_client = self._get_neutron_client(keystone_client)

        floatingips = neutron_client.list_floatingips()['floatingips']
        floatingip = next( (x for x in floatingips if x['port_id'] == port_id), None)
        if floatingip is None:
            LOG.error('Unable to determine floatingip for port_id %s' % port_id)
            return

        self._associate(keystone_client, payload, floatingip)

    def process_floatingip_update_end(self, context, payload):
        tenant_id = context['tenant_id']
        floatingip = payload['floatingip']

        keystone_client = self._get_keystone_client(tenant_id)

        # The port_id will be None if this event is a result of disassociation.
        # But, we have to always disassociate since a floatingip can be assigned
        # to a new port without us being told to remove it from the previously
        # assigned port.
        self._disassociate(keystone_client.tenant_id, floatingip_id=floatingip['id'])
        if floatingip['port_id'] is None:
            return

        self._associate(keystone_client, payload, floatingip)

    def process_floatingip_delete_end(self, context, payload):
        """Process the floatingip.delete.end event

        If a floatingip is associated with a port and the floatingip is deleted,
        the only indication is the floatingip.delete.end event, so clean up any
        records with this floatingip.
        """

        tenant_id = context['tenant_id']

        self._disassociate(tenant_id, floatingip_id=payload['floatingip_id'])

    def process_notification(self, context, event_type, payload):
        """Process floating IP notifications from Neutron"""

        LOG.info('%s received notification - %s' %
                 (self.get_canonical_name(), event_type))

        LOG.debug('PAYLOAD %s' % payload)

        if event_type == 'port.update.end':
            self.process_port_update_end(context, payload)
        elif event_type == 'port.delete.end':
            self.process_port_delete_end(context, payload)
        elif event_type == 'floatingip.update.end':
            self.process_floatingip_update_end(context, payload)
        elif event_type == 'floatingip.delete.end':
            self.process_floatingip_delete_end(context, payload)


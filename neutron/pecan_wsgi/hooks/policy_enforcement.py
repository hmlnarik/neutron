# Copyright (c) 2015 Mirantis, Inc.
# All Rights Reserved.
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

import copy
import simplejson

from oslo_policy import policy as oslo_policy
from oslo_utils import excutils
from pecan import hooks
import webob

from neutron._i18n import _
from neutron.api.v2 import attributes as v2_attributes
from neutron.common import constants as const
from neutron import manager
from neutron import policy


class PolicyHook(hooks.PecanHook):
    priority = 135
    ACTION_MAP = {'POST': 'create', 'PUT': 'update', 'GET': 'get',
                  'DELETE': 'delete'}

    def _fetch_resource(self, neutron_context, resource, resource_id):
        attrs = v2_attributes.get_resource_info(resource)
        field_list = [name for (name, value) in attrs.items()
                      if (value.get('required_by_policy') or
                          value.get('primary_key') or 'default' not in value)]
        plugin = manager.NeutronManager.get_plugin_for_resource(resource)
        getter = getattr(plugin, 'get_%s' % resource)
        # TODO(kevinbenton): the parent_id logic currently in base.py
        return getter(neutron_context, resource_id, fields=field_list)

    def before(self, state):
        # This hook should be run only for PUT,POST and DELETE methods and for
        # requests targeting a neutron resource
        # FIXME(salv-orlando): DELETE support. It does not work with the
        # current logic. See LP Bug #1520180
        items = state.request.context.get('resources')
        if state.request.method not in ('POST', 'PUT') or not items:
            return
        neutron_context = state.request.context.get('neutron_context')
        resource = state.request.context.get('resource')
        collection = state.request.context.get('collection')
        is_update = (state.request.method == 'PUT')
        policy.init()
        action = '%s_%s' % (self.ACTION_MAP[state.request.method], resource)

        # NOTE(salv-orlando): As bulk updates are not supported, in case of PUT
        # requests there will be only a single item to process, and its
        # identifier would have been already retrieved by the lookup process
        for item in items:
            if is_update:
                resource_id = state.request.context.get('resource_id')
                obj = copy.copy(self._fetch_resource(neutron_context,
                                                     resource,
                                                     resource_id))
                obj.update(item)
                obj[const.ATTRIBUTES_TO_UPDATE] = item.keys()
                item = obj
            try:
                policy.enforce(
                    neutron_context, action, item,
                    pluralized=collection)
            except oslo_policy.PolicyNotAuthorized:
                with excutils.save_and_reraise_exception() as ctxt:
                    # If a tenant is modifying it's own object, it's safe to
                    # return a 403. Otherwise, pretend that it doesn't exist
                    # to avoid giving away information.
                    if (is_update and
                            neutron_context.tenant_id != obj['tenant_id']):
                        ctxt.reraise = False
                msg = _('The resource could not be found.')
                raise webob.exc.HTTPNotFound(msg)

    def after(self, state):
        neutron_context = state.request.context.get('neutron_context')
        resource = state.request.context.get('resource')
        collection = state.request.context.get('collection')
        if not resource:
            # can't filter a resource we don't recognize
            return
        # NOTE(kevinbenton): extension listing isn't controlled by policy
        if resource == 'extension':
            return
        try:
            data = state.response.json
        except simplejson.JSONDecodeError:
            return
        action = '%s_%s' % (self.ACTION_MAP[state.request.method],
                            resource)
        if not data or (resource not in data and collection not in data):
            return
        is_single = resource in data
        key = resource if is_single else collection
        to_process = [data[resource]] if is_single else data[collection]
        # in the single case, we enforce which raises on violation
        # in the plural case, we just check so violating items are hidden
        policy_method = policy.enforce if is_single else policy.check
        plugin = manager.NeutronManager.get_plugin_for_resource(resource)
        resp = [self._get_filtered_item(state.request, resource,
                                        collection, item)
                for item in to_process
                if (state.request.method != 'GET' or
                    policy_method(neutron_context, action, item,
                                  plugin=plugin,
                                  pluralized=collection))]
        if is_single:
            resp = resp[0]
        data[key] = resp
        state.response.json = data

    def _get_filtered_item(self, request, resource, collection, data):
        neutron_context = request.context.get('neutron_context')
        to_exclude = self._exclude_attributes_by_policy(
            neutron_context, resource, collection, data)
        return self._filter_attributes(request, data, to_exclude)

    def _filter_attributes(self, request, data, fields_to_strip):
        # TODO(kevinbenton): this works but we didn't allow the plugin to
        # only fetch the fields we are interested in. consider moving this
        # to the call
        user_fields = request.params.getall('fields')
        return dict(item for item in data.items()
                    if (item[0] not in fields_to_strip and
                        (not user_fields or item[0] in user_fields)))

    def _exclude_attributes_by_policy(self, context, resource,
                                      collection, data):
        """Identifies attributes to exclude according to authZ policies.

        Return a list of attribute names which should be stripped from the
        response returned to the user because the user is not authorized
        to see them.
        """
        attributes_to_exclude = []
        for attr_name in data.keys():
            attr_data = v2_attributes.get_resource_info(
                resource).get(attr_name)
            if attr_data and attr_data['is_visible']:
                if policy.check(
                    context,
                    # NOTE(kevinbenton): this used to reference a
                    # _plugin_handlers dict, why?
                    'get_%s:%s' % (resource, attr_name),
                    data,
                    might_not_exist=True,
                    pluralized=collection):
                    # this attribute is visible, check next one
                    continue
            # if the code reaches this point then either the policy check
            # failed or the attribute was not visible in the first place
            attributes_to_exclude.append(attr_name)
        return attributes_to_exclude

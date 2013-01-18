/*
* Licensed to the Apache Software Foundation (ASF) under one or more
* contributor license agreements.  See the NOTICE file distributed with
* this work for additional information regarding copyright ownership.
* The ASF licenses this file to You under the Apache License, Version 2.0
* (the "License"); you may not use this file except in compliance with
* the License.  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#include <trust_policy_util.h>
#include <trust_constants.h>

AXIS2_EXTERN rp_algorithmsuite_t *AXIS2_CALL
trust_policy_util_get_algorithmsuite(
    const axutil_env_t * env,
    neethi_policy_t * policy, 
	rp_secpolicy_t **secpolicy)
{
    rp_binding_commons_t *binding_commons = NULL;

    AXIS2_ENV_CHECK(env, NULL);

	if(!*secpolicy)
		*secpolicy = rp_secpolicy_builder_build(env, policy);
    
	if (!*secpolicy)
    {
        return NULL;
    }

    binding_commons = trust_policy_util_get_binding_commons(env, *secpolicy);

    return rp_binding_commons_get_algorithmsuite(binding_commons, env);
}

AXIS2_EXTERN rp_trust10_t *AXIS2_CALL
trust_policy_util_get_trust10(
    const axutil_env_t * env,
    neethi_policy_t * policy, 
	rp_secpolicy_t **secpolicy)
{
    AXIS2_ENV_CHECK(env, NULL);

	if(!*secpolicy)
		*secpolicy = rp_secpolicy_builder_build(env, policy);
    if (!*secpolicy)
    {
        return NULL;
    }

    return rp_secpolicy_get_trust10(*secpolicy, env);
}

AXIS2_EXTERN rp_binding_commons_t *AXIS2_CALL
trust_policy_util_get_binding_commons(
    const axutil_env_t * env,
    rp_secpolicy_t * secpolicy)
{
    rp_property_t *property = NULL;
    property = rp_secpolicy_get_binding(secpolicy, env);
    if (!property)
        return NULL;

    if (rp_property_get_type(property, env) == RP_PROPERTY_ASYMMETRIC_BINDING)
    {
        rp_asymmetric_binding_t *asymmetric_binding = NULL;
        rp_symmetric_asymmetric_binding_commons_t *sym_asym_commons = NULL;
        asymmetric_binding = (rp_asymmetric_binding_t *) rp_property_get_value(property, env);
        if (!asymmetric_binding)
            return NULL;

        sym_asym_commons =
            rp_asymmetric_binding_get_symmetric_asymmetric_binding_commons(asymmetric_binding, env);
        if (!sym_asym_commons)
            return NULL;

        return rp_symmetric_asymmetric_binding_commons_get_binding_commons(sym_asym_commons, env);
    }
    else if (rp_property_get_type(property, env) == RP_PROPERTY_SYMMETRIC_BINDING)
    {
        rp_symmetric_binding_t *symmetric_binding = NULL;
        rp_symmetric_asymmetric_binding_commons_t *sym_asym_commons = NULL;
        symmetric_binding = (rp_symmetric_binding_t *) rp_property_get_value(property, env);
        if (!symmetric_binding)
            return NULL;

        sym_asym_commons =
            rp_symmetric_binding_get_symmetric_asymmetric_binding_commons(symmetric_binding, env);
        if (!sym_asym_commons)
            return NULL;

        return rp_symmetric_asymmetric_binding_commons_get_binding_commons(sym_asym_commons, env);

    }
    else if (rp_property_get_type(property, env) == RP_PROPERTY_TRANSPORT_BINDING)
    {
        rp_transport_binding_t *transport_binding = NULL;
        transport_binding = (rp_transport_binding_t *) rp_property_get_value(property, env);
        if (!transport_binding)
            return NULL;

        return rp_transport_binding_get_binding_commons(transport_binding, env);
    }
    else
        return NULL;
}

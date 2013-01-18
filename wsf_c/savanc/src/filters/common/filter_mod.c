/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
#include <savan_filter_mod.h>
#include <savan_constants.h>
#include <savan_error.h>
#include <savan_util.h>
#include <axutil_log.h>
#include <axutil_hash.h>
#include <axutil_property.h>
#include <axutil_uuid_gen.h>
#include <axis2_conf_ctx.h>

AXIS2_EXTERN void AXIS2_CALL
savan_filter_mod_free(
    savan_filter_mod_t *filtermod,
    const axutil_env_t *env)
{
     filtermod->ops->free(filtermod, env);
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
savan_filter_mod_apply(
    savan_filter_mod_t *filtermod, 
    const axutil_env_t *env,
    savan_subscriber_t *subscriber,
    axiom_node_t *payload)
{
    return filtermod->ops->apply(filtermod, env, subscriber, payload);
}


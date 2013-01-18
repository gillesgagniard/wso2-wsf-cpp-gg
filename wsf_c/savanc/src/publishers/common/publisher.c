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
 
#include <savan_publisher.h>
#include <savan_constants.h>
#include <savan_error.h>
#include <savan_util.h>
#include <axutil_log.h>
#include <axutil_hash.h>
#include <axutil_property.h>
#include <axutil_uuid_gen.h>
#include <axis2_conf_ctx.h>
#include <axis2_msg_ctx.h>

AXIS2_EXTERN void AXIS2_CALL
savan_publisher_free(
    savan_publisher_t *publishermod,
    const axutil_env_t *env)
{
     return publishermod->ops->free(publishermod, env);
}

AXIS2_EXTERN void AXIS2_CALL
savan_publisher_publish(
    savan_publisher_t *publishermod, 
    const axutil_env_t *env,
    void *msg_ctx,
    savan_subs_mgr_t *subs_mgr)
{
    publishermod->ops->publish(publishermod, env, msg_ctx, subs_mgr);
}


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

#include <axis2_svc_skeleton.h>
#include "saml_issuer.h"
#include <axutil_array_list.h>
#include <axis2_op_ctx.h>
#include <axis2_msg_ctx.h>
#include <axis2_const.h>
#include <trust_context.h>
#include <trust_rst.h>
#include <trust_rstr.h>

#include <stdio.h>

int AXIS2_CALL saml_issuer_free(
    axis2_svc_skeleton_t *svc_skeleton,
    const axutil_env_t *env);

axiom_node_t *AXIS2_CALL saml_issuer_invoke(
    axis2_svc_skeleton_t *svc_skeleton,
    const axutil_env_t *env,
    axiom_node_t *node,
    axis2_msg_ctx_t *msg_ctx);

int AXIS2_CALL saml_issuer_init(
    axis2_svc_skeleton_t *svc_skeleton,
    const axutil_env_t *env);

axiom_node_t * AXIS2_CALL
saml_issuer_on_fault(
        axis2_svc_skeleton_t *svc_skel,
        const axutil_env_t *env,
        axiom_node_t *node);

static const axis2_svc_skeleton_ops_t saml_issuer_svc_skeleton_ops_var = {
    saml_issuer_init,
    saml_issuer_invoke,
    saml_issuer_on_fault,
    saml_issuer_free
};

AXIS2_EXTERN axis2_svc_skeleton_t *AXIS2_CALL
axis2_saml_issuer_create(
    const axutil_env_t *env)
{
    axis2_svc_skeleton_t *svc_skeleton = NULL;
    svc_skeleton = AXIS2_MALLOC(env->allocator, sizeof(axis2_svc_skeleton_t));
    svc_skeleton->ops = &saml_issuer_svc_skeleton_ops_var;
    svc_skeleton->func_array = NULL;
    return svc_skeleton;
}

int AXIS2_CALL
saml_issuer_init(
    axis2_svc_skeleton_t *svc_skeleton,
    const axutil_env_t *env)
{
    return AXIS2_SUCCESS;
}

int AXIS2_CALL
saml_issuer_free(
    axis2_svc_skeleton_t *svc_skeleton,
    const axutil_env_t *env)
{
    if (svc_skeleton)
    {
        AXIS2_FREE(env->allocator, svc_skeleton);
        svc_skeleton = NULL;
    }
    return AXIS2_SUCCESS;
}

axiom_node_t *AXIS2_CALL
saml_issuer_invoke(
    axis2_svc_skeleton_t *svc_skeleton,
    const axutil_env_t *env,
    axiom_node_t *node,
    axis2_msg_ctx_t *msg_ctx)
{  
    axis2_msg_ctx_t *in_msg_ctx = NULL;
    axis2_op_ctx_t *op_ctx = NULL;
    
	trust_context_t *trust_ctx = NULL;
	    
	printf("RST Received\n");
    op_ctx = axis2_msg_ctx_get_op_ctx(msg_ctx, env);
    in_msg_ctx = axis2_op_ctx_get_msg_ctx(op_ctx, env, AXIS2_WSDL_MESSAGE_LABEL_IN);
    
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sts] create data..!");

	trust_ctx = trust_context_create(env);/*Trust Version is passed */
	

	/*Populating RST*/
	if(AXIS2_FAILURE == trust_context_process_rst(trust_ctx, env, in_msg_ctx))
	{
		printf("RST Processing Failed!\n");
	}
	
    return axis2_saml_issuer_issue(env, trust_ctx);  
}

axiom_node_t * AXIS2_CALL
saml_issuer_on_fault(
        axis2_svc_skeleton_t *svc_skel,
        const axutil_env_t *env,
        axiom_node_t *node)
{
    return NULL;
}

AXIS2_EXPORT int
axis2_get_instance(
    struct axis2_svc_skeleton **inst,
    const axutil_env_t * env)
{
    *inst = axis2_saml_issuer_create(env);
    if (!(*inst))
    {
        return AXIS2_FAILURE;
    }
    return AXIS2_SUCCESS;
}

AXIS2_EXPORT int
axis2_remove_instance(
    axis2_svc_skeleton_t *inst,
    const axutil_env_t *env)
{
    axis2_status_t status = AXIS2_FAILURE;
    if (inst)
    {
        status = AXIS2_SVC_SKELETON_FREE(inst, env);
    }
    return status;
}

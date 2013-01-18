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
 */

#include <rampart_issued.h>
#include <rampart_saml.h>

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_issued_supporting_token_build(rampart_context_t *rampart_context, const axutil_env_t *env, axiom_node_t *sec_node,
                                      axutil_array_list_t *sign_parts)
{
	rp_property_t *token = NULL;
    issued_token_callback_func issued_func = NULL;
    rampart_issued_token_t *issued_token = NULL;
    void *tok_val = NULL;

	token = rampart_context_get_supporting_token(rampart_context, env, RP_PROPERTY_ISSUED_TOKEN);
	if (!token)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][issued] Issued token not specified. ERROR");
        return AXIS2_FAILURE;
	}
	issued_func = rampart_context_get_issued_token_aquire_function(rampart_context, env);

    if (!issued_func)
    {
	    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][issued] Issued token call back function not set. ERROR");
        return AXIS2_FAILURE;
    }
    issued_token = issued_func(env, token, rampart_context);

    if (!issued_token)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][issued] Issued token call back returned NULL. ERROR");
        return AXIS2_FAILURE;
    }
    tok_val = rampart_issued_token_get_token(issued_token, env);
    if (!tok_val)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[rampart][issued] Issued token call back returned NULL token value. ERROR");
        return AXIS2_FAILURE;
    }

    if (rampart_issued_token_get_token_type(issued_token, env) == RP_PROPERTY_SAML_TOKEN)
    {
        rampart_context_add_saml_token(rampart_context, env, tok_val);        
        if (rampart_saml_supporting_token_build(env, rampart_context, sec_node, sign_parts))
        {
            return AXIS2_SUCCESS;
        }
    }
    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][issued] Not supported token type. ERROR");    
	return AXIS2_FAILURE;
}


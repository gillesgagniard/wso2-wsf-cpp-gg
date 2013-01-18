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
#include <trust_context.h>
#

struct trust_context
{
    axis2_char_t *wst_namespace;
    axis2_char_t *soap_namespace;
    
    /*RST Context*/
    trust_rst_t *rst;

    /*RSTR Context*/
    trust_rstr_t *rstr;
    
    
    /*To store the built RST node*/  
    axiom_node_t *rst_node;
    
    /*To store the built RSTR node*/
    axiom_node_t *rstr_node;
    
    /*Extensible - Other Contexts Related to Trust */
    
    
};


AXIS2_EXTERN trust_context_t *AXIS2_CALL
trust_context_create(
    const axutil_env_t * env)
{
    trust_context_t *trust_context = NULL;
    
    trust_context = (trust_context_t *) AXIS2_MALLOC(env->allocator, sizeof(trust_context_t));
   
   	trust_context->wst_namespace = NULL;
	trust_context->soap_namespace = NULL;	
    trust_context->rst = NULL;
    trust_context->rstr = NULL;
    trust_context->rst_node = NULL;
    trust_context->rstr_node = NULL;
    
    return trust_context;
}

/*Free Contexts*/
AXIS2_EXTERN  void AXIS2_CALL
trust_context_free(
	trust_context_t *trust_context,            
    const axutil_env_t * env)
{
    if (trust_context)
    {
		if(trust_context->rst)
			trust_rst_free(trust_context->rst, env);
		if(trust_context->rstr)
			trust_rstr_free(trust_context->rstr, env);

        /*Free Other Contexts*/
        AXIS2_FREE(env->allocator, trust_context);
    }
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_process_rst(
	trust_context_t *trust_context,
    const axutil_env_t * env,    
    axis2_msg_ctx_t * in_msg_ctx)
{       
    axiom_soap_envelope_t *soap_env = NULL;
    axiom_soap_body_t *soap_body = NULL;
    axiom_namespace_t *soap_ns = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axiom_node_t *body_base_node = NULL;
    axiom_element_t *rst_ele = NULL;
    int trust_version = -1;
    
    /* Processing Message Context*/
    soap_env = axis2_msg_ctx_get_soap_envelope(in_msg_ctx, env);
    soap_body = axiom_soap_envelope_get_body(soap_env, env);
    body_base_node = axiom_soap_body_get_base_node(soap_body, env);
    trust_context->rst_node = axiom_node_get_first_child(body_base_node, env); 
    
    /* Processing SOAP Namespace */
    soap_ns = axiom_soap_envelope_get_namespace(soap_env, env);
    trust_context->soap_namespace = axiom_namespace_get_uri(soap_ns, env);
    
        /* Processing WS-Trust namespace*/
    rst_ele = (axiom_element_t *) axiom_node_get_data_element(trust_context->rst_node, env);
    wst_ns = axiom_element_get_namespace(rst_ele, env, trust_context->rst_node);

    trust_context->wst_namespace = axiom_namespace_get_uri(wst_ns, env);

    if(0 == axutil_strcmp(trust_context->wst_namespace, TRUST_WST_XMLNS_05_02))
    {
        trust_version = 1;
    }
    if(0 == axutil_strcmp(trust_context->wst_namespace, TRUST_WST_XMLNS_05_12))
    {
        trust_version = 2;
    }
	
	trust_context->rst = trust_rst_create(env);
    
    if(trust_version != -1)
    {        
		trust_rst_set_wst_ns_uri(trust_context->rst, env, trust_context->wst_namespace);            
		if(AXIS2_SUCCESS == trust_rst_populate_rst(trust_context->rst, env, trust_context->rst_node))
		{
				return AXIS2_SUCCESS;
		}
    }
    
    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Invalid WST Version in RST message or RST node processing failed!");
    return AXIS2_FAILURE; 
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_process_rstr(
		trust_context_t *trust_context,
        const axutil_env_t * env,
        axis2_msg_ctx_t * in_msg_ctx)
{
    axiom_soap_envelope_t *soap_env = NULL;
    axiom_soap_body_t *soap_body = NULL;
    axiom_namespace_t *soap_ns = NULL;
    axiom_namespace_t *wst_ns = NULL;
    axiom_node_t *body_base_node = NULL;
    axiom_element_t *rstr_ele = NULL;
    int trust_version = -1;

    /* Processing Message Context*/
    soap_env = axis2_msg_ctx_get_soap_envelope(in_msg_ctx, env);
    soap_body = axiom_soap_envelope_get_body(soap_env, env);
    body_base_node = axiom_soap_body_get_base_node(soap_body, env);
    trust_context->rstr_node = axiom_node_get_first_child(body_base_node, env); 

    /* Processing SOAP Namespace */
    soap_ns = axiom_soap_envelope_get_namespace(soap_env, env);
    trust_context->soap_namespace = axiom_namespace_get_uri(soap_ns, env);

    rstr_ele = (axiom_element_t *) axiom_node_get_data_element(trust_context->rstr_node, env);
    wst_ns = axiom_element_get_namespace(rstr_ele, env, trust_context->rstr_node);
    trust_context->wst_namespace = axiom_namespace_get_uri(wst_ns, env);

    if(0 == axutil_strcmp(trust_context->wst_namespace, TRUST_WST_XMLNS_05_02))
    {
        trust_version = 1;
    }
    if(0 == axutil_strcmp(trust_context->wst_namespace, TRUST_WST_XMLNS_05_12))
    {
        trust_version = 2;
    }

	trust_context->rstr = trust_rstr_create(env);
    
    if(trust_version != -1)
    {
		trust_rstr_set_wst_ns_uri(trust_context->rstr, env, trust_context->wst_namespace);
		if(AXIS2_SUCCESS == trust_rstr_populate_rstr(trust_context->rstr, env, trust_context->rstr_node))
		{
			return AXIS2_SUCCESS;
		}
    }
    
    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Invalid WST Version in RSTR message");
    return AXIS2_FAILURE; 
}



/*Build RST Node from created RST_CONTEXT */
AXIS2_EXTERN axiom_node_t* AXIS2_CALL
trust_context_build_rst_node(
	trust_context_t *trust_context,
    const axutil_env_t * env)
{
    if(trust_context->rst)
    {        
        trust_context->rst_node = trust_rst_build_rst(trust_context->rst, env, NULL);        
		if(trust_context->rst_node)
		{
			AXIS2_LOG_INFO(env->log, "Node Not NULL");
		}
		else
		{
			AXIS2_LOG_INFO(env->log, "Node -- NULL");
		}

        return trust_context->rst_node;
    }
    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST_OM -> RST node FAILED:RST_OM NULL");
	return NULL;
}
    
/*Build RSTR Node from created RSTR_CONTEXT */
AXIS2_EXTERN axiom_node_t* AXIS2_CALL
trust_context_build_rstr_node(
	trust_context_t *trust_context,
    const axutil_env_t * env)
{
    if(trust_context->rstr)
    {
        trust_context->rstr_node = trust_rstr_build_rstr(trust_context->rstr, env, NULL);
        return trust_context->rstr_node;
    }
    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RSTR_OM -> RSTR node FAILED:RSTR_OM NULL");
	return NULL;

}
    
    
/*Get Populated RST_CONTEXT */
AXIS2_EXTERN trust_rst_t* AXIS2_CALL
trust_context_get_rst(
	trust_context_t *trust_context,
    const axutil_env_t * env)
{
    if(trust_context)
        return trust_context->rst;
    return NULL;
}
    
/*Get Populated RSTR_CONTEXT */
AXIS2_EXTERN trust_rstr_t* AXIS2_CALL
trust_context_get_rstr(
	trust_context_t *trust_context,
    const axutil_env_t * env)
{
    if(trust_context)
    {
        return trust_context->rstr;
    }
    return NULL;
}
    
/*Set RST_CONTEXT */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_set_rst(
	trust_context_t *trust_context,
    const axutil_env_t * env,    
    trust_rst_t *rst)
{
    if(trust_context)
    {
        trust_context->rst = rst;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;

}
    
/*Set RSTR_CONTEXT */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_context_set_rstr(
	trust_context_t *trust_context,
    const axutil_env_t * env,
    trust_rstr_t *rstr)
{
    if(trust_context)
    {
        trust_context->rstr = rstr;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;
}








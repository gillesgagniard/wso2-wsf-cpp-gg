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

#include <oxs_saml_token.h>
#include <saml.h>
#include <oxs_axiom.h>

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_saml_token_build_key_identifier_reference_local(const axutil_env_t *env, 
                                             axiom_node_t *parent, 
                                             axiom_node_t *assertion)
{
    axiom_node_t *key_id = NULL, *stre = NULL;
    axis2_char_t *id = NULL;  
    axiom_element_t *e = NULL;
    e = axiom_node_get_data_element(assertion, env);
    id = axiom_element_get_attribute_value_by_name(e, env, SAML_ASSERTION_ID);    
    if (!id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
			    "[oxs][saml token] Assertion doesn't contain an id.");         
        return NULL;
    }
    stre = oxs_token_build_security_token_reference_element(env, parent);
    if (!stre)
    {         
        return NULL;
    }
    key_id = oxs_token_build_key_identifier_element(env, stre, NULL, 
                                        OXS_ST_KEY_ID_VALUE_TYPE, id);
    return stre;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_saml_token_build_key_identifier_reference_remote(const axutil_env_t *env, 
                                             axiom_node_t *parent, 
                                             axiom_node_t *assertion, 
                                             axiom_node_t *auth_bind)
{
    axiom_node_t *key_id = NULL, *stre = NULL;
    axis2_char_t *id = NULL;
    axiom_element_t *e = NULL;
    e = axiom_node_get_data_element(assertion, env);
    id = axiom_element_get_attribute_value_by_name(e, env, SAML_ASSERTION_ID);
    if (!id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
			    "[oxs][saml token] Assertion doesn't contain an id.");         
        return NULL;
    }
    stre = oxs_token_build_security_token_reference_element(env, parent);
    if (!stre)
    { 
        return NULL;
    }
    key_id = oxs_token_build_key_identifier_element(env, parent, NULL, 
                                        OXS_ST_KEY_ID_VALUE_TYPE, id);       
    if (!key_id)
    {
        return NULL;
    }
    /* Add the autherity bindng element to the key identifier */
    axiom_node_add_child(stre, env, auth_bind);
    return stre;    
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_saml_token_build_embeded_reference(const axutil_env_t *env, 
                                             axiom_node_t *parent, 
                                             axiom_node_t *assertion)
{
    axiom_node_t *embeded = NULL, *stre = NULL;    
    if (!assertion)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
			    "[oxs][saml token] Assertion To OM failed.");         
        return NULL;
    }
    stre = oxs_token_build_security_token_reference_element(env, parent);
    if (!stre)
    {
        return NULL;
    }
    embeded = oxs_token_build_embedded_element(env, stre, NULL);    
    if (embeded)
    {
        axiom_node_add_child(embeded, env, assertion); 
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
			    "[oxs][saml token] Embeded Token creation failed.");         
    }
    return stre;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_saml_token_get_from_key_identifer_reference(const axutil_env_t *env, 
                                                axiom_node_t *key_id,
                                                axiom_node_t *scope)
{
    axis2_char_t *value_type = NULL, *id = NULL;
    axiom_element_t *key_id_e = NULL; 
    axiom_node_t *assertion = NULL;

    key_id_e = axiom_node_get_data_element(key_id, env);
    value_type = axiom_element_get_attribute_value_by_name(key_id_e, env, 
		OXS_ATTR_VALUE_TYPE);
    if (!value_type || axutil_strcmp(OXS_ST_KEY_ID_VALUE_TYPE, value_type) != 0)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
	    "[oxs][saml token] KeyId reference doesn't contain the ValueType attribute.");    
        return NULL;
    }
    id = axiom_element_get_text(key_id_e, env, key_id);
    if (!id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
	    "[oxs][saml token] ID reference doesn't contain a value.");    
        return NULL;
    }
    if (!scope)
    {
        assertion = oxs_axiom_get_first_node_by_name_and_attr_val_from_xml_doc(env, key_id, 
		    SAML_ASSERTION, SAML_NMSP_URI, SAML_ASSERTION_ID, id, NULL);
    }
    else
    {
        assertion = oxs_axiom_get_first_node_by_name_and_attr_val(env, scope, 
		    SAML_ASSERTION, SAML_NMSP_URI, SAML_ASSERTION_ID, id, NULL);
    }
    if (!assertion)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
	        "[oxs][saml token] SAML Token cannot be found.");                
    }
    return assertion;    
}


AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_saml_token_get_from_embeded_reference(const axutil_env_t *env, 
                                                  axiom_node_t *embeded)
{
    axiom_node_t *assertion = NULL;
    axiom_element_t *e = NULL;
    axutil_qname_t *qname = axutil_qname_create(env, SAML_ASSERTION, SAML_NMSP_URI, NULL);
    if (!qname)
    {
        return NULL;
    }
    e = axiom_node_get_data_element(assertion, env);
    axiom_element_get_first_child_with_qname(e, env, qname, embeded, &assertion); 

    if (!assertion)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
	        "[oxs][saml token] SAML Token cannot be found.");    
    }
    return assertion;
}


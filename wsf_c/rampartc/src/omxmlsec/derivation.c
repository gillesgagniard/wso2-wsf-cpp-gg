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

#include <stdio.h>
#include <axis2_util.h>
#include <oxs_derivation.h>
#include <oxs_key.h>
#include <oxs_error.h>
#include <oxs_utility.h>
#include <oxs_asym_ctx.h>
#include <oxs_tokens.h>
#include <openssl_hmac.h>

#if 0
/*Remove this funciton if not in use*/
AXIS2_EXTERN oxs_key_t* AXIS2_CALL
oxs_derivation_get_the_referenced_base_key(const axutil_env_t *env,
    axiom_node_t *dk_token_node,
        axiom_node_t *root_node)
{
    axiom_node_t *str_node = NULL;
    axiom_node_t *ref_node = NULL;
    axiom_node_t *refed_node = NULL;
    axis2_char_t *ref_val = NULL;
    axis2_char_t *id = NULL;

    str_node = oxs_axiom_get_first_child_node_by_name(env, dk_token_node, OXS_NODE_SECURITY_TOKEN_REFRENCE, OXS_WSSE_XMLNS, NULL);
    ref_node = oxs_axiom_get_first_child_node_by_name(env, str_node, OXS_NODE_REFERENCE, OXS_WSSE_XMLNS, NULL);
    if(!ref_node) {return NULL ;}

    ref_val  = oxs_token_get_reference(env, ref_node);
    if(!ref_val) {return NULL ;}
 
    /*Need to remove # sign from the ID*/
    id = axutil_string_substring_starting_at(ref_val, 1);

    /*Search for an element with the val(@Id)=@URI*/
    refed_node =  oxs_axiom_get_node_by_id(env, root_node, OXS_ATTR_ID, id, NULL);
    if(!refed_node){
      oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_INVALID_DATA, "Cannot find the referenced key for the derived key");    
      return NULL;
    }
    
    return NULL;
}
#endif

AXIS2_EXTERN oxs_key_t* AXIS2_CALL
oxs_derivation_extract_derived_key_from_token(
    const axutil_env_t *env,
    axiom_node_t *dk_token_node,
    axiom_node_t *root_node,
    oxs_key_t *session_key)
{
    oxs_key_t *base_key = NULL;
    oxs_key_t *derived_key = NULL;
    axiom_node_t *nonce_node = NULL;
    axiom_node_t *length_node = NULL;
    axiom_node_t *offset_node = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axis2_char_t *nonce = NULL;
    axis2_char_t *id = NULL;
    axiom_element_t *dk_token_element = NULL;
    axis2_char_t *wsc_ns_uri = NULL;
    
    /* Default values */
    int offset = 0;
    int length = 0;


    /* If the session_key is NULL then extract it form the refered EncryptedKey. Otherwise use it */
    if(!session_key)
    {
        /* TODO Lots of work including decrypting the EncryptedKey */
    }
    else
    {
        base_key = session_key;
    }

    dk_token_element =(axiom_element_t *) axiom_node_get_data_element(dk_token_node, env);
    if (dk_token_element)
    {
        axutil_qname_t *node_qname = NULL;
        node_qname = axiom_element_get_qname(dk_token_element, env, dk_token_node);
        if(!node_qname)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart] Cannot get qname from dervied key token.");
            return NULL;
        }

        wsc_ns_uri = axutil_qname_get_uri(node_qname, env);
    }

    if(!wsc_ns_uri)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart] Cannot get namespace from dervied key token.");
        return NULL;
    }


    /* Get offset value */
    offset_node = oxs_axiom_get_first_child_node_by_name(
        env, dk_token_node, OXS_NODE_OFFSET, wsc_ns_uri, NULL);  
    if(offset_node)
    {
        offset = oxs_token_get_offset_value(env, offset_node);
    }
    
    /* Get length value */
    length_node = oxs_axiom_get_first_child_node_by_name(
        env, dk_token_node, OXS_NODE_LENGTH, wsc_ns_uri, NULL);
    if(length_node)
    {
        length = oxs_token_get_length_value(env, length_node);
    }

    /* Get nonce value */
    nonce_node = oxs_axiom_get_first_child_node_by_name(
        env, dk_token_node, OXS_NODE_NONCE, wsc_ns_uri, NULL);
    if(nonce_node)
    {
        nonce = oxs_token_get_nonce_value(env, nonce_node);
    }

    /* Create a new(empty) key as the derived key */
    derived_key = oxs_key_create(env);
    oxs_key_set_offset(derived_key, env, offset);
    oxs_key_set_nonce(derived_key, env, nonce);
    oxs_key_set_length(derived_key, env, length);

    /* Now derive the key using the base_key and other parematers */
    status = oxs_derivation_derive_key(env, base_key, derived_key, AXIS2_FALSE);     
    if(status != AXIS2_SUCCESS)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot derive the key from given element.");
        oxs_key_free(derived_key, env);
        derived_key = NULL;
    }

    /* We need to set the name of the derived key */
    id = oxs_axiom_get_attribute_value_of_node_by_name(
        env, dk_token_node, OXS_ATTR_ID, OXS_WSU_XMLNS); 
    oxs_key_set_name(derived_key, env, id);
    
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
        "[rampart] DK=%s derived from Sk=%s ", id , oxs_key_get_name(base_key, env) );
    return derived_key;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_derivation_build_derived_key_token(
    const axutil_env_t *env,
    oxs_key_t *derived_key,
    axiom_node_t *parent,
    axis2_char_t *stref_uri,
    axis2_char_t *stref_val_type, 
    axis2_char_t *wsc_ns_uri)
{
    axiom_node_t *str_token = NULL;
    axiom_node_t *ref_token = NULL;
    axis2_char_t *uri = NULL;

    uri = axutil_stracat(env, OXS_LOCAL_REFERENCE_PREFIX, stref_uri);
    str_token = oxs_token_build_security_token_reference_element(env, NULL); 
    ref_token = oxs_token_build_reference_element(env, str_token, uri, stref_val_type); 
    AXIS2_FREE(env->allocator, uri);
    return oxs_derivation_build_derived_key_token_with_stre(
        env, derived_key, parent, str_token, wsc_ns_uri); 
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
oxs_derivation_build_derived_key_token_with_stre(const axutil_env_t *env,
    oxs_key_t *derived_key,
    axiom_node_t *parent,    
    axiom_node_t *stre, 
    axis2_char_t *wsc_ns_uri)
{
    axiom_node_t *dk_token = NULL;
    axiom_node_t *nonce_token = NULL;
    axiom_node_t *offset_token = NULL;
    axiom_node_t *length_token = NULL;	
	/*axiom_node_t *label_token = NULL;*/
    
    axis2_char_t *dk_id = NULL;
    axis2_char_t *dk_name = NULL;
    axis2_char_t *nonce = NULL;
	axis2_char_t *label = NULL;
    int offset = -1;
    int length = 0; 

    dk_name = oxs_key_get_name(derived_key, env);
    dk_id = axutil_string_substring_starting_at(dk_name, 1);
	
    dk_token = oxs_token_build_derived_key_token_element(env, parent, dk_id, NULL, wsc_ns_uri);
    axiom_node_add_child(dk_token, env, stre);

    /* Create offset */
    offset = oxs_key_get_offset(derived_key, env);
    if(offset > -1)
    {
        offset_token = oxs_token_build_offset_element(env, dk_token, offset, wsc_ns_uri);
    }

    /* Create length */
    length = oxs_key_get_length(derived_key, env);
    if(length > 0)
    {
        length_token = oxs_token_build_length_element(env, dk_token, length, wsc_ns_uri);
    }
    
    /* Create nonce */
    nonce = oxs_key_get_nonce(derived_key, env);
    if(nonce)
    {
        nonce_token = oxs_token_build_nonce_element(env, dk_token, nonce, wsc_ns_uri);
    }

    /* Create label. Hmm we dont need to send the label. Use the default. */
    label = oxs_key_get_label(derived_key, env);
    /*if(label)
    {
        label_token = oxs_token_build_label_element(env, dk_token, label, wsc_ns_uri);
    }*/
   
    return dk_token; 
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
oxs_derivation_derive_key(
    const axutil_env_t *env,
    oxs_key_t *secret,
    oxs_key_t *derived_key,
    axis2_bool_t build)
{
    axis2_status_t status = AXIS2_FAILURE;

    /* TODO check for derivation algorithm */

	if (build)
	{
		status = openssl_p_sha1(env, secret, NULL, NULL, derived_key);
	}
	else
	{
		status = openssl_p_sha1(env, secret, oxs_key_get_label(derived_key, env), 
            oxs_key_get_nonce(derived_key, env), derived_key);
	}
    return status;
}


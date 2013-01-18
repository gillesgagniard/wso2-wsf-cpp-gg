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
#include <trust_rst.h>
#include <trust_constants.h>


struct trust_rst
{
   
    axis2_char_t *attr_context;
    
    axis2_char_t *token_type;
    
    axis2_char_t *request_type;
    
	axis2_char_t *wsa_action;
    
    axis2_char_t *applies_to_addr;
    
    trust_claims_t *claims;
    
    trust_entropy_t *entropy;       
    
    axis2_bool_t allow_postdating;
    
    axis2_bool_t renewing;
    
    axis2_bool_t attr_allow;
    
    axis2_bool_t attr_ok;
    
    axiom_node_t *renew_target;
    
    axiom_node_t *cancel_target;
    
    axis2_char_t *wst_ns_uri;
    
    trust_life_time_t *life_time;


    

    axis2_char_t *key_type;    
    int key_size;
    axis2_char_t *authentication_type;
    axis2_char_t *signature_algo;
    axis2_char_t *encryption_algo;
    axis2_char_t *canonicalization_algo;
    axis2_char_t *computed_key_algo;
    
    axiom_node_t *desired_encryption;
    axiom_node_t *proof_encryption;
    axiom_node_t *usekey;
    axis2_char_t *usekey_sig_attr;
    axis2_char_t *sign_with;
    axis2_char_t *encrypt_with;
    
    
    
    /*ToDo : Federation - Trust Extensions 
     * - Authorization : AdditionalContext and CommonClaim Dialect
     * - Prefix:auth
    */
    
};

AXIS2_EXTERN trust_rst_t * AXIS2_CALL
trust_rst_create(
    const axutil_env_t *env)
{
    trust_rst_t *rst = NULL;
    rst = (trust_rst_t*)AXIS2_MALLOC(env->allocator, sizeof(trust_rst_t));
    
    if(rst)
    {
        rst->attr_context = NULL;
        rst->token_type = NULL;
        rst->request_type = NULL;
	    rst->wsa_action = NULL;
        rst->applies_to_addr = NULL;
        rst->claims = NULL;
        rst->entropy = NULL;
        rst->key_type = NULL;
        rst->key_size = -1;
        rst->allow_postdating = AXIS2_FALSE;
        rst->renewing = AXIS2_FALSE;
        rst->attr_allow = AXIS2_FALSE;
        rst->attr_ok = AXIS2_FALSE;
        rst->renew_target = NULL;
        rst->cancel_target = NULL;
        rst->wst_ns_uri = NULL;    
        rst->life_time = NULL;
        rst->authentication_type = NULL;
        rst->signature_algo = NULL;
        rst->encryption_algo = NULL;
        rst->canonicalization_algo = NULL;
        rst->computed_key_algo = NULL;
        rst->desired_encryption = NULL;
        rst->proof_encryption = NULL;
        rst->usekey = NULL;
        rst->usekey_sig_attr = NULL;
        rst->sign_with = NULL;
        rst->encrypt_with = NULL;
    }
    
    return rst;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_populate_rst(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axiom_node_t *rst_node)
{    
    axiom_element_t *rst_ele = NULL;
    axutil_qname_t *attr_ctx_qname = NULL;
    axis2_char_t *attr_ctx = NULL;
    
    axiom_node_t *token_type_node = NULL;
    axiom_element_t *token_type_ele = NULL;
    axutil_qname_t *token_type_qname = NULL;
    axis2_char_t *token_type = NULL;
    
    axiom_element_t *req_type_ele = NULL;
    axiom_node_t *req_type_node = NULL;
    axutil_qname_t *req_type_qname = NULL;
    axis2_char_t *req_type = NULL;
    
    axutil_qname_t *applies_to_qname = NULL;        /*AppliesTo*/
    axiom_node_t *applies_to_node = NULL;
    axiom_element_t *applies_to_ele = NULL;
    axutil_qname_t *applies_to_epr_qname = NULL;    /*EPR*/
    axiom_node_t *applies_to_epr_node = NULL;
    axiom_element_t *applies_to_epr_ele = NULL;
    axutil_qname_t *applies_to_addr_qname = NULL;   /*Addr*/
    axiom_node_t *applies_to_addr_node = NULL;  
    axiom_element_t *applies_to_addr_ele = NULL;
    
    trust_claims_t *claims = NULL;
    axiom_node_t *claims_node = NULL;
    axiom_element_t *claims_ele = NULL;
    axutil_qname_t *claims_qname = NULL;
    
    trust_entropy_t *entropy = NULL;
    axiom_node_t *entropy_node = NULL;
    axiom_element_t *entropy_ele = NULL;
    axutil_qname_t *entropy_qname = NULL;
    
    axiom_node_t *lifetime_node = NULL;
    axiom_element_t *lifetime_ele = NULL;
    axutil_qname_t *lifetime_qname = NULL;
    
    axiom_node_t *key_type_node = NULL;
    axiom_element_t *key_type_ele = NULL;
    axutil_qname_t *key_type_qname = NULL;
    axis2_char_t *key_type = NULL;
    
    axiom_node_t *key_size_node = NULL;
    axiom_element_t *key_size_ele = NULL;
    axutil_qname_t *key_size_qname = NULL;
    axis2_char_t *key_size = NULL;
    
    axiom_node_t *authnetication_type_node = NULL;
    axiom_element_t *authnetication_type_ele = NULL;
    axutil_qname_t *authnetication_type_qname = NULL;
    axis2_char_t *authnetication_type = NULL;

    axiom_node_t *signature_algo_node = NULL;
    axiom_element_t *signature_algo_ele = NULL;
    axutil_qname_t *signature_algo_qname = NULL;
    axis2_char_t *signature_algo = NULL;
    
    axiom_node_t *encryption_algo_node = NULL;
    axiom_element_t *encryption_algo_ele = NULL;
    axutil_qname_t *encryption_algo_qname = NULL;
    axis2_char_t *encryption_algo = NULL;
    
    axiom_node_t *canonocalization_algo_node = NULL;
    axiom_element_t *canonocalization_algo_ele = NULL;
    axutil_qname_t *canonocalization_algo_qname = NULL;
    axis2_char_t *canonocalization_algo = NULL;
    
    axiom_node_t *computedkey_algo_node = NULL;
    axiom_element_t *computedkey_algo_ele = NULL;
    axutil_qname_t *computedkey_algo_qname = NULL;
    axis2_char_t *computedkey_algo = NULL;
    
    axiom_node_t *desired_encryption_node = NULL;
    axiom_element_t *desired_encryption_ele = NULL;
    axutil_qname_t *desired_encryption_qname = NULL;
    axiom_node_t *desired_encryption_key_node = NULL;   /*This can be either Key or STR*/
    axiom_element_t *desired_encryption_key_ele = NULL;
    
    axiom_node_t *proof_encryption_node = NULL;
    axiom_element_t *proof_encryption_ele = NULL;
    axutil_qname_t *proof_encryption_qname = NULL;
    axiom_node_t *proof_encryption_key_node = NULL;   /*This can be either Key or STR*/
    axiom_element_t *proof_encryption_key_ele = NULL;
    
    axiom_node_t *use_key_node = NULL;
    axiom_element_t *use_key_ele = NULL;
    axutil_qname_t *use_key_qname = NULL;
    axiom_node_t *usekey_key_node = NULL;   /*This can be either Key or STR*/
    axiom_element_t *usekey_key_ele = NULL;
    
    axiom_node_t *sign_with_node = NULL;
    axiom_element_t *sign_with_ele = NULL;
    axutil_qname_t *sign_with_qname = NULL;
    axis2_char_t *sign_with = NULL;
        
    axiom_node_t *encrypt_with_node = NULL;
    axiom_element_t *encrypt_with_ele = NULL;
    axutil_qname_t *encrypt_with_qname = NULL;
    axis2_char_t *encrypt_with = NULL;
    
    
    if(NULL == rst_node || NULL == rst)
    {
        return AXIS2_FAILURE;
    }
    
    rst_ele = (axiom_element_t*)axiom_node_get_data_element(rst_node, env);
    
    if(NULL == rst_ele)
    {
        return AXIS2_FAILURE;
    }
        
    /*@Context*/
    attr_ctx_qname = axutil_qname_create(env, TRUST_RST_CONTEXT, rst->wst_ns_uri, TRUST_WST);
    if (!attr_ctx_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Context Attribute Qname creation failed.");
        return AXIS2_FAILURE;
    }
    attr_ctx = axiom_element_get_attribute_value(rst_ele, env, attr_ctx_qname);
    if (attr_ctx)
    {
        rst->attr_context = attr_ctx;
    }
	axutil_qname_free(attr_ctx_qname, env);
    
    
    /*TokenType*/
    token_type_qname = axutil_qname_create(env, TRUST_TOKEN_TYPE, rst->wst_ns_uri, TRUST_WST);
    if (!token_type_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] TokenType Qname creation failed.");
        return AXIS2_FAILURE;
    }
    
    token_type_ele = axiom_element_get_first_child_with_qname(rst_ele, env, token_type_qname, rst_node, &token_type_node);
    if (token_type_ele)
    {
        token_type = axiom_element_get_text(token_type_ele, env, token_type_node);
        if(token_type)
        {
            rst->token_type = token_type;
        }        
    }
	axutil_qname_free(token_type_qname, env);
        
    /* RequestType */
    req_type_qname = axutil_qname_create(env, TRUST_REQUEST_TYPE, rst->wst_ns_uri, TRUST_WST);
    if (!req_type_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RequestType Qname creation failed.");
        return AXIS2_FAILURE;
    }
    
    req_type_ele = axiom_element_get_first_child_with_qname(rst_ele, env, req_type_qname, rst_node, &req_type_node);
    if(req_type_ele)
    {
        req_type = axiom_element_get_text(req_type_ele, env, req_type_node);
        if(req_type)
        {
            rst->request_type = req_type;
        }
    }
	axutil_qname_free(req_type_qname, env);
    
    /* AppliesTo */
    applies_to_qname = axutil_qname_create(env, TRUST_APPLIES_TO, TRUST_WSP_XMLNS, TRUST_WSP);
    applies_to_epr_qname = axutil_qname_create(env, TRUST_EPR, TRUST_WSA_XMLNS, TRUST_WSA);
    applies_to_addr_qname = axutil_qname_create(env, TRUST_EPR_ADDRESS, TRUST_WSA_XMLNS, TRUST_WSA);
    if (!applies_to_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Appliesto Qname creation failed.");
        return AXIS2_FAILURE;
    }
    
    applies_to_ele = axiom_element_get_first_child_with_qname(rst_ele, env, applies_to_qname, rst_node, &applies_to_node);
    if(applies_to_ele)
    {  
        applies_to_epr_ele = axiom_element_get_first_child_with_qname(applies_to_ele, env, applies_to_epr_qname, 
                applies_to_node, &applies_to_epr_node);
        
        if(applies_to_epr_ele)
        {
            applies_to_addr_ele = axiom_element_get_first_child_with_qname(applies_to_epr_ele, env, applies_to_addr_qname, 
                applies_to_epr_node, &applies_to_addr_node);
            
            if(applies_to_addr_ele)
            {
                rst->applies_to_addr = axiom_element_get_text(applies_to_addr_ele, env, applies_to_addr_node);
            }
        }
    }
	axutil_qname_free(applies_to_qname, env);
	axutil_qname_free(applies_to_epr_qname, env);
	axutil_qname_free(applies_to_addr_qname, env);
    
    
    /* Claims */
    claims_qname = axutil_qname_create(env, TRUST_CLAIMS, rst->wst_ns_uri, TRUST_WST);
    if (!claims_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Claims Qname creation failed.");
        return AXIS2_FAILURE;
    }
    
    claims_ele = axiom_element_get_first_child_with_qname(rst_ele, env, claims_qname, rst_node, &claims_node);
    if (claims_ele)
    {
		claims = trust_claims_create(env);
        if(AXIS2_SUCCESS == trust_claims_deserialize(claims, env, claims_node))
        {
            rst->claims = claims;
        }
    }
    axutil_qname_free(claims_qname, env);

    /*Entropy */
    entropy_qname = axutil_qname_create(env, TRUST_ENTROPY, rst->wst_ns_uri, TRUST_WST);
    if (!entropy_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Entropy Qname creation failed.");
        return AXIS2_FAILURE;
    }
    entropy_ele = axiom_element_get_first_child_with_qname(rst_ele, env, entropy_qname, rst_node, &entropy_node);
    if(entropy_ele)
    {
        entropy = trust_entropy_create(env);
        trust_entropy_set_ns_uri(entropy, env, rst->wst_ns_uri);
        
        if(AXIS2_SUCCESS == trust_entropy_deserialize(entropy, env, entropy_node))
        {
            rst->entropy = entropy;
        }
    }
	axutil_qname_free(entropy_qname, env);
    
    /*LifeTime*/
    lifetime_qname = axutil_qname_create(env, TRUST_LIFE_TIME, rst->wst_ns_uri, TRUST_WST);
    if(!lifetime_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] LifeTime Qname creation failed.");
        return AXIS2_FAILURE;        
    }
    lifetime_ele = axiom_element_get_first_child_with_qname(rst_ele, env, lifetime_qname, rst_node, &lifetime_node);
    if(lifetime_ele)
    {
        if(AXIS2_SUCCESS == trust_life_time_deserialize(rst->life_time, env, lifetime_node))
        {
            rst->life_time = NULL;
        }
    }
	axutil_qname_free(lifetime_qname, env);
 
    /*Key and Encryption Requirements*/
    
    /* KeyType */
    key_type_qname = axutil_qname_create(env, TRUST_KEY_TYPE, rst->wst_ns_uri, TRUST_WST);
    if(!key_type_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] KeyType Qname creation failed.");
        return AXIS2_FAILURE;        
    }
    key_type_ele = axiom_element_get_first_child_with_qname(rst_ele, env, key_type_qname, rst_node, &key_type_node);
    if(key_type_ele)
    {
        key_type = axiom_element_get_text(key_type_ele, env, key_type_node);
        if(key_type)
        {
            rst->key_type = key_type;
        }
    }
	axutil_qname_free(key_type_qname, env);
    
    
    /* KeySize */
    key_size_qname = axutil_qname_create(env, TRUST_KEY_SIZE, rst->wst_ns_uri, TRUST_WST);
    key_size_ele = axiom_element_get_first_child_with_qname(rst_ele, env, key_size_qname, rst_node, &key_size_node);
    if(key_size_ele)
    {
        key_size = axiom_element_get_text(key_size_ele, env, key_size_node);
        if(key_size)
        {
            rst->key_size = atoi(key_size);
        }
    }
    axutil_qname_free(key_size_qname, env);

    /*AuthenticationType*/
    authnetication_type_qname = axutil_qname_create(env, TRUST_AUTHENTICATION_TYPE, rst->wst_ns_uri, TRUST_WST); 
    authnetication_type_ele = axiom_element_get_first_child_with_qname(rst_ele, env, authnetication_type_qname, rst_node, &authnetication_type_node);
    if(authnetication_type_ele)
    {
        authnetication_type = axiom_element_get_text(authnetication_type_ele, env, authnetication_type_node);    
        if(authnetication_type)
        {
            rst->authentication_type = authnetication_type;
        }
    }
	axutil_qname_free(authnetication_type_qname, env);
    
    /*SignatureAlgorithm*/
    signature_algo_qname = axutil_qname_create(env, TRUST_SIGNATURE_ALGO, rst->wst_ns_uri, TRUST_WST); 
    signature_algo_ele = axiom_element_get_first_child_with_qname(rst_ele, env, signature_algo_qname, rst_node, &signature_algo_node);
    if(signature_algo_ele)
    {
        signature_algo = axiom_element_get_text(signature_algo_ele, env, signature_algo_node);    
        if(signature_algo)
        {
            rst->signature_algo = signature_algo;
        }
    }
	axutil_qname_free(signature_algo_qname, env);
    
    /*EncryptionAlgorithm*/
    encryption_algo_qname = axutil_qname_create(env, TRUST_ENCRYPTION_ALGO, rst->wst_ns_uri, TRUST_WST); 
    encryption_algo_ele = axiom_element_get_first_child_with_qname(rst_ele, env, encryption_algo_qname, rst_node, &encryption_algo_node);
    if(encryption_algo_ele)
    {
        encryption_algo = axiom_element_get_text(encryption_algo_ele, env, encryption_algo_node);    
        if(encryption_algo)
        {
            rst->encryption_algo = encryption_algo;
        }
    }
	axutil_qname_free(encryption_algo_qname, env);
    
    /*CanonicalizationAlgorithm*/
    canonocalization_algo_qname = axutil_qname_create(env, TRUST_CANONICAL_ALGO, rst->wst_ns_uri, TRUST_WST); 
    canonocalization_algo_ele = axiom_element_get_first_child_with_qname(rst_ele, env, canonocalization_algo_qname, rst_node, &canonocalization_algo_node);
    if(canonocalization_algo_ele)
    {
        canonocalization_algo = axiom_element_get_text(canonocalization_algo_ele, env, canonocalization_algo_node);    
        if(canonocalization_algo)
        {
            rst->canonicalization_algo = canonocalization_algo;
        }
    }
	axutil_qname_free(canonocalization_algo_qname, env);

    /*ComputedKeyAlgorithm*/
    computedkey_algo_qname = axutil_qname_create(env, TRUST_COMPUTED_KEY_ALGO, rst->wst_ns_uri, TRUST_WST); 
    computedkey_algo_ele = axiom_element_get_first_child_with_qname(rst_ele, env, computedkey_algo_qname, rst_node, &computedkey_algo_node);
    if(computedkey_algo_ele)
    {
        computedkey_algo = axiom_element_get_text(computedkey_algo_ele, env, computedkey_algo_node);    
        if(computedkey_algo)
        {
            rst->computed_key_algo = computedkey_algo;
        }
    }
	axutil_qname_free(computedkey_algo_qname, env);
    
    
    /*(Desired)Encryption */
    desired_encryption_qname = axutil_qname_create(env, TRUST_DESIRED_ENCRYPTION, rst->wst_ns_uri, TRUST_WST);
    if (!desired_encryption_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Encryption Qname creation failed.");
        return AXIS2_FAILURE;
    }
    desired_encryption_ele = axiom_element_get_first_child_with_qname(rst_ele, env, desired_encryption_qname, rst_node, &desired_encryption_node);
    if(desired_encryption_ele)
    {                
        desired_encryption_key_ele = axiom_element_get_first_element(desired_encryption_ele, env, desired_encryption_node, &desired_encryption_key_node);
        rst->desired_encryption = desired_encryption_key_node;      
    }
	axutil_qname_free(desired_encryption_qname, env);
    
    /*ProofEncryption*/
    proof_encryption_qname = axutil_qname_create(env, TRUST_PROOF_ENCRYPTION, rst->wst_ns_uri, TRUST_WST);
    if (!proof_encryption_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] ProofEncryption Qname creation failed.");
        return AXIS2_FAILURE;
    }
    proof_encryption_ele = axiom_element_get_first_child_with_qname(rst_ele, env, proof_encryption_qname, rst_node, &proof_encryption_node);
    if(proof_encryption_ele)
    {                
        proof_encryption_key_ele = axiom_element_get_first_element(proof_encryption_ele, env, proof_encryption_node, &proof_encryption_key_node);
        rst->proof_encryption = proof_encryption_key_node;             
        
    }
	axutil_qname_free(proof_encryption_qname, env);
    
    /*UseKey*/
    use_key_qname = axutil_qname_create(env, TRUST_USE_KEY, rst->wst_ns_uri, TRUST_WST);
    if(!use_key_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] UseKey Qname creation failed.");
        return AXIS2_FAILURE;   
        
    }
    use_key_ele = axiom_element_get_first_child_with_qname(rst_ele, env, use_key_qname, rst_node, &use_key_node);
    if(use_key_ele)
    {
        usekey_key_ele = axiom_element_get_first_element(use_key_ele, env, use_key_node, &usekey_key_node);
        rst->usekey = usekey_key_node;
    }
	axutil_qname_free(use_key_qname, env);
    
    /*SignWith*/
    sign_with_qname = axutil_qname_create(env, TRUST_SIGN_WITH, rst->wst_ns_uri, TRUST_WST); 
    sign_with_ele = axiom_element_get_first_child_with_qname(rst_ele, env, sign_with_qname, rst_node, &sign_with_node);
    if(sign_with_ele)
    {
        sign_with = axiom_element_get_text(sign_with_ele, env, sign_with_node);    
        if(sign_with)
        {
            rst->sign_with = sign_with;
        }
    }
	axutil_qname_free(sign_with_qname, env);
    
    /*EncryptWith*/
    encrypt_with_qname = axutil_qname_create(env, TRUST_ENCRYPT_WITH, rst->wst_ns_uri, TRUST_WST); 
    if(!encrypt_with_qname)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] EncryptWith Qname creation failed.");
        return AXIS2_FAILURE;        
    }
    encrypt_with_ele = axiom_element_get_first_child_with_qname(rst_ele, env, encrypt_with_qname, rst_node, &encrypt_with_node);
    if(encrypt_with_ele)
    {
        encrypt_with = axiom_element_get_text(encrypt_with_ele, env, encrypt_with_node);    
        if(encrypt_with)
        {
            rst->encrypt_with = encrypt_with;
        }
    }
	axutil_qname_free(encrypt_with_qname, env);
        
    return AXIS2_SUCCESS;
}



AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_rst_build_rst(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axiom_node_t *parent)
{
    axiom_node_t *rst_node = NULL;    
    axis2_char_t *key_size = NULL;
    
    rst_node = (axiom_node_t*)trust_util_create_rst_element(env, rst->wst_ns_uri, rst->attr_context);
    
    if(rst_node)
    {
        if(rst->token_type || rst->applies_to_addr)
        {
            if(rst->token_type)
            {
                if(NULL == (axiom_node_t*)trust_util_create_token_type_element(env, rst->wst_ns_uri, rst_node, rst->token_type))
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] TokenType element creation failed.");
                    return NULL;
                }                
            }
            
            if(rst->applies_to_addr)
            {
                /*AppliesTo in WSP - No Need to pass the trust version*/
                if(NULL == (axiom_node_t*)trust_util_create_applies_to_element(env, rst_node, rst->applies_to_addr, TRUST_WSA_XMLNS))
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] AppliesTo element creation failed.");
                    return NULL;
                }
            }
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] You must at least give token type or applies to address.");
            return NULL;
        }

        if(rst->request_type)
        {
            if(NULL == (axiom_node_t*)trust_util_create_request_type_element(env, rst->wst_ns_uri, rst_node, rst->request_type))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RequestType element creation failed.");
                return NULL;
            }
        }
        
        if(rst->claims)
        {
            if(NULL == trust_claims_serialize(rst->claims, env, rst_node))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Claims element creation failed.");
                return NULL;
            }
        }
        
        if(rst->entropy)
        {
            if(NULL == trust_entropy_serialize(rst->entropy, env, rst_node))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Entropy element creation failed.");
                return NULL;
            }
        }
        
        if(rst->life_time)
        {
            if(NULL == trust_life_time_serialize(rst->life_time, env, rst_node))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] LifeTime element creation failed.");
                return NULL;
            }
        }
        
        if(rst->key_type)
        {
            if(NULL == (axiom_node_t*)trust_util_create_key_type_element(env, rst->wst_ns_uri, rst_node, rst->key_type))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] KeyType element creation failed.");
                return NULL;                
            }
        }
        
        if(rst->key_size > 0)
        {
            /*INFO -keysize Malloc Size = 128 */
            key_size = AXIS2_MALLOC( env->allocator, sizeof(char)*128);
            sprintf(key_size, "%d", rst->key_size);
            if(NULL == (axiom_node_t*)trust_util_create_key_size_element(env, rst->wst_ns_uri, rst_node, key_size))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] KeySize element creation failed.");
                return NULL; 
            }
        }
        
        if(rst->authentication_type)
        {
            if(NULL == (axiom_node_t*)trust_util_create_authentication_type_element(env, rst->wst_ns_uri, rst_node, rst->authentication_type))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] AuthenticationType element creation failed.");
                return NULL;                
            }            
        }
        
        if(rst->signature_algo)
        {
            if(NULL == (axiom_node_t*)trust_util_create_signature_algo_element(env, rst->wst_ns_uri, rst_node, rst->signature_algo))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] SignatureAlgo element creation failed.");
                return NULL;                
            }            
        }
        
        if(rst->encryption_algo)
        {
            if(NULL == (axiom_node_t*)trust_util_create_encryption_algo_element(env, rst->wst_ns_uri, rst_node, rst->encryption_algo))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] EncryptionAlgo element creation failed.");
                return NULL;                
            }            
        }
        
        if(rst->canonicalization_algo)
        {
            if(NULL == (axiom_node_t*)trust_util_create_canonicalization_algo_element(env, rst->wst_ns_uri, rst_node, rst->canonicalization_algo))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] CanonicalizationAlgo element creation failed.");
                return NULL;                
            }            
        }
        
        if(rst->computed_key_algo)
        {
            if(NULL == (axiom_node_t*)trust_util_create_computedkey_algo_element(env, rst->wst_ns_uri, rst_node, rst->computed_key_algo))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] ComputedKeyAlgo element creation failed.");
                return NULL;                
            }            
        }
        
        if(rst->desired_encryption)
        {
            if(NULL == (axiom_node_t*)trust_util_create_desired_encryption_element(env, rst->wst_ns_uri, rst_node, rst->desired_encryption))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] DesiredEncryption element creation failed.");
                return NULL;                
            }            
        }
        
        if(rst->proof_encryption)
        {
            if(NULL == (axiom_node_t*)trust_util_create_proof_encryption_element(env, rst->wst_ns_uri, rst_node, rst->proof_encryption))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] ProofEncryption element creation failed.");
                return NULL;                
            }            
        }
        
        if(rst->usekey)
        {
            if(NULL == (axiom_node_t*)trust_util_create_usekey_element(env, rst->wst_ns_uri, rst_node, rst->usekey))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] UseKey element creation failed.");
                return NULL;                
            }            
        }
        
        if(rst->sign_with)
        {
            if(NULL == (axiom_node_t*)trust_util_create_signwith_element(env, rst->wst_ns_uri, rst_node, rst->sign_with))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] SignWith element creation failed.");
                return NULL;                
            }            
        }
        
        if(rst->encrypt_with)
        {
            if(NULL == (axiom_node_t*)trust_util_create_encryptwith_element(env, rst->wst_ns_uri, rst_node, rst->encrypt_with))
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] EncryptWith element creation failed.");
                return NULL;                
            }            
        }
    
        
        return rst_node;
    }
    
    return NULL;
}


AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_rst_build_rst_with_issued_token_assertion(
		trust_rst_t *rst,
		const axutil_env_t *env,
		rp_issued_token_t *issued_token)
{
	axiom_node_t *rst_node = NULL;
	axiom_node_t *rst_template_node = NULL;
	axiom_element_t * rst_template_element = NULL;
	axiom_children_iterator_t *rst_template_children_iter = NULL;
	axiom_node_t *rst_template_child = NULL;


	/*Attr Context is NULL -?*/
	rst_node = (axiom_node_t*)trust_util_create_rst_element(env, rst->wst_ns_uri, rst->attr_context);
	rst_template_node = rp_issued_token_get_requested_sec_token_template(issued_token, env);
	rst_template_node = axiom_node_detach(rst_template_node, env);	/*Detaching RSTTemplate from the original location- FIX - Detaching problem with NS'*/
	rst_template_element = axiom_node_get_data_element(rst_template_node, env);

	rst_template_children_iter = axiom_element_get_children(rst_template_element, env, rst_template_node);


	while(axiom_children_iterator_has_next(rst_template_children_iter, env))
	{
		rst_template_child = axiom_children_iterator_next(rst_template_children_iter, env);
		if(rst_template_node)
			axiom_node_add_child(rst_node, env, rst_template_child);
	}

	if(rst_node)
		return rst_node;
	

	return NULL;
}


 
AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_attr_context(
        trust_rst_t *rst,
        const axutil_env_t *env)
{
    return rst->attr_context;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_attr_context(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *attr_context)
{
    if(attr_context)
    {
        rst->attr_context = attr_context;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_token_type(
        trust_rst_t *rst,
        const axutil_env_t *env)
{
    return rst->token_type;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_token_type(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *token_type)
{
    if(token_type)
    {
        rst->token_type = token_type;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_request_type(
        trust_rst_t *rst,
        const axutil_env_t *env)
{
    return rst->request_type;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_request_type(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *request_type)
{
    if(request_type)
    {
        rst->request_type = request_type;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}


AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_wsa_action(                
		trust_rst_t *rst,
		const axutil_env_t *env)
{
	return rst->wsa_action;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_wsa_action(
		trust_rst_t *rst,
		const axutil_env_t *env,
		axis2_char_t *wsa_action)
{
	if(wsa_action)
	{
		rst->wsa_action = wsa_action;
		return AXIS2_SUCCESS;
	}
	return AXIS2_FAILURE;
}


AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_applies_to_addr(
        trust_rst_t *rst,
        const axutil_env_t *env)
{
    return rst->applies_to_addr;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_appliesto(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *applies_to_addr)
{
    if(applies_to_addr)
    {
        rst->applies_to_addr = applies_to_addr;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}
        
AXIS2_EXTERN trust_claims_t * AXIS2_CALL
trust_rst_get_claims(
        trust_rst_t *rst,
        const axutil_env_t *env)
{
    return rst->claims;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_claims(
        trust_rst_t *rst,
        const axutil_env_t *env,
        trust_claims_t *claims)
{
    if(claims)
    {
        rst->claims = claims;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN trust_entropy_t * AXIS2_CALL
trust_rst_get_entropy(
        trust_rst_t *rst,
        const axutil_env_t *env)
{
    return rst->entropy;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_entropy(
        trust_rst_t *rst,
        const axutil_env_t *env,
        trust_entropy_t *entropy)
{
    if(entropy)
    {
        rst->entropy = entropy;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN  trust_life_time_t * AXIS2_CALL
trust_rst_get_life_time(
        trust_rst_t *rst,
        const axutil_env_t *env)
{
    return rst->life_time;            
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_life_time(
        trust_rst_t *rst,
        const axutil_env_t *env,
        trust_life_time_t *life_time)
{
    if(life_time)
    {
        rst->life_time = life_time;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_key_type(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *key_type)
{
    if(key_type)
    {
        rst->key_type = key_type;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;
}
    
AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_key_type(
    trust_rst_t *rst,
    const axutil_env_t *env)
{
    return rst->key_type;
}
    
      
AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_key_size(
    trust_rst_t *rst,
    const axutil_env_t *env,
    int key_size)
{
    if(key_size > 0)
    {
        rst->key_size = key_size;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;
}
    
AXIS2_EXTERN int AXIS2_CALL
trust_rst_get_key_size(
    trust_rst_t *rst,
    const axutil_env_t *env)
{
    return rst->key_size;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
    trust_rst_set_authentication_type(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *authentication_type)
{
    if(authentication_type)
    {
        rst->authentication_type = authentication_type;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;    
}
    
AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    trust_rst_get_authentication_type(
        trust_rst_t *rst,
        const axutil_env_t *env)
{
    return rst->authentication_type;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_signature_algorithm(
    trust_rst_t *rst,
    const axutil_env_t *env,
    axis2_char_t *signature_algorithm)
{
    if(signature_algorithm)
    {
        rst->signature_algo = signature_algorithm;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;    
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_signature_algorithm(
    trust_rst_t *rst,
    const axutil_env_t *env)
{
    return rst->signature_algo; 
}

    
AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_encryption_algorithm(
    trust_rst_t *rst,
    const axutil_env_t *env,
    axis2_char_t *encryption_algorithm)
{
    if(encryption_algorithm)
    {
        rst->encryption_algo = encryption_algorithm;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;      
}
    
AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_encryption_algorithm(
    trust_rst_t *rst,
    const axutil_env_t *env)
{
    return rst->encryption_algo;
}

    
AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_canonicalization_algorithm(
    trust_rst_t *rst,
    const axutil_env_t *env,
    axis2_char_t *canonicalization_algorithm)
{
    if(canonicalization_algorithm)
    {
        rst->canonicalization_algo = canonicalization_algorithm;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;     
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_canonicalization_algorithm(
    trust_rst_t *rst,
    const axutil_env_t *env)
{
    return rst->canonicalization_algo;
}

    
AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_computedkey_algorithm(
    trust_rst_t *rst,
    const axutil_env_t *env,
    axis2_char_t *computedkey_algorithm)
{
    if(computedkey_algorithm)
    {
        rst->computed_key_algo = computedkey_algorithm;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;   
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_computedkey_algorithm(
    trust_rst_t *rst,
    const axutil_env_t *env)
{
    return rst->computed_key_algo;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_desired_encryption(
    trust_rst_t *rst,
    const axutil_env_t *env,
    axiom_node_t *desired_encryption_key)
{
    if(desired_encryption_key)
    {
        rst->desired_encryption = desired_encryption_key;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;   
}



AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_rst_get_desired_encryption(
    trust_rst_t *rst,
    const axutil_env_t *env)
{
    return rst->desired_encryption;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_proof_encryption(
    trust_rst_t *rst,
    const axutil_env_t *env,
    axiom_node_t *proof_encryption_key)
{
    if(proof_encryption_key)
    {
        rst->proof_encryption = proof_encryption_key;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_rst_get_proof_encryption(
    trust_rst_t *rst,
    const axutil_env_t *env)
{
    return rst->proof_encryption;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_usekey(
    trust_rst_t *rst,
    const axutil_env_t *env,
    axiom_node_t *usekey_key)
{
    if(usekey_key)
    {
        rst->usekey = usekey_key;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axiom_node_t * AXIS2_CALL
trust_rst_get_usekey(
    trust_rst_t *rst,
    const axutil_env_t *env)
{
    return rst->usekey;
}
/*FIX Usekey attr @Sig*/


AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_signwith(
    trust_rst_t *rst,
    const axutil_env_t *env,
    axis2_char_t *signwith)
{
    if(signwith)
    {
        rst->sign_with = signwith;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_signwith(
    trust_rst_t *rst,
    const axutil_env_t *env)
{
    return rst->sign_with;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_encryptwith(
    trust_rst_t *rst,
    const axutil_env_t *env,
    axis2_char_t *encryptwith)
{
    if(encryptwith)
    {
        rst->encrypt_with = encryptwith;
        return AXIS2_SUCCESS;
    }
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_encryptwith(
    trust_rst_t *rst,
    const axutil_env_t *env)
{
    return rst->encrypt_with;
}

AXIS2_EXTERN axis2_char_t * AXIS2_CALL
trust_rst_get_wst_ns_uri(
        trust_rst_t *rst,
        const axutil_env_t *env)
{
    return rst->wst_ns_uri;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_rst_set_wst_ns_uri(
        trust_rst_t *rst,
        const axutil_env_t *env,
        axis2_char_t *wst_ns_uri)
{
    if(wst_ns_uri)
    {
        rst->wst_ns_uri = wst_ns_uri;
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FAILURE;
}


AXIS2_EXTERN void AXIS2_CALL
trust_rst_free(
        trust_rst_t *rst,
        const axutil_env_t *env)
{
    AXIS2_FREE(env->allocator, rst);
}




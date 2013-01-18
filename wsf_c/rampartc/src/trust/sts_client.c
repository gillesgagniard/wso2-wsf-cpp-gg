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

#include <trust_sts_client.h>
#include <axis2_op_client.h>
#include <openssl_hmac.h>
#include <oxs_utility.h>
#include <axiom_util.h>

static void
trust_sts_client_insert_entropy(
    trust_sts_client_t *sts_client, 
    const axutil_env_t *env, 
    trust_rst_t *rst);

static oxs_buffer_t*
trust_sts_client_compute_key(
     trust_sts_client_t *sts_client, 
     const axutil_env_t *env, 
     trust_rst_t *rst,
     trust_rstr_t *rstr);

struct trust_sts_client
{

    /* Algorithm Suite for Entropy */
    rp_algorithmsuite_t *algo_suite;

    /* Trust 1.0 Assertions */
    rp_trust10_t *trust10;

    /* Issuer Address */
    axis2_char_t *issuer_address;

    /* STS Client Home Directory */
    axis2_char_t *home_dir;

    /* Location of the issuer's policy file */
    axis2_char_t *issuer_policy_location;

    /* Location of the service's (relying party's) policy file */
    axis2_char_t *service_policy_location;

	/*SVC Client Reference*/
	axis2_svc_client_t *svc_client;

	/*SENT RST - Most Recent*/
	axiom_node_t *sent_rst_node;

	/*RECEIVED RSTR - Most Recent*/
	axiom_node_t *received_rstr_node;

	/*RECEIVED In_msg_ctx*/
	axis2_msg_ctx_t *received_in_msg_ctx;

	rp_secpolicy_t *sec_policy;


};

AXIS2_EXTERN trust_sts_client_t *AXIS2_CALL
trust_sts_client_create(
    const axutil_env_t * env)
{
    trust_sts_client_t *sts_client = NULL;

    sts_client = (trust_sts_client_t *) AXIS2_MALLOC(env->allocator, sizeof(trust_sts_client_t));

    sts_client->algo_suite = NULL;
    sts_client->trust10 = NULL;
    sts_client->home_dir = NULL;
    sts_client->issuer_address = NULL;
    sts_client->issuer_policy_location = NULL;
    sts_client->service_policy_location = NULL;
	sts_client->svc_client = NULL;
	sts_client->sec_policy = NULL;

    return sts_client;
}

AXIS2_EXTERN void AXIS2_CALL
trust_sts_client_free(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(sts_client->sec_policy)
	{
		rp_secpolicy_free(sts_client->sec_policy, env);
		sts_client->sec_policy = NULL;
	}

	if(sts_client->svc_client)
	{
		axis2_svc_client_free(sts_client->svc_client, env);
		sts_client->svc_client = NULL;
	}

    if (sts_client)
    {
        AXIS2_FREE(env->allocator, sts_client);
    }

}

AXIS2_EXTERN void AXIS2_CALL
trust_sts_client_request_security_token(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    trust_context_t *trust_context)
{
    neethi_policy_t *issuer_policy = NULL;
    neethi_policy_t *service_policy = NULL;
    axis2_status_t status = AXIS2_SUCCESS;
    axiom_node_t *rst_node = NULL;
    axiom_node_t *return_node = NULL;

	axis2_op_client_t* op_client = NULL;
	axis2_msg_ctx_t *in_msg_ctx = NULL;

    
    /*Action Logic*/
    trust_rst_t *rst = NULL;
    axis2_char_t *request_type = NULL;
    axis2_char_t *wsa_action = NULL;
    
    if(sts_client->issuer_policy_location && sts_client->service_policy_location)
    {
        issuer_policy = neethi_util_create_policy_from_file(env, sts_client->issuer_policy_location);
        service_policy = neethi_util_create_policy_from_file(env, sts_client->service_policy_location);
    }
    
    if (!issuer_policy || !service_policy)
    {
        status = AXIS2_FAILURE;
    }
    else
    {
        trust_sts_client_process_policies(sts_client, env, issuer_policy, service_policy);
    }

 
    /*Action Logic - RequestType - used for specify the requesting action*/
    rst = trust_context_get_rst(trust_context, env);
    if(NULL == rst)
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST is NULL: Created RST_CTX may not set to TrustContext");
            return;
    }

    request_type = trust_rst_get_request_type(rst, env);
	wsa_action = trust_rst_get_wsa_action(rst, env);

    if(NULL == request_type)
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST-RequestType is NOT set. RST MUST have a RequestType");
            return;
    }

	if(NULL == wsa_action)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST-WSA-Action is NOT set");
	}

    sts_client->svc_client =
    trust_sts_client_get_svc_client(sts_client, env, wsa_action, NULL, AXIS2_FALSE);
														  

    if (status == AXIS2_SUCCESS)
    {
        status = axis2_svc_client_set_policy(sts_client->svc_client, env, issuer_policy);
        if (status == AXIS2_FAILURE)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Policy setting failed.");
        }
		/*Building the RST */
        rst_node = trust_context_build_rst_node(trust_context, env);
        if(rst_node)
        {
            return_node = axis2_svc_client_send_receive(sts_client->svc_client, env, rst_node);
			sts_client->sent_rst_node = return_node;

			/*Processing Response*/
			if(!return_node)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Return axiom node NULL");
			}
			else
			{
				/*Processing IN_MSG_CONTEXT*/
				op_client = axis2_svc_client_get_op_client(sts_client->svc_client, env);
				if(op_client)
				{
					in_msg_ctx = (axis2_msg_ctx_t *)axis2_op_client_get_msg_ctx (op_client, env, AXIS2_WSDL_MESSAGE_LABEL_IN);
					
					if(in_msg_ctx)
					{
						trust_context_process_rstr(trust_context, env, in_msg_ctx);
						sts_client->received_in_msg_ctx = in_msg_ctx;	/*Store the in_msg_context for sec_header extentions in trust*/
					}
				}

			}
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST-Not send -> RST Node building failed");
            return;
        }
    }

    return;
}

AXIS2_EXTERN axis2_svc_client_t *AXIS2_CALL
trust_sts_client_get_svc_client(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * action, 
    axis2_char_t *address_version, 
    axis2_bool_t is_soap11)
{
    axis2_endpoint_ref_t *endpoint_ref = NULL;
    axis2_options_t *options = NULL;
    axis2_svc_client_t *svc_client = NULL;

    endpoint_ref = axis2_endpoint_ref_create(env, sts_client->issuer_address);

    options = axis2_options_create(env);
    axis2_options_set_to(options, env, endpoint_ref);
    axis2_options_set_action(options, env, action);
    axis2_options_set_xml_parser_reset(options, env, AXIS2_FALSE); 
    if(is_soap11)
    {
        axis2_options_set_soap_action(options, env, axutil_string_create(env, action));
        axis2_options_set_soap_version(options, env, AXIOM_SOAP11);
    }

	if(!(sts_client->svc_client))
	{
		svc_client = axis2_svc_client_create(env, sts_client->home_dir);
		sts_client->svc_client = svc_client;
	}
	else
	{
		svc_client = sts_client->svc_client;
	}

    if (!svc_client)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Stub invoke FAILED: Error code:" " %d :: %s",
                        env->error->error_number, AXIS2_ERROR_GET_MESSAGE(env->error));
        return NULL;
    }

    /* Set service client options */
    axis2_svc_client_set_options(svc_client, env, options);

    /* Engage addressing module and rampart module */
    axis2_svc_client_engage_module(svc_client, env, AXIS2_MODULE_ADDRESSING);
    axis2_svc_client_engage_module(svc_client, env, RAMPART_RAMPART);

    /*set the address version*/
    if(address_version)
    {
        axutil_property_t *property  = NULL;

        property = axutil_property_create(env);
        axutil_property_set_scope(property, env, AXIS2_SCOPE_APPLICATION);
        axutil_property_set_value(property, env, axutil_strdup(env, address_version));
        axis2_options_set_property(options, env, AXIS2_WSA_VERSION, property);
    }

    return svc_client;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_process_policies(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    neethi_policy_t * issuer_policy,
    neethi_policy_t * service_policy)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if (issuer_policy)
    {
        sts_client->algo_suite = trust_policy_util_get_algorithmsuite(env, issuer_policy, &sts_client->sec_policy);
    }

    if (service_policy)
    {
        sts_client->trust10 = trust_policy_util_get_trust10(env, service_policy, &sts_client->sec_policy);
    }

    return AXIS2_SUCCESS;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_issuer_address(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * address)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, address, AXIS2_FAILURE);

    sts_client->issuer_address = address;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_issuer_address(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->issuer_address;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_home_dir(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * directory)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, directory, AXIS2_FAILURE);

    sts_client->home_dir = directory;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_home_dir(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->home_dir;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_issuer_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * file_path)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, file_path, AXIS2_FAILURE);

    sts_client->issuer_policy_location = file_path;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_issuer_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->issuer_policy_location;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
trust_sts_client_set_service_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    axis2_char_t * file_path)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, file_path, AXIS2_FAILURE);

    sts_client->service_policy_location = file_path;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
trust_sts_client_get_service_policy_location(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    return sts_client->service_policy_location;
}

AXIS2_EXTERN oxs_buffer_t* AXIS2_CALL
trust_sts_client_request_security_token_using_policy(
    trust_sts_client_t * sts_client,
    const axutil_env_t * env,
    trust_context_t *trust_context,
    neethi_policy_t *issuer_policy, 
    axis2_char_t *address_version, 
    axis2_bool_t is_soap11, 
    rampart_context_t *rampart_context)
{
    axis2_status_t status = AXIS2_SUCCESS;
    axiom_node_t *rst_node = NULL;
    axiom_node_t *return_node = NULL;
    axis2_op_client_t* op_client = NULL;
	axis2_msg_ctx_t *in_msg_ctx = NULL;

    
    /*Action Logic*/
    trust_rst_t *rst = NULL;
    axis2_char_t *request_type = NULL;
    axis2_char_t *wsa_action = NULL;
    
    trust_sts_client_process_policies(sts_client, env, issuer_policy, issuer_policy);
 
    /*Action Logic - RequestType - used for specify the requesting action*/
    rst = trust_context_get_rst(trust_context, env);
    if(NULL == rst)
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST is NULL: Created RST_CTX may not set to TrustContest");
            return NULL;
    }

    request_type = trust_rst_get_request_type(rst, env);
    wsa_action = trust_rst_get_wsa_action(rst, env);

    if(NULL == request_type)
    {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST-RequestType is NOT set. RST MUST have a RequestType");
            return NULL;
    }

	if(NULL == wsa_action)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST-WSA-Action is NOT set");
	}

    sts_client->svc_client =
    trust_sts_client_get_svc_client(sts_client, env, wsa_action, address_version, is_soap11);														  

    if (sts_client->svc_client)
    {
        /* if rampart context is set, we can set it to svc_client. This will be used by 
         * scripting bindings to specify rampart specific values */
        if(rampart_context)
        {
            axis2_svc_ctx_t *svc_ctx = NULL;
            axis2_conf_ctx_t *conf_ctx = NULL;
            axis2_conf_t *conf = NULL;
            axutil_param_t *security_param = NULL;

            svc_ctx = axis2_svc_client_get_svc_ctx (sts_client->svc_client, env);
            conf_ctx = axis2_svc_ctx_get_conf_ctx (svc_ctx, env);
            conf = axis2_conf_ctx_get_conf (conf_ctx, env);
            security_param = axutil_param_create (
                env, RAMPART_CONFIGURATION, (void *)rampart_context);
            axis2_conf_add_param (conf, env, security_param);
        }

		if(issuer_policy)
		{
			status = axis2_svc_client_set_policy(sts_client->svc_client, env, issuer_policy);
			if (status == AXIS2_FAILURE)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Policy setting failed.");
			}

            /*insert entropy if needed*/
            trust_sts_client_insert_entropy(sts_client, env, rst);
		}

		/*Building the RST */
        rst_node = trust_context_build_rst_node(trust_context, env);
        if(rst_node)
        {
            return_node = axis2_svc_client_send_receive(sts_client->svc_client, env, rst_node);
			sts_client->sent_rst_node = return_node;

			/*Processing Response*/
			if(!return_node)
			{
				AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] Return axiom node NULL");
			}
			else
			{
                /*---- for debug ------*/
                /*axis2_char_t *serialise_node = NULL;
                serialise_node = axiom_node_to_string(return_node, env);
                printf("sct reply is %s\n", serialise_node);*/
                /*---- End for debug ------*/


				/*Processing IN_MSG_CONTEXT*/
				op_client = axis2_svc_client_get_op_client(sts_client->svc_client, env);
				if(op_client)
				{
					in_msg_ctx = (axis2_msg_ctx_t *)axis2_op_client_get_msg_ctx (op_client, env, AXIS2_WSDL_MESSAGE_LABEL_IN);
					
					if(in_msg_ctx)
					{
						trust_context_process_rstr(trust_context, env, in_msg_ctx);
						sts_client->received_in_msg_ctx = in_msg_ctx;	/*Store the in_msg_context for sec_header extentions in trust*/
                        return trust_sts_client_compute_key(sts_client, env, rst, trust_context_get_rstr(trust_context, env));
					}
				}

			}
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] RST-Not send -> RST Node building failed");
            return NULL;
        }
    }

    return NULL;
}

static void
trust_sts_client_insert_entropy(
    trust_sts_client_t *sts_client, 
    const axutil_env_t *env, 
    trust_rst_t *rst)
{
    axis2_char_t *request_type = NULL;
    int key_size = 0;
    axis2_char_t *nonce = NULL;
    trust_entropy_t* entropy = NULL;
    
    request_type = trust_rst_get_request_type(rst, env);

    /*we support entropy for issue only*/
    if(0 != axutil_strcmp(request_type, TRUST_REQ_TYPE_ISSUE))
        return;

    /*if entropy is already give, no need to create*/
    if(trust_rst_get_entropy(rst, env))
        return;

    /*if algorithm suite is missing or trust10 is missing, then we can't proceed*/
    if((!sts_client->algo_suite) || (!sts_client->trust10))
        return;

    /*check whether client entropy is needed. If not can return*/
    if(!rp_trust10_get_require_client_entropy(sts_client->trust10, env))
        return;

    key_size = rp_algorithmsuite_get_max_symmetric_keylength(sts_client->algo_suite, env);
    if (key_size <= 0)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] maximum symmetric key length of issuer algorithm suite is not valid");
        return;
    }

    /*nonce should be created with half the size. size is in bits, have to convert it to bytes*/
    nonce = oxs_util_generate_nonce(env, key_size/16);
    if(!nonce)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[trust] cannon create nonce with length %d", key_size/16);
        return;
    }

    entropy = trust_entropy_create(env);
    trust_entropy_set_binary_secret(entropy, env, nonce);
    trust_entropy_set_ns_uri(entropy, env, trust_rst_get_wst_ns_uri(rst, env));
    trust_entropy_set_binary_secret_type(entropy, env, NONCE);

    trust_rst_set_key_size(rst, env, key_size);
    trust_rst_set_entropy(rst, env, entropy);
    return;
}

static oxs_buffer_t*
trust_sts_client_compute_key(trust_sts_client_t *sts_client, 
                             const axutil_env_t *env, 
                             trust_rst_t *rst,
                             trust_rstr_t *rstr)
{
    trust_entropy_t* requester_entropy = NULL;
    axiom_node_t *proof_token = NULL;
    
    /*if rstr is not valid, then can't proceed*/
    if(!rstr)
        return NULL;

    /*if requester doesn't provide entropy, then no need to compute the key */
    requester_entropy = trust_rst_get_entropy(rst, env);
    if((!requester_entropy) || (!trust_entropy_get_binary_secret(requester_entropy, env)))
        return NULL;

    /*check the proof token whether to compute the token or not*/
    proof_token = trust_rstr_get_requested_proof_token(rstr, env);
    
    /*if issuer doesn't give a proof token/entropy, then requester_entropy is the key*/
    if(!proof_token)
    {
        oxs_buffer_t *buffer = NULL;
        int decoded_len = 0;
        axis2_char_t *decoded_shared_secret = NULL;
        axis2_char_t* shared_secret = NULL;
        
        shared_secret = trust_entropy_get_binary_secret(requester_entropy, env);
        decoded_len = axutil_base64_decode_len(shared_secret);
	    decoded_shared_secret = AXIS2_MALLOC(env->allocator, decoded_len);
	    axutil_base64_decode_binary((unsigned char*)decoded_shared_secret, shared_secret);
        buffer = oxs_buffer_create(env);
        oxs_buffer_populate(buffer, env, (unsigned char*)decoded_shared_secret, decoded_len);
        AXIS2_FREE(env->allocator, decoded_shared_secret);
        return buffer;
    }
    else
    /*proof token is available. We have to check the content of proof token*/
    {
        axis2_char_t *local_name = NULL;
        axis2_char_t *compute_key_algo = NULL;
        trust_entropy_t* issuer_entropy = NULL;
        int key_size = 0;
        axis2_char_t *output = NULL;

        oxs_buffer_t *buffer = NULL;
        int requester_entropy_len = 0;
        axis2_char_t *decoded_requester_entropy = NULL;
        axis2_char_t *requester_nonce = NULL;
        int issuer_entropy_len = 0;
        axis2_char_t *decoded_issuer_entropy = NULL;
        axis2_char_t *issuer_nonce = NULL;
        
        local_name = axiom_util_get_localname(proof_token, env);
        /*if local name is not ComputedKey, then we can return*/
        if(axutil_strcmp(local_name, TRUST_COMPUTED_KEY) != 0)
            return NULL;

        key_size = trust_rst_get_key_size(rst, env)/8;
        if(key_size <= 0)
            return NULL;

        compute_key_algo = oxs_axiom_get_node_content(env, proof_token);

        buffer = oxs_buffer_create(env);
        requester_nonce = trust_entropy_get_binary_secret(requester_entropy, env);
        requester_entropy_len = axutil_base64_decode_len(requester_nonce);
        decoded_requester_entropy = AXIS2_MALLOC(env->allocator, requester_entropy_len);
        axutil_base64_decode_binary((unsigned char*)decoded_requester_entropy, requester_nonce);

        issuer_entropy = trust_rstr_get_entropy(rstr, env);

        /*if issuer doesn't provide entropy, we can take requester entropy as key*/
        if((!requester_entropy) || (!trust_entropy_get_binary_secret(requester_entropy, env)))
        {   
            oxs_buffer_populate(buffer, env, (unsigned char*)decoded_requester_entropy, requester_entropy_len);
            AXIS2_FREE(env->allocator, decoded_requester_entropy);
            return buffer;
        }

        issuer_nonce = trust_entropy_get_binary_secret(issuer_entropy, env);
        issuer_entropy_len = axutil_base64_decode_len(issuer_nonce);
        decoded_issuer_entropy = AXIS2_MALLOC(env->allocator, issuer_entropy_len);
        axutil_base64_decode_binary((unsigned char*)decoded_issuer_entropy, issuer_nonce);
        output = AXIS2_MALLOC(env->allocator, key_size);

        openssl_p_hash(env, (unsigned char*)decoded_requester_entropy, requester_entropy_len,
                            (unsigned char*)decoded_issuer_entropy, issuer_entropy_len, 
                            (unsigned char*)output, key_size);
        oxs_buffer_populate(buffer, env, (unsigned char*)output, key_size);
        return buffer;
    }
}

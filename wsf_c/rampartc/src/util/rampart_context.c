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

#include "oxs_key_mgr.h"
#include <rampart_context.h>
#include <rampart_constants.h>
#include <oxs_axiom.h>
#include <oxs_x509_cert.h>
#include <rampart_replay_detector.h>
#include <rampart_sct_provider.h>
#include <rampart_util.h>
#include <rp_saml_token.h>
#include <rp_issued_token.h>
#include <rampart_saml_token.h>
#include <oxs_key_mgr.h>
#include <axis2_conf_ctx.h>

struct rampart_context_t
{
    /*****************************/
    axiom_node_t *policy_node;   
    axis2_char_t *user;
    axis2_char_t *password;
    axis2_char_t *password_type;
    axis2_char_t *prv_key_password;
    password_callback_fn pwcb_function;
    rampart_is_replayed_fn is_replayed_function;
    int ttl;
    axis2_bool_t need_millisecond_precision;
    int clock_skew_buffer;
    axis2_char_t *rd_val;
    int ref;
    oxs_key_mgr_t *key_mgr;
    /****************************/
    /* Set true when the issued token is aquired and set to the rampart conext*/
    issued_token_callback_func aquire_issued_token; 
	
    /* SAML tokens. */
    axutil_array_list_t *saml_tokens;
    
    /* Custom tokens. */
    axutil_array_list_t *custom_tokens;
    
    /*Rampart specific members*/
    rp_secpolicy_t *secpolicy;
    rampart_callback_t *password_callback_module;
    rampart_authn_provider_t *authn_provider;
    rampart_replay_detector_t *replay_detector;
    rampart_sct_provider_t *sct_provider;
    auth_password_func authenticate_with_password;
    auth_digest_func authenticate_with_digest;

    axis2_char_t *encryption_token_id;
    axis2_char_t *signature_token_id;

    axis2_bool_t require_timestamp;
    axis2_bool_t require_ut;

    axutil_array_list_t *key_list;
    /* This is used in callback functions.
     * Used to store password callback user parameters.
     */
    void *pwcb_user_params;
    
    /* This is used in replay detector functions.
     * Used to store replay detector user parameters.
     */
    void *rd_user_params;
    
    /* Used to store and track whether we found the clients certificate while processing
     * the security headers key info element. found_cert_in_shp is used to track the status.
     */
    axis2_bool_t found_cert_in_shp;
    oxs_x509_cert_t *receiver_cert;   

    /* Security Context token operation related objects */
    store_security_context_token_fn store_sct_funtion;
    obtain_security_context_token_fn obtain_sct_function;
    delete_security_context_token_fn delete_sct_function;
    validate_security_context_token_fn validate_sct_function;
    void *sct_user_params;
};

/*void rampart_context_set_callback_fn(axutil_env_t *env,
                                axis2_char_t *(*callback)(
                                    axutil_env_t  *env, 
                                    axis2_char_t *user ,
                                    void *ctx), void *ctx);
 
*/
/*private functions*/

rp_symmetric_asymmetric_binding_commons_t
*rampart_context_get_symmetric_asymmetric_binding_commons(
    rampart_context_t *rampart_context,
    const axutil_env_t *env);

rp_binding_commons_t *rampart_context_get_binding_commons(
    rampart_context_t *rampart_context,
    const axutil_env_t *env);

axis2_bool_t rampart_context_use_username_token(
    rp_supporting_tokens_t *signed_supporting,
    const axutil_env_t *env);

axis2_bool_t rampart_context_validate_ut(
    rp_username_token_t *username_token,
    const axutil_env_t *env);

rp_supporting_tokens_t
*rampart_context_get_signed_supporting_from_binding(
    rampart_context_t *rampart_context,
    const axutil_env_t *env);

/*
axis2_status_t rampart_context_set_nodes_to_encrypt(
    rp_header_t *header,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_encrypt);
*/

axis2_status_t rampart_context_set_nodes_to_encrypt_or_sign(
    rp_header_t *header,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_encrypt_or_sign);

axis2_status_t rampart_context_set_elements_to_encrypt_or_sign(
    rp_element_t *element,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_encrypt_or_sign);

axis2_status_t AXIS2_CALL
rampart_context_get_nodes_to_protect(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_sign_or_encrypt,
    axis2_bool_t is_sign);

axis2_status_t AXIS2_CALL
rampart_context_get_elements_to_protect(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_sign_or_encrypt,
    axis2_bool_t is_sign);

axis2_char_t *AXIS2_CALL
rampart_context_get_key_identifier_from_wss(
    rampart_context_t *rampart_context,
    const axutil_env_t *env);


AXIS2_EXTERN rampart_context_t *AXIS2_CALL
rampart_context_create(const axutil_env_t *env)
{
    rampart_context_t *rampart_context = NULL;

    AXIS2_ENV_CHECK(env, NULL);

    rampart_context =  (rampart_context_t *) AXIS2_MALLOC (env->allocator,
                       sizeof (rampart_context_t));

    if(rampart_context == NULL)
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_NO_MEMORY, AXIS2_FAILURE);
        return NULL;
    }
    rampart_context->policy_node = NULL;
    
    rampart_context->user = 0;
    rampart_context->password = NULL;
    rampart_context->pwcb_function = NULL;
    rampart_context->is_replayed_function = NULL;
    rampart_context->ttl = 300;
    rampart_context->clock_skew_buffer = 0;
    rampart_context->need_millisecond_precision = AXIS2_TRUE;
    rampart_context->rd_val = NULL;
    rampart_context->password_type = NULL;
    rampart_context->saml_tokens = NULL;
    rampart_context->custom_tokens = NULL;
	rampart_context->aquire_issued_token = NULL;

    rampart_context->secpolicy = NULL;
    rampart_context->password_callback_module = NULL;
    rampart_context->authn_provider = NULL;
	rampart_context->replay_detector = NULL;
    rampart_context->sct_provider = NULL;
    rampart_context->authenticate_with_password = NULL;
    rampart_context->authenticate_with_digest = NULL;
    rampart_context->require_ut = AXIS2_FALSE;
    rampart_context->require_timestamp = AXIS2_FALSE;
    rampart_context->rd_user_params = NULL;
    rampart_context->pwcb_user_params = NULL;
    rampart_context->ref = 0;

    rampart_context->encryption_token_id = NULL;
    rampart_context->signature_token_id = NULL;

    rampart_context->key_list = axutil_array_list_create(env, 2);
    rampart_context->key_mgr = oxs_key_mgr_create(env);
    
    rampart_context->found_cert_in_shp = AXIS2_FALSE;
    rampart_context->receiver_cert = NULL;

    rampart_context->store_sct_funtion = NULL;
    rampart_context->obtain_sct_function = NULL;
    rampart_context->delete_sct_function = NULL;
    rampart_context->validate_sct_function = NULL;
    rampart_context->sct_user_params = NULL;
    
    return rampart_context;
}

AXIS2_EXTERN void AXIS2_CALL
rampart_context_free(rampart_context_t *rampart_context,
                     const axutil_env_t *env)
{
    AXIS2_ENV_CHECK(env, AXIS2_FAILURE);

    if(rampart_context)
    {
        if ((rampart_context->ref) > 0)
        {
            rampart_context->ref--;
            return;
        }

        if(rampart_context->secpolicy)
        {
            rp_secpolicy_free(rampart_context->secpolicy,env);
            rampart_context->secpolicy = NULL;
        }

        if(rampart_context->password_callback_module)
        {
            axutil_param_t *param = NULL;
            param = rampart_context->password_callback_module->param;
			/*User specific free logic*/
            RAMPART_CALLBACK_FREE(rampart_context->password_callback_module , env);
            rampart_context->password_callback_module = NULL;
            if(param){
                /*We actually free the dll_desc, which is set as the value of the axutil parameter.*/
				axutil_param_free(param, env);
                /*axutil_dll_desc_t *dll_desc_l = NULL;
                dll_desc_l = axutil_param_get_value(param, env);
                status = axutil_class_loader_delete_dll(env, dll_desc_l);
                dll_desc_l = NULL;*/
            }
        }

        if(rampart_context->authn_provider)
        {
            axutil_param_t *param = NULL;
            param = rampart_context->authn_provider->param;
			/*User specific free logic*/
            RAMPART_AUTHN_PROVIDER_FREE(rampart_context->authn_provider, env);
            rampart_context->authn_provider = NULL;
            if(param){
                /*We actually free the dll_desc, which is set as the value of the axutil parameter.*/
				axutil_param_free(param, env);
                /*axutil_dll_desc_t *dll_desc_l = NULL;
                dll_desc_l = axutil_param_get_value(param, env);
                status = axutil_class_loader_delete_dll(env, dll_desc_l);
                dll_desc_l = NULL;*/
            }
        }

        if(rampart_context->replay_detector)
        {
            axutil_param_t *param = NULL;
            param = rampart_context->replay_detector->param;
			/*User specific free logic*/
            RAMPART_REPLAY_DETECTOR_FREE(rampart_context->replay_detector, env);
            rampart_context->replay_detector = NULL;
            if(param){
                /*We actually free the dll_desc, which is set as the value of the axutil parameter.*/
				axutil_param_free(param, env);
                /*axutil_dll_desc_t *dll_desc_l = NULL;
                dll_desc_l = axutil_param_get_value(param, env);
                status = axutil_class_loader_delete_dll(env, dll_desc_l);
                dll_desc_l = NULL;*/
            }
        }

        if(rampart_context->sct_provider)
        {
            axutil_param_t *param = NULL;
            param = rampart_context->sct_provider->param;
			/*User specific free logic*/
            RAMPART_SCT_PROVIDER_FREE(rampart_context->sct_provider, env);
            rampart_context->sct_provider = NULL;
            if(param){
                /*We actually free the dll_desc, which is set as the value of the axutil parameter.*/
				axutil_param_free(param, env);
                /*axutil_dll_desc_t *dll_desc_l = NULL;
                dll_desc_l = axutil_param_get_value(param, env);
                status = axutil_class_loader_delete_dll(env, dll_desc_l);
                dll_desc_l = NULL;*/
            }
        }

        /*Free derived key list*/
		if (rampart_context->key_list)
		{
			int i;
			for(i=0 ; i < axutil_array_list_size(rampart_context->key_list, env); i++)
			{
				oxs_key_t* dk = NULL;
				dk = (oxs_key_t*)axutil_array_list_get(rampart_context->key_list, env, i);
				oxs_key_free(dk, env);
			}
			axutil_array_list_free(rampart_context->key_list, env);
			rampart_context->key_list = NULL;
		}

        if(rampart_context->key_list){
            /*Need to free data of the list*/
            int size = 0;
            int j = 0;
            size = axutil_array_list_size(rampart_context->key_list, env);
            for (j = 0; j < size; j++)
            {
                oxs_key_t *key = NULL;

                key = axutil_array_list_get(rampart_context->key_list, env, j);
                oxs_key_free(key , env);
                key = NULL;
            }

            axutil_array_list_free(rampart_context->key_list, env);
            rampart_context->key_list = NULL;
        }

        /*Free custom tokens list*/
        if(rampart_context->custom_tokens){
            /*No need to free the contents*/
            axutil_array_list_free(rampart_context->custom_tokens, env);
            rampart_context->custom_tokens = NULL;
        }
        
        /* Free receiver certificate we found when processing incoming security header */
        if(rampart_context->receiver_cert && rampart_context->found_cert_in_shp)
        {
            oxs_x509_cert_free(rampart_context->receiver_cert, env);
            rampart_context->receiver_cert = NULL;
        }

        if(rampart_context->key_mgr)
        {
            oxs_key_mgr_free(rampart_context->key_mgr, env);
        }

        AXIS2_FREE(env->allocator,rampart_context);
        rampart_context = NULL;
    }
    return;
}


/* Implementations */


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_policy_node(rampart_context_t *rampart_context,
                                const axutil_env_t *env,
                                axiom_node_t *policy_node)
{
    AXIS2_PARAM_CHECK(env->error,policy_node,AXIS2_FAILURE);

    rampart_context->policy_node = policy_node;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_prv_key(rampart_context_t *rampart_context,
                            const axutil_env_t *env,
                            void *prv_key)
{

	AXIS2_PARAM_CHECK(env->error,prv_key,AXIS2_FAILURE);
	if (rampart_context->key_mgr)
	{
		oxs_key_mgr_set_prv_key(rampart_context->key_mgr, env, prv_key);
		return AXIS2_SUCCESS;
	}    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_prv_key_type(rampart_context_t *rampart_context,
                                 const axutil_env_t *env,
                                 axis2_key_type_t type)
{
    AXIS2_PARAM_CHECK(env->error,type,AXIS2_FAILURE);
	if (rampart_context->key_mgr)
	{
		oxs_key_mgr_set_prv_key_type(rampart_context->key_mgr, env, type);
		return AXIS2_SUCCESS;
	}    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_certificate(rampart_context_t *rampart_context,
                                const axutil_env_t *env,
                                void *certificate)
{
    AXIS2_PARAM_CHECK(env->error,certificate,AXIS2_FAILURE);
	if (rampart_context->key_mgr)
	{
		oxs_key_mgr_set_certificate(rampart_context->key_mgr, env, certificate);
		return AXIS2_SUCCESS;
	}    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_certificate_type(rampart_context_t *rampart_context,
                                     const axutil_env_t *env,
                                     axis2_key_type_t type)
{
    AXIS2_PARAM_CHECK(env->error,type,AXIS2_FAILURE);
	if (rampart_context->key_mgr)
	{
		oxs_key_mgr_set_certificate_type(rampart_context->key_mgr, env, type);
		return AXIS2_SUCCESS;
	}    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_receiver_certificate(rampart_context_t *rampart_context,
        const axutil_env_t *env,
        void *receiver_certificate)
{
    AXIS2_PARAM_CHECK(env->error,receiver_certificate,AXIS2_FAILURE);
	if (rampart_context->key_mgr)
	{
		oxs_key_mgr_set_receiver_certificate(rampart_context->key_mgr, env, receiver_certificate);
		return AXIS2_SUCCESS;
	}    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_receiver_certificate_type(rampart_context_t *rampart_context,
        const axutil_env_t *env,
        axis2_key_type_t type)
{
    AXIS2_PARAM_CHECK(env->error,type,AXIS2_FAILURE);
	if (rampart_context->key_mgr)
	{
		oxs_key_mgr_set_receiver_certificate_type(rampart_context->key_mgr, env, type);
		return AXIS2_SUCCESS;
	}    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_user(rampart_context_t *rampart_context,
                         const axutil_env_t *env,
                         axis2_char_t *user)
{

    AXIS2_PARAM_CHECK(env->error,user,AXIS2_FAILURE);

    rampart_context->user = user;
    return AXIS2_SUCCESS;

}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_password(rampart_context_t *rampart_context,
                             const axutil_env_t *env,
                             axis2_char_t *password)
{

    AXIS2_PARAM_CHECK(env->error,password,AXIS2_FAILURE);

    rampart_context->password = password;
    return AXIS2_SUCCESS;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_prv_key_password(rampart_context_t *rampart_context,
                                     const axutil_env_t *env,
                                     axis2_char_t *prv_key_password)
{

    AXIS2_PARAM_CHECK(env->error,prv_key_password,AXIS2_FAILURE);

    if (rampart_context->key_mgr)
	{
		oxs_key_mgr_set_prv_key_password(rampart_context->key_mgr, env, prv_key_password);
		return AXIS2_SUCCESS;
	}  
	return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_pwcb_function(rampart_context_t *rampart_context,
                                  const axutil_env_t *env,
                                  password_callback_fn pwcb_function,
                                  void *user_params)
{
    AXIS2_PARAM_CHECK(env->error,pwcb_function,AXIS2_FAILURE);

    rampart_context->pwcb_function = pwcb_function;
    rampart_context->pwcb_user_params = user_params;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_replay_detect_function(rampart_context_t *rampart_context,
        const axutil_env_t *env,
        rampart_is_replayed_fn is_replayed_function,
        void *user_params)
{
    AXIS2_PARAM_CHECK(env->error, is_replayed_function, AXIS2_FAILURE);
    rampart_context->is_replayed_function = is_replayed_function;
    rampart_context->rd_user_params = user_params;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN void * AXIS2_CALL
rampart_context_get_rd_user_params(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->rd_user_params;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_password_type(rampart_context_t *rampart_context,
                                  const axutil_env_t *env,
                                  axis2_char_t *password_type)
{

    AXIS2_PARAM_CHECK(env->error,password_type,AXIS2_FAILURE);

    rampart_context->password_type = password_type;
    return AXIS2_SUCCESS;

}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_ttl(rampart_context_t *rampart_context,
                        const axutil_env_t *env,
                        int ttl)
{

    AXIS2_PARAM_CHECK(env->error,ttl,AXIS2_FAILURE);

    rampart_context->ttl = ttl;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_get_need_millisecond_precision(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->need_millisecond_precision;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_need_millisecond_precision(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axis2_bool_t need_millisecond_precision)
{
    rampart_context->need_millisecond_precision = need_millisecond_precision;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_clock_skew_buffer(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    int skew_buffer)
{
    rampart_context->clock_skew_buffer = skew_buffer;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_context_get_clock_skew_buffer(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->clock_skew_buffer;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_rd_val(rampart_context_t *rampart_context,
                           const axutil_env_t *env,
                           axis2_char_t *rd_val)
{

    AXIS2_PARAM_CHECK(env->error, rd_val, AXIS2_FAILURE);

    rampart_context->rd_val = rd_val;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_private_key_file(rampart_context_t *rampart_context,
                                     const axutil_env_t *env,
                                     axis2_char_t *private_key_file)
{

    if (rampart_context->key_mgr)
	{
		oxs_key_mgr_set_private_key_file(rampart_context->key_mgr, env, private_key_file);
		return AXIS2_SUCCESS;
	}    
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_certificate_file(rampart_context_t *rampart_context,
                                     const axutil_env_t *env,
                                     axis2_char_t *certificate_file)
{
   if (rampart_context->key_mgr)
	{
		oxs_key_mgr_set_certificate_file(rampart_context->key_mgr, env, certificate_file);
		return AXIS2_SUCCESS;
	}    
    return AXIS2_FAILURE;
}

/*End of implementation*/

/*Getters of the PHP-RAMPART interface*/

AXIS2_EXTERN axiom_node_t *AXIS2_CALL
rampart_context_get_policy_node(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->policy_node;
}

AXIS2_EXTERN void *AXIS2_CALL
rampart_context_get_prv_key(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    if (rampart_context->key_mgr)
	{
		return oxs_key_mgr_get_prv_key(rampart_context->key_mgr, env);
	}
    return NULL;
}

AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
rampart_context_get_prv_key_type(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    if (rampart_context->key_mgr)
	{
		return oxs_key_mgr_get_prv_key_type(rampart_context->key_mgr, env);
	}
    return AXIS2_KEY_TYPE_UNKNOWN;
}

AXIS2_EXTERN void *AXIS2_CALL
rampart_context_get_certificate(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    if (rampart_context->key_mgr)
	{
		return oxs_key_mgr_get_certificate(rampart_context->key_mgr, env);
	}
    return NULL;
}

AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
rampart_context_get_certificate_type(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    if (rampart_context->key_mgr)
	{
		return oxs_key_mgr_get_certificate_type(rampart_context->key_mgr, env);
	}
    return AXIS2_KEY_TYPE_UNKNOWN;
}


AXIS2_EXTERN void *AXIS2_CALL
rampart_context_get_receiver_certificate(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    if (rampart_context->key_mgr)
	{
		return oxs_key_mgr_get_receiver_certificate(rampart_context->key_mgr, env);
	}
    return NULL;
}

AXIS2_EXTERN axis2_key_type_t AXIS2_CALL
rampart_context_get_receiver_certificate_type(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    if (rampart_context->key_mgr)
	{
		return oxs_key_mgr_get_receiver_certificate_type(rampart_context->key_mgr, env);
	}
    return AXIS2_KEY_TYPE_UNKNOWN;
}



AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_user(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->user;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_password(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->password;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_prv_key_password(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    if (rampart_context->key_mgr)
	{
		return oxs_key_mgr_get_prv_key_password(rampart_context->key_mgr, env);
	}
    return NULL;
}

AXIS2_EXTERN password_callback_fn AXIS2_CALL
rampart_context_get_pwcb_function(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->pwcb_function;
}

AXIS2_EXTERN rampart_is_replayed_fn AXIS2_CALL
rampart_context_get_replay_detect_function(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->is_replayed_function;
}


AXIS2_EXTERN void * AXIS2_CALL
rampart_context_get_pwcb_user_params(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->pwcb_user_params;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_context_get_ttl(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->ttl;
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
rampart_context_get_rd_val(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->rd_val;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_password_type(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->password_type;
}

/*End of getters*/

AXIS2_EXTERN rp_secpolicy_t *AXIS2_CALL
rampart_context_get_secpolicy(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->secpolicy;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_secpolicy(rampart_context_t *rampart_context,
                              const axutil_env_t *env,
                              rp_secpolicy_t *secpolicy)
{
    AXIS2_PARAM_CHECK(env->error,secpolicy,AXIS2_FAILURE);

    rampart_context->secpolicy = secpolicy;
    return AXIS2_SUCCESS;
}


AXIS2_EXTERN rampart_callback_t *AXIS2_CALL
rampart_context_get_password_callback(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->password_callback_module;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_password_callback(rampart_context_t *rampart_context,
                                      const axutil_env_t *env,
                                      rampart_callback_t *password_callback_module)
{
    AXIS2_PARAM_CHECK(env->error,password_callback_module,AXIS2_FAILURE);

    rampart_context->password_callback_module = password_callback_module;
    return AXIS2_SUCCESS;
}

/*The 4 functions below deals with setting and getting authentication
 *module function pointers */

AXIS2_EXTERN auth_password_func AXIS2_CALL
rampart_context_get_auth_password_function(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->authenticate_with_password;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_auth_password_function(rampart_context_t *rampart_context,
        const axutil_env_t *env,
        auth_password_func authenticate_with_password)
{
    AXIS2_PARAM_CHECK(env->error,authenticate_with_password,AXIS2_FAILURE);

    rampart_context->authenticate_with_password = authenticate_with_password;
    return AXIS2_SUCCESS;
}



AXIS2_EXTERN auth_digest_func AXIS2_CALL
rampart_context_get_auth_digest_function(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->authenticate_with_digest;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_auth_digest_function(rampart_context_t *rampart_context,
        const axutil_env_t *env,
        auth_digest_func authenticate_with_digest)
{
    AXIS2_PARAM_CHECK(env->error,authenticate_with_digest,AXIS2_FAILURE);

    rampart_context->authenticate_with_digest = authenticate_with_digest;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN rampart_authn_provider_t *AXIS2_CALL
rampart_context_get_authn_provider(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->authn_provider;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_authn_provider(rampart_context_t *rampart_context,
                                   const axutil_env_t *env,
                                   rampart_authn_provider_t *authn_provider)
{
    AXIS2_PARAM_CHECK(env->error,authn_provider,AXIS2_FAILURE);

    rampart_context->authn_provider = authn_provider;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN void *AXIS2_CALL
rampart_context_get_replay_detector(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return (void*)rampart_context->replay_detector;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_replay_detector(rampart_context_t *rampart_context,
                                   const axutil_env_t *env,
                                   void *replay_detector)
{
    AXIS2_PARAM_CHECK(env->error,replay_detector,AXIS2_FAILURE);

    rampart_context->replay_detector = (rampart_replay_detector_t*)replay_detector;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN void *AXIS2_CALL
rampart_context_get_sct_provider(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return (void*)rampart_context->sct_provider;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_sct_provider(rampart_context_t *rampart_context,
                                   const axutil_env_t *env,
                                   void *sct_provider)
{
    AXIS2_PARAM_CHECK(env->error,sct_provider,AXIS2_FAILURE);

    rampart_context->sct_provider= (rampart_sct_provider_t*)sct_provider;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN oxs_key_t *AXIS2_CALL
rampart_context_get_encryption_session_key(rampart_context_t *rampart_context,
                                            const axutil_env_t *env)
{
    oxs_key_t* key = NULL;
    int i = 0;

    /*Repeat thru all the keys and find the matching one*/
    for(i=0 ; i < axutil_array_list_size(rampart_context->key_list, env); i++)
    {
        key = (oxs_key_t*)axutil_array_list_get(rampart_context->key_list, env, i);
        if(OXS_KEY_USAGE_SESSION == oxs_key_get_usage(key, env))
        {
            return key;
        }        
    }
    
    return NULL;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_encryption_session_key(rampart_context_t *rampart_context,
                                            const axutil_env_t *env,
                                            oxs_key_t *session_key)
{
    if(rampart_context->key_list)
    {
        oxs_key_set_usage(session_key, env, OXS_KEY_USAGE_SESSION);
        axutil_array_list_add(rampart_context->key_list, env, session_key);
        return AXIS2_SUCCESS;
    }
        
    return AXIS2_FALSE;
}

AXIS2_EXTERN oxs_key_t *AXIS2_CALL
rampart_context_get_signature_session_key(rampart_context_t *rampart_context,
                                            const axutil_env_t *env)
{
    oxs_key_t* key = NULL;
    int i = 0;
    int key_usage = OXS_KEY_USAGE_SESSION;

    if(rampart_context_is_different_session_key_for_enc_and_sign(env, rampart_context))
        key_usage = OXS_KEY_USAGE_SIGNATURE_SESSION;

    /*Repeat thru all the keys and find the matching one*/
    for(i=0 ; i < axutil_array_list_size(rampart_context->key_list, env); i++)
    {
        key = (oxs_key_t*)axutil_array_list_get(rampart_context->key_list, env, i);
        if(key_usage == oxs_key_get_usage(key, env))
        {
            return key;
        }        
    }
    
    return NULL;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_signature_session_key(rampart_context_t *rampart_context,
                                            const axutil_env_t *env,
                                            oxs_key_t *session_key)
{
    if(rampart_context->key_list)
    {
        int key_usage = OXS_KEY_USAGE_SESSION;
        if(rampart_context_is_different_session_key_for_enc_and_sign(env, rampart_context))
            key_usage = OXS_KEY_USAGE_SIGNATURE_SESSION;

        oxs_key_set_usage(session_key, env, key_usage);
        axutil_array_list_add(rampart_context->key_list, env, session_key);
        return AXIS2_SUCCESS;
    }
    
    return AXIS2_FALSE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_add_key(rampart_context_t *rampart_context,
                                const axutil_env_t *env,
                                oxs_key_t *key)
{
    if(rampart_context->key_list){
        axutil_array_list_add(rampart_context->key_list, env, key);
    }else{
        return AXIS2_FALSE;
    }
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL
rampart_context_get_keys(rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->key_list;
}

AXIS2_EXTERN oxs_key_t* AXIS2_CALL
rampart_context_get_key(rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axis2_char_t* key_id)
{   
    oxs_key_t* key = NULL;
    int i = 0;

    /*Repeat thru all the derived keys and find the matching one*/
    for(i=0 ; i < axutil_array_list_size(rampart_context->key_list, env); i++)
    {
        axis2_char_t *key_name = NULL;

        key = (oxs_key_t*)axutil_array_list_get(rampart_context->key_list, env, i);
        key_name = oxs_key_get_name(key, env);
        if(0 == axutil_strcmp(key_name, key_id)){
            return key;
        }        
    }
    
    return NULL;
}

AXIS2_EXTERN oxs_key_t* AXIS2_CALL
rampart_context_get_key_using_hash(rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axis2_char_t* hash)
{   
    oxs_key_t* key = NULL;
    int i = 0;

    /*Repeat thru all the derived keys and find the matching one*/
    for(i=0 ; i < axutil_array_list_size(rampart_context->key_list, env); i++)
    {
        axis2_char_t *key_hash = NULL;

        key = (oxs_key_t*)axutil_array_list_get(rampart_context->key_list, env, i);
        key_hash = oxs_key_get_key_sha(key, env);
        if(0 == axutil_strcmp(key_hash, hash))
        {
            return key;
        }        
    }
    
    return NULL;
}


AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_get_require_timestamp(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->require_timestamp;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_get_require_ut(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->require_ut;
}

AXIS2_EXTERN rp_property_type_t AXIS2_CALL
rampart_context_get_binding_type(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_property_t *property = NULL;

    property = rp_secpolicy_get_binding(rampart_context->secpolicy,env);
    if(!property)
        return -1;

    return rp_property_get_type(property,env);
}

rp_symmetric_asymmetric_binding_commons_t
*rampart_context_get_symmetric_asymmetric_binding_commons(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_property_t *property = NULL;
    property = rp_secpolicy_get_binding(rampart_context->secpolicy,env);
    if(!property)
        return NULL;

    if(rp_property_get_type(property,env) == RP_PROPERTY_ASYMMETRIC_BINDING)
    {
        rp_asymmetric_binding_t *asymmetric_binding = NULL;
        asymmetric_binding = (rp_asymmetric_binding_t*)rp_property_get_value(property,env);
        if(!asymmetric_binding)
            return NULL;

        return rp_asymmetric_binding_get_symmetric_asymmetric_binding_commons(asymmetric_binding,env);
    }
    else if(rp_property_get_type(property,env) == RP_PROPERTY_SYMMETRIC_BINDING)
    {
        rp_symmetric_binding_t *symmetric_binding = NULL;
        symmetric_binding = (rp_symmetric_binding_t*)rp_property_get_value(property,env);
        if(!symmetric_binding)
            return NULL;

        return rp_symmetric_binding_get_symmetric_asymmetric_binding_commons(symmetric_binding,env);
    }
    else
        return NULL;
}

rp_binding_commons_t
*rampart_context_get_binding_commons(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_property_t *property = NULL;
    property = rp_secpolicy_get_binding(rampart_context->secpolicy,env);
    if(!property)
        return NULL;

    if(rp_property_get_type(property,env) == RP_PROPERTY_ASYMMETRIC_BINDING)
    {
        rp_asymmetric_binding_t *asymmetric_binding = NULL;
        rp_symmetric_asymmetric_binding_commons_t *sym_asym_commons = NULL;
        asymmetric_binding = (rp_asymmetric_binding_t*)rp_property_get_value(property, env);
        if(!asymmetric_binding)
            return NULL;

        sym_asym_commons = rp_asymmetric_binding_get_symmetric_asymmetric_binding_commons(asymmetric_binding,env);
        if(!sym_asym_commons)
            return NULL;

        return rp_symmetric_asymmetric_binding_commons_get_binding_commons(sym_asym_commons,env);
    }
    else if(rp_property_get_type(property,env) == RP_PROPERTY_SYMMETRIC_BINDING)
    {
        rp_symmetric_binding_t *symmetric_binding = NULL;
        rp_symmetric_asymmetric_binding_commons_t *sym_asym_commons = NULL;
        symmetric_binding = (rp_symmetric_binding_t*)rp_property_get_value(property,env);
        if(!symmetric_binding)
            return NULL;

        sym_asym_commons = rp_symmetric_binding_get_symmetric_asymmetric_binding_commons(symmetric_binding,env);
        if(!sym_asym_commons)
            return NULL;

        return rp_symmetric_asymmetric_binding_commons_get_binding_commons(sym_asym_commons,env);

    }
    else if(rp_property_get_type(property,env) == RP_PROPERTY_TRANSPORT_BINDING)
    {
        rp_transport_binding_t *transport_binding = NULL;
        transport_binding = (rp_transport_binding_t*)rp_property_get_value(property,env);
        if(!transport_binding)
            return NULL;

        return rp_transport_binding_get_binding_commons(transport_binding,env);
    }
    else
        return NULL;
}
/*supporting tokens may contain under binding*/

rp_supporting_tokens_t
*rampart_context_get_signed_supporting_from_binding(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_binding_commons_t *commons = NULL;
    commons = rampart_context_get_binding_commons(rampart_context,env);
    if(!commons)
        return NULL;
    return rp_binding_commons_get_signed_supporting_tokens(commons,env);
}

axis2_bool_t
rampart_context_validate_ut(
    rp_username_token_t *username_token,
    const axutil_env_t *env)
{
    axis2_char_t *inclusion = NULL;
    axis2_bool_t bval = AXIS2_FALSE;

    bval = rp_username_token_get_useUTprofile10(username_token,env);
    if(bval)
    {
        inclusion = rp_username_token_get_inclusion(username_token,env);
        if((axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS)==0)||
                (axutil_strcmp(inclusion,RP_INCLUDE_ONCE)==0)||
                (axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS_TO_RECIPIENT)==0) ||
                (axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS_SP12)==0) ||
                (axutil_strcmp(inclusion,RP_INCLUDE_ONCE_SP12)==0)||
                (axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS_TO_RECIPIENT_SP12)==0))
            return bval;
        else
            bval = AXIS2_FALSE;
    }
    return bval;
}



axis2_bool_t
rampart_context_use_username_token(
    rp_supporting_tokens_t *signed_supporting,
    const axutil_env_t *env)
{
    axutil_array_list_t *array_list = NULL;
    axis2_bool_t bvalidate = AXIS2_FALSE;
    array_list = rp_supporting_tokens_get_tokens(signed_supporting,env);
    if(!array_list)
        return AXIS2_FALSE;

    else
    {
        int i = 0;
        for (i = 0; i < axutil_array_list_size(array_list,env); i++)
        {
            rp_property_t *token = NULL;
            token = (rp_property_t *)
                    axutil_array_list_get(array_list,env, i);
            if (token)
            {
                if(rp_property_get_type(token,env) == RP_PROPERTY_USERNAME_TOKEN)
                {
                    rp_username_token_t *username_token =
                        (rp_username_token_t *)rp_property_get_value(token,env);
                    bvalidate = rampart_context_validate_ut(username_token,env);
                    break;
                }
            }
        }
    }
    return bvalidate;
}

axis2_status_t rampart_context_set_nodes_to_encrypt_or_sign(
    rp_header_t *header,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_encrypt_or_sign)
{
    axis2_char_t *nspace = NULL;
    axis2_char_t *local_name = NULL;
    axiom_soap_header_t *soap_header = NULL;
    axiom_node_t *header_node = NULL;

    soap_header = axiom_soap_envelope_get_header(soap_envelope, env);
    if(!soap_header)
        return AXIS2_FAILURE;

    nspace = (axis2_char_t *) rp_header_get_namespace(header, env);
    if(!nspace)
        return AXIS2_FAILURE;

    local_name = (axis2_char_t*) rp_header_get_name(header, env);

    /*if(axutil_strcmp(nspace, RP_SECURITY_NS)==0)*/
    if((axutil_strcmp(nspace, RP_SECURITY_NS)==0) && (!local_name))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_context] We do not sign or encrypt security namespace headers");
        return AXIS2_FAILURE;
    }

    if(!local_name)
    {
        axutil_array_list_t *soap_header_blocks = NULL;
        int i = 0;
        soap_header_blocks = axiom_soap_header_get_header_blocks_with_namespace_uri(soap_header, env, nspace);
        if(!soap_header_blocks){
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][rampart_context] Header cannot find with namespace %s", nspace);
            return AXIS2_SUCCESS;
        }
        for(i=0 ; i<axutil_array_list_size(soap_header_blocks, env); i++)
        {
            axiom_soap_header_block_t *header_block = NULL;
            axiom_node_t *node = NULL;
            header_block = (axiom_soap_header_block_t *)axutil_array_list_get(soap_header_blocks, env, i);
            if(header_block)
            {
                node = axiom_soap_header_block_get_base_node(header_block, env);
                if(node)
                {
                    axutil_array_list_add(nodes_to_encrypt_or_sign, env, node);
                }
            }
        }/*eof for*/
        axutil_array_list_free(soap_header_blocks, env);
        soap_header_blocks = NULL;
        return AXIS2_SUCCESS;
    }
    else if(axutil_strcmp(local_name,"Security")==0)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_context] We do not sign or encrypt %s", local_name);
        return AXIS2_FAILURE;
    }
    else
    {
        axiom_node_t *ret_node = NULL;
        header_node = axiom_soap_header_get_base_node(soap_header, env);
        if(header_node)
        {
            ret_node = oxs_axiom_get_node_by_local_name(env, header_node, local_name);
            if(ret_node)
            {
                axiom_element_t *ret_node_ele = NULL;
                ret_node_ele = (axiom_element_t *)
                               axiom_node_get_data_element(ret_node, env);
                if(ret_node_ele)
                {
                    axiom_namespace_t *ns = NULL;
                    axis2_char_t *namespace_uri = NULL;
                    ns = axiom_element_get_namespace(ret_node_ele, env, ret_node);
                    if(ns)
                    {
                        namespace_uri = axiom_namespace_get_uri(ns, env);
                        if (axutil_strcmp(namespace_uri, nspace) == 0)
                        {
                            axutil_array_list_add(nodes_to_encrypt_or_sign, env, ret_node);
                            return AXIS2_SUCCESS;
                        }
                    }
                }
            }
            else
            {
                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][rampart_context] Cannot find the header with name %s", local_name);
                return AXIS2_SUCCESS;
            }
        }
    }
    return AXIS2_SUCCESS;
}

axis2_status_t rampart_context_set_elements_to_encrypt_or_sign(
    rp_element_t *element,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_encrypt_or_sign)
{
    axis2_char_t *nspace = NULL;
    axis2_char_t *local_name = NULL;
    axiom_node_t *envelope_node = NULL;

    nspace = (axis2_char_t *) rp_element_get_namespace(element, env);
    if(!nspace)
        return AXIS2_FAILURE;

    if(axutil_strcmp(nspace, RP_SECURITY_NS)==0)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_context] We do not sign or encrypt security namespace elements");
        return AXIS2_FAILURE;
    }

    local_name = (axis2_char_t*)rp_element_get_name(element,env);
    /*  if(!local_name)
        {
            axutil_array_list_t *soap_header_blocks = NULL;
            int i = 0;
            soap_header_blocks = axiom_soap_header_get_header_blocks_with_namespace_uri(soap_header,env,namespace);
            if(!soap_header_blocks)
                return AXIS2_FAILURE;
     
            for(i=0 ; i<axutil_array_list_size(soap_header_blocks,env); i++)
            {
                axiom_soap_header_block_t *header_block = NULL;
                axiom_node_t *node = NULL;
                header_block = (axiom_soap_header_block_t *)axutil_array_list_get(soap_header_blocks,env,i);
                if(header_block)
                {
                    node = axiom_soap_header_block_get_base_node(header_block,env);
                    if(node)
                    {
                        axutil_array_list_add(nodes_to_encrypt_or_sign,env,node);
                        return AXIS2_SUCCESS;
                    }
                }
     
            }
        }
    */  if(local_name)
    {
        if(axutil_strcmp(local_name,"Security")==0)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart][rampart_context] We do not sign or encrypt %s", local_name);
            return AXIS2_FAILURE;
        }
        else
        {
            axiom_node_t *ret_node = NULL;
            envelope_node = axiom_soap_envelope_get_base_node(soap_envelope, env);
            if(envelope_node)
            {
                ret_node = oxs_axiom_get_node_by_local_name(env, envelope_node, local_name);
                if(ret_node)
                {
                    axiom_element_t *ret_node_ele = NULL;
                    ret_node_ele = (axiom_element_t *)
                                   axiom_node_get_data_element(ret_node, env);
                    if(ret_node_ele)
                    {
                        axiom_namespace_t *ns = NULL;
                        axis2_char_t *namespace_uri = NULL;
                        ns = axiom_element_get_namespace(ret_node_ele, env,ret_node);
                        if(ns)
                        {
                            namespace_uri = axiom_namespace_get_uri(ns, env);
                            if (axutil_strcmp(namespace_uri, nspace) == 0)
                            {
                                axutil_array_list_add(nodes_to_encrypt_or_sign, env, ret_node);
                                return AXIS2_SUCCESS;
                            }
                        }
                    }
                }
            }
        }
    }
    return AXIS2_FAILURE;
}

AXIS2_EXTERN rp_algorithmsuite_t *AXIS2_CALL
rampart_context_get_algorithmsuite(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_binding_commons_t *binding_commons = NULL;

    binding_commons = rampart_context_get_binding_commons(rampart_context,env);

    if(!binding_commons)
        return AXIS2_FALSE;

    return rp_binding_commons_get_algorithmsuite(binding_commons,env);
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_is_sig_confirmation_reqd(rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_property_t *wss = NULL;
    rp_wss11_t *wss11 = NULL;

    wss = rp_secpolicy_get_wss(rampart_context->secpolicy,env);
    if(!wss){
        return AXIS2_FALSE;
    }

    if(rp_property_get_type(wss,env) == RP_PROPERTY_WSS11)
{		    
    wss11 = rp_property_get_value(wss,env);
    if(wss11){
        return rp_wss11_get_require_signature_confirmation(wss11, env);
    }else{
        return AXIS2_FALSE;
    }
}
else
	return AXIS2_FALSE;

}

axis2_char_t *AXIS2_CALL
rampart_context_get_key_identifier_from_wss(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_property_t *wss = NULL;
    axis2_char_t *identifier = NULL;

    wss = rp_secpolicy_get_wss(rampart_context->secpolicy,env);
    if(!wss)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI,"Problem identifying the key Identifier." );
        return identifier;
    }

    if(rp_property_get_type(wss,env) == RP_PROPERTY_WSS10)
    {
        rp_wss10_t *wss10 = NULL;
        wss10 = rp_property_get_value(wss,env);
        if(!wss10)
            return NULL;

        if(rp_wss10_get_must_support_ref_key_identifier(wss10,env))
            identifier = RAMPART_STR_KEY_IDENTIFIER;
        else if(rp_wss10_get_must_support_ref_issuer_serial(wss10,env))
            identifier = RAMPART_STR_ISSUER_SERIAL;
        else if(rp_wss10_get_must_support_ref_external_uri(wss10,env))
            identifier = RAMPART_STR_EXTERNAL_URI;
        else if(rp_wss10_get_must_support_ref_embedded_token(wss10,env))
            identifier = RAMPART_STR_EMBEDDED;
        else
            identifier = NULL;

        return identifier;
    }
    else if(rp_property_get_type(wss,env) == RP_PROPERTY_WSS11)
    {
        rp_wss11_t *wss11 = NULL;
        wss11 = rp_property_get_value(wss,env);
        if(!wss11)
            return NULL;

        if(rp_wss11_get_must_support_ref_key_identifier(wss11,env))
            identifier = RAMPART_STR_KEY_IDENTIFIER;
        else if(rp_wss11_get_must_support_ref_issuer_serial(wss11,env))
            identifier = RAMPART_STR_ISSUER_SERIAL;
        else if(rp_wss11_get_must_support_ref_external_uri(wss11,env))
            identifier = RAMPART_STR_EXTERNAL_URI;
        else if(rp_wss11_get_must_support_ref_embedded_token(wss11,env))
            identifier = RAMPART_STR_EMBEDDED;
        else if(rp_wss11_get_must_support_ref_thumbprint(wss11,env))
            identifier = RAMPART_STR_THUMB_PRINT;
        else if(rp_wss11_get_must_support_ref_encryptedkey(wss11,env))
            identifier = RAMPART_STR_ENCRYPTED_KEY;
        else
            identifier = NULL;

        return identifier;
    }
    else return NULL;
}


axis2_bool_t AXIS2_CALL
rampart_context_is_key_identifier_supported(
    rp_property_t *token,
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_property_t *wss = NULL;
    rp_wss10_t *wss10 = NULL;
    rp_wss11_t *wss11 = NULL;

    wss = rp_secpolicy_get_wss(rampart_context->secpolicy,env);
    if(!wss)
    {
        /*TODO error*/
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "wss properties are not set" );
        return AXIS2_FALSE;
    }

    if(rp_property_get_type(wss,env) == RP_PROPERTY_WSS10)
    {
        wss10 = (rp_wss10_t *)rp_property_get_value(wss,env);
    }
    else if(rp_property_get_type(wss,env) == RP_PROPERTY_WSS11)
    {
        wss11 = (rp_wss11_t *)rp_property_get_value(wss,env);
    }

    if(rp_property_get_type(token,env)== RP_PROPERTY_X509_TOKEN)
    {
        rp_x509_token_t *x509_token = NULL;
        x509_token = (rp_x509_token_t *)rp_property_get_value(token,env);

        if(!x509_token)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot get the token value from policy.");
            return AXIS2_FALSE;
        }
        if(rp_x509_token_get_require_key_identifier_reference(x509_token,env))
            return AXIS2_TRUE;
    }
    else if(rp_property_get_type(token, env) == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
    {
        rp_security_context_token_t *security_context_token;
        security_context_token = (rp_security_context_token_t *)rp_property_get_value(token, env);
        if(security_context_token)
        {
            return AXIS2_TRUE;
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot get the token value from policy.");
            return AXIS2_FALSE;
        }
    }
    else
        return AXIS2_FALSE;

    if(wss10)
        return rp_wss10_get_must_support_ref_key_identifier(wss10,env);

    else if(wss11)
        return rp_wss11_get_must_support_ref_key_identifier(wss11,env);

    else return AXIS2_FALSE;

}

axis2_bool_t AXIS2_CALL
rampart_context_is_issuer_serial_supported(
    rp_property_t *token,
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_property_t *wss = NULL;
    rp_wss10_t *wss10 = NULL;
    rp_wss11_t *wss11 = NULL;

    wss = rp_secpolicy_get_wss(rampart_context->secpolicy,env);
    if(!wss)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"wss properties are not set.." );
        return AXIS2_FALSE;
    }

    if(rp_property_get_type(wss,env)== RP_PROPERTY_WSS10)
    {
        wss10 = (rp_wss10_t *)rp_property_get_value(wss,env);
    }
    else if(rp_property_get_type(wss,env)== RP_PROPERTY_WSS11)
    {
        wss11 = (rp_wss11_t *)rp_property_get_value(wss,env);
    }

    if(rp_property_get_type(token,env) == RP_PROPERTY_X509_TOKEN)
    {
        rp_x509_token_t *x509_token = NULL;
        x509_token = (rp_x509_token_t *)rp_property_get_value(token,env);

        if(!x509_token)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot get the token value from policy.");
            return AXIS2_FALSE;
        }
        if(rp_x509_token_get_require_issuer_serial_reference(x509_token,env))
            return AXIS2_TRUE;
    }
    else
        return AXIS2_FALSE;

    if(wss10)
        return rp_wss10_get_must_support_ref_issuer_serial(wss10,env);

    else if(wss11)
        return rp_wss11_get_must_support_ref_issuer_serial(wss11,env);

    else return AXIS2_FALSE;

}

axis2_bool_t AXIS2_CALL
rampart_context_is_embedded_token_supported(
    rp_property_t *token,
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_property_t *wss = NULL;
    rp_wss10_t *wss10 = NULL;
    rp_wss11_t *wss11 = NULL;

    wss = rp_secpolicy_get_wss(rampart_context->secpolicy,env);
    if(!wss)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "wss properties are not set.." );
        return AXIS2_FALSE;
    }

    if(rp_property_get_type(wss,env) == RP_PROPERTY_WSS10)
    {
        wss10 = (rp_wss10_t *)rp_property_get_value(wss,env);
    }
    else if(rp_property_get_type(wss,env) == RP_PROPERTY_WSS11)
    {
        wss11 = (rp_wss11_t *)rp_property_get_value(wss,env);
    }

    if(rp_property_get_type(token,env) == RP_PROPERTY_X509_TOKEN)
    {
        rp_x509_token_t *x509_token = NULL;
        x509_token = (rp_x509_token_t *)rp_property_get_value(token,env);

        if(!x509_token)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot get the token value from policy.");
            return AXIS2_FALSE;
        }
        if(rp_x509_token_get_require_embedded_token_reference(x509_token,env))
            return AXIS2_TRUE;
    }
    else
        return AXIS2_FALSE;

    if(wss10)
        return rp_wss10_get_must_support_ref_embedded_token(wss10,env);

    else if(wss11)
        return rp_wss11_get_must_support_ref_embedded_token(wss11,env);

    else return AXIS2_FALSE;
}




AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_is_include_timestamp(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_binding_commons_t *binding_commons = NULL;

    binding_commons = rampart_context_get_binding_commons(rampart_context,env);

    if(!binding_commons)
        return AXIS2_FALSE;

    rampart_context->require_timestamp = rp_binding_commons_get_include_timestamp(binding_commons,env);

    return rampart_context->require_timestamp;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_is_include_username_token(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    /*Username tokens should be in signed supporting tikens.
      Otherwise no meaning  */

    rp_supporting_tokens_t *signed_supporting = NULL;

    /*First we should check in the direct policy members*/
    signed_supporting = rp_secpolicy_get_signed_supporting_tokens(rampart_context->secpolicy,env);
    /*If not there then we should ckeck in the binding*/
    if(!signed_supporting)
    {
        signed_supporting = rampart_context_get_signed_supporting_from_binding(rampart_context,env);
        if(!signed_supporting)
            return AXIS2_FALSE;
    }
    /*Now we have signed supporting tokens*/
    /*Get the user name token if available and check the validity*/
    rampart_context->require_ut = rampart_context_use_username_token(signed_supporting,env);
    return rampart_context->require_ut;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_is_include_supporting_token(
    rampart_context_t *rampart_context, const axutil_env_t *env,
	axis2_bool_t server_side, axis2_bool_t is_inpath, rp_property_type_t token_type)
{
    axutil_array_list_t *array_list = NULL;
    axis2_bool_t bvalidate = AXIS2_FALSE;
    rp_supporting_tokens_t *signed_supporting = NULL;
    /*First we should check in the direct policy members*/
    signed_supporting = rp_secpolicy_get_signed_supporting_tokens(rampart_context->secpolicy,env);
    /*If not there then we should ckeck in the binding*/
    if (!signed_supporting)
    {
        signed_supporting = rampart_context_get_signed_supporting_from_binding(rampart_context,env);
        if (!signed_supporting)
            return AXIS2_FALSE;
    }
    array_list = rp_supporting_tokens_get_tokens(signed_supporting, env);
    if (!array_list)
        return AXIS2_FALSE;
    else
    {
        int i = 0;
        for (i = 0; i < axutil_array_list_size(array_list, env); i++)
        {
            rp_property_t *token = NULL;
            token = (rp_property_t *)
                    axutil_array_list_get(array_list, env, i);
            if (token)
            {
                if(rp_property_get_type(token,env) == token_type)
                {
                    bvalidate = rampart_context_is_token_include(
                                        rampart_context, token, 
                                        token_type, server_side, 
                                        is_inpath, env);
                    break;
                }
            }
        }
    }
    return bvalidate;
}


AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_is_include_protection_saml_token(
    rampart_context_t *rampart_context, axis2_bool_t server_side, 
    axis2_bool_t is_inpath, const axutil_env_t *env)
{
    rp_property_t *binding = NULL;
    binding = rp_secpolicy_get_binding(rampart_context->secpolicy,env);
    if(!binding)
        return AXIS2_FALSE;

    if(rp_property_get_type(binding,env) == RP_PROPERTY_ASYMMETRIC_BINDING)
    {
        return AXIS2_FALSE;
    }
    /*We support SAML tokens as protection tokens only in symmetrc binding*/
    else if(rp_property_get_type(binding,env) == RP_PROPERTY_SYMMETRIC_BINDING)
    {
        rp_symmetric_binding_t *sym_binding = NULL;
        rp_property_t *token = NULL;
        sym_binding = (rp_symmetric_binding_t *)rp_property_get_value(binding,env);
        if(sym_binding)
        {
            /*First check protection tokens have being specified.*/
            token = rp_symmetric_binding_get_protection_token(sym_binding,env);                
            if (token && rp_property_get_type(token, env) == RP_PROPERTY_SAML_TOKEN && 
                rampart_context_is_token_include(rampart_context, token, 
                                                RP_PROPERTY_SAML_TOKEN, server_side, 
                                                is_inpath, env))
            {
                return AXIS2_TRUE;
            }
            token = rp_symmetric_binding_get_encryption_token(sym_binding,env);                               
            if (token && rp_property_get_type(token, env) == RP_PROPERTY_SAML_TOKEN && 
                rampart_context_is_token_include(rampart_context, token, 
                                                RP_PROPERTY_SAML_TOKEN, server_side, 
                                                is_inpath, env))
            {
                return AXIS2_TRUE;
            }
            token = rp_symmetric_binding_get_signature_token(sym_binding, env);
            if (token && rp_property_get_type(token, env) == RP_PROPERTY_SAML_TOKEN && 
                rampart_context_is_token_include(rampart_context, token, 
                                                RP_PROPERTY_SAML_TOKEN, server_side, 
                                                is_inpath, env))
            {
                return AXIS2_TRUE;
            }
            return AXIS2_FALSE;                
        }
        else
            return AXIS2_FALSE;
    }
    else if(rp_property_get_type(binding,env) == RP_PROPERTY_TRANSPORT_BINDING)
    {
        return AXIS2_FALSE;
    }
    else return AXIS2_FALSE;
}

AXIS2_EXTERN rp_property_t * AXIS2_CALL
rampart_context_get_supporting_token(
    rampart_context_t *rampart_context,
    const axutil_env_t *env, rp_property_type_t token_type)
{
    axutil_array_list_t *array_list = NULL;
    rp_supporting_tokens_t *signed_supporting = NULL;
    /*First we should check in the direct policy members*/
    signed_supporting = rp_secpolicy_get_signed_supporting_tokens(rampart_context->secpolicy,env);
    /*If not there then we should ckeck in the binding*/
    if (!signed_supporting)
    {
        signed_supporting = rampart_context_get_signed_supporting_from_binding(rampart_context,env);
        if (!signed_supporting)
            return NULL;
    }
    array_list = rp_supporting_tokens_get_tokens(signed_supporting, env);
    if (!array_list)
        return NULL;
    else
    {
        int i = 0;
        for (i = 0; i < axutil_array_list_size(array_list, env); i++)
        {
            rp_property_t *token = NULL;
            token = (rp_property_t *)
                    axutil_array_list_get(array_list, env, i);
            if (token)
            {
                if(rp_property_get_type(token,env) == token_type)
                {                                            
                    return token; 
                }
            }
        }
    }
    return NULL;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_user_from_file(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{

    rp_rampart_config_t *config = NULL;
    config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(!config)
        return AXIS2_FAILURE;

    rampart_context->user = rp_rampart_config_get_user(config,env);
    return AXIS2_SUCCESS;
}


AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_password_callback_class(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *config = NULL;
    config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(!config)
        return NULL;

    return rp_rampart_config_get_password_callback_class(config,env);
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_authn_module_name(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *config = NULL;
    config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(!config)
        return NULL;

    return rp_rampart_config_get_authenticate_module(config,env);
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_replay_detector_name(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *config = NULL;
    config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(!config)
        return NULL;

    return rp_rampart_config_get_replay_detector(config,env);
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_sct_provider_name(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *config = NULL;
    config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(!config)
        return NULL;

    return rp_rampart_config_get_sct_provider(config,env);
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_pkcs12_file_name(
	rampart_context_t *rampart_context,
	const axutil_env_t *env)
{
	rp_rampart_config_t *config = NULL;
	config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
	if(!config)
	    return NULL;

	return rp_rampart_config_get_pkcs12_file(config,env);	
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_password_type_from_file(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *config = NULL;
    config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(!config)
        return AXIS2_FAILURE;

    rampart_context->password_type = rp_rampart_config_get_password_type(config,env);
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_ttl_from_file(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *config = NULL;
    axis2_char_t *time_to_live = NULL;
    config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(!config)
        return AXIS2_FAILURE;

    time_to_live = rp_rampart_config_get_time_to_live(config,env);
    if(time_to_live)
        rampart_context->ttl = axutil_atoi(time_to_live);

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_clock_skew_buffer_from_file(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *config = NULL;
    axis2_char_t *clock_skew_buffer = NULL;
    config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(!config)
        return AXIS2_FAILURE;

    clock_skew_buffer = rp_rampart_config_get_clock_skew_buffer(config,env);
    if(clock_skew_buffer)
        rampart_context->clock_skew_buffer = axutil_atoi(clock_skew_buffer);

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_need_millisecond_precision_from_file(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *config = NULL;
    axis2_char_t *need_millisecond = NULL;
    config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(!config)
        return AXIS2_FAILURE;

    need_millisecond = rp_rampart_config_get_need_millisecond_precision(config,env);
    if(need_millisecond)
    {
        if(!axutil_strcasecmp(need_millisecond, "TRUE"))
            rampart_context->need_millisecond_precision = AXIS2_TRUE;
        else
            rampart_context->need_millisecond_precision = AXIS2_FALSE;
    }

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_rd_val_from_file(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *config = NULL;
    axis2_char_t *rd_val = NULL;
    config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(!config)
        return AXIS2_FAILURE;

    rd_val = rp_rampart_config_get_rd_val(config,env);
    rampart_context->rd_val = rd_val;

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_is_encrypt_before_sign(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    axis2_char_t *protection_order = NULL;
    rp_symmetric_asymmetric_binding_commons_t *sym_asym_commons = NULL;
    sym_asym_commons = rampart_context_get_symmetric_asymmetric_binding_commons(rampart_context,env);

    if(!sym_asym_commons)
        return AXIS2_FALSE;
    else
    {
        protection_order = rp_symmetric_asymmetric_binding_commons_get_protection_order(sym_asym_commons,env);
        if(!protection_order || axutil_strcmp(protection_order,RP_SIGN_BEFORE_ENCRYPTING)==0)
            return AXIS2_FALSE;

        else if(axutil_strcmp(protection_order,RP_ENCRYPT_BEFORE_SIGNING)==0)
            return AXIS2_TRUE;
    }
    return AXIS2_FALSE;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_is_encrypt_signature(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{

    rp_symmetric_asymmetric_binding_commons_t *sym_asym_commons = NULL;
    sym_asym_commons = rampart_context_get_symmetric_asymmetric_binding_commons(rampart_context, env);

    if(!sym_asym_commons)
        return AXIS2_FALSE;

    else
    {
        return rp_symmetric_asymmetric_binding_commons_get_signature_protection(sym_asym_commons, env);
    }
}

/*Following methods will return all the parts in the soap message
outside the security header which needs to be encrypted or signed.*/

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_get_nodes_to_encrypt(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_encrypt)
{

    return rampart_context_get_nodes_to_protect(rampart_context,env,soap_envelope,nodes_to_encrypt,AXIS2_FALSE);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_get_nodes_to_sign(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_sign)
{
    rp_header_t *header = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    status = rampart_context_get_nodes_to_protect(rampart_context, env, soap_envelope,
        nodes_to_sign, AXIS2_TRUE);
    if(status != AXIS2_SUCCESS)
    {
        return AXIS2_FAILURE;
    }

    header = rp_header_create(env);
    rp_header_set_name(header, env, RAMPART_SECURITY_TIMESTAMP);
    rp_header_set_namespace(header, env, RAMPART_WSU_XMLNS);
    status = rampart_context_set_nodes_to_encrypt_or_sign(header, env, soap_envelope, nodes_to_sign);
    rp_header_free(header, env);
    if(status != AXIS2_SUCCESS)
    {
        return AXIS2_FAILURE;
    }

    header = rp_header_create(env);
    rp_header_set_name(header, env, RAMPART_SECURITY_USERNAMETOKEN);
    rp_header_set_namespace(header, env, RAMPART_WSSE_XMLNS);
    status = rampart_context_set_nodes_to_encrypt_or_sign(header, env, soap_envelope, nodes_to_sign);
    rp_header_free(header, env);
    if(status != AXIS2_SUCCESS)
    {
        return AXIS2_FAILURE;
    }

    header = rp_header_create(env);
    rp_header_set_name(header, env, OXS_NODE_SIGNATURE_CONFIRMATION);
    rp_header_set_namespace(header, env, RAMPART_WSSE_XMLNS);
    status = rampart_context_set_nodes_to_encrypt_or_sign(header, env, soap_envelope, nodes_to_sign);
    rp_header_free(header, env);
    if(status != AXIS2_SUCCESS)
    {
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_get_elements_to_encrypt(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_encrypt)
{

    return rampart_context_get_elements_to_protect(rampart_context,env,soap_envelope,nodes_to_encrypt,AXIS2_FALSE);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_get_elements_to_sign(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_sign)
{

    return rampart_context_get_elements_to_protect(rampart_context,env,soap_envelope,nodes_to_sign,AXIS2_TRUE);
}


axis2_status_t AXIS2_CALL
rampart_context_get_nodes_to_protect(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_sign_or_encrypt,
    axis2_bool_t is_sign)
{
    rp_signed_encrypted_parts_t *signed_encrypted_parts = NULL;
    axutil_array_list_t *parts = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    if(is_sign)
        signed_encrypted_parts = rp_secpolicy_get_signed_parts(rampart_context->secpolicy,env);
    else
        signed_encrypted_parts = rp_secpolicy_get_encrypted_parts(rampart_context->secpolicy,env);

    if(!signed_encrypted_parts)
    {
        if(is_sign)
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][rampart_context] Nothing to sign outside Secyrity header.");
        }
        else
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][rampart_context] Nothing to encrypt outside Secyrity header.");
        }
        return AXIS2_SUCCESS;
    }

    parts = rp_signed_encrypted_parts_get_headers(signed_encrypted_parts,env);
    if(parts && (axutil_array_list_size(parts,env)!=0))
    {
        int i = 0;
        for(i=0; i<axutil_array_list_size(parts,env); i++)
        {
            rp_header_t *header = NULL;
            header = (rp_header_t *)axutil_array_list_get(parts,env,i);
            if(header)
            {
                status = rampart_context_set_nodes_to_encrypt_or_sign(header,env,soap_envelope,nodes_to_sign_or_encrypt);
                if(status == AXIS2_FAILURE){
                    return AXIS2_FAILURE;
                }
            }
        }
    }

    if(rp_signed_encrypted_parts_get_body(signed_encrypted_parts,env))
    {
        axiom_soap_body_t *body = NULL;
        axiom_node_t *body_node = NULL;

        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "Including the body for encryption/sign.");
        body = axiom_soap_envelope_get_body(soap_envelope, env);
        body_node = axiom_soap_body_get_base_node(body, env);

        if(is_sign)
        {
            axutil_array_list_add(nodes_to_sign_or_encrypt, env, body_node);
        }
        else
        {
            axiom_node_t *body_child_node = NULL;
            body_child_node = axiom_node_get_first_element(body_node, env);
            if(body_child_node)
            {
                axutil_array_list_add(nodes_to_sign_or_encrypt, env, body_child_node);
            }
        }

        return AXIS2_SUCCESS;
    }

    return status;
}

axis2_status_t AXIS2_CALL
rampart_context_get_elements_to_protect(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axiom_soap_envelope_t *soap_envelope,
    axutil_array_list_t *nodes_to_sign_or_encrypt,
    axis2_bool_t is_sign)
{
    rp_signed_encrypted_items_t *signed_encrypted_items = NULL;
    axutil_array_list_t *items = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    if(is_sign)
        signed_encrypted_items = rp_secpolicy_get_signed_items(rampart_context->secpolicy,env);
    else
        signed_encrypted_items = rp_secpolicy_get_encrypted_items(rampart_context->secpolicy,env);

    if(!signed_encrypted_items)
        return AXIS2_FAILURE;

    items = rp_signed_encrypted_items_get_elements(signed_encrypted_items,env);
    if(!items || (axutil_array_list_size(items,env)==0))
    {
        if(is_sign){
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][rampart_context] Nothing to sign outside Secyrity header.");
        
        }else{
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][rampart_context] Nothing to encrypt outside Secyrity header.");
        }
        return AXIS2_FAILURE;
    }
    else
    {
        int i = 0;
        for(i=0; i<axutil_array_list_size(items,env); i++)
        {
            rp_element_t *element = NULL;
            element = (rp_element_t *)axutil_array_list_get(items,env,i);
            if(element)
            {
                status = rampart_context_set_elements_to_encrypt_or_sign(element,env,soap_envelope,nodes_to_sign_or_encrypt);
                if(status!=AXIS2_FAILURE)
                    return status;
            }
        }
    }
    return status;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_check_whether_to_encrypt(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_signed_encrypted_parts_t *encrypted_parts = NULL;
    rp_signed_encrypted_items_t *encrypted_items = NULL;
    axutil_array_list_t *parts = NULL;

    encrypted_parts = rp_secpolicy_get_encrypted_parts(rampart_context->secpolicy,env);
    if(!encrypted_parts)
    {
        encrypted_items = rp_secpolicy_get_encrypted_items(rampart_context->secpolicy,env);
        if(!encrypted_items)
            return AXIS2_FALSE;
        else
        {
            parts = rp_signed_encrypted_items_get_elements(encrypted_items,env);
            if(!parts||(axutil_array_list_size(parts,env)==0))
            {
                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][rampart_context] No Signed parts specified Nothing to Verify");
                return AXIS2_FALSE;
            }
            else{
                return AXIS2_TRUE;
            }
        }
    }
    parts = rp_signed_encrypted_parts_get_headers(encrypted_parts,env);
    if(!parts || (axutil_array_list_size(parts,env)==0))
    {
        if(rp_signed_encrypted_parts_get_body(encrypted_parts,env))
            return AXIS2_TRUE;

        else
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][rampart_context]No encryption parts specified Nothing to decrypt");
            return AXIS2_FALSE;
        }
    }
    return AXIS2_TRUE;
}


AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_check_whether_to_sign(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_signed_encrypted_parts_t *signed_parts = NULL;
    rp_signed_encrypted_items_t *signed_items = NULL;
    axutil_array_list_t *parts = NULL;

    signed_parts = rp_secpolicy_get_signed_parts(rampart_context->secpolicy,env);
    if(!signed_parts)
    {
        signed_items = rp_secpolicy_get_signed_items(rampart_context->secpolicy,env);
        if(!signed_items)
            return AXIS2_FALSE;
        else
        {
            parts = rp_signed_encrypted_items_get_elements(signed_items,env);
            if(!parts||(axutil_array_list_size(parts,env)==0))
            {
                AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][rampart_context]No Signed parts specified Nothing to Verify");
                return AXIS2_FALSE;
            }
            else
                return AXIS2_TRUE;
        }
    }
    parts = rp_signed_encrypted_parts_get_headers(signed_parts,env);
    if(!parts || (axutil_array_list_size(parts,env)==0))
    {
        if(rp_signed_encrypted_parts_get_body(signed_parts,env))
            return AXIS2_TRUE;

        else
        {
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][rampart_context]No Signed parts specified Nothing to Verify");
            return AXIS2_FALSE;
        }
    }
    return AXIS2_TRUE;
}



AXIS2_EXTERN rp_property_t *AXIS2_CALL
rampart_context_get_token(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axis2_bool_t for_encryption,
    axis2_bool_t server_side,
    axis2_bool_t is_inpath)
{
    rp_property_t *binding = NULL;
    binding = rp_secpolicy_get_binding(rampart_context->secpolicy,env);
    if(!binding)
        return NULL;

    if(rp_property_get_type(binding,env) == RP_PROPERTY_ASYMMETRIC_BINDING)
    {
        rp_asymmetric_binding_t *asym_binding = NULL;
        asym_binding = (rp_asymmetric_binding_t *)rp_property_get_value(binding,env);
        if(asym_binding)
        {
            if(is_inpath)
            {
                if((for_encryption && server_side) || (!for_encryption && !server_side))
                {
                    return rp_asymmetric_binding_get_recipient_token(asym_binding,env);
                }
                else if((for_encryption && !server_side) || (!for_encryption && server_side))
                {
                    return rp_asymmetric_binding_get_initiator_token(asym_binding,env);
                }
                else return NULL;
            }
            else
            {
                if((server_side && for_encryption) || (!for_encryption && !server_side))
                {
                    return rp_asymmetric_binding_get_initiator_token(asym_binding,env);
                }
                else if((server_side && !for_encryption)|| (for_encryption && !server_side))
                {
                    return rp_asymmetric_binding_get_recipient_token(asym_binding,env);
                }
                else return NULL;
            }
        }
        else
            return NULL;
    }
    /*In symmetric binding same tokens are used in the client and server sides.*/
    else if(rp_property_get_type(binding,env) == RP_PROPERTY_SYMMETRIC_BINDING)
    {
        rp_symmetric_binding_t *sym_binding = NULL;
        rp_property_t *token = NULL;
        sym_binding = (rp_symmetric_binding_t *)rp_property_get_value(binding,env);
        if(sym_binding)
        {
            /*First check protection tokens have being specified.*/
            token = rp_symmetric_binding_get_protection_token(sym_binding,env);
            if(token)
                return token;

            else
            {
                if(for_encryption)
                {
                    return rp_symmetric_binding_get_encryption_token(sym_binding,env);
                }
                else
                {
                    return rp_symmetric_binding_get_signature_token(sym_binding,env);
                }
            }
        }
        else
            return NULL;
    }
    else if(rp_property_get_type(binding,env) == RP_PROPERTY_TRANSPORT_BINDING)
    {
        rp_transport_binding_t *transport_binding = NULL;
        transport_binding = (rp_transport_binding_t *)rp_property_get_value(binding,env);
        if(transport_binding)
        {
            return rp_transport_binding_get_transport_token(transport_binding,env);
        }
        else return NULL;
    }
    else return NULL;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_check_is_derived_keys(
    const axutil_env_t *env,
    rp_property_t *token)
{
    derive_key_type_t key_type = DERIVEKEY_NONE;
    if(rp_property_get_type(token,env) == RP_PROPERTY_X509_TOKEN)
    {
        rp_x509_token_t *x509_token = NULL;
        x509_token = (rp_x509_token_t *)rp_property_get_value(token,env);
        key_type = rp_x509_token_get_derivedkey(x509_token,env);
    }
    else if(rp_property_get_type(token, env) == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
    {
        rp_security_context_token_t *security_context_token = NULL;
        security_context_token = (rp_security_context_token_t *)rp_property_get_value(token, env);
        key_type = rp_security_context_token_get_derivedkey(security_context_token, env);
    }
    /*This can be extended when we are supporting other token types.*/
    else
    {
        return AXIS2_FALSE;
    }

    if(key_type == DERIVEKEY_NONE)
    {
        return AXIS2_FALSE;
    }
    else
    {
        return AXIS2_TRUE;
    }
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_derived_key_version(
    const axutil_env_t *env, 
    rp_property_t *token)
{
    derive_key_version_t key_version = DERIVEKEY_VERSION_SC13;
    if(rp_property_get_type(token,env) == RP_PROPERTY_X509_TOKEN)
    {
        rp_x509_token_t *x509_token = NULL;
        x509_token = (rp_x509_token_t *)rp_property_get_value(token,env);
        key_version = rp_x509_token_get_derivedkey_version(x509_token,env);
    }
    else if(rp_property_get_type(token, env) == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
    {
        rp_security_context_token_t *security_context_token = NULL;
        security_context_token = (rp_security_context_token_t *)rp_property_get_value(token, env);
        key_version = rp_security_context_token_get_derivedkey_version(security_context_token, env);
    }
    /*This can be extended when we are supporting other token types.*/
    else
    {
        return NULL;
    }

    if(key_version == DERIVEKEY_VERSION_SC13)
    {
        return OXS_WSC_NS_05_12;
    }
    else
    {
        return OXS_WSC_NS_05_02;
    }
}

AXIS2_EXTERN int AXIS2_CALL
rampart_context_get_encryption_derived_key_len(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_algorithmsuite_t *algosuite = NULL;

    algosuite = rampart_context_get_algorithmsuite(rampart_context,env);
    if(algosuite)
    {
        return rp_algorithmsuite_get_encryption_derivation_keylength(algosuite,env)/8;
    }
    else
        return 0;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_context_get_signature_derived_key_len(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_algorithmsuite_t *algosuite = NULL;

    algosuite = rampart_context_get_algorithmsuite(rampart_context,env);
    if(algosuite)
    {
        return rp_algorithmsuite_get_signature_derivation_keylength(algosuite,env)/8;
    }
    else
        return 0;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_enc_sym_algo(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_algorithmsuite_t *algosuite = NULL;

    algosuite = rampart_context_get_algorithmsuite(rampart_context,env);
    if(algosuite)
    {
        return rp_algorithmsuite_get_encryption(algosuite,env);
    }
    else
        return NULL;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_enc_asym_algo(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_algorithmsuite_t *algosuite = NULL;

    algosuite = rampart_context_get_algorithmsuite(rampart_context,env);
    if(algosuite)
    {
        return rp_algorithmsuite_get_asymmetrickeywrap(algosuite,env);
    }
    else
        return NULL;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_asym_sig_algo(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_algorithmsuite_t *algosuite = NULL;

    algosuite = rampart_context_get_algorithmsuite(rampart_context,env);
    if(algosuite)
    {
        return rp_algorithmsuite_get_asymmetric_signature(algosuite,env);
    }
    else
        return NULL;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_sym_sig_algo(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_algorithmsuite_t *algosuite = NULL;

    algosuite = rampart_context_get_algorithmsuite(rampart_context, env);
    if(algosuite)
    {
        return rp_algorithmsuite_get_symmetric_signature(algosuite, env);
    }
    else
        return NULL;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_digest_mtd(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_algorithmsuite_t *algosuite = NULL;

    algosuite = rampart_context_get_algorithmsuite(rampart_context,env);
    if(algosuite)
    {
        return rp_algorithmsuite_get_digest(algosuite,env);
    }
    else
        return NULL;
}


AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_certificate_file(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *rampart_config = NULL;

    if(rampart_context->key_mgr && oxs_key_mgr_get_certificate_file(rampart_context->key_mgr, env))
    {
        return oxs_key_mgr_get_certificate_file(rampart_context->key_mgr, env);
    }

    rampart_config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(rampart_config)
    {
        return rp_rampart_config_get_certificate_file(rampart_config,env);
    }
    else
        return NULL;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_receiver_certificate_file(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *rampart_config = NULL;

    if(rampart_context->key_mgr && oxs_key_mgr_get_reciever_certificate_file(rampart_context->key_mgr, env))
    {
        return oxs_key_mgr_get_reciever_certificate_file(rampart_context->key_mgr, env);
    }

    rampart_config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(rampart_config)
    {
        return rp_rampart_config_get_receiver_certificate_file(rampart_config,env);
    }
    else
        return NULL;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_receiver_certificate_file(
	rampart_context_t *rampart_context,
	const axutil_env_t *env,
	axis2_char_t *receiver_certificate_file)
{
	AXIS2_PARAM_CHECK(env->error, receiver_certificate_file, AXIS2_FAILURE);

	return oxs_key_mgr_set_reciever_certificate_file(rampart_context->key_mgr, env, receiver_certificate_file);
}


AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_private_key_file(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *rampart_config = NULL;

    if(rampart_context->key_mgr && oxs_key_mgr_get_private_key_file(rampart_context->key_mgr, env))
    {
        return oxs_key_mgr_get_private_key_file(rampart_context->key_mgr, env);
    }
    rampart_config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(rampart_config)
    {
        return rp_rampart_config_get_private_key_file(rampart_config,env);
    }
    else
        return NULL;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_encryption_user(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_rampart_config_t *config = NULL;
    config = rp_secpolicy_get_rampart_config(rampart_context->secpolicy,env);
    if(!config)
        return NULL;

    return rp_rampart_config_get_encryption_user(config,env);

}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_is_token_type_supported(
    rp_property_type_t token_type,
    const axutil_env_t *env)
{
    if(token_type == RP_PROPERTY_X509_TOKEN)
        return AXIS2_TRUE;
    else if (token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
        return AXIS2_TRUE;
    else if (token_type == RP_PROPERTY_SAML_TOKEN)
        return AXIS2_TRUE;
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "We still only suppport X509 Tokens and security context tokens.");
        return AXIS2_FALSE;
    }
    /*This method will be extended when we are supporting other types of tokens.*/
}


AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_is_token_include(
    rampart_context_t *rampart_context,
    rp_property_t *token,
    rp_property_type_t token_type,
    axis2_bool_t server_side,
    axis2_bool_t is_inpath,
    const axutil_env_t *env)
{
    axis2_char_t *inclusion = NULL;
    axis2_bool_t include = AXIS2_FALSE;

    if(token_type == RP_PROPERTY_X509_TOKEN)
    {
        rp_x509_token_t *x509_token = NULL;
        x509_token = (rp_x509_token_t *)rp_property_get_value(token,env);
        inclusion = rp_x509_token_get_inclusion(x509_token,env);        
    }
    else if (token_type == RP_PROPERTY_ISSUED_TOKEN)
    {
        rp_issued_token_t *issued_token = NULL;
        issued_token = (rp_issued_token_t *)rp_property_get_value(token, env);
        inclusion = rp_issued_token_get_inclusion(issued_token,env);        
    }
    else if (token_type == RP_PROPERTY_SAML_TOKEN)
    {
        rp_saml_token_t *saml_token = NULL;
        saml_token = (rp_saml_token_t *)rp_property_get_value(token, env);
        inclusion = rp_saml_token_get_inclusion(saml_token, env);        
    }
    else if (token_type == RP_PROPERTY_SECURITY_CONTEXT_TOKEN)
    {
        rp_security_context_token_t *security_context_token = NULL;
        security_context_token = (rp_security_context_token_t *)rp_property_get_value(token, env);
        inclusion = rp_security_context_token_get_inclusion(security_context_token, env);
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "We still only support x509 tokens and security context tokens");
        return AXIS2_FALSE;
    }

    if(server_side)
    {
        if(is_inpath)
        {
            include = ((axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS)==0)||
                       (axutil_strcmp(inclusion,RP_INCLUDE_ONCE)==0)||
                       (axutil_strcmp(inclusion,RP_INCLUDE_ONCE_SP12)==0)||
                       (axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS_SP12)==0)||
                       (axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS_TO_RECIPIENT_SP12)==0)||
                       (axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS_TO_RECIPIENT)==0));
        }
        else
            include = ((axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS)==0) ||
                        (axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS_SP12)==0));
    }
    else
    {
        if(!is_inpath)
        {
            include = ((axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS)==0)||
                       (axutil_strcmp(inclusion,RP_INCLUDE_ONCE)==0)||
                       (axutil_strcmp(inclusion,RP_INCLUDE_ONCE_SP12)==0)||
                       (axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS_SP12)==0)||
                       (axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS_TO_RECIPIENT_SP12)==0)||
                       (axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS_TO_RECIPIENT)==0));
        }
        else
            include = ((axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS)==0) ||
                        (axutil_strcmp(inclusion,RP_INCLUDE_ALWAYS_SP12)==0));
    }
    return include;
    
}


AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_key_identifier(
    rampart_context_t *rampart_context,
    rp_property_t *token,
    const axutil_env_t *env)
{
    axis2_char_t *identifier = NULL;

    if(rp_property_get_type(token,env) == RP_PROPERTY_X509_TOKEN)
    {
        rp_x509_token_t *x509_token = NULL;
        x509_token = (rp_x509_token_t *)rp_property_get_value(token,env);

        if(!x509_token)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot get the token value from policy.");
            return NULL;
        }
        else
        {
            if(rp_x509_token_get_require_key_identifier_reference(x509_token,env))
                identifier = RAMPART_STR_KEY_IDENTIFIER;
            else if(rp_x509_token_get_require_issuer_serial_reference(x509_token,env))
                identifier = RAMPART_STR_ISSUER_SERIAL;
            else if(rp_x509_token_get_require_embedded_token_reference(x509_token,env))
                identifier = RAMPART_STR_EMBEDDED;
            else if(rp_x509_token_get_require_thumb_print_reference(x509_token,env))
                identifier = RAMPART_STR_THUMB_PRINT;
            else
                return rampart_context_get_key_identifier_from_wss(rampart_context,env);

            return identifier;
        }
    }
    /*This can be extended when we are supporting other token types.*/
    else return NULL;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_is_key_identifier_type_supported(
    rampart_context_t *rampart_context,
    rp_property_t *token,
    axis2_char_t *identifier,
    const axutil_env_t *env)
{
    if(axutil_strcmp(identifier, RAMPART_STR_KEY_IDENTIFIER)==0)
        return rampart_context_is_key_identifier_supported(token,rampart_context,env);

    else if(axutil_strcmp(identifier, RAMPART_STR_ISSUER_SERIAL)==0)
        return rampart_context_is_issuer_serial_supported(token,rampart_context,env);

    else if(axutil_strcmp(identifier, RAMPART_STR_EMBEDDED)==0)
        return rampart_context_is_embedded_token_supported(token,rampart_context,env);

    else
        return AXIS2_FALSE;
}


AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_layout(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    rp_binding_commons_t *binding_commons = NULL;
    rp_layout_t *layout = NULL;

    binding_commons = rampart_context_get_binding_commons(rampart_context,env);

    if(!binding_commons)
        return NULL;

    layout = rp_binding_commons_get_layout(binding_commons,env);
    if(!layout)
        return RP_LAYOUT_STRICT;

    return rp_layout_get_value(layout,env);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_increment_ref(rampart_context_t *rampart_context,
                              const axutil_env_t *env)
{
    rampart_context->ref++;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_encryption_token_id(
    rampart_context_t *rampart_context,
    const axutil_env_t *env, 
    axis2_msg_ctx_t *msg_ctx)
{
    if((!rampart_context->encryption_token_id) && (!axis2_msg_ctx_get_server_side(msg_ctx, env)))
    {
        /* used by scripting bindings */
        axis2_conf_ctx_t *conf_ctx = NULL;
        axis2_ctx_t *ctx = NULL;
        axutil_property_t *property = NULL;
        
        /* Get the conf ctx */
        conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
        if(!conf_ctx)
        {
            AXIS2_LOG_ERROR(env->log,AXIS2_LOG_SI, 
                "[rampart]Conf context is NULL. Cannot get encryption token id.");
            return NULL;
        }

        ctx = axis2_conf_ctx_get_base(conf_ctx,env);
        if(!ctx)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "[rampart]Axis2 context is NULL. Cannot get encryption token id.");
            return NULL;
        }

        /* Get the hash store property */
        property = axis2_ctx_get_property(ctx, env, RAMPART_ENC_TOKEN_ID);
        if(property)
        {
            /* Get the store */
            rampart_context->encryption_token_id = 
                (axis2_char_t*)axutil_property_get_value(property, env);
        }
    }
    return rampart_context->encryption_token_id;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
rampart_context_get_signature_token_id(
    rampart_context_t *rampart_context,
    const axutil_env_t *env, 
    axis2_msg_ctx_t *msg_ctx)
{
    if((!rampart_context->signature_token_id)&& (!axis2_msg_ctx_get_server_side(msg_ctx, env)))
    {
        /* used by scripting bindings */
        axis2_conf_ctx_t *conf_ctx = NULL;
        axis2_ctx_t *ctx = NULL;
        axutil_property_t *property = NULL;
        
        /* Get the conf ctx */
        conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
        if(!conf_ctx)
        {
            AXIS2_LOG_ERROR(env->log,AXIS2_LOG_SI, 
                "[rampart]Conf context is NULL. Cannot get signature token id.");
            return NULL;
        }

        ctx = axis2_conf_ctx_get_base(conf_ctx,env);
        if(!ctx)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "[rampart]Axis2 context is NULL. Cannot get signature token id.");
            return NULL;
        }

        /* Get the hash store property */
        property = axis2_ctx_get_property(ctx, env, RAMPART_SIG_TOKEN_ID);
        if(property)
        {
            /* Get the store */
            rampart_context->signature_token_id = 
                (axis2_char_t*)axutil_property_get_value(property, env);
        }
    }
    return rampart_context->signature_token_id;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_encryption_token_id(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axis2_char_t *sct_id, 
    axis2_msg_ctx_t *msg_ctx)
{
    if (!axis2_msg_ctx_get_server_side(msg_ctx, env))
    {
        /* used by scripting bindings */
        axis2_conf_ctx_t *conf_ctx = NULL;
        axis2_ctx_t *ctx = NULL;
        axutil_property_t *property = NULL;
        
        /* Get the conf ctx */
        conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
        if(!conf_ctx)
        {
            AXIS2_LOG_ERROR(env->log,AXIS2_LOG_SI, 
                "[rampart]Conf context is NULL. Cannot store encryption token id.");
            return AXIS2_FAILURE;
        }

        ctx = axis2_conf_ctx_get_base(conf_ctx,env);
        if(!ctx)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "[rampart]Axis2 context is NULL. Cannot store encryption token id.");
            return AXIS2_FAILURE;
        }

        /* Get the hash store property */
        property = axis2_ctx_get_property(ctx, env, RAMPART_ENC_TOKEN_ID);
        if(property)
        {
            axutil_property_set_value(property, env, sct_id);
        }
        else
        {
            property = axutil_property_create_with_args(env, AXIS2_SCOPE_APPLICATION,
                AXIS2_TRUE, (void *)NULL, sct_id);
            axis2_ctx_set_property(ctx, env, RAMPART_ENC_TOKEN_ID, property);
        }
    }
    rampart_context->encryption_token_id = sct_id;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_signature_token_id(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axis2_char_t *sct_id,
    axis2_msg_ctx_t *msg_ctx)
{
    if (!axis2_msg_ctx_get_server_side(msg_ctx, env))
    {
        /* used by scripting bindings */
        axis2_conf_ctx_t *conf_ctx = NULL;
        axis2_ctx_t *ctx = NULL;
        axutil_property_t *property = NULL;
        
        /* Get the op ctx */
        conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
        if(!conf_ctx)
        {
            AXIS2_LOG_ERROR(env->log,AXIS2_LOG_SI, 
                "[rampart]Conf context is NULL. Cannot store signature token id.");
            return AXIS2_FAILURE;
        }

        ctx = axis2_conf_ctx_get_base(conf_ctx,env);
        if(!ctx)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "[rampart]Axis2 context is NULL. Cannot store signature token id.");
            return AXIS2_FAILURE;
        }

        /* Get the hash store property */
        property = axis2_ctx_get_property(ctx, env, RAMPART_SIG_TOKEN_ID);
        if(property)
        {
            axutil_property_set_value(property, env, sct_id);
        }
        else
        {
            property = axutil_property_create_with_args(env, AXIS2_SCOPE_APPLICATION,
                AXIS2_TRUE, (void *)NULL, sct_id);
            axis2_ctx_set_property(ctx, env, RAMPART_SIG_TOKEN_ID, property);
        }
    }

    rampart_context->signature_token_id = sct_id;
    return AXIS2_SUCCESS;
}


AXIS2_EXTERN rampart_saml_token_t * AXIS2_CALL
rampart_context_get_saml_token(rampart_context_t *rampart_context,
                                        const axutil_env_t *env, 
										rampart_st_type_t token_type)
{
	rampart_saml_token_t *saml = NULL;
	int i = 0, size = 0;
    if (rampart_context->saml_tokens)
	{
		size = axutil_array_list_size(rampart_context->saml_tokens, env);
		for (i = 0; i < size; i++)
		{
			saml = axutil_array_list_get(rampart_context->saml_tokens, env, i);
			if (saml && rampart_saml_token_get_token_type(saml, env) == token_type)
			{
				return saml;
			}
		}
	}
	return NULL;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_add_saml_token(rampart_context_t *rampart_context,
                                        const axutil_env_t *env,
                                        rampart_saml_token_t *token)
{
	if (!rampart_context->saml_tokens)
	{
		rampart_context->saml_tokens = axutil_array_list_create(env, 3);
	}
	if (token)
	{
		axutil_array_list_add(rampart_context->saml_tokens, env, token);
		return AXIS2_SUCCESS;
	}
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_custom_tokens(rampart_context_t *rampart_context,
                                        const axutil_env_t *env,
                                        axutil_array_list_t *tokens)
{
    
    rampart_context->custom_tokens = tokens;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL
rampart_context_get_custom_tokens(rampart_context_t *rampart_context,
                                        const axutil_env_t *env)
{
    return rampart_context->custom_tokens;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_saml_tokens(rampart_context_t *rampart_context,
                                        const axutil_env_t *env,
                                        axutil_array_list_t *tokens)
{
	rampart_saml_token_t *saml = NULL;
	int i = 0, size = 0;
	if (rampart_context->saml_tokens)
	{
		size = axutil_array_list_size(rampart_context->saml_tokens, env);
		for (i = 0; i < size; i++)
		{
			saml = axutil_array_list_get(rampart_context->saml_tokens, env, i);
			if (saml)
			{
				rampart_saml_token_free(saml, env);
			}
		}
		axutil_array_list_free(rampart_context->saml_tokens, env);
	}
	rampart_context->saml_tokens = tokens;
	return AXIS2_SUCCESS;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_issued_token_aquire_function(rampart_context_t *rampart_context,
							  const axutil_env_t *env,
							  issued_token_callback_func issued_token_aquire)
{
	rampart_context->aquire_issued_token = issued_token_aquire;
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN issued_token_callback_func AXIS2_CALL
rampart_context_get_issued_token_aquire_function(rampart_context_t *rampart_context, 
							  const axutil_env_t *env)  
{
	return rampart_context->aquire_issued_token;
}

AXIS2_EXTERN rp_property_t *AXIS2_CALL
rampart_context_get_endorsing_token(rampart_context_t *rampart_context, 
                                    const axutil_env_t *env)
{
    axutil_array_list_t *array_list = NULL;
    rp_supporting_tokens_t *endorsing_supporting = NULL;
    /*First we should check in the direct policy members*/
    endorsing_supporting = rp_secpolicy_get_endorsing_supporting_tokens(rampart_context->secpolicy,env);
    /*If not there then we should check in the binding*/
    if (!endorsing_supporting)
    {
        rp_binding_commons_t *commons = NULL;
        commons = rampart_context_get_binding_commons(rampart_context,env);
        if(!commons)
            return NULL;
        endorsing_supporting = rp_binding_commons_get_endorsing_supporting_tokens(commons,env);
        if (!endorsing_supporting)
            return NULL;
    }
    array_list = rp_supporting_tokens_get_tokens(endorsing_supporting, env);
    if (!array_list)
        return NULL;
    else
    {
        int i = 0;
        for (i = 0; i < axutil_array_list_size(array_list, env); i++)
        {
            rp_property_t *token = NULL;
            token = (rp_property_t *)
                    axutil_array_list_get(array_list, env, i);
            if (token)
            {
                    return token; 
            }
        }
    }
    return NULL;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_key_mgr(rampart_context_t *rampart_context,
    const axutil_env_t *env, 
    oxs_key_mgr_t *key_mgr)  
{
    if (rampart_context->key_mgr)
        oxs_key_mgr_free(rampart_context->key_mgr, env);
    
    rampart_context->key_mgr = key_mgr;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN oxs_key_mgr_t * AXIS2_CALL
rampart_context_get_key_mgr(
	rampart_context_t *rampart_context,
	const axutil_env_t *env)
{
	return rampart_context->key_mgr;
}


AXIS2_EXTERN void * AXIS2_CALL
rampart_context_get_key_store_buff(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return oxs_key_mgr_get_key_store_buff(rampart_context->key_mgr, env);
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_key_store_buff(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    void *key_store_buf,
    int len)
{
    AXIS2_PARAM_CHECK(env->error, key_store_buf, AXIS2_FAILURE);
         
    oxs_key_mgr_set_key_store_buff(rampart_context->key_mgr, env, key_store_buf, len);
    
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_get_found_cert_in_shp(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->found_cert_in_shp;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_found_cert_in_shp(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    axis2_bool_t found_cert_in_shp)
{
    rampart_context->found_cert_in_shp = found_cert_in_shp;
    return AXIS2_SUCCESS;
}

/* This certificate is set to rampart context when we process the incoming security header
 * with key info
 */
AXIS2_EXTERN oxs_x509_cert_t *AXIS2_CALL
rampart_context_get_receiver_cert_found_in_shp(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->receiver_cert;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_receiver_cert_found_in_shp(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    oxs_x509_cert_t *cert)
{
    AXIS2_PARAM_CHECK(env->error, cert, AXIS2_FAILURE);
    
    rampart_context->receiver_cert = cert;
    
    return AXIS2_SUCCESS;
}


AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_store_security_context_token_fn(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    store_security_context_token_fn store_fn)
{
    rampart_context->store_sct_funtion = store_fn;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_obtain_security_context_token_fn(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    obtain_security_context_token_fn get_fn)
{
    rampart_context->obtain_sct_function = get_fn;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_delete_security_context_token_fn(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    delete_security_context_token_fn delete_fn)
{
    rampart_context->delete_sct_function = delete_fn;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_security_context_token_user_params(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    void* user_params)
{
    rampart_context->sct_user_params = user_params;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_context_set_validate_security_context_token_fn(
    rampart_context_t *rampart_context,
    const axutil_env_t *env,
    validate_security_context_token_fn validate_fn)
{
    rampart_context->validate_sct_function = validate_fn;
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN store_security_context_token_fn AXIS2_CALL
rampart_context_get_store_security_context_token_fn(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->store_sct_funtion;
}

AXIS2_EXTERN obtain_security_context_token_fn AXIS2_CALL
rampart_context_get_obtain_security_context_token_fn(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->obtain_sct_function;
}

AXIS2_EXTERN delete_security_context_token_fn AXIS2_CALL
rampart_context_get_delete_security_context_token_fn(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->delete_sct_function;
}

AXIS2_EXTERN void* AXIS2_CALL
rampart_context_get_security_context_token_user_params(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->sct_user_params;
}

AXIS2_EXTERN validate_security_context_token_fn AXIS2_CALL
rampart_context_get_validate_security_context_token_fn(
    rampart_context_t *rampart_context,
    const axutil_env_t *env)
{
    return rampart_context->validate_sct_function;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
rampart_context_is_different_session_key_for_enc_and_sign(
    const axutil_env_t *env,
    rampart_context_t *rampart_context)
{
    rp_property_t *binding = NULL;
    axis2_bool_t use_different_key = AXIS2_FALSE;

    if(rampart_context)
    {
        binding = rp_secpolicy_get_binding(rampart_context_get_secpolicy(rampart_context, env),env);
        if(binding)
        {
            if(rp_property_get_type(binding,env) == RP_PROPERTY_SYMMETRIC_BINDING)
            {
                rp_symmetric_binding_t *sym_binding = NULL;
                rp_property_t *token = NULL;
                sym_binding = (rp_symmetric_binding_t *)rp_property_get_value(binding,env);
                if(sym_binding)
                {
                    /* check protection tokens have being specified. If not (means encryption token 
                       and signature token is specified), use different session key for 
                       encryption and signature 
                    */
                    token = rp_symmetric_binding_get_protection_token(sym_binding,env);
                    if(!token)
                        use_different_key = AXIS2_TRUE;
                }
            }
        }
    }

    return use_different_key;
}



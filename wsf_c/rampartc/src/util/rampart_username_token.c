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

#include <rampart_username_token.h>
#include <rampart_crypto_util.h>
#include <rampart_util.h>
#include <rampart_handler_util.h>
#include <rampart_sec_processed_result.h>

/*
 * builds username token
 * @param env pointer to environment struct
 * @param rampart_context pointer to rampart context structure
 * @param sec_node Security header node
 * @param sec_ns_obj security namespace object
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
 */
axis2_status_t AXIS2_CALL
rampart_username_token_build(
    const axutil_env_t *env,
    rampart_context_t *rampart_context,
    axiom_node_t *sec_node,
    axiom_namespace_t *sec_ns_obj)
{
    axiom_node_t *ut_node = NULL;
    axiom_node_t *un_node = NULL;
    axiom_node_t *pw_node = NULL;
    axiom_element_t  *ut_ele = NULL;
    axiom_element_t *un_ele = NULL;
    axiom_element_t *pw_ele = NULL;
    axiom_namespace_t *wsu_ns_obj = NULL;
    axis2_char_t *password = NULL;
    axis2_char_t *username = NULL;
    axis2_char_t *password_type = NULL;
    axiom_attribute_t *om_attr = NULL;

    username = rampart_context_get_user(rampart_context, env);
    if(!username)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart] User name is not specified.");
        return AXIS2_FAILURE;
    }

    /* check whether password is given in the configuration. If it is given, we should use it */
    password = rampart_context_get_password(rampart_context, env);
    if(!password)
    {
        /* password is not given. So have to check whether call back function is given, or call back
         * module is given */

        password_callback_fn password_function = NULL;
        password_function = rampart_context_get_pwcb_function(rampart_context, env);
        if(password_function)
        {
            /* We can use the callback function to get the password */

            void *param = NULL;
            param = rampart_context_get_pwcb_user_params(rampart_context, env);
            if(!param)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[rampart]Callback parameter needed password callback function is not set.");
                return AXIS2_FAILURE;
            }
            password = (*password_function)(env, username, param);
        }
        else
        {
            /* callback function is not set. Check for password callback module */

            rampart_callback_t *password_callback = NULL;
            password_callback = rampart_context_get_password_callback(rampart_context, env);
            if(!password_callback)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[rampart]Password callback module is not loaded.");
                return AXIS2_FAILURE;
            }
            password = rampart_callback_password(env, password_callback, username);
        }

        /* check whether the password is valid */
        if(!password)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Cannot find the password for user %s.", username);
            return AXIS2_FAILURE;
        }
    }
    
    /* we have valid username and password. Can start to build UsernameToken */
    axiom_namespace_increment_ref(sec_ns_obj, env);
    ut_ele = axiom_element_create(
        env, sec_node, RAMPART_SECURITY_USERNAMETOKEN, sec_ns_obj, &ut_node);
    if(!ut_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]UsernameToken element creation failed.");
        return AXIS2_FAILURE;
    }

    wsu_ns_obj = axiom_namespace_create(env, RAMPART_WSU_XMLNS, RAMPART_WSU);
    axiom_element_declare_namespace(ut_ele, env, ut_node, wsu_ns_obj);
    
    /* Build Username element */
    axiom_namespace_increment_ref(sec_ns_obj, env);
    un_ele = axiom_element_create(
        env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_USERNAME, sec_ns_obj, &un_node);
    if(un_ele)
    {
        axiom_element_set_text(un_ele, env, username, un_node);
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Username element creation failed.");
        return AXIS2_FAILURE;
    }

    /* build remaining token based on password type */
    password_type = rampart_context_get_password_type(rampart_context, env);
    if(!password_type)
    {
        password_type = RAMPART_PASSWORD_TEXT;
    }

    if (!axutil_strcmp(password_type, RAMPART_PASSWORD_DIGEST))
    {
        axis2_char_t *nonce_val = NULL;
        axis2_char_t *created_val = NULL;
        axis2_char_t *digest_val = NULL;
        axis2_bool_t need_millisecond = AXIS2_TRUE;
        axiom_node_t *nonce_node = NULL;
        axiom_node_t *created_node = NULL;
        axiom_element_t *nonce_ele = NULL;
        axiom_element_t *created_ele = NULL;

        need_millisecond = rampart_context_get_need_millisecond_precision(rampart_context, env);
        nonce_val = oxs_util_generate_nonce(env, RAMPART_USERNAME_TOKEN_NONCE_LENGTH) ;
        created_val = rampart_generate_time(env, 0, need_millisecond); /* current time */
        digest_val = rampart_crypto_sha1(env, nonce_val, created_val, password);

        /* create password element */
        axiom_namespace_increment_ref(sec_ns_obj, env);
        pw_ele = axiom_element_create(
            env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_PASSWORD, sec_ns_obj, &pw_node);
        if(pw_ele)
        {
            axiom_element_set_text(pw_ele, env, digest_val, pw_node);
            om_attr = axiom_attribute_create(env, RAMPART_SECURITY_USERNAMETOKEN_PASSWORD_ATTR_TYPE, 
                RAMPART_PASSWORD_DIGEST_URI, NULL);
            axiom_element_add_attribute(pw_ele, env, om_attr, pw_node);
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Password element creation failed.");
            return AXIS2_FAILURE;
        }

        /* create Nonce element */
		axiom_namespace_increment_ref(sec_ns_obj, env);
        nonce_ele = axiom_element_create(
            env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_NONCE, sec_ns_obj, &nonce_node);
        if (nonce_ele)
        {
            axiom_element_set_text(nonce_ele, env, nonce_val , nonce_node);
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Nonce element creation failed.");
            return AXIS2_FAILURE;
        }

        /* create Created element */
        created_ele = axiom_element_create(
            env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_CREATED, wsu_ns_obj, &created_node);
        if (created_ele)
        {
            axiom_element_set_text(created_ele, env, created_val, created_node);
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Created element creation failed.");
            return AXIS2_FAILURE;
        }

        if(nonce_val)
        {
            AXIS2_FREE(env->allocator, nonce_val);
            nonce_val = NULL;
        }
        if(created_val)
        {
            AXIS2_FREE(env->allocator, created_val);
            created_val = NULL;
        }
        if(digest_val)
        {
            AXIS2_FREE(env->allocator, digest_val);
            digest_val = NULL;
        }
    }
    else 
    {
        /* default is passwordText */
		axiom_namespace_increment_ref(sec_ns_obj, env);
        pw_ele = axiom_element_create(
            env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_PASSWORD, sec_ns_obj, &pw_node);
        if (pw_ele)
        {
            axiom_element_set_text(pw_ele, env, password, pw_node);
            om_attr = axiom_attribute_create(env, RAMPART_SECURITY_USERNAMETOKEN_PASSWORD_ATTR_TYPE, 
                RAMPART_PASSWORD_TEXT_URI, NULL);
            axiom_element_add_attribute(pw_ele, env, om_attr, pw_node);
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Password element creation failed.");
            return AXIS2_FAILURE;
        }
    }

    return AXIS2_SUCCESS;
}

/*
 * Validates the given username token
 * @param env pointer to environment struct
 * @param msg_ctx axis2 message context
 * @param ut_node User name token node
 * @param rampart_context pointer to rampart context structure
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
 */
axis2_status_t AXIS2_CALL
rampart_username_token_validate(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx,
    axiom_node_t *ut_node,
    rampart_context_t *rampart_context)
{
    axiom_child_element_iterator_t *children = NULL;
    axis2_char_t *username = NULL;
    axis2_char_t *password = NULL;
    axis2_char_t *nonce = NULL;
    axis2_char_t *created = NULL;
    axis2_char_t *password_type = NULL;
    rampart_authn_provider_t *authn_provider = NULL;
    axis2_char_t *password_from_svr = NULL;
    axis2_char_t *password_to_compare = NULL;
	axis2_bool_t free_password_to_compare = AXIS2_FALSE;
    rampart_authn_provider_status_t auth_status= RAMPART_AUTHN_PROVIDER_GENERAL_ERROR ;
    axiom_element_t *ut_ele = NULL;
    
    ut_ele = axiom_node_get_data_element(ut_node, env);
    if(!ut_ele)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]UsernameToken element could not be retrieved from the node.");
        return AXIS2_FAILURE;
    }

    /* Check: Any USERNAME_TOKEN MUST NOT have more than one PASSWORD */
    if(1 <  oxs_axiom_get_number_of_children_with_qname(
        env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_PASSWORD, RAMPART_WSSE_XMLNS, RAMPART_WSSE))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Username token must not have more than one password");
        return AXIS2_FAILURE;
    }

    /* Check: Any USERNAME_TOKEN MUST NOT have more than one CREATED */
    if(1 <  oxs_axiom_get_number_of_children_with_qname(
        env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_CREATED, RAMPART_WSSE_XMLNS, RAMPART_WSSE))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Username token must not have more than one creted element");
        return AXIS2_FAILURE;
    }

    /* Check: Any USERNAME_TOKEN MUST NOT have more than one NONCE */
    if(1 < oxs_axiom_get_number_of_children_with_qname(
        env, ut_node, RAMPART_SECURITY_USERNAMETOKEN_NONCE, RAMPART_WSSE_XMLNS, RAMPART_WSSE))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Username token must not have more than one nonce element");
        return AXIS2_FAILURE;
    }

    /* Go thru children of UsernameToken element and validate */
    children = axiom_element_get_child_elements(ut_ele, env, ut_node);
    if(!children)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot find child elements of UsernameToken");
        return AXIS2_FAILURE;
    }

    /*Go thru children and find username token parameters*/
    while(axiom_child_element_iterator_has_next(children, env))
    {
        axiom_node_t *node = NULL;
        axiom_element_t *element = NULL;
        axis2_char_t *localname = NULL;

        node = axiom_child_element_iterator_next(children, env);
        element = axiom_node_get_data_element(node, env);
        localname =  axiom_element_get_localname(element, env);

        if(!axutil_strcmp(localname, RAMPART_SECURITY_USERNAMETOKEN_USERNAME))
        {
            username = axiom_element_get_text(element, env, node);
        }
        else if(!axutil_strcmp(localname, RAMPART_SECURITY_USERNAMETOKEN_PASSWORD))
        {
            axis2_char_t *password_type_pol = NULL;

            password_type = axiom_element_get_attribute_value_by_name(
                element, env, RAMPART_SECURITY_USERNAMETOKEN_PASSWORD_ATTR_TYPE);

            if(!password_type)
            {
                password_type = RAMPART_PASSWORD_TEXT_URI;
            }

            /* Then we must check the password type with policy */
            password_type_pol = rampart_context_get_password_type(rampart_context, env);
            if(!password_type_pol)
            {
                password_type_pol = RP_PLAINTEXT;
            }

            if(!axutil_strcmp(password_type_pol, RP_DIGEST))
            {
                if(axutil_strcmp(password_type, RAMPART_PASSWORD_DIGEST_URI))
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Password Type is wrong");
                    rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_AUTHENTICATION, 
                        "Password Type is Wrong. Should be Digested.", 
                        RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
                    return AXIS2_FAILURE;
                }
            }
            else if(!axutil_strcmp(password_type_pol, RP_PLAINTEXT))
            {
                if(!axutil_strcmp(password_type, RAMPART_PASSWORD_DIGEST_URI))
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Password Type is Wrong ");
                    rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_AUTHENTICATION,
                        "Password Type is Wrong. Should be PlainText.",
                        RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
                    return AXIS2_FAILURE;
                }
            }
            password = axiom_element_get_text(element, env, node);
        }
        else if(!axutil_strcmp(localname, RAMPART_SECURITY_USERNAMETOKEN_NONCE))
        {
            nonce = axiom_element_get_text(element, env, node);
            rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_UT_NONCE, nonce);
        }
        else if (!axutil_strcmp(localname , RAMPART_SECURITY_USERNAMETOKEN_CREATED))
        {
            created = axiom_element_get_text(element, env, node);
            rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_UT_CREATED, created);
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Unknown element found %s -> %s", 
                localname, axiom_element_get_text(element, env, node));
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_AUTHENTICATION,
                "Unknown element found in UsernameToken.", 
                RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
            return AXIS2_FAILURE;
        }
    }/* end of while */

    /* Now we process collected usernametoken parameters */
    if(!username)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart] Username is not specified in the UsernameToken.");
        rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_AUTHENTICATION,
            "Username is not specified in UsernameToken.", RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
        return AXIS2_FAILURE;
    }

    /* Set the username to the SPR */
    rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_UT_USERNAME, username);

    /**
     * NOTE: Here we will try following apraoches to get the UT validated
     * 1. Authentication function (will get username, password and verify them)
     * 2. Authentication module (will get username, password and verify them)
     * 3. Direct username and password set in rampart context. 
     * 4. Password callback function (will get username and return password)
     * 5. Password callback module (will get username and return password)
     *
     * If authentication module is defined use it. 
     * Else try the usual approach to get password from the callback and compare
     **/

    /* We should first try to use function pointers. Function pointers will be different for digest 
     * password and plain password. */
    if (!axutil_strcmp(password_type, RAMPART_PASSWORD_DIGEST_URI))
    {
        auth_digest_func authenticate_with_digest = NULL;
        authenticate_with_digest = rampart_context_get_auth_digest_function( rampart_context, env);
        if(authenticate_with_digest)
        {
            auth_status = authenticate_with_digest(env, username, nonce, created, password, NULL);
            if(RAMPART_AUTHN_PROVIDER_GRANTED == auth_status)
            {
                AXIS2_LOG_INFO(env->log, "[rampart]User authenticated");
                rampart_set_security_processed_result(
                    env, msg_ctx,RAMPART_SPR_UT_CHECKED, RAMPART_YES);
                return AXIS2_SUCCESS;
            }
            else
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[rampart]Password is not valid for user %s : status %d", 
                    username, auth_status);
                return AXIS2_FAILURE;
            }
        }
    }
    else
    {
        auth_password_func auth_with_password = NULL;
        auth_with_password = rampart_context_get_auth_password_function(rampart_context, env);
        if(auth_with_password)
        {
            auth_status = auth_with_password(env, username, password, NULL);
            if(RAMPART_AUTHN_PROVIDER_GRANTED == auth_status)
            {
                AXIS2_LOG_INFO(env->log, "[rampart]User authenticated");
                rampart_set_security_processed_result(
                    env, msg_ctx, RAMPART_SPR_UT_CHECKED, RAMPART_YES);
                return AXIS2_SUCCESS;
            }
            else
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[rampart]Password is not valid for user %s : status %d", 
                    username, auth_status);
                return AXIS2_FAILURE;
            }
        }
    }

    /* password function is not given. so check authentication provider module */
    authn_provider = rampart_context_get_authn_provider(rampart_context, env);
    if(authn_provider)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[rampart]Password authentication using AUTH MODULE");
        auth_status = rampart_authenticate_un_pw(
            env, authn_provider, username, password, nonce, created, password_type, msg_ctx);
        if(RAMPART_AUTHN_PROVIDER_GRANTED == auth_status)
        {
            AXIS2_LOG_INFO(env->log, "[rampart]User authenticated");
            rampart_set_security_processed_result(
                env, msg_ctx, RAMPART_SPR_UT_CHECKED, RAMPART_YES);
            return AXIS2_SUCCESS;
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "[rampart]Password is not valid for user %s : status %d", username, auth_status);
            return AXIS2_FAILURE;
        }
    }

    /* Authentication provider module is not given. Then we must check the direct password. */
    password_from_svr = rampart_context_get_password( rampart_context, env);
    if(password_from_svr)
    {
        /* If the direct passowrd is available, then chk for the username too in the context. 
         * We need to compare it with the message's username. The reason is here we do not use 
         * callbacks. Thus there will be no failure if the username is wrong and the password is 
         * correct */
        axis2_char_t *context_usr = NULL;
        context_usr = rampart_context_get_user(rampart_context, env);
        if(axutil_strcmp(context_usr, username))
        {
            rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, "Username is not valid.", 
                RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Username given in UsernameToken is not valid");
            return AXIS2_FAILURE;
        }
    }
    else
    {
        /* direct password is not given. so have to check whether password callback function is
         * available. If so, use it to get the password */

        password_callback_fn password_function = NULL;
        password_function = rampart_context_get_pwcb_function(rampart_context, env);
        if(password_function)
        {
            void *param = NULL;
            param = rampart_context_get_pwcb_user_params(rampart_context, env);
            if(!param)
            {
                rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, 
                    "Error in the Internal configuration.", 
                    RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[rampart]User parameter needed by password callback function is not given.");
                return AXIS2_FAILURE;
            }
            password_from_svr = (*password_function)(env, username, param);
        }
        else
        {
            /* password callback function is not given. so have to check password callback module */
            
            rampart_callback_t *password_callback = NULL;
            password_callback = rampart_context_get_password_callback(rampart_context, env);
            if(!password_callback)
            {
                rampart_create_fault_envelope(env, RAMPART_FAULT_FAILED_CHECK, 
                    "Error in the Internal configuration.", 
                    RAMPART_FAULT_IN_USERNAMETOKEN, msg_ctx);
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                    "[rampart]Password callback module is not specified");
                return AXIS2_FAILURE;
            }
            password_from_svr = rampart_callback_password(env, password_callback, username);
        }

        if(!password_from_svr)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[rampart]Cannot get the password for user %s", username);
            return AXIS2_FAILURE;
        }
    }

    /* NOW we have the password. Is digest needed? */
    if (!axutil_strcmp(password_type, RAMPART_PASSWORD_DIGEST_URI))
    {
        password_to_compare = rampart_crypto_sha1(env, nonce, created, password_from_svr);
        rampart_set_security_processed_result(
            env, msg_ctx, RAMPART_SPR_UT_PASSWORD_TYPE, RAMPART_PASSWORD_DIGEST_URI);
		free_password_to_compare = AXIS2_TRUE;
    }
    else
    {
        password_to_compare = password_from_svr;
        rampart_set_security_processed_result(
            env, msg_ctx, RAMPART_SPR_UT_PASSWORD_TYPE, RAMPART_PASSWORD_TEXT_URI);
    }

    /* The BIG moment. Compare passwords */
    if (!axutil_strcmp(password_to_compare , password))
    {
        AXIS2_LOG_INFO(env->log, "[rampart]Password comparison SUCCESS");
        rampart_set_security_processed_result(env, msg_ctx, RAMPART_SPR_UT_CHECKED, RAMPART_YES);
		if(free_password_to_compare)
		{
			AXIS2_FREE(env->allocator, password_to_compare);
		}
        return AXIS2_SUCCESS;
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Password is not valid for user %s", username);
		if(free_password_to_compare)
		{
			AXIS2_FREE(env->allocator, password_to_compare);
		}
        return AXIS2_FAILURE;
    }
}

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

#include <oxs_key_mgr.h>
#include <oxs_tokens.h>
#include <oxs_xml_key_processor.h>
#include <axiom_util.h>
#include <rampart_token_processor.h>
#include <rampart_saml.h>
#include <rampart_sec_header_processor.h>
#include <saml.h>

/**
 * extract certificate/key using reference id given in reference node
 */
static axis2_status_t
rampart_token_process_direct_ref(
    const axutil_env_t *env,
    axiom_node_t *ref_node,
    axiom_node_t *scope_node,
    axis2_msg_ctx_t *msg_ctx,
    rampart_context_t *rampart_context,
    oxs_x509_cert_t **cert,
    oxs_key_t **key,
    axis2_char_t **token_type)
{
    axis2_char_t *ref_id = NULL;
    axis2_bool_t external_reference = AXIS2_TRUE;

    /* Get the reference value in the @URI */
    ref_id = oxs_token_get_reference(env, ref_node);
    *token_type = oxs_token_get_reference_value_type(env, ref_node);

    if(!ref_id)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Failed to get key name from reference node");
        return AXIS2_FAILURE;
    }

    if(ref_id[0] == '#')
    {
        /* Need to remove # sign from the ID */
        axis2_char_t *id = NULL;
        id = axutil_string_substring_starting_at(axutil_strdup(env, ref_id), 1);
        external_reference = AXIS2_FALSE;
        ref_id = id;
        if(!ref_id)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Failed to get key name from reference node");
            return AXIS2_FAILURE;
        }
    }

    if(!external_reference)
    {
        /* this could point to binary security token, which means it is x509 token */
        axiom_node_t *bst_node = NULL;
        axis2_char_t *data = NULL;

        bst_node = oxs_axiom_get_node_by_id(env, scope_node, OXS_ATTR_ID, ref_id, OXS_WSU_XMLNS);
        if(bst_node)
        {
            axis2_char_t *local_name = NULL;
            local_name = axiom_util_get_localname(bst_node, env);
            if(!axutil_strcmp(local_name, OXS_NODE_BINARY_SECURITY_TOKEN))
            {
                /* This is an X509 token */
                *token_type = oxs_token_get_reference_value_type(env, bst_node);

                /* Process data. */
                data = oxs_axiom_get_node_content(env, bst_node);
                *cert = oxs_key_mgr_load_x509_cert_from_string(env, data);
                if(*cert)
                {
                    return AXIS2_SUCCESS;
                }
                else
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "Cannot load certificate from string =%s", data);
                    return AXIS2_FAILURE;
                }
            }
        }
    }

    *key = rampart_context_get_key(rampart_context, env, ref_id);
    if(!(*key) && external_reference)
    {
        if((0 == axutil_strcmp(*token_type, OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_02)) ||
            (0 == axutil_strcmp(*token_type, OXS_VALUE_TYPE_SECURITY_CONTEXT_TOKEN_05_12)))
        {
            rampart_shp_add_security_context_token(env, ref_id, ref_id, rampart_context, msg_ctx);
        }
        *key = rampart_context_get_key(rampart_context, env, ref_id);
    }

    if(!(*key))
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot find key referenced by URI %s", ref_id);
        return AXIS2_FAILURE;
    }
    return AXIS2_SUCCESS;
}

/**
 * extract certificate/key using key identifier
 */
static axis2_status_t
rampart_token_process_key_identifier(
    const axutil_env_t *env,
    axiom_node_t *key_identifier_node,
    axiom_node_t *scope_node,
    axiom_node_t *str_node,
    rampart_context_t *rampart_context,
    axis2_bool_t is_signature,
    oxs_x509_cert_t **cert,
    oxs_key_t **key,
    axis2_char_t **token_type)
{
    axis2_char_t *value_type = NULL;
    value_type = oxs_axiom_get_attribute_value_of_node_by_name(env, key_identifier_node,
        OXS_ATTR_VALUE_TYPE, NULL);

    if(axutil_strcmp(value_type, OXS_X509_SUBJ_KI) == 0)/* X509 Token */
    {
        /* In the client side, it is preferred to use certificate files instead of key store,
         * because one client normally interact with only one service. To handle this scenario,
         * if we found receiver certificate file specified in rampart_context we directly call the
         * get_reciever_certificate.
         */
        *cert = rampart_context_get_receiver_certificate(rampart_context, env);
        if(!*cert)
        {
            axis2_char_t *ski = NULL;
            oxs_key_mgr_t *key_mgr = NULL;
            key_mgr = rampart_context_get_key_mgr(rampart_context, env);
            ski = oxs_axiom_get_node_content(env, key_identifier_node);
            *cert = oxs_key_mgr_get_receiver_certificate_from_ski(key_mgr, env, ski);
            if(!*cert)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                    "Cannot retrieve certificate using key identifier");
                return AXIS2_FAILURE;
            }
        }
    }
    else if(axutil_strcmp(value_type, OXS_X509_ENCRYPTED_KEY_SHA1) == 0) /* EncryptedKey */
    {
        axis2_char_t *hash_value = NULL;
        hash_value = oxs_axiom_get_node_content(env, key_identifier_node);
        if(!hash_value)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Failed to get value of EncryptedKeySHA1");
            return AXIS2_FAILURE;
        }

        *key = rampart_context_get_key_using_hash(rampart_context, env, hash_value);
        if(!*key)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "Cannot get key corresponding to EncryptedKeySHA1");
            return AXIS2_FAILURE;
        }
    }
    else if(axutil_strcmp(value_type, OXS_ST_KEY_ID_VALUE_TYPE) == 0) /* SAML token reference */
    {
        axiom_node_t *assertion = NULL;
        rampart_saml_token_t *saml = NULL;
        rampart_st_type_t tok_type;
        oxs_key_mgr_t *key_mgr = NULL;
        openssl_pkey_t *pvt_key = NULL;

        key_mgr = rampart_context_get_key_mgr(rampart_context, env);
        pvt_key = oxs_key_mgr_get_prv_key(key_mgr, env);
        if(!pvt_key)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot load private key");
            return AXIS2_FAILURE;
        }

        assertion = oxs_saml_token_get_from_key_identifer_reference(env, key_identifier_node, NULL);
        if(!assertion)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot get key SAML Assertion");
            return AXIS2_FAILURE;
        }
        if(is_signature)
        {
            tok_type = RAMPART_ST_TYPE_SIGNATURE_TOKEN;
        }
        else
        {
            tok_type = RAMPART_ST_TYPE_ENCRYPTION_TOKEN;
        }
        saml = rampart_saml_add_token(rampart_context, env, assertion, str_node, tok_type);
        *key = rampart_saml_token_get_session_key(saml, env);
        if(!*key)
        {
            *key = saml_assertion_get_session_key(env, assertion, pvt_key);
            rampart_saml_token_set_session_key(saml, env, *key);
            oxs_key_set_name(*key, env, "for-algo");
        }

        if(!*key)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot get key corresponding to SAML Token");
            return AXIS2_FAILURE;
        }
    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Failed to identify Key Identifier %s", value_type);
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}
/**
 * extract embedded certificate from given embed_node
 */
static axis2_status_t
rampart_token_process_embedded(
    const axutil_env_t *env,
    axiom_node_t *embed_node,
    oxs_x509_cert_t **cert)
{
    axis2_char_t *data = NULL;
    axiom_node_t *bst_node = NULL;

    bst_node = axiom_node_get_first_element(embed_node, env);
    if(!bst_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "BinarySecurityToken element is not found");
        return AXIS2_FAILURE;
    }

    /* Process data */
    data = oxs_axiom_get_node_content(env, bst_node);
    *cert = oxs_key_mgr_load_x509_cert_from_string(env, data);
    if(!*cert)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot load certificate from string =%s", data);
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}

/* Get the client certificate from key manager by giving
 * issuer and serial number of the certificate
 */
static oxs_x509_cert_t *
rampart_token_process_issuer_serial(
    const axutil_env_t *env,
    rampart_context_t *rampart_ctx,
    axiom_node_t *x509_data_node)
{
    oxs_x509_cert_t *cert = NULL;
    axiom_node_t *issuer_serial_node = NULL;
    axiom_element_t *issuer_serial_ele = NULL;
    axiom_child_element_iterator_t *child_itr = NULL;
    axiom_node_t *child_node = NULL;
    axiom_element_t *child_ele = NULL;
    axis2_char_t *ele_name = NULL;
    axis2_char_t *issuer_name_str = NULL;
    axis2_char_t *serial_num_str = NULL;
    int serial_num = -1;
    oxs_key_mgr_t *key_mgr = NULL;

    if((cert = rampart_context_get_receiver_certificate(rampart_ctx, env)))
    {
        /* In the client side, it is preferred to use certificate files instead
         * of key store, because one client normally interact with only one
         * service. To handle this scenario, if we found receiver certificate file
         * specified in rampart_context we directly call the get_reciever_certificate.
         */
        return cert;
    }

    issuer_serial_node = axiom_node_get_first_child(x509_data_node, env);
    issuer_serial_ele = axiom_node_get_data_element(issuer_serial_node, env);

    child_itr = axiom_element_get_child_elements(issuer_serial_ele, env, issuer_serial_node);
    while(axiom_child_element_iterator_has_next(child_itr, env))
    {
        child_node = axiom_child_element_iterator_next(child_itr, env);
        child_ele = axiom_node_get_data_element(child_node, env);
        ele_name = axiom_element_get_localname(child_ele, env);
        if(axutil_strcmp(ele_name, OXS_NODE_X509_ISSUER_NAME) == 0)
        {
            issuer_name_str = axiom_element_get_text(child_ele, env, child_node);
            if(!issuer_name_str)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Issuer Name cannot be NULL.");
                return NULL;
            }
            AXIS2_LOG_INFO(env->log, AXIS2_LOG_SI, "X509 Certificate Issuer Name Found: %s",
                issuer_name_str);
        }
        else if(axutil_strcmp(ele_name, OXS_NODE_X509_SERIAL_NUMBER) == 0)
        {
            serial_num_str = axiom_element_get_text(child_ele, env, child_node);
            if(!serial_num_str)
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Serial number cannot be null.");
            }
            AXIS2_LOG_INFO(env->log, AXIS2_LOG_SI, "X509 Certificate Serial Number Found: %s",
                serial_num_str);
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "Error in incoming key info. These types not supported: %", ele_name);
            return NULL;
        }
    }

    serial_num = atoi(serial_num_str);
    key_mgr = rampart_context_get_key_mgr(rampart_ctx, env);

    cert = oxs_key_mgr_get_receiver_certificate_from_issuer_serial(key_mgr, env, issuer_name_str,
        serial_num);

    return cert;
}

/**
 * Extract certificate/session_key related information using given key_info node and scope node
 * This will extract either certificate(asymmetric signing) or session_key (symmetric signing)
 * @param env Environment structure
 * @param key_info_node key info node.
 * @param rampart_context rampart context where key details could be found.
 * @param msg_ctx message context
 * @param is_signature boolean denoting whether the key_info is for signature
 * @param cert where the certificate extracted (if any) should be populated
 * @param key where the session key extracted (if any) should be populated
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_process_key_info(
    const axutil_env_t *env,
    axiom_node_t *key_info_node,
    axiom_node_t *sec_node,
    rampart_context_t* rampart_context,
    axis2_msg_ctx_t *msg_ctx,
    axis2_bool_t is_signature,
    oxs_x509_cert_t **cert,
    oxs_key_t **key,
    axis2_char_t **token_type,
    axis2_char_t **reference_method)
{
    axiom_node_t *str_node = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    /* Get the SecurityTokenReference, which is the common case, but not the only case */
    str_node = oxs_axiom_get_first_child_node_by_name(env, key_info_node,
        OXS_NODE_SECURITY_TOKEN_REFRENCE, OXS_WSSE_XMLNS, NULL);

    if(str_node)
    {
        axiom_node_t *str_child_node = NULL;

        /* A <wsse:SecurityTokenReference> element MAY reference an X.509 token type
         * by one of the following means:
         *  - Reference to a Subject Key Identifier (<wsse:KeyIdentifier>)
         *  - Reference to a Binary Security Token (<wsse:Reference> element that
         *    references a local <wsse:BinarySecurityToken> element or a remote data
         *    source that contains the token data itself)
         *  - Reference to an Issuer and Serial Number (<ds:X509Data> element that
         *    contains a <ds:X509IssuerSerial> element that uniquely identifies an
         *    end entity certificate)
         */
        str_child_node = axiom_node_get_first_element(str_node, env);
        if(!str_child_node)
        {
             AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "No Child node in the Security Token Reference Element.");
            return AXIS2_FAILURE;
        }

        *reference_method = axiom_util_get_localname(str_child_node, env);
        if(!*reference_method)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "Cannot get the key Reference Type from the message.");
            return AXIS2_FAILURE;
        }

        if(0 == axutil_strcmp(*reference_method, OXS_NODE_REFERENCE))
        {
            status = rampart_token_process_direct_ref(env, str_child_node, sec_node, msg_ctx,
                rampart_context, cert, key, token_type);
        }
        else if(0 == axutil_strcmp(*reference_method, OXS_NODE_EMBEDDED))
        {
            /* embedded tokens are only possible with x509 token */
            status = rampart_token_process_embedded(env, str_child_node, cert);
        }
        else if(0 == axutil_strcmp(*reference_method, OXS_NODE_KEY_IDENTIFIER))
        {
            status = rampart_token_process_key_identifier(env, str_child_node, sec_node, str_node,
                rampart_context, is_signature, cert, key, token_type);
        }
        else if(0 == axutil_strcmp(*reference_method, OXS_NODE_X509_DATA))
        {
            /* <ds:X509Data> contains a <ds:X509IssuerSerial> element which is used to specify a
             * reference to an X.509 security token by means of the certificate issuer name and
             * serial number. */
            *cert = rampart_token_process_issuer_serial(env, rampart_context, str_child_node);
            status = AXIS2_SUCCESS;
        }
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Key Reference %s not supported ",
                *reference_method);
            return AXIS2_FAILURE;
        }
    }
    else
    {
        /* There may be scenarios where there is no Security Token Reference Element. */

        /*In such case policy support only Isssuer Serial scenario.*/

        /*if(axutil_strcmp(eki, RAMPART_STR_ISSUER_SERIAL) == 0)
        {
            key_info_child_node = axiom_node_get_first_element(key_info_node, env);
            if(key_info_child_node)
            {
                axis2_char_t *key_info_child_name = NULL;
                key_info_child_name = axiom_util_get_localname(key_info_child_node, env);
                if(key_info_child_name)
                {
                    if(0 == axutil_strcmp(key_info_child_name, OXS_NODE_X509_DATA))
                    {
                        status = rampart_token_process_x509_data(env, key_info_child_node, cert);
                        if(status != AXIS2_SUCCESS || !cert)
                        {
                            rampart_create_fault_envelope(env,
                                RAMPART_FAULT_INVALID_SECURITY_TOKEN,
                                "Cannot load the key to verify the message .",
                                RAMPART_FAULT_IN_SIGNATURE, msg_ctx);
                            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                                "[Rampart][shp] Cannot load the key to verify the message");
                            return AXIS2_FAILURE;
                        }
                    }
                    else
                    {
                        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[Rampart][shp]Cannot get the key Reference Type from the message.");
                        return AXIS2_FAILURE;
                    }
                }
                else
                {
                    AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[Rampart][shp]Cannot get the key Reference Type from the message.");
                    return AXIS2_FAILURE;
                }
            }
            else
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                    "[Rampart][shp]Cannot get the key Reference Type from the message.");
                return AXIS2_FAILURE;
            }
        }

        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                "[Rampart][shp]Can't be used as a direct child of Key Info");
            return AXIS2_FAILURE;
        }*/

        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Failed to key from key_info node");
        return AXIS2_FAILURE;
    }

    if((status != AXIS2_SUCCESS) || ((!*cert) && (!*key)))
    {
        /* either status is AXIS2_FAILURE or both cert and key are NULL. This means error */
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Cannot get key/certificate from key info node");
        return AXIS2_FAILURE;
    }

    return AXIS2_SUCCESS;
}




#if 0
/**
 * extract certificate related information using given token_reference node and scope node
 * @param env Environment structure
 * @param st_ref_node security token reference node.
 * @param scope_node node where additional details should be found. Can be NULL for all other
 *  scenarios but the Direct Reference
 * @param cert certificate where values extracted shuold be populated
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_process_security_token_reference(
    const axutil_env_t *env,
    axiom_node_t *st_ref_node,
    axiom_node_t *scope_node,
    oxs_x509_cert_t *cert)
{
    axis2_char_t *child_name = NULL;
    axiom_node_t *child_node = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    child_node = axiom_node_get_first_element(st_ref_node, env);
    child_name = axiom_util_get_localname(child_node, env);

    if(!axutil_strcmp(child_name, OXS_NODE_REFERENCE))
    {
        status = rampart_token_process_direct_ref(env, child_node, scope_node, cert);
    }
    else if(!axutil_strcmp(child_name, OXS_NODE_EMBEDDED))
    {
        status = rampart_token_process_embedded(env, child_node, cert);
    }
    else if(!axutil_strcmp(child_name, OXS_NODE_KEY_IDENTIFIER))
    {
        status = rampart_token_process_key_identifier(env, child_node, cert);
    }
    else if(!axutil_strcmp(child_name, OXS_NODE_X509_DATA))
    {
        status = rampart_token_process_x509_data(env, child_node, cert);
    }
    else
    {
        /* reference method is not supported */
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart]%s of wsse:SecurityTokenReference is not supported.", child_name);
        return AXIS2_FAILURE;
    }

    return status;
}

/**
 * extract key identifier and populate the certificate
 * @param env Environment structure
 * @param ki_node node where key identifier is available.
 * @param cert certificate where values extracted shuold be populated
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_process_key_identifier(
    const axutil_env_t *env,
    axiom_node_t *ki_node,
    oxs_x509_cert_t *cert)
{
    axis2_char_t *ki = NULL;

    ki = oxs_axiom_get_node_content(env, ki_node);
    oxs_x509_cert_set_key_identifier(cert, env, ki);
    return AXIS2_SUCCESS;
}

/**
 * extract key details from x509data node
 * @param env Environment structure
 * @param x509_data_node x509data node.
 * @param cert certificate where values extracted shuold be populated
 * @return status of the operation
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_process_x509_data(
    const axutil_env_t *env,
    axiom_node_t *x509_data_node,
    oxs_x509_cert_t *cert)
{
    return oxs_xml_key_process_X509Data(env, x509_data_node, cert);
}

#endif

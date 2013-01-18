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

#include <axis2_util.h>
#include <rampart_token_builder.h>
#include <oxs_tokens.h>
#include <rampart_constants.h>

/**
 * Build a SecurityTokenReference element according to the pattern specified in @pattern.
 * The token will be attached to the node @parent and relavent data will be extracted from 
 * certificate @cert. 
 * @param env pointer to environment struct
 * @param parent The parent node
 * @param cert The X509 certificate
 * @param pattern The build pattern
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_build_security_token_reference(
    const axutil_env_t *env,
    axiom_node_t *parent,
    oxs_x509_cert_t *cert,
    rampart_token_build_pattern_t pattern)
{
    axis2_status_t status = AXIS2_FAILURE;
    axiom_node_t *stref_node = NULL;

    stref_node = oxs_token_build_security_token_reference_element(env, parent);

    if(RTBP_EMBEDDED == pattern)
    {
        status = rampart_token_build_embedded(env, stref_node, cert);
    }
    else if(RTBP_KEY_IDENTIFIER == pattern)
    {
        status = rampart_token_build_key_identifier(env, stref_node, cert);
    }
    else if(RTBP_X509DATA_X509CERTIFICATE == pattern)
    {
        status = rampart_token_build_x509_data_x509_certificate(env, stref_node, cert);
    }
    else if(RTBP_X509DATA_ISSUER_SERIAL == pattern)
    {
        status = rampart_token_build_x509_data_issuer_serial(env, stref_node, cert);
    }
    else if(RTBP_THUMBPRINT == pattern)
    {
        status = rampart_token_build_thumbprint_reference(env, stref_node, cert);
    }
    else
    {
        /* reference method is not supported */
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Unsupported pattern %d to build wsse:SecurityTokenReference ", pattern);
        return AXIS2_FAILURE;
    }

    return status;
}

/**
 * Build an Embedded token with data available in the certificate.
 *        <SecurityTokenReference>
 *            <Embedded>
 *                <BinarySecurityToken>UYISDjsdaousdWEqswOIUsd</BinarySecurityToken>
 *            </Embedded>
 *        </SecurityTokenReference>
 * @param env pointer to environment struct
 * @param parent The parent node
 * @param cert The X509 certificate
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_build_embedded(
    const axutil_env_t *env,
    axiom_node_t *parent,
    oxs_x509_cert_t *cert)
{
    axis2_char_t *data  = NULL;
    axis2_char_t *bst_id  = NULL;
    axiom_node_t *embedded_node = NULL;
    axiom_node_t *bst_node = NULL;

    /* Get data from the certificate */
    data = oxs_x509_cert_get_data(cert, env);
    if(!data)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get data from the x509 certificate.");
        return AXIS2_FAILURE;
    }

    embedded_node = oxs_token_build_embedded_element(env, parent, RAMPART_EMBED_TOKEN_ID);
    bst_id = oxs_util_generate_id(env, RAMPART_BST_ID_PREFIX);
    bst_node =  oxs_token_build_binary_security_token_element(
        env, embedded_node, bst_id ,OXS_ENCODING_BASE64BINARY, OXS_VALUE_X509V3, data);
    return AXIS2_SUCCESS;
}

/**
 * Build a KeyIndentifer token with data available in the certificate.
 *        <SecurityTokenReference>
 *            <KeyIdentifier>WEqswOIUsd</KeyIdentifier>
 *        </SecurityTokenReference>
 * @param env pointer to environment struct
 * @param parent The parent node
 * @param cert The X509 certificate
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_build_key_identifier(
    const axutil_env_t *env,
    axiom_node_t *parent,
    oxs_x509_cert_t *cert)
{
    axiom_node_t *ki_node = NULL;
    axis2_char_t *ki =  NULL;

    ki = oxs_x509_cert_get_key_identifier(cert, env);
    if(!ki)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get key identifier from the x509 certificate.");
        return AXIS2_FAILURE;
    }

    ki_node = oxs_token_build_key_identifier_element(
        env, parent, OXS_ENCODING_BASE64BINARY, OXS_X509_SUBJ_KI, ki);
    return AXIS2_SUCCESS;
}

/*
 * Build an X509Certificate token with data available in the certificate.
 *        <SecurityTokenReference>
 *          <ds:X509Data>
 *              <ds:X509Certificate>
 *                  MIICzjCCAjegAwIBAgIJANyD+jwekxGuMA......
 *              </ds:X509Certificate>
 *          <ds:X509Data>
 *        </SecurityTokenReference>
 * @param env pointer to environment struct
 * @param parent The parent node
 * @param cert The X509 certificate
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_build_x509_data_x509_certificate(
    const axutil_env_t *env,
    axiom_node_t *parent,
    oxs_x509_cert_t *cert)
{
    axiom_node_t *x509_data_node = NULL;
    axiom_node_t *x509_cert_node = NULL;
    axis2_char_t *data = NULL;

    data = oxs_x509_cert_get_data(cert, env);
    if(!data)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get data from the x509 certificate.");
        return AXIS2_FAILURE;
    }

    x509_data_node = oxs_token_build_x509_data_element(env, parent);
    x509_cert_node = oxs_token_build_x509_certificate_element(env, x509_data_node, data);

    return AXIS2_SUCCESS;
}

/**
 * Build an X509IssuerSerial token with data available in the certificate.
 *        <SecurityTokenReference>
 *            <x509Data>
 *                <X509IssuerSerial>
 *                    <X509IssuerName>C=US, O=VeriSign, Inc.,</X509IssuerName>
 *                    <X509SerialNumber>93243297328</X509SerialNumber>
 *                </X509IssuerSerial>
 *            </x509Data>
 *        </SecurityTokenReference>
 * @param env pointer to environment struct
 * @param parent The parent node
 * @param cert The X509 certificate
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_build_x509_data_issuer_serial(
    const axutil_env_t *env,
    axiom_node_t *parent,
    oxs_x509_cert_t *cert)
{
    axiom_node_t *x509_data_node = NULL;
    axiom_node_t *x509_issuer_serial_node = NULL;
    axis2_char_t *issuer = NULL;
    int serial = -1;
    axis2_char_t serial_no[20];

    issuer = oxs_x509_cert_get_issuer(cert, env);
    serial = oxs_x509_cert_get_serial_number(cert, env);

    if(!issuer)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get issuer from the x509 certificate.");
        return AXIS2_FAILURE;
    }

    if(serial == -1)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot get serial from the x509 certificate.");
        return AXIS2_FAILURE;
    }

    sprintf(serial_no, "%d", serial);

    /* Build tokens */
    x509_data_node = oxs_token_build_x509_data_element(env, parent);
    x509_issuer_serial_node = oxs_token_build_x509_issuer_serial_with_data(
        env, x509_data_node, issuer, serial_no);

    return AXIS2_SUCCESS;
}


/**
 * Build a Thumbprint Reference of the certificate.
   <wsse:SecurityTokenReference>
                  <wsse:KeyIdentifier EncodingType="..." ValueType="...#
                    ThumbprintSHA1">bg6I8267h0TUcPYvYE0D6k6+UJQ=</wsse:KeyIdentifier>
   </wsse:SecurityTokenReference> 

 * @param env pointer to environment struct
 * @param parent The parent node
 * @param cert The X509 certificate
 * @return AXIS2_SUCCESS on success, else AXIS2_FAILURE
 */
AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_token_build_thumbprint_reference(
    const axutil_env_t *env,
    axiom_node_t *parent,
    oxs_x509_cert_t *cert)
{

    axiom_node_t *key_identifier_node = NULL;
    axis2_char_t *key_identifier = NULL;
    axis2_char_t *val_type = NULL;

    key_identifier = oxs_x509_cert_get_fingerprint(cert, env);
    val_type = OXS_X509_TUMBP_PRINT_SHA1;
        
    if(!key_identifier)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[rampart] Cannot create the Thumpprint from Cert.");
        return AXIS2_FAILURE;
    }
    /*Build KeyIdentifier node*/
    key_identifier_node = oxs_token_build_key_identifier_element(
                              env, parent, OXS_ENCODING_BASE64BINARY,
                              val_type, key_identifier);
    if(key_identifier_node)
    {
        return AXIS2_SUCCESS;

    }
    else
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "Thumbpring node creation failed");
        return AXIS2_FAILURE;
    }
}

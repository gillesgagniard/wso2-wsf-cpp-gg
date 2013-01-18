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

#ifndef OXS_TOKENS_H
#define OXS_TOKENS_H

#include <axis2_util.h>
#include <stdio.h>
#include <axutil_qname.h>
#include <axis2_defines.h>
#include <axutil_env.h>
#include <axiom_node.h>
#include <axiom_element.h>
#include <axiom_attribute.h>
#include <oxs_constants.h>
#include <rampart_constants.h>
#include <oxs_utility.h>
#include <oxs_axiom.h>
#include <axutil_array_list.h>

/**
* @file oxs_tokens.h
* @brief includes all tokens of OMXMLSecurity.
*/
#ifdef __cplusplus
extern "C"
{
#endif
    /**
     * @defgroup oxs_token OMXMLSecurity Tokens
     * @ingroup oxs
     * @{
     */
    
    /**
    * Creates <wsse:BinarySecurityToken> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_binary_security_token_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * id,
		axis2_char_t * encoding_type,
		axis2_char_t * value_type,
		axis2_char_t * data);
   
    /**
    * Creates <ds:CanonicalizationMethod> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_c14n_method_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * algorithm);

	/**
	 * Gets algorithm from <ds:CanonicalizationMethod> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_c14n_method(
		const axutil_env_t * env, 
		axiom_node_t * c14n_mtd_node);

    /**
    * Creates <xenc:CipherData> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_cipher_data_element(
		const axutil_env_t * env,
		axiom_node_t * parent);

	/**
	 * Gets cipher value from <xenc:CipherData> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_cipher_value_from_cipher_data(
		const axutil_env_t * env,
		axiom_node_t * cd_node);

	/**
	 * Creates <xenc:CipherValue> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_cipher_value_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * cipher_val);

	/**
	 * Gets value from <xenc:CipherValue> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_cipher_value(
		const axutil_env_t * env,
		axiom_node_t * cv_node);

	/**
	 * Creates <xenc:DataReference> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_data_reference_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * data_ref);

	/**
	 * Gets URI reference from <xenc:DataReference> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_data_reference(
		const axutil_env_t * env, 
		axiom_node_t * data_ref_node);

    /**
    * Creates <ds:DigestMethod> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_digest_method_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * algorithm);

	/**
	 * Gets the algorithm from <ds:DigestMethod> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_digest_method(
		const axutil_env_t * env, 
		axiom_node_t * enc_mtd_node);

	/**
	 * Creates <ds:DigestValue> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_digest_value_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * digest_val);

	/**
	 * Gets the value from <ds:DigestValue> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_digest_value(
		const axutil_env_t * env,
		axiom_node_t * sv_node);

    /**
    * Creates <ds:Reference> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_ds_reference_element(
		const axutil_env_t *env,
		axiom_node_t *parent,
		axis2_char_t *id,
		axis2_char_t *uri,
		axis2_char_t *type);

	/**
	 * Gets URI reference from <ds:Reference> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_ds_reference(
		const axutil_env_t * env, 
		axiom_node_t * ref_node);

	/**
	 * Creates <wsse:Embedded> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_embedded_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * id);

	/**
	 * Gets id from <wsse:Embedded> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_embedded_id(
		const axutil_env_t * env, 
		axiom_node_t * embedded_node);

    /**
    * Creates <xenc:EncryptedData> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_encrypted_data_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * type_attribute,
		axis2_char_t * id);

	/**
	 * Creates <xenc:EncryptedKey> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_encrypted_key_element(
		const axutil_env_t * env,
		axiom_node_t * parent );

    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_get_encrypted_key_node(
		const axutil_env_t * env,
		axiom_node_t * parent);

    /**
    * Creates <xenc:EncryptionMethod> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_encryption_method_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * algorithm);

	/**
	 * Gets algorithm from <xenc:EncryptionMethod> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_encryption_method(
		const axutil_env_t * env, 
		axiom_node_t * enc_mtd_node);

    /**
    * Creates <wsse:KeyIdentifier> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_key_identifier_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * encoding_type,
		axis2_char_t * value_type,
		axis2_char_t * value);

    /**
    * Creates <ds:KeyInfo> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_key_info_element(
		const axutil_env_t * env,
		axiom_node_t * parent);

	/**
	 * Creates <ds:KeyName> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_key_name_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * key_name_val);

	/**
	 * Creates <wsse:Reference> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_reference_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * ref,
		axis2_char_t * value_type);

	/**
	 * Gets URI reference from <wsse:Reference> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_reference(
		const axutil_env_t * env, 
		axiom_node_t * ref_node);

	/**
	 * Gets value type from <wsse:Reference> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_reference_value_type(
		const axutil_env_t * env, 
        axiom_node_t * ref_node);

	/**
	 * Creates <xenc:ReferenceList> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_reference_list_element(
		const axutil_env_t * env,
		axiom_node_t * parent);

	/**
	 * Creates <xenc:DataReference> elements under <xenc:ReferenceList> element
	 */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    oxs_token_build_data_reference_list(
		const axutil_env_t * env, 
		axiom_node_t * parent, 
		axutil_array_list_t * id_list);

	/**
	 * Gets URI references from <xenc:DataReference> elements under <xenc:ReferenceList> element
	 */
    AXIS2_EXTERN axutil_array_list_t * AXIS2_CALL
    oxs_token_get_reference_list_data(
		const axutil_env_t * env, 
		axiom_node_t * ref_list_node);

	/**
	 * Creates <wsse:SecurityTokenReference> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_security_token_reference_element(
		const axutil_env_t * env,
		axiom_node_t * parent);

    /**
    * Creates <ds:Signature> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_signature_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * id);

    /**
    * Creates <wss11:EncryptedHeader> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_enc_header_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * id);

	/**
	 * Creates <ds:SignatureMethod> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_signature_method_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * algorithm);

	/**
	 * Gets algorithm from <ds:SignatureMethod> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_signature_method(
		const axutil_env_t * env, 
		axiom_node_t * enc_mtd_node);

	/**
	 * Creates <ds:SignatureValue> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_signature_value_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * signature_val);

	/**
	 * Gets signature value from <ds:SignatureValue> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_signature_value(
		const axutil_env_t * env,
		axiom_node_t * sv_node);

	/**
	 * Creates <ds:SignedInfo> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_signed_info_element(
		const axutil_env_t * env,
		axiom_node_t * parent);

    /**
    * Creates <ds:Transform> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_transform_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * algorithm);

	/**
	 * Gets algorithm from <ds:Transform> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_transform(
		const axutil_env_t * env, 
		axiom_node_t * transform_node);

    /**
    * Creates <ds:Transforms> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_transforms_element(
		const axutil_env_t * env,
		axiom_node_t * parent);

    /**
    * Creates <ds:X509Certificate> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_x509_certificate_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * cert_data);

	/**
	 * Gets data from <ds:X509Certificate> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_x509_certificate(
		const axutil_env_t * env,
		axiom_node_t * sv_node);

    /**
    * Creates <ds:X509Data> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_x509_data_element(
		const axutil_env_t * env,
		axiom_node_t * parent);

    /**
    * Creates <ds:X509IssuerName> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_issuer_name_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * value );

	/**
	 * Gets issuer name from <ds:X509IssuerName> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_issuer_name(
		const axutil_env_t * env,
		axiom_node_t * issuer_name_node);

    /**
    * Creates <ds:X509IssuerSerial> element
    */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_x509_issuer_serial_element(
		const axutil_env_t * env,
		axiom_node_t * parent);
	
	/**
	 * Creates <ds:X509IssuerSerial> element with issuer name and serial number
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_x509_issuer_serial_with_data(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * issuer_name,
		axis2_char_t * serial_number);

	/**
	 * Creates <ds:X509SerialNumber> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_serial_number_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * value );

	/**
	 * Gets serial number from <ds:X509SerialNumber> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_serial_number(
		const axutil_env_t * env,
		axiom_node_t * serial_number_node);

    /**
	 * Creates <wsse11:SignatureConfirmation> element
	 */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_signature_confirmation_element(
		const axutil_env_t * env,
		axiom_node_t * parent,
		axis2_char_t * id,
		axis2_char_t * val); 

	/**
	 * Gets value from <wsse11:SignatureConfirmation> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_signature_confirmation_value(
		const axutil_env_t * env, 
		axiom_node_t * signature_confirmation_node);

	/**
	 * Gets id from <wsse11:SignatureConfirmation> element
	 */
    AXIS2_EXTERN axis2_char_t * AXIS2_CALL
    oxs_token_get_signature_confirmation_id(
		const axutil_env_t * env, 
		axiom_node_t * signature_confirmation_node);

    /**
     * Creates <wsc:DerivedKeyToken> element
     */
    AXIS2_EXTERN axiom_node_t * AXIS2_CALL
    oxs_token_build_derived_key_token_element(
        const axutil_env_t * env,
        axiom_node_t * parent,
        axis2_char_t * id,
        axis2_char_t * algo, 
        axis2_char_t* wsc_ns_uri);

    /**
     * Creates <wsc:Length> element
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    oxs_token_build_length_element(
        const axutil_env_t *env,
        axiom_node_t *parent,
        int length, 
        axis2_char_t *wsc_ns_uri);

	/**
	 * Gets value from <wsc:Length> element
	 */
    AXIS2_EXTERN int AXIS2_CALL
    oxs_token_get_length_value(
        const axutil_env_t *env,
        axiom_node_t *length_node);

    /**
     * Creates <wsc:Offset> element
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    oxs_token_build_offset_element(
        const axutil_env_t *env,
        axiom_node_t *parent,
        int offset, 
        axis2_char_t *wsc_ns_uri);

	/**
	 * Gets value from <wsc:Offset> element
	 */
    AXIS2_EXTERN int AXIS2_CALL
    oxs_token_get_offset_value(
        const axutil_env_t *env,
        axiom_node_t *offset_node);

    /**
     * Creates <wsc:Nonce> element
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    oxs_token_build_nonce_element(
        const axutil_env_t *env,
        axiom_node_t *parent,
        axis2_char_t *nonce_val,
        axis2_char_t *wsc_ns_uri);

    /**
	 * Gets value from <wsc:Nonce> element
	 */
    AXIS2_EXTERN axis2_char_t* AXIS2_CALL
    oxs_token_get_nonce_value(
        const axutil_env_t *env,
        axiom_node_t *nonce_node);

	/**
	 * Creates <wsc:Label> element
	 */
	AXIS2_EXTERN axiom_node_t* AXIS2_CALL
	oxs_token_build_label_element(
        const axutil_env_t *env,
		axiom_node_t *parent,
		axis2_char_t *label, 
        axis2_char_t *wsc_ns_uri);

	/**
	 * Gets value from <wsc:Label> element
	 */
    AXIS2_EXTERN axis2_char_t* AXIS2_CALL
    oxs_token_get_label_value(
        const axutil_env_t *env,
        axiom_node_t *label_node);

    /**
     * Creates <wsc:Properties> element
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    oxs_token_build_properties_element(
        const axutil_env_t *env,
        axiom_node_t *parent,
        axis2_char_t* properties_val, 
        axis2_char_t *wsc_ns_uri);

	/**
	 * Gets value from <wsc:Properties> element
	 */
    AXIS2_EXTERN axis2_char_t* AXIS2_CALL
    oxs_token_get_properties_value(
        const axutil_env_t *env,
        axiom_node_t *properties_node);
    
    /**
     * Creates <wsc:Generation> element
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    oxs_token_build_generation_element(
        const axutil_env_t *env,
        axiom_node_t *parent,
        axis2_char_t *generation_val, 
        axis2_char_t *wsc_ns_uri);
    
	/**
	 * Gets value from <wsc:Generation> element
	 */
    AXIS2_EXTERN axis2_char_t* AXIS2_CALL
    oxs_token_get_generation_value(
        const axutil_env_t *env,
        axiom_node_t *generation_node);

    /** @} */

#ifdef __cplusplus
}
#endif

#endif /*OXS_TOKENS_H */

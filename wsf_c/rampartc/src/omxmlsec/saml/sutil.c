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

#include <saml.h>
#include <saml_req.h>
#include <openssl_pkey.h>
#include <oxs_key_mgr.h>
#include <oxs_encryption.h>
#include <oxs_xml_encryption.h>
#include <oxs_tokens.h>

AXIS2_EXTERN int AXIS2_CALL saml_util_set_sig_ctx_defaults(oxs_sign_ctx_t *sig_ctx, const axutil_env_t *env, axis2_char_t *id)
{
	oxs_sign_part_t* sig_part = NULL;
	oxs_transform_t *tr = NULL;	
	axutil_array_list_t *sig_parts = NULL, *trans = NULL;
	trans = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);

	/*create transform sor SAML XML signature with identifier*/
	tr = oxs_transforms_factory_produce_transform(env, OXS_HREF_TRANSFORM_ENVELOPED_SIGNATURE);
	axutil_array_list_add(trans, env, tr);

    /*Create the EXCL-C14N Transformation*/
    tr = oxs_transforms_factory_produce_transform(env, OXS_HREF_TRANSFORM_XML_EXC_C14N);
    axutil_array_list_add(trans, env, tr);

	sig_part = oxs_sign_part_create(env);
	oxs_sign_part_set_digest_mtd(sig_part, env, OXS_HREF_SHA1);

	
	oxs_sign_part_set_transforms(sig_part, env, trans);
	oxs_sign_part_set_id_name(sig_part, env, id);

	/*ns = axiom_namespace_create(env, "", "");
	oxs_sign_part_set_sign_namespace(sig_part,env, ns);*/

	sig_parts = axutil_array_list_create(env, SAML_ARRAY_LIST_DEF);
	axutil_array_list_add(sig_parts, env, sig_part);
	
	/*create the specific sign context*/
	
	oxs_sign_ctx_set_c14n_mtd(sig_ctx, env, OXS_HREF_XML_EXC_C14N);
	oxs_sign_ctx_set_operation(sig_ctx, env, OXS_SIGN_OPERATION_SIGN);
	oxs_sign_ctx_set_sign_mtd_algo(sig_ctx, env, OXS_HREF_RSA_SHA1);
	oxs_sign_ctx_set_sign_parts(sig_ctx, env, sig_parts);

	return AXIS2_SUCCESS;
}



AXIS2_EXTERN oxs_key_t * AXIS2_CALL
saml_assertion_get_session_key(const axutil_env_t *env, axiom_node_t *assertion, 
                               openssl_pkey_t *pvt_key)
{
    axiom_node_t *encrypted_key_node = NULL;
    axiom_node_t *enc_mtd_node = NULL;
    axis2_char_t *enc_asym_algo = NULL;
    oxs_asym_ctx_t *asym_ctx = NULL;
    oxs_key_t *decrypted_sym_key = NULL;
    axis2_status_t status = AXIS2_FAILURE;    

	if (!pvt_key)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[oxs][saml] Private key not specified");
		return NULL;
	}

    encrypted_key_node = oxs_axiom_get_node_by_local_name(env, assertion, OXS_NODE_ENCRYPTED_KEY);
	if (!encrypted_key_node)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[oxs][saml] Encrypted key cannot be found");
		return NULL;
	}

    enc_mtd_node = oxs_axiom_get_first_child_node_by_name(
                       env, encrypted_key_node, OXS_NODE_ENCRYPTION_METHOD, OXS_ENC_NS, NULL);

	if (!enc_mtd_node)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[oxs][saml] EncryptedKey node cannot be found");
		return NULL;
	}
    enc_asym_algo = oxs_token_get_encryption_method(env, enc_mtd_node); 
	if (!enc_asym_algo)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[oxs][saml] Encryption Algorithm cannot be found");
		return NULL;
	}
    asym_ctx = oxs_asym_ctx_create(env);
    oxs_asym_ctx_set_algorithm(asym_ctx, env, enc_asym_algo);
		    	
	oxs_asym_ctx_set_private_key(asym_ctx, env, pvt_key);
    oxs_asym_ctx_set_operation(asym_ctx, env, OXS_ASYM_CTX_OPERATION_PRV_DECRYPT);

    decrypted_sym_key = oxs_key_create(env);

    /*Call decrypt for the EncryptedKey*/
    status = oxs_xml_enc_decrypt_key(env, asym_ctx,
                                     NULL, encrypted_key_node,  decrypted_sym_key);
    if (status == AXIS2_FAILURE)
    {
		oxs_key_free(decrypted_sym_key, env);
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                            "[oxs][saml] Decryption failed in SAML encrypted key");
		return NULL;
    }
    return decrypted_sym_key;
}

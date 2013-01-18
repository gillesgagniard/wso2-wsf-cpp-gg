/*
 *   Copyright 2003-2004 The Apache Software Foundation.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */

#include <axis2_util.h>
#include <rampart_saml.h>
#include <oxs_constants.h>
#include <rp_property.h>
#include <oxs_xml_signature.h>
#include <oxs_transform.h>
#include <oxs_utility.h>
#include <oxs_transforms_factory.h>
#include <rp_includes.h>
#include <rp_secpolicy.h>

oxs_sign_part_t * AXIS2_CALL
rampart_saml_token_create_sign_part(const axutil_env_t *env, 
                            rampart_context_t *rampart_context, 
                            rampart_saml_token_t *saml, 
							axiom_node_t *str);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_validate(const axutil_env_t *env, 
                            rampart_context_t *rampart_context, 
                            axiom_node_t *assertion);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_supporting_token_build(const axutil_env_t *env, 
                         rampart_context_t *rampart_context,                         
                         axiom_node_t *sec_node, 
                         axutil_array_list_t *sign_parts)
{
    axiom_node_t *strn = NULL, *assertion = NULL;
    oxs_sign_part_t *sign_part = NULL;
    rampart_saml_token_t *saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_SIGNED_SUPPORTING_TOKEN);
    if (!saml)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rs] SAML token not set in the rampart context. ERROR");			
        return AXIS2_FAILURE;
    }
    assertion = rampart_saml_token_get_assertion(saml, env);
    if (!assertion)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rs] SAML assertion not set in the rampart_saml_token. ERROR");			
        return AXIS2_FAILURE;
    }
    axiom_node_add_child(sec_node, env, assertion);
    strn = rampart_saml_token_get_str(saml, env);
    if (!strn)
    {
        strn = oxs_saml_token_build_key_identifier_reference_local(env, NULL, assertion);
        /*rampart_saml_token_set_str(saml, env, strn);*/
    }
    axiom_node_add_child(sec_node, env, strn);    
    sign_part = rampart_saml_token_create_sign_part(env, rampart_context, saml, strn);
    if (!sign_part)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rs] Sign part creation failed. ERROR");			
        return AXIS2_FAILURE;
    }
    axutil_array_list_add(sign_parts, env, sign_part);
    return AXIS2_SUCCESS;
}

oxs_sign_part_t * AXIS2_CALL
rampart_saml_token_create_sign_part(const axutil_env_t *env, 
                            rampart_context_t *rampart_context, 
                            rampart_saml_token_t *saml,
							axiom_node_t *strn)
{
    axiom_element_t *stre = NULL;
    /*axiom_node_t *strn = NULL;*/
    axutil_qname_t *qname = NULL;    
    axis2_char_t *id = NULL;
    oxs_sign_part_t *sign_part = NULL;
    oxs_transform_t *tr = NULL;
    axutil_array_list_t *tr_list = NULL;

    axis2_char_t * digest_method = rampart_context_get_digest_mtd(rampart_context, env);
    stre = axiom_node_get_data_element(strn, env);

    qname = axutil_qname_create(env, OXS_NODE_SECURITY_TOKEN_REFRENCE, OXS_WSSE_XMLNS, NULL);
    sign_part = oxs_sign_part_create(env);
    tr_list = axutil_array_list_create(env, 0);
    /* If ID is not present we add it */
    id = axiom_element_get_attribute_value(stre, env, qname);
    if (!id)
    {
        id = oxs_util_generate_id(env, (axis2_char_t*)OXS_SIG_ID);
        oxs_axiom_add_attribute(env, strn,
                            RAMPART_WSU, RAMPART_WSU_XMLNS, OXS_ATTR_ID, id);
    }
    oxs_sign_part_set_id(sign_part, env, id);
    tr = oxs_transforms_factory_produce_transform(env,
            OXS_HREF_TRANSFORM_STR_TRANSFORM);
    axutil_array_list_add(tr_list, env, tr);
    oxs_sign_part_set_transforms(sign_part, env, tr_list);                
    /* Sign the assertion, not the securitytokenreference */
    oxs_sign_part_set_node(sign_part, env, strn);
    oxs_sign_part_set_digest_mtd(sign_part, env, digest_method);
    
	axutil_qname_free(qname, env);
    AXIS2_FREE(env->allocator, id);   
    return sign_part;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_saml_token_validate(const axutil_env_t *env, 
                            rampart_context_t *rampart_context, 
                            axiom_node_t *assertion)
{	
    axis2_status_t status = AXIS2_FAILURE;
    oxs_sign_ctx_t *sign_ctx = NULL;
	oxs_x509_cert_t *certificate = NULL; 
	axiom_node_t *sig_node = NULL;
	rp_rampart_config_t *rampart_config = NULL;
	rp_secpolicy_t *secpolicy;
	axis2_char_t *cert_file = NULL;
	secpolicy = rampart_context_get_secpolicy(rampart_context, env);
	if (!secpolicy)
	{
		return AXIS2_SUCCESS;
	}
    rampart_config = rp_secpolicy_get_rampart_config(secpolicy, env);
    if(!rampart_config)
    {
        return AXIS2_SUCCESS;
    }
	/* Still we don't have a mechanism to get the SAML signing key */
	/* cert_file = rp_rampart_config_get_sts_certificate_file(rampart_config, env); */
	if (!cert_file)
	{
		return AXIS2_SUCCESS;
	}
	certificate = oxs_key_mgr_load_x509_cert_from_pem_file(env, cert_file);
	/* Need to get the certificate of the STS */
	if (!certificate)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rs] Certificate cannot be found for the STS");			
        return AXIS2_FAILURE;
	}
	/*Create sign context*/
    sign_ctx = oxs_sign_ctx_create(env);
    
    /*Set the Certificate*/
    oxs_sign_ctx_set_certificate(sign_ctx, env, certificate);
	sig_node = oxs_axiom_get_node_by_local_name(env, assertion, OXS_NODE_SIGNATURE);
	if (!sig_node)
	{    
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rs] No Signature node in the SAML Assertion");			
        return AXIS2_FAILURE;
	}
    status = oxs_xml_sig_verify(env, sign_ctx, sig_node, assertion);	
	if (status == AXIS2_SUCCESS)
	{
		AXIS2_LOG_INFO(env->log, "SAML Signature Verification Successfull");
	}
    return status;
}

AXIS2_EXTERN rampart_saml_token_t * AXIS2_CALL
rampart_saml_add_token(rampart_context_t *rampart_context, 
					   const axutil_env_t *env, 
					   axiom_node_t *assertion, 
					   axiom_node_t *str,
					   rampart_st_type_t type)
{	
	rampart_saml_token_t *saml = NULL;	
	rp_property_t *binding = NULL;
	rp_secpolicy_t *secpolicy = NULL;	

	if (AXIS2_FAILURE == rampart_saml_token_validate(env, rampart_context, assertion))
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                   "[rampart][rs] SAML Signature Verification Failed");			        
		return NULL;
	}
	if (type == RAMPART_ST_TYPE_SIGNED_SUPPORTING_TOKEN)
	{
		saml = rampart_saml_token_create(env, assertion, RAMPART_ST_CONFIR_TYPE_SENDER_VOUCHES);        
        rampart_saml_token_set_token_type(saml, env, RAMPART_ST_TYPE_SIGNED_SUPPORTING_TOKEN);
		if (str)
			rampart_saml_token_set_str(saml, env, str);

		rampart_context_add_saml_token(rampart_context, env, saml);
		return saml;
	}

	secpolicy = rampart_context_get_secpolicy(rampart_context, env);
    binding = rp_secpolicy_get_binding(secpolicy,env);
	if(rp_property_get_type(binding,env) == RP_PROPERTY_SYMMETRIC_BINDING)
    {
        rp_symmetric_binding_t *sym_binding = NULL;
        sym_binding = (rp_symmetric_binding_t *)rp_property_get_value(binding,env);
        if(sym_binding)
        {
            /*First check protection tokens have being specified.*/
            if(rp_symmetric_binding_get_protection_token(sym_binding,env))
			{
				saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_PROTECTION_TOKEN);				
				if (!saml)
				{
					saml = rampart_saml_token_create(env, assertion, RAMPART_ST_CONFIR_TYPE_HOLDER_OF_KEY);
                    rampart_saml_token_set_token_type(saml, env, RAMPART_ST_TYPE_PROTECTION_TOKEN);
					if (str)
						rampart_saml_token_set_str(saml, env, str);
					rampart_context_add_saml_token(rampart_context, env, saml);
				}
                return saml;
			}           
            else if (type == RAMPART_ST_TYPE_ENCRYPTION_TOKEN && rp_symmetric_binding_get_encryption_token(sym_binding,env))
            {
				saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_ENCRYPTION_TOKEN);				
				if (!saml)
				{
					saml = rampart_saml_token_create(env, assertion, RAMPART_ST_CONFIR_TYPE_HOLDER_OF_KEY);
                    rampart_saml_token_set_token_type(saml, env, RAMPART_ST_TYPE_ENCRYPTION_TOKEN);
					if (str)
						rampart_saml_token_set_str(saml, env, str);
					rampart_context_add_saml_token(rampart_context, env, saml);				
				}
                return saml;
            }
			else if (type == RAMPART_ST_TYPE_SIGNATURE_TOKEN && rp_symmetric_binding_get_signature_token(sym_binding,env))
            {
				saml = rampart_context_get_saml_token(rampart_context, env, RAMPART_ST_TYPE_SIGNATURE_TOKEN);				                
				if (!saml)
				{
					saml = rampart_saml_token_create(env, assertion, RAMPART_ST_CONFIR_TYPE_HOLDER_OF_KEY);
                    rampart_saml_token_set_token_type(saml, env, RAMPART_ST_TYPE_SIGNATURE_TOKEN);
					if (str)
						rampart_saml_token_set_str(saml, env, str);
					rampart_context_add_saml_token(rampart_context, env, saml);				
				}										                
                return saml;
            }
        }
        else
		{
			AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
                        "[rampart][rs] SAML tokens as protection tokens, supported only in symmetric binding");
            return NULL;
		}
    }	
	return NULL;
}

AXIS2_EXTERN char * AXIS2_CALL
rampart_saml_token_get_subject_confirmation(const axutil_env_t *env, axiom_node_t *assertion)
{
    axiom_node_t *node = oxs_axiom_get_node_by_local_name(env, assertion, OXS_NODE_SAML_SUBJECT_CONFIRMATION_METHOD);
    if (node) 
    {
        return oxs_axiom_get_node_content(env, node);
    }
    return NULL;
}

/** Faults Defined by the specification **/
AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_securitytokenunavailable(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx)
{
    axiom_soap_envelope_t *envelope = NULL;
    int soap_version = AXIOM_SOAP12;    
    axutil_array_list_t *sub_codes = NULL;

    sub_codes = axutil_array_list_create(env, 1);
    axutil_array_list_add(sub_codes, env, axutil_strdup(env, RAMPART_ST_FAULT_SECURITYTOKENUNAVAILABLE_CODE));    

    envelope = axiom_soap_envelope_create_default_soap_fault_envelope(env,
               RAMPART_SAML_FAULT_CODE,
               RAMPART_ST_FAULT_SECURITYTOKENUNAVAILABLE_STR,
               soap_version, sub_codes, NULL);

	if (!envelope)
	{
		axutil_array_list_free(sub_codes, env);
		return AXIS2_FAILURE;
	}

    axis2_msg_ctx_set_fault_soap_envelope(ctx, env, envelope);	
	axutil_array_list_free(sub_codes, env);
	return AXIS2_SUCCESS;
}

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_unsupportedsecuritytoken(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx)
{
    axiom_soap_envelope_t *envelope = NULL;
    int soap_version = AXIOM_SOAP12;    
    axutil_array_list_t *sub_codes = NULL;

    sub_codes = axutil_array_list_create(env, 1);
    axutil_array_list_add(sub_codes, env, axutil_strdup(env, RAMPART_ST_FAULT_UNSUPPORTEDSECURITYTOKEN_CODE));    

    envelope = axiom_soap_envelope_create_default_soap_fault_envelope(env,
               RAMPART_SAML_FAULT_CODE,
               RAMPART_ST_FAULT_UNSUPPORTEDSECURITYTOKEN_STR,
               soap_version, sub_codes, NULL);

	if (!envelope)
	{
		axutil_array_list_free(sub_codes, env);
		return AXIS2_FAILURE;
	}

    axis2_msg_ctx_set_fault_soap_envelope(ctx, env, envelope);	
	axutil_array_list_free(sub_codes, env);
	return AXIS2_SUCCESS;    
}


AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_failedcheck(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx)
{
    axiom_soap_envelope_t *envelope = NULL;
    int soap_version = AXIOM_SOAP12;    
    axutil_array_list_t *sub_codes = NULL;

    sub_codes = axutil_array_list_create(env, 1);
    axutil_array_list_add(sub_codes, env, axutil_strdup(env, RAMPART_ST_FAULT_FAILEDCHECK_CODE));    

    envelope = axiom_soap_envelope_create_default_soap_fault_envelope(env,
               RAMPART_SAML_FAULT_CODE,
               RAMPART_ST_FAULT_FAILEDCHECK_STR,
               soap_version, sub_codes, NULL);

	if (!envelope)
	{
		axutil_array_list_free(sub_codes, env);
		return AXIS2_FAILURE;
	}

    axis2_msg_ctx_set_fault_soap_envelope(ctx, env, envelope);	
	axutil_array_list_free(sub_codes, env);
	return AXIS2_SUCCESS;    
}

AXIS2_EXTERN int AXIS2_CALL
rampart_saml_token_fault_invalidsecuritytoken(axutil_env_t *env, 
                                                  axis2_msg_ctx_t *ctx)
{
    axiom_soap_envelope_t *envelope = NULL;
    int soap_version = AXIOM_SOAP12;    
    axutil_array_list_t *sub_codes = NULL;

    sub_codes = axutil_array_list_create(env, 1);
    axutil_array_list_add(sub_codes, env, axutil_strdup(env, RAMPART_ST_FAULT_INVALIDSECURITYTOKEN_CODE));    

    envelope = axiom_soap_envelope_create_default_soap_fault_envelope(env,
               RAMPART_SAML_FAULT_CODE,
               RAMPART_ST_FAULT_INVALIDSECURITYTOKEN_STR,
               soap_version, sub_codes, NULL);

	if (!envelope)
	{
		axutil_array_list_free(sub_codes, env);
		return AXIS2_FAILURE;
	}

    axis2_msg_ctx_set_fault_soap_envelope(ctx, env, envelope);	
	axutil_array_list_free(sub_codes, env);
	return AXIS2_SUCCESS;    
}


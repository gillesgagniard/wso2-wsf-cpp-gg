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
#include <oxs_constants.h>
#include <oxs_error.h>
#include <oxs_buffer.h>
#include <oxs_transform.h>
#include <oxs_transforms_factory.h>
#include <oxs_buffer.h>
#include <oxs_c14n.h>
#include <oxs_saml_token.h>
#include <axiom_util.h>

/*Functions that implements transforms*/
oxs_tr_dtype_t AXIS2_CALL
oxs_transforms_exc_c14n(const axutil_env_t *env,
                        axiom_node_t *input,
                        oxs_tr_dtype_t input_dtype,
                        axis2_char_t **output)
{
    axiom_document_t *doc = NULL;
    axis2_char_t *algo = NULL;
    axis2_char_t *c14nized = NULL;
    oxs_tr_dtype_t output_dtype = OXS_TRANSFORM_TYPE_UNKNOWN;

    if(input_dtype != OXS_TRANSFORM_TYPE_NODE){
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_TRANSFORM_FAILED,"Transform expects a NODE.");
        return OXS_TRANSFORM_TYPE_UNKNOWN;
    }

    doc = axiom_node_get_document(input, env);
    algo = OXS_HREF_TRANSFORM_XML_EXC_C14N;
    oxs_c14n_apply_algo(env, doc, &c14nized, NULL, input, algo);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart][c14n-OutPut] is\n\n%s\n\n",c14nized);
    *output= c14nized;
    output_dtype = OXS_TRANSFORM_TYPE_CHAR;
    return output_dtype;
}

oxs_tr_dtype_t AXIS2_CALL
oxs_transforms_enveloped_xmldsig(const axutil_env_t *env,
                        axiom_node_t *input,
                        oxs_tr_dtype_t input_dtype,
                        void **output)
{         
	axiom_node_t *sig_node = NULL, *child_node = NULL;

    if(input_dtype != OXS_TRANSFORM_TYPE_NODE){
        oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_TRANSFORM_FAILED, "Transform expects a NODE.");
        return OXS_TRANSFORM_TYPE_UNKNOWN;
    }
	child_node = axiom_node_get_first_element(input, env);	
	while(child_node)
	{
		axis2_char_t *node_local_name = NULL;
		node_local_name = axiom_util_get_localname(child_node, env);
		if(!(axutil_strcmp(node_local_name, OXS_NODE_SIGNATURE)))
		{	
			sig_node = axiom_node_detach(child_node, env); /* TODO should we use detach_without_namespace here?? */
			break;
		}
		child_node = axiom_node_get_next_sibling(child_node, env);
	}	    

    if (sig_node)
    {
        axutil_array_list_t *out = axutil_array_list_create(env, 2);
        if (out)
        {
            axutil_array_list_add(out, env, input);
            axutil_array_list_add(out, env, sig_node);            
            *output = out;
            return OXS_TRANSFORM_TYPE_NODE_ARRAY_LIST; 
        }
        axiom_node_add_child(input, env, sig_node);    
    }
    return OXS_TRANSFORM_TYPE_UNKNOWN;
}

oxs_tr_dtype_t AXIS2_CALL
oxs_transforms_STR(const axutil_env_t *env,
                        axiom_node_t *input,
                        oxs_tr_dtype_t input_dtype,
                        void **output)
{ 
    axiom_document_t *doc = NULL;
    axis2_char_t *algo = NULL;
    axis2_char_t *c14nized = NULL;
    oxs_tr_dtype_t output_dtype = OXS_TRANSFORM_TYPE_UNKNOWN;

    axiom_node_t *cn = NULL, *node = NULL;
    axiom_element_t *stre = NULL, *ce = NULL;
    axiom_child_element_iterator_t *it = NULL;    
    axutil_qname_t *qname = NULL, *key_qname = NULL, *embeded_qname = NULL;

    embeded_qname = axutil_qname_create(env, OXS_NODE_EMBEDDED, OXS_WSSE_XMLNS, NULL);
    key_qname = axutil_qname_create(env, OXS_NODE_KEY_IDENTIFIER, OXS_WSSE_XMLNS, NULL);

    if (!embeded_qname || !key_qname)
    {
		if(embeded_qname)
			axutil_qname_free(embeded_qname, env);
		if(key_qname)
			axutil_qname_free(key_qname, env);
        return OXS_TRANSFORM_TYPE_UNKNOWN;
    }

    stre = axiom_node_get_data_element(input, env);    
    it = axiom_element_get_child_elements(stre, env, input);    
    if (it)
    {
        while (AXIS2_TRUE == axiom_child_element_iterator_has_next(it, env))
        {
            axis2_char_t *attr_val = NULL;
            cn = axiom_child_element_iterator_next(it, env);
            ce = axiom_node_get_data_element(cn, env);                        
            /* At the moment we are supporting only saml token references */
            attr_val = axiom_element_get_attribute_value_by_name(ce, env, OXS_ATTR_VALUE_TYPE);
            if (attr_val && 0 == axutil_strcmp(OXS_ST_KEY_ID_VALUE_TYPE, attr_val))
            {
                qname = axiom_element_get_qname(ce, env, cn);              
                if (axutil_qname_equals(qname, env, key_qname) == AXIS2_TRUE)
                {
                    node = oxs_saml_token_get_from_key_identifer_reference(env, cn, NULL);     
                    break;
                }
                else if (axutil_qname_equals(qname, env, embeded_qname) == AXIS2_TRUE)
                {
                    node = oxs_saml_token_get_from_embeded_reference(env, cn);          
                    break;
                }
                else
                {
					axutil_qname_free(embeded_qname, env);
					axutil_qname_free(key_qname, env);
                    oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_TRANSFORM_FAILED, "Unrecognized reference type  NODE.");
                    return OXS_TRANSFORM_TYPE_UNKNOWN;   
                }
            }
        }
    }

	axutil_qname_free(embeded_qname, env);
	axutil_qname_free(key_qname, env);
    if (node)
    {
        doc = axiom_node_get_document(node, env);
        algo = OXS_HREF_TRANSFORM_XML_EXC_C14N;
        oxs_c14n_apply_algo(env, doc, &c14nized, NULL, node, algo);        
        *output= c14nized;
        output_dtype = OXS_TRANSFORM_TYPE_CHAR;
        return output_dtype;
    }
    *output = NULL;
    oxs_error(env, OXS_ERROR_LOCATION, OXS_ERROR_TRANSFORM_FAILED, "Referenced node couln't be found in the specifed scope.");
    return OXS_TRANSFORM_TYPE_UNKNOWN;    
}

/*Public functions*/
AXIS2_EXTERN oxs_transform_t *AXIS2_CALL
oxs_transforms_factory_produce_transform(const axutil_env_t *env,
        axis2_char_t *id)
{
    oxs_transform_t *tr =  NULL;

    /*Inspect the id and produce a transform*/
    if(0 == axutil_strcmp(id, OXS_HREF_TRANSFORM_XML_EXC_C14N)){
        tr = oxs_transform_create(env);
        oxs_transform_set_id(tr, env, id);
        oxs_transform_set_input_data_type(tr, env, OXS_TRANSFORM_TYPE_NODE);
        oxs_transform_set_output_data_type(tr, env, OXS_TRANSFORM_TYPE_CHAR);
        oxs_transform_set_transform_func(tr, env, (oxs_transform_tr_func)oxs_transforms_exc_c14n);
        return tr;

    }else if(0 == axutil_strcmp(id, OXS_HREF_TRANSFORM_ENVELOPED_SIGNATURE)){
        tr = oxs_transform_create(env);
        oxs_transform_set_id(tr, env, id);
        oxs_transform_set_input_data_type(tr, env, OXS_TRANSFORM_TYPE_NODE);
        oxs_transform_set_output_data_type(tr, env, OXS_TRANSFORM_TYPE_NODE_ARRAY_LIST);
        oxs_transform_set_transform_func(tr, env, (oxs_transform_tr_func)oxs_transforms_enveloped_xmldsig);
        return tr; 

    }else if (0 == axutil_strcmp(id, OXS_HREF_TRANSFORM_STR_TRANSFORM)) {
        tr = oxs_transform_create(env);
        oxs_transform_set_id(tr, env, id);
        oxs_transform_set_input_data_type(tr, env, OXS_TRANSFORM_TYPE_NODE);
        oxs_transform_set_output_data_type(tr, env, OXS_TRANSFORM_TYPE_NODE);
        oxs_transform_set_transform_func(tr, env, (oxs_transform_tr_func)oxs_transforms_STR);
        return tr; 
    }
	else
		return NULL;
}



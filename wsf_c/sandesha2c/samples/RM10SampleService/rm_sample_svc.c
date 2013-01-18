/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "rm_sample_svc.h"
#include <axiom_xml_writer.h>
#include <stdio.h>
#include <axutil_qname.h>
#include <axiom_output.h>
#include <axiom_element.h>

axiom_node_t *build_response1(
    const axutil_env_t * env,
    axis2_char_t * text);

axiom_node_t *build_response2(
    const axutil_env_t *env,
    axiom_data_handler_t *data_handler);

axiom_node_t *
build_echo_om(
    const axutil_env_t *env, 
    const axis2_char_t *text);

axiom_node_t *
rm_sample_svc_echo (
    const axutil_env_t *env, 
    axiom_node_t *node)
{
    axiom_node_t *text_parent_node = NULL;
    axiom_node_t *text_node = NULL;
    axiom_node_t *ret_node = NULL;

    /* Expected request format is :-
     * <ns1:echoString xmlns:ns1="http://ws.apache.org/axis2/c/samples">
     *      <text>echo5</text>
     * </ns1:echoString>
     */
    if (!node) /* 'echoString' node */
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_SVC_SKEL_INPUT_OM_NODE_NULL, AXIS2_FAILURE);
        return NULL;
    }

    text_parent_node = axiom_node_get_first_element(node, env);
    if (!text_parent_node) /* 'text' node */
    {
        AXIS2_ERROR_SET(env->error, 
            AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);

        return NULL;
    }
    
    text_node = axiom_node_get_first_child(text_parent_node, env);
    if (!text_node) /* actual text to echo */
    {
        AXIS2_ERROR_SET(env->error, 
            AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);
        return NULL;
    }
    
    if (axiom_node_get_node_type(text_node, env) == AXIOM_TEXT)
    {
        axiom_text_t *text = (axiom_text_t *)axiom_node_get_data_element(text_node, env);
        if( text && axiom_text_get_value(text , env))
        {
            const axis2_char_t *text_str = axiom_text_get_value(text, env);
            ret_node = build_echo_om(env, text_str);
        }
    }
    else
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);
        return NULL;
    }
   
    return ret_node;
}

/* Builds the response content */
axiom_node_t *
build_echo_om(
    const axutil_env_t *env, 
    const axis2_char_t *text)
{
    axiom_node_t *echo_om_node = NULL;
    axiom_element_t* echo_om_ele = NULL;
    axiom_node_t* text_om_node = NULL;
    axiom_element_t * text_om_ele = NULL;
    axiom_namespace_t *ns1 = NULL;
    
    ns1 = axiom_namespace_create (env, "http://tempuri.org/", "ns1");

    echo_om_ele = axiom_element_create(env, NULL, "echoStringResponse", ns1, &echo_om_node);
    text_om_ele = axiom_element_create(env, echo_om_node, "EchoStringReturn", ns1, &text_om_node);
    axiom_element_set_text(text_om_ele, env, text, text_om_node);

    
    return echo_om_node;
}

void
rm_sample_svc_ping (
    const axutil_env_t *env, 
    axiom_node_t *node)
{
    axiom_node_t *text_parent_node = NULL;
    axiom_element_t *text_parent_element = NULL;
    axiom_node_t *text_node = NULL;
    axiom_element_t *element = NULL;
    axis2_char_t *ns = "http://tempuri.org/";
    axutil_qname_t *qname = NULL;

    AXIS2_ENV_CHECK(env, NULL);
   
    /* Expected request format is :-
     * <ns1:echoString xmlns:ns1="http://ws.apache.org/axis2/c/samples">
     *      <text>echo5</text>
     * </ns1:echoString>
     */
    if (!node) /* 'echoString' node */
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_SVC_SKEL_INPUT_OM_NODE_NULL, AXIS2_FAILURE);
        return;
    }
    else
    {
        axiom_xml_writer_t *writer = NULL;
        axiom_output_t *om_output = NULL;
        axis2_char_t *buffer = NULL;
  
        writer = axiom_xml_writer_create_for_memory(env, NULL, AXIS2_TRUE, 0,
            AXIS2_XML_PARSER_TYPE_BUFFER);
        om_output = axiom_output_create (env, writer);
        if (!om_output)
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "Could not create om_output");
            axiom_xml_writer_free(writer, env);
            writer = NULL;
            return;
        }
        axiom_node_serialize (node, env, om_output);
        buffer = axiom_xml_writer_get_xml(writer, env);
        axiom_output_free(om_output, env);
    }

    element = axiom_node_get_data_element(node, env);
    qname = axutil_qname_create(env, "Text", ns, NULL);
    text_parent_element = axiom_element_get_first_child_with_qname(element, env, 
            qname, node, &text_parent_node);
    axutil_qname_free(qname, env);
    if (!text_parent_node) /* 'text' node */
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);
        return;
    }
    
    text_node = axiom_node_get_first_child(text_parent_node, env);
    if (!text_node) /* actual text to echo */
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);
        return;
    }
    
    if (axiom_node_get_node_type(text_node, env) == AXIOM_TEXT)
    {
        /*axiom_text_t *text = (axiom_text_t *)axiom_node_get_data_element(text_node, env);
        if( text && axiom_text_get_value(text , env))
        {
            axis2_char_t *text_str = axiom_text_get_value(text, env);
        }*/
    }
    else
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST, AXIS2_FAILURE);
        return;
    }
   
    return;
}

axiom_node_t *
rm_sample_svc_mtom(
    const axutil_env_t *env, 
    axiom_node_t *node,
    axis2_msg_ctx_t *msg_ctx)
{
    axiom_node_t *file_name_node = NULL;
    axiom_node_t *file_text_node = NULL;
    axiom_node_t *ret_node = NULL;

    AXIS2_ENV_CHECK(env, NULL);

    /* Expected request format is :-
     * <ns1:mtomSample xmlns:ns1="http://ws.apache.org/axis2/c/samples">
     <ns1:fileName>test.jpg</ns1:fileName>
     <ns1:image>
     <xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="cid:1.dd5183d4-d58a-1da1-2578-001125b4c063@apache.org"></xop:Include>
     </ns1:image>
     </ns1:mtomSample>
     */
    if (!node)                  /* 'mtomSample' node */
    {
        AXIS2_ERROR_SET(env->error, AXIS2_ERROR_SVC_SKEL_INPUT_OM_NODE_NULL,
                        AXIS2_FAILURE);
        printf("Echo client ERROR: input parameter NULL\n");
        return NULL;
    }

    file_name_node = axiom_node_get_first_child(node, env);
    if (!file_name_node)        /* 'text' node */
    {
        AXIS2_ERROR_SET(env->error,
                        AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST,
                        AXIS2_FAILURE);
        printf("Echo client ERROR: invalid XML in request\n");
        return NULL;
    }

    file_text_node = axiom_node_get_first_child(file_name_node, env);
    if (!file_text_node)        /* actual text to mtom */
    {
        AXIS2_ERROR_SET(env->error,
                        AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST,
                        AXIS2_FAILURE);
        printf("Echo client ERROR: invalid XML in request\n");
        return NULL;
    }

    if (axiom_node_get_node_type(file_text_node, env) == AXIOM_TEXT)
    {
        axiom_text_t *text =
            (axiom_text_t *) axiom_node_get_data_element(file_text_node, env);
        if (text && axiom_text_get_value(text, env))
        {
            axiom_node_t *image_node = NULL;
            axis2_char_t *text_str =
                (axis2_char_t *) axiom_text_get_value(text, env);
            printf("File Name  %s \n", text_str);

            image_node = axiom_node_get_next_sibling(file_name_node, env);
            if (image_node)
            {
                /* axiom_node_t *inc_node = NULL;
                   inc_node = axiom_node_get_first_child(image_node, env);
                   if (inc_node)
                   { */
                axiom_node_t *binary_node = NULL;
                binary_node = axiom_node_get_first_child(image_node, env);
                if (binary_node)
                {
                    axiom_data_handler_t *data_handler = NULL;
                    axiom_text_t *bin_text = (axiom_text_t *)
                        axiom_node_get_data_element(binary_node, env);
                    data_handler = axiom_text_get_data_handler(bin_text, env);
                    if (data_handler)
                    {
                        axiom_data_handler_t *data_handler_res = NULL;
                        axis2_byte_t *input_buff = NULL;
                        axis2_byte_t *buff = NULL;
                        int buff_len = 0;


                        axiom_data_handler_set_file_name(data_handler, env,
                                                         text_str);
                        axiom_data_handler_write_to(data_handler, env);
                        
                        input_buff = axiom_data_handler_get_input_stream(data_handler, env);
                        buff_len = axiom_data_handler_get_input_stream_len(data_handler, env);
                        
                        data_handler_res = axiom_data_handler_create(env, NULL, NULL);
                        
                        buff = AXIS2_MALLOC(env->allocator, sizeof(axis2_byte_t)*buff_len);
                        memcpy(buff, input_buff, buff_len);

                        axiom_data_handler_set_binary_data(data_handler_res, env, buff, buff_len);

                        axis2_msg_ctx_set_doing_mtom (msg_ctx, env, AXIS2_TRUE);
                        ret_node = build_response2(env, data_handler_res);
                    }
                    else if (axiom_node_get_node_type(binary_node, env) == AXIOM_TEXT) /* attachment has come by value, as non-optimized binary */
                    {
                        int plain_binary_len = 0;
                        int ret_len = 0;
                        axiom_text_t *bin_text = (axiom_text_t *)
                            axiom_node_get_data_element(binary_node, env);
                        axis2_byte_t *plain_binary = NULL;
                        axiom_data_handler_t *data_handler = NULL;

                        axis2_char_t *base64text =
                            (axis2_char_t *) axiom_text_get_value(bin_text,
                                                                  env);
                        printf("base64text = %s\n", base64text);
                        plain_binary_len = axutil_base64_decode_len(base64text);
                        plain_binary = AXIS2_MALLOC(env->
                                                    allocator,
                                                    sizeof(unsigned char) *
                                                    plain_binary_len);
                        ret_len =
                            axutil_base64_decode_binary((unsigned char *)
                                                        plain_binary,
                                                        base64text);
                        data_handler =
                            axiom_data_handler_create(env, text_str, NULL);
                        axiom_data_handler_set_binary_data(data_handler, env,
                                                           plain_binary,
                                                           ret_len);
                        axiom_data_handler_write_to(data_handler, env);
                        ret_node = build_response1(env, base64text);
                    }
                    else /* attachement missing */
                    {
                        AXIS2_ERROR_SET(env->error,
                            AXIS2_ERROR_ATTACHMENT_MISSING,
                            AXIS2_FAILURE);
                        printf("Echo client ERROR: attachment is missing.\n");
                        return NULL;
                    }
                    /* } */
                }
            }

        }
    }
    else
    {
        AXIS2_ERROR_SET(env->error,
                        AXIS2_ERROR_SVC_SKEL_INVALID_XML_FORMAT_IN_REQUEST,
                        AXIS2_FAILURE);
        printf("Echo client ERROR: invalid XML in request\n");
        return NULL;
    }
    return ret_node;
}

axiom_node_t *
build_response1(
    const axutil_env_t * env,
    axis2_char_t * text)
{
    axiom_node_t *mtom_om_node = NULL;
    axiom_element_t *mtom_om_ele = NULL;
    axiom_node_t *om_node = NULL;
    axiom_element_t *om_ele = NULL;

   
    axiom_namespace_t *ns1 = NULL;

    ns1 =
        axiom_namespace_create(env, "http://ws.apache.org/axis2/c/samples",
                               "ns1");

    mtom_om_ele =
        axiom_element_create(env, NULL, "response", ns1, &mtom_om_node);

    om_ele  = axiom_element_create(env, mtom_om_node, "string", NULL, &om_node);
    
    axiom_element_set_text(mtom_om_ele, env, text, om_node);
   

    return mtom_om_node;
}


axiom_node_t *build_response2(
    const axutil_env_t *env,
    axiom_data_handler_t *data_handler)
{
    axiom_node_t *mtom_om_node = NULL;
    axiom_element_t *mtom_om_ele = NULL;
    axiom_node_t *text_node = NULL;
    axiom_namespace_t *ns1 = NULL;

    ns1 =
        axiom_namespace_create(env, "http://ws.apache.org/axis2/c/samples",
                               "ns1");
    mtom_om_ele =
        axiom_element_create(env, NULL, "response", ns1, &mtom_om_node);

    axiom_text_create_with_data_handler(env, mtom_om_node, data_handler,
        &text_node);

    return mtom_om_node;
}

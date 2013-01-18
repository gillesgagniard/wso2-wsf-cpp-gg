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
 
#include <sandesha2_utils.h>
#include <sandesha2_constants.h>
#include <sandesha2_transport_sender.h>
#include <sandesha2_seq_property_mgr.h>
#include <sandesha2_error.h>
#include <sandesha2_seq.h>
#include <sandesha2_seq_ack.h>
#include <sandesha2_ack_requested.h>
#include <sandesha2_close_seq.h>
#include <sandesha2_close_seq_res.h>
#include <sandesha2_polling_mgr.h>
#include <sandesha2_permanent_storage_mgr.h>
#include <axutil_string.h>
#include <axis2_conf.h>
#include <axis2_const.h>
#include <axutil_property.h>
#include <axutil_uuid_gen.h>
#include <axiom_soap_body.h>
#include <axis2_options.h>
#include <axis2_msg_ctx.h>
#include <axis2_engine.h>
#include <axis2_transport_out_desc.h>
#include <axis2_transport_in_desc.h>
#include <axutil_qname.h>
#include <axis2_http_transport.h>
#include <axis2_addr.h>
#include <axiom_soap_header.h>
#include <axutil_param.h>
#include <stdlib.h>
#include <sys/timeb.h>
#include <axis2_policy_include.h>
#include <neethi_policy.h>
#include <axis2_rm_assertion.h>
#include <sandesha2_property_mgr.h>

static axutil_array_list_t *
get_sorted_msg_no_list(
        const axutil_env_t *env,
        axis2_char_t *msg_no_str,
        axis2_char_t *delim);

static axutil_array_list_t *
sandesha2_utils_sort(
        const axutil_env_t *env,
        axutil_array_list_t *list);

AXIS2_EXTERN void AXIS2_CALL
sandesha2_util_dummy_prop_free();

AXIS2_EXTERN axis2_msg_ctx_t * AXIS2_CALL
sandesha2_utils_create_out_msg_ctx(
    const axutil_env_t *env,
    axis2_msg_ctx_t *in_msg_ctx);

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_utils_remove_soap_body_part(
    const axutil_env_t *env, 
    axiom_soap_envelope_t *envelope, 
    axutil_qname_t *qname)
{
    axiom_soap_body_t *soap_body = NULL;
    axiom_node_t *body_node = NULL;
    axiom_node_t *body_rm_node = NULL;
    axiom_element_t *body_element = NULL;
    axiom_element_t *body_rm_element = NULL;
    
    AXIS2_PARAM_CHECK(env->error, envelope, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, qname, AXIS2_FAILURE);
    
    soap_body = axiom_soap_envelope_get_body(envelope, env);
    if(!soap_body)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[sandesha2] Soap envelope does not have a soap body");
        return AXIS2_FAILURE;
    }

    body_node = axiom_soap_body_get_base_node(soap_body, env);
    if(!body_node)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Soap body does not have a base node");
        return AXIS2_FAILURE;
    }

    body_element = axiom_node_get_data_element(body_node, env);
    if(!body_element)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[sandesha2] Soap body node does not have a node element");
        return AXIS2_FAILURE;
    }

    body_rm_element = axiom_element_get_first_child_with_qname(body_element, env, qname, body_node, 
            &body_rm_node);

    if(body_rm_element)
    {
        axiom_node_t *temp_node = NULL;

        temp_node = axiom_node_detach(body_rm_node, env);
        if(temp_node)
        {
            axiom_node_free_tree(temp_node, env);
        }
    }

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN long AXIS2_CALL
sandesha2_utils_get_current_time_in_millis(
    const axutil_env_t *env)
{
    /*const long fixed_time = 1153918446;
    long millis = -1;*/
    long seconds = -1;
    struct timeb *tp = AXIS2_MALLOC(env->allocator, sizeof(struct timeb));
    ftime(tp);
    /* To prevent an overflow we substract a contstant from seconds value
     * This value is taken as 18.23.xx seconds on 26 Jul 2006
     *
     */
    seconds = tp->time;
    /*seconds -= fixed_time;
    seconds *= 1000;
    millis = tp->millitm;
    millis = millis + seconds;

    return millis;*/
    if(tp)
        AXIS2_FREE(env->allocator, tp);
    return seconds;
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
sandesha2_utils_get_rm_version(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx)
{
    axis2_char_t *value = NULL;
    sandesha2_property_bean_t *prop_bean = NULL;
    axis2_svc_t *svc = NULL;
    
    svc = axis2_msg_ctx_get_svc(msg_ctx, env);
    prop_bean = sandesha2_utils_get_property_bean(env, svc);
    if(prop_bean)
    {
        value = sandesha2_property_bean_get_spec_version(prop_bean, env);
    }
    
    return value;
}

AXIS2_EXTERN sandesha2_storage_mgr_t* AXIS2_CALL
sandesha2_utils_get_storage_mgr(
    const axutil_env_t *env,
    axis2_char_t *dbname)
{
    sandesha2_storage_mgr_t *storage_mgr = NULL;
   
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2]Entry:sandesha2_utils_get_storage_mgr");
    
    storage_mgr = sandesha2_utils_get_permanent_storage_mgr(env, dbname);
    AXIS2_LOG_TRACE(env->log, AXIS2_LOG_SI, 
        "[sandesha2]Exit:sandesha2_utils_get_storage_mgr");
    return storage_mgr;
}
                        
AXIS2_EXTERN axis2_char_t* AXIS2_CALL
sandesha2_utils_get_seq_property(
    const axutil_env_t *env,
    const axis2_char_t *incoming_seq_id,
    const axis2_char_t *name,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_char_t *value = NULL;
    sandesha2_seq_property_bean_t *seq_prop_bean = NULL;
    
    AXIS2_PARAM_CHECK(env->error, incoming_seq_id, NULL);
    AXIS2_PARAM_CHECK(env->error, name, NULL);
    AXIS2_PARAM_CHECK(env->error, seq_prop_mgr, NULL);
    
    seq_prop_bean = sandesha2_seq_property_mgr_retrieve(seq_prop_mgr, env, incoming_seq_id, name);
    if(!seq_prop_bean)
    {
        return NULL;
    }

    value = axutil_strdup(env, sandesha2_seq_property_bean_get_value(seq_prop_bean, env));
    sandesha2_seq_property_bean_free(seq_prop_bean, env);
    return value;
}

AXIS2_EXTERN sandesha2_property_bean_t* AXIS2_CALL
sandesha2_utils_get_property_bean(
    const axutil_env_t *env,
    axis2_svc_t *svc)
    
{
    axutil_param_t *param = NULL;
    sandesha2_property_bean_t *property_bean = NULL; 

    AXIS2_PARAM_CHECK(env->error, svc, NULL);

    axutil_allocator_switch_to_global_pool(env->allocator);
    param = axis2_svc_get_param(svc, env, SANDESHA2_SANDESHA_PROPERTY_BEAN);
    if(!param)
    {
        axis2_rm_assertion_t *rm_assertion = NULL;

        rm_assertion = sandesha2_util_get_rm_assertion(env, svc); 
        if(rm_assertion)
        {
            property_bean = sandesha2_property_mgr_load_properties_from_policy(
                env, rm_assertion);
            if(property_bean)
            {
                param = axutil_param_create(env, SANDESHA2_SANDESHA_PROPERTY_BEAN, property_bean);
                axutil_param_set_value_free(param, env, sandesha2_property_bean_free_void_arg);
                axis2_svc_add_param(svc, env, param);
            }
            else
            {
                AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Cannot create Property bean");
                axutil_allocator_switch_to_local_pool(env->allocator);
                return NULL;
            }
        }   
        else
        {
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] Cannot Retreive RM assertion");
            axutil_allocator_switch_to_local_pool(env->allocator);
            return NULL;
        }
    }
    else
    {
        property_bean = (sandesha2_property_bean_t*) axutil_param_get_value(param, env);
    }

    axutil_allocator_switch_to_local_pool(env->allocator);
    if(!property_bean)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
                "[sandesha2] Property bean not found as a parameter in service");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CONFIGURATION_NOT_SET, AXIS2_FAILURE);

        return NULL;
    }

    return property_bean;
}

AXIS2_EXTERN axutil_array_list_t* AXIS2_CALL
sandesha2_utils_get_array_list_from_string(
    const axutil_env_t *env,
    axis2_char_t *str)
{
    axis2_char_t *dup_str = NULL;
    axis2_char_t *temp_str = NULL;
    axutil_array_list_t *ret = NULL;
    
    if(!str || 0 == axutil_strcmp("", str))
    {
        return NULL;
    }
    dup_str = axutil_strdup(env, str);
        
    ret = axutil_array_list_create(env, AXIS2_ARRAY_LIST_DEFAULT_CAPACITY);
    temp_str = NULL;
    temp_str = strtok(dup_str, ",");
    while(temp_str)
    {
        if(!sandesha2_utils_array_list_contains(env, ret, temp_str))
        {
            axis2_char_t *temp_element = axutil_strdup(env, temp_str);
            axutil_array_list_add(ret, env, temp_element);
        }
        temp_str = strtok(NULL, ",");
    }
    AXIS2_FREE(env->allocator, dup_str);
    return ret;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
sandesha2_utils_array_list_contains(
    const axutil_env_t *env,
    axutil_array_list_t *list,
    axis2_char_t *str)
{
    int i = 0;
    AXIS2_PARAM_CHECK(env->error, list, AXIS2_FALSE);
    AXIS2_PARAM_CHECK(env->error, str, AXIS2_FALSE);
    
    for(i = 0; i < axutil_array_list_size(list, env); i++)
    {
        axis2_char_t *element = axutil_array_list_get(list, env, i);
        if(element && 0 == axutil_strcmp(element, str))
            return AXIS2_TRUE;
    }
    return AXIS2_FAILURE;
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
sandesha2_utils_array_list_to_string(
        const axutil_env_t *env,
        axutil_array_list_t *list, 
        int type)
{
    axis2_char_t *list_str = NULL;
    int i = 0, size = 0;
    
    AXIS2_PARAM_CHECK(env->error, list, NULL);
    size = axutil_array_list_size(list, env);
    if(size > 0)
    {
        list_str = (axis2_char_t *) AXIS2_MALLOC(env->allocator, 
            size * 64 * sizeof(axis2_char_t));
        if(SANDESHA2_ARRAY_LIST_STRING == type)
        {
            axis2_char_t *element = axutil_array_list_get(list, env, 0);
            sprintf(list_str, "%s", element);
        }
        else if(SANDESHA2_ARRAY_LIST_LONG == type)
        {
            long *element = axutil_array_list_get(list, env, 0);
            sprintf(list_str, "%ld", *element);
        }
    }
    for(i = 1; i < size; i++)
    {
        int len = axutil_strlen(list_str);
        if(SANDESHA2_ARRAY_LIST_STRING == type)
        {
            axis2_char_t *element = axutil_array_list_get(list, env, i);
            sprintf(list_str + len, ",%s", element);
        }
        else if(SANDESHA2_ARRAY_LIST_LONG == type)
        {
            long *element = axutil_array_list_get(list, env, i);
            sprintf(list_str + len, ",%ld", *element);
        } 
    }
    return list_str;

}

/*AXIS2_EXTERN axis2_status_t AXIS2_CALL                        
sandesha2_utils_start_invoker_for_seq(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *seq_id)
{
    sandesha2_in_order_invoker_t *invoker = NULL;
    axutil_property_t *property = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FAILURE);
    
    property = axis2_ctx_get_property(axis2_conf_ctx_get_base(conf_ctx, env),
        env, SANDESHA2_INVOKER);
    if(property)
        invoker = axutil_property_get_value(property, env);
    if(!invoker)
    {
        invoker = sandesha2_in_order_invoker_create(env);
        property = axutil_property_create_with_args(env, AXIS2_SCOPE_APPLICATION, 
            AXIS2_FALSE, (void *)sandesha2_in_order_invoker_free_void_arg, 
            invoker);
        axis2_ctx_set_property(axis2_conf_ctx_get_base(conf_ctx, env),
            env, SANDESHA2_INVOKER, property);
    }
    status = sandesha2_in_order_invoker_run_for_seq(invoker, env, conf_ctx, 
        seq_id);
    return status;
}*/

AXIS2_EXTERN axis2_status_t AXIS2_CALL                        
sandesha2_utils_start_sender_for_seq(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx,
    axis2_char_t *seq_id,
    const axis2_bool_t persistent)
{
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, seq_id, AXIS2_FAILURE);
    
    /*return sandesha2_sender_run_for_seq(env, conf_ctx, seq_id, persistent);*/
    return AXIS2_SUCCESS;
}
 
AXIS2_EXTERN axis2_char_t* AXIS2_CALL
sandesha2_utils_get_internal_sequence_id(
    const axutil_env_t *env,
    axis2_char_t *rmd_sequence_id)
{
    AXIS2_PARAM_CHECK(env->error, rmd_sequence_id, NULL);
    
    return axutil_strcat(env, SANDESHA2_INTERNAL_SEQ_PREFIX, ":", rmd_sequence_id, NULL);
}

AXIS2_EXTERN axis2_transport_out_desc_t* AXIS2_CALL
sandesha2_utils_get_transport_out(const axutil_env_t *env)
{
    axis2_transport_out_desc_t *out_desc = NULL;
    axis2_transport_sender_t *transport_sender = NULL;
    
    transport_sender = sandesha2_transport_sender_create(env);
    out_desc = axis2_transport_out_desc_create(env, AXIS2_TRANSPORT_ENUM_HTTP);
    axis2_transport_out_desc_set_sender(out_desc, env, transport_sender);
    return out_desc;
}

AXIS2_EXTERN sandesha2_storage_mgr_t* AXIS2_CALL
sandesha2_utils_get_permanent_storage_mgr(
    const axutil_env_t *env,
    axis2_char_t *dbname)
{
    sandesha2_storage_mgr_t *storage_mgr = NULL;
    
    storage_mgr = sandesha2_permanent_storage_mgr_create(env, dbname);
    return storage_mgr;
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL                       
sandesha2_utils_get_rmd_seq_id(
        const axutil_env_t *env,
        axis2_char_t *internal_sequence_id)
{
    axis2_char_t *start_str = NULL;
    axis2_char_t *ret = NULL;
    int start_len = 0;
    
    AXIS2_PARAM_CHECK(env->error, internal_sequence_id, NULL);
    
    start_str = axutil_strcat(env, SANDESHA2_INTERNAL_SEQ_PREFIX, ":", NULL);
    start_len = axutil_strlen(start_str);
    if(0 != axutil_strncmp(internal_sequence_id, start_str, start_len))
        return NULL;
    ret = axutil_strdup(env, (internal_sequence_id + start_len * sizeof(axis2_char_t)));
    
    return ret;    
}


AXIS2_EXTERN sandesha2_property_bean_t* AXIS2_CALL
sandesha2_utils_get_property_bean_from_op(
    const axutil_env_t *env,
    axis2_op_t *op)
{
        axutil_param_t *param = NULL;
    
    AXIS2_PARAM_CHECK(env->error, op, NULL);
    
    param = axis2_op_get_param(op, env, SANDESHA2_SANDESHA_PROPERTY_BEAN);
    if(!param)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[sandesha2]Configuration not set.");
        AXIS2_ERROR_SET(env->error, SANDESHA2_ERROR_CONFIGURATION_NOT_SET,
            AXIS2_FAILURE);
        return NULL;
    }
    return (sandesha2_property_bean_t*)axutil_param_get_value(param, env);

}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
sandesha2_utils_get_client_internal_sequence_id(
    const axutil_env_t *env,
    axis2_char_t *to,
    axis2_char_t *seq_key)
{
    axis2_char_t *ret = NULL;

    if(!to && !seq_key)
    {
        return NULL;
    }
    else if(!to)
    {
        return axutil_strdup(env, seq_key);
    }
    else if(!seq_key)
    {
        return axutil_strdup(env, to);
    }
    else
    {
        ret = axutil_strcat(env, SANDESHA2_INTERNAL_SEQ_PREFIX, ":", to, ":", 
            seq_key, NULL);
        return ret;
    }
    return NULL;
}

AXIS2_EXTERN axis2_msg_ctx_t *AXIS2_CALL
sandesha2_utils_create_new_related_msg_ctx(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *ref_rm_msg)
{
    axis2_msg_ctx_t *ref_msg = NULL;
    axis2_msg_ctx_t *new_msg = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_conf_t *conf = NULL;
    axis2_transport_out_desc_t *out_desc = NULL;
    axis2_transport_in_desc_t *in_desc = NULL;
    axis2_op_ctx_t *op_ctx = NULL;
    axis2_svc_ctx_t *svc_ctx = NULL;
    axis2_op_t *op = NULL;
    axis2_op_t *op_new = NULL;
    axiom_soap_envelope_t *soap_env = NULL;
    axutil_property_t *property = NULL;
    axis2_char_t *addr_ver = NULL;
    axis2_char_t *paused_phase_name = NULL;
    axis2_svc_grp_t *svc_grp = NULL;
    axis2_svc_t *svc = NULL;
    axutil_stream_t *out_stream = NULL;
    axis2_char_t *transport_to = NULL;
    
    AXIS2_PARAM_CHECK(env->error, ref_rm_msg, NULL);
    
    ref_msg = sandesha2_msg_ctx_get_msg_ctx(ref_rm_msg, env);
    conf_ctx = axis2_msg_ctx_get_conf_ctx(ref_msg, env);
    conf = axis2_conf_ctx_get_conf(conf_ctx, env);
    
    out_desc = axis2_msg_ctx_get_transport_out_desc(ref_msg, env);
    in_desc = axis2_msg_ctx_get_transport_in_desc(ref_msg, env);
    
    new_msg = axis2_msg_ctx_create(env, conf_ctx, in_desc, out_desc);
    svc_grp = axis2_msg_ctx_get_svc_grp(ref_msg, env); 
    if(svc_grp)
    {
        axis2_msg_ctx_set_svc_grp(new_msg, env, svc_grp);
    }

    svc = axis2_msg_ctx_get_svc(ref_msg, env);

    if(axis2_msg_ctx_get_svc(ref_msg, env))
    {
        axis2_msg_ctx_set_svc(new_msg, env, svc);
    }

    svc_ctx = axis2_msg_ctx_get_svc_ctx(ref_msg, env);
    op = axis2_msg_ctx_get_op(ref_msg, env);
    op_new = axis2_svc_get_op_with_name(svc, env, "RMInOutOperation");

    op_ctx = axis2_op_ctx_create(env, op_new, svc_ctx);
    axis2_msg_ctx_set_op_ctx(new_msg, env, op_ctx);
    axis2_op_ctx_add_msg_ctx(op_ctx, env, new_msg);
    axis2_msg_ctx_set_svc_ctx(new_msg, env, svc_ctx);
    axis2_msg_ctx_set_svc_grp_ctx(new_msg, env, axis2_msg_ctx_get_svc_grp_ctx(ref_msg, env));

    soap_env = axiom_soap_envelope_create_default_soap_envelope(env, 
            sandesha2_utils_get_soap_version(env, axis2_msg_ctx_get_soap_envelope(ref_msg, env)));

    axis2_msg_ctx_set_soap_envelope(new_msg, env, soap_env);
    
    transport_to = axis2_msg_ctx_get_transport_url(ref_msg, env);
    if(transport_to)
    {
        axis2_msg_ctx_set_transport_url(new_msg, env, transport_to);
    }

    sandesha2_util_clone_property_map(env, ref_msg, new_msg);
    property = axis2_msg_ctx_get_property(ref_msg, env, AXIS2_WSA_VERSION);
    if(!property)
    {
        axis2_msg_ctx_t *req_msg = NULL;
        axis2_op_ctx_t *temp_op_ctx = NULL;
        
        temp_op_ctx = axis2_msg_ctx_get_op_ctx(ref_msg, env);
        if(temp_op_ctx)
        {
            req_msg =  axis2_op_ctx_get_msg_ctx(temp_op_ctx, env, AXIS2_WSDL_MESSAGE_LABEL_IN);
        }

        if(req_msg)
        {
            property = axis2_msg_ctx_get_property(req_msg, env, AXIS2_WSA_VERSION);
            if(property)
            {
                addr_ver = axutil_strdup(env, axutil_property_get_value(property, env));
            }
        }
    }
    else
    {
        addr_ver = axutil_strdup(env, axutil_property_get_value(property, env));
    }

    property = axutil_property_create_with_args(env, 0, AXIS2_TRUE, 0, addr_ver);
    axis2_msg_ctx_set_property(new_msg, env, AXIS2_WSA_VERSION, property);
    
    out_stream = axis2_msg_ctx_get_transport_out_stream(ref_msg, env);
    axis2_msg_ctx_set_transport_out_stream(new_msg, env, out_stream);
    /*property = axis2_msg_ctx_get_property(ref_msg, env, AXIS2_TRANSPORT_IN);
    if(property)
    {
        axis2_msg_ctx_set_property(new_msg, env, AXIS2_TRANSPORT_IN, sandesha2_util_property_clone(
                    env, property));
    }*/

    axis2_msg_ctx_set_out_transport_info(new_msg, env, axis2_msg_ctx_get_out_transport_info(ref_msg, 
                env));

    axis2_msg_ctx_set_charset_encoding(new_msg, env, axis2_msg_ctx_get_charset_encoding(ref_msg, 
                env));

    /*property = axis2_msg_ctx_get_property(ref_msg, env, AXIS2_TRANSPORT_HEADERS);
    if(property)
    {
        axis2_msg_ctx_set_property(new_msg, env, AXIS2_TRANSPORT_HEADERS, sandesha2_util_property_clone(
                    env, property));
    }*/

    paused_phase_name = (axis2_char_t*)axis2_msg_ctx_get_paused_phase_name(ref_msg, env);

    axis2_msg_ctx_set_paused_phase_name(new_msg, env, paused_phase_name);

    return new_msg;
}

AXIS2_EXTERN  int AXIS2_CALL
sandesha2_utils_get_soap_version(
    const axutil_env_t *env, 
    axiom_soap_envelope_t *envelope)
{
    AXIS2_PARAM_CHECK(env->error, envelope, -1);
    
    return axiom_soap_envelope_get_soap_version(envelope, env);
}

AXIS2_EXTERN axis2_char_t* AXIS2_CALL
sandesha2_utils_trim_string(
    const axutil_env_t *env, 
    axis2_char_t *orig_str)
{
    axis2_char_t *tmp = NULL;
    axis2_char_t *tmp2 = NULL;
    axis2_char_t *ret = NULL;
    int len = 0;
    
    AXIS2_PARAM_CHECK(env->error, orig_str, NULL);
    
    tmp = orig_str;
    while(' ' == *tmp)
        tmp++;
        
    tmp2 = orig_str + axutil_strlen(orig_str);
    while(' ' == *tmp2 && tmp2 != orig_str)
        tmp2--;
        
    len = tmp2 - tmp;
    if(len > 0)
        ret = AXIS2_MALLOC(env->allocator, len + sizeof(axis2_char_t));
        
    memcpy(ret, tmp, len);
    ret[len] = '\0';
    return ret;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL                        
sandesha2_utils_is_retrievable_on_faults(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx)
{
    axis2_bool_t ret = AXIS2_FALSE;
    axis2_char_t *action = NULL;
    
    AXIS2_PARAM_CHECK(env->error, msg_ctx, AXIS2_FALSE);
    
    action =  (axis2_char_t*)axis2_msg_ctx_get_wsa_action(msg_ctx, env);
    if(!action)
        return AXIS2_FALSE;
        
    if(0 == axutil_strcmp(action, SANDESHA2_SPEC_2005_02_ACTION_CREATE_SEQ))
        ret = AXIS2_TRUE;
    else if(0 == axutil_strcmp(action, SANDESHA2_SPEC_2007_02_ACTION_CREATE_SEQ))
        ret = AXIS2_TRUE;
        
    return ret;
}

AXIS2_EXTERN axis2_bool_t AXIS2_CALL
sandesha2_utils_is_rm_global_msg(
    const axutil_env_t *env,
    axis2_msg_ctx_t *msg_ctx)
{
    axis2_bool_t is_global_msg = AXIS2_FALSE;
    axis2_char_t *action = NULL;
    axiom_soap_envelope_t *soap_env = NULL;
    axiom_soap_header_t *soap_header = NULL;
    axiom_element_t *header_element = NULL;
    axiom_node_t *header_node = NULL;
    axiom_element_t *seq_element = NULL;
    axiom_node_t *seq_node = NULL;
    axutil_qname_t *qname = NULL;
    
    AXIS2_PARAM_CHECK(env->error, msg_ctx, AXIS2_FALSE);
    
    action = (axis2_char_t*)axis2_msg_ctx_get_wsa_action(msg_ctx, env);
    soap_env = axis2_msg_ctx_get_soap_envelope(msg_ctx, env);
    
    if(!soap_env)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[sandesha2] SOAP envelope is"
            " NULL");
        return AXIS2_FALSE;
    }
    soap_header = axiom_soap_envelope_get_header(soap_env, env);
    
    if(soap_header)
    {
        header_node = axiom_soap_header_get_base_node(soap_header, env);
        header_element = axiom_node_get_data_element(header_node, env);
    
        qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_SEQ,
                        SANDESHA2_SPEC_2005_02_NS_URI, NULL);
        seq_element = axiom_element_get_first_child_with_qname(header_element, 
                        env, qname, header_node, &seq_node);
        if(qname)
            axutil_qname_free(qname, env);
        if(!seq_element)
        {
            qname = axutil_qname_create(env, SANDESHA2_WSRM_COMMON_SEQ,
                        SANDESHA2_SPEC_2007_02_NS_URI, NULL);
            seq_element = axiom_element_get_first_child_with_qname(
                        header_element, env, qname, header_node, &seq_node);
            if(qname)
                axutil_qname_free(qname, env);
        }
    }
    if(seq_element)
        is_global_msg = AXIS2_TRUE;
        
    if(0 == axutil_strcmp(action, 
                        SANDESHA2_SPEC_2005_02_ACTION_SEQ_ACKNOWLEDGEMENT))
        is_global_msg = AXIS2_TRUE;
        
    if(0 == axutil_strcmp(action, 
                        SANDESHA2_SPEC_2005_02_ACTION_CREATE_SEQ_RESPONSE))
        is_global_msg = AXIS2_TRUE;
        
    if(0 == axutil_strcmp(action, SANDESHA2_SPEC_2005_02_ACTION_TERMINATE_SEQ))
        is_global_msg = AXIS2_TRUE;    
        
    if(0 == axutil_strcmp(action, 
                        SANDESHA2_SPEC_2007_02_ACTION_SEQ_ACKNOWLEDGEMENT))
        is_global_msg = AXIS2_TRUE;
        
    if(0 == axutil_strcmp(action, 
                        SANDESHA2_SPEC_2007_02_ACTION_CREATE_SEQ_RESPONSE))
        is_global_msg = AXIS2_TRUE;
        
    if(0 == axutil_strcmp(action, SANDESHA2_SPEC_2007_02_ACTION_TERMINATE_SEQ))
        is_global_msg = AXIS2_TRUE;    
    
    return is_global_msg;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
sandesha2_utils_get_seq_id_from_rm_msg_ctx(
    const axutil_env_t *env, 
    sandesha2_msg_ctx_t *rm_msg_ctx)
{
    int msg_type = -1;
    axis2_char_t *seq_id = NULL;
    
    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, NULL);
    
    msg_type = sandesha2_msg_ctx_get_msg_type(rm_msg_ctx, env);
    
    if(SANDESHA2_MSG_TYPE_APPLICATION == msg_type)
    {
        sandesha2_seq_t *seq = NULL;
        seq = sandesha2_msg_ctx_get_sequence(rm_msg_ctx, env);
        seq_id = sandesha2_identifier_get_identifier(
                        sandesha2_seq_get_identifier(seq, env), env);
    }
    else if(SANDESHA2_MSG_TYPE_ACK == msg_type)
    {
        sandesha2_seq_ack_t *seq_ack = NULL;
        seq_ack = sandesha2_msg_ctx_get_seq_ack(rm_msg_ctx, env);
        seq_id = sandesha2_identifier_get_identifier(
                        sandesha2_seq_ack_get_identifier(seq_ack, env), env);
    }
    else if(SANDESHA2_MSG_TYPE_ACK_REQUEST == msg_type)
    {
        sandesha2_ack_requested_t *ack_requested = NULL;
        ack_requested = sandesha2_msg_ctx_get_ack_requested(rm_msg_ctx, env);
        seq_id = sandesha2_identifier_get_identifier(
                        sandesha2_ack_requested_get_identifier(ack_requested, 
                        env), env);
    }
    else if(SANDESHA2_MSG_TYPE_CLOSE_SEQ == msg_type)
    {
        sandesha2_close_seq_t *close_seq = NULL;
        close_seq = sandesha2_msg_ctx_get_close_seq(rm_msg_ctx, env);
        seq_id = sandesha2_identifier_get_identifier(
                        sandesha2_close_seq_get_identifier(close_seq, 
                        env), env);
    }
    else if(SANDESHA2_MSG_TYPE_CLOSE_SEQ_RESPONSE == msg_type)
    {
        sandesha2_close_seq_res_t *close_seq_res = NULL;
        close_seq_res = sandesha2_msg_ctx_get_close_seq_res(rm_msg_ctx, env);
        seq_id = sandesha2_identifier_get_identifier(
                        sandesha2_close_seq_res_get_identifier(close_seq_res, 
                        env), env);
    }
    return seq_id;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_utils_stop_invoker(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx)
{
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    
    /*TODO */
    return AXIS2_SUCCESS;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
sandesha2_utils_stop_sender(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx)
{
    AXIS2_PARAM_CHECK(env->error, conf_ctx, AXIS2_FAILURE);
    
    /*TODO */
    return AXIS2_SUCCESS;
}
 
/**
 * Used to convert a message number list (a comma seperated list of message
 * numbers) into a set of Acknowledgement Ranges. This breaks the list, sort
 * the items and group them to create the ack_range objects.
 * 
 * @param msg_no_str
 * @return
 */
AXIS2_EXTERN axutil_array_list_t *AXIS2_CALL
sandesha2_utils_get_ack_range_list(
    const axutil_env_t *env,
    axis2_char_t *msg_no_str,
    axis2_char_t *rm_ns_value)
{
    axutil_array_list_t *ack_ranges = NULL;
    axutil_array_list_t *sorted_msg_no_list = NULL;
    int i = 0, size = 0;
    long lower = 0;
    long upper = 0;
    axis2_bool_t completed = AXIS2_TRUE;

    ack_ranges = axutil_array_list_create(env, 0);
    sorted_msg_no_list = get_sorted_msg_no_list(env, msg_no_str, ",");
    if(sorted_msg_no_list)
        size = axutil_array_list_size(sorted_msg_no_list, env);
    for(i = 0; i < size; i++)
    {
        long *temp = axutil_array_list_get(sorted_msg_no_list, env, i);
        if(lower == 0)
        {
            lower = *temp;
            upper = *temp;
            completed = AXIS2_FALSE;
        }
        else if(*temp == (upper + 1))
        {
            upper = *temp;
            completed = AXIS2_FALSE;
        }
        else
        {
             sandesha2_ack_range_t *ack_range = NULL;
             
             ack_range = sandesha2_ack_range_create(env, rm_ns_value, NULL);
             sandesha2_ack_range_set_lower_value(ack_range, env, lower);
             sandesha2_ack_range_set_upper_value(ack_range, env, upper);
             axutil_array_list_add(ack_ranges, env, ack_range);
             lower = *temp;
             upper = *temp;
             completed = AXIS2_FALSE;
        }
        if(temp)
        {
            AXIS2_FREE(env->allocator, temp);
        }
    }
    if(!completed)
    {
         sandesha2_ack_range_t *ack_range = NULL;
         
         ack_range = sandesha2_ack_range_create(env, rm_ns_value, NULL);
         sandesha2_ack_range_set_lower_value(ack_range, env, lower);
         sandesha2_ack_range_set_upper_value(ack_range, env, upper);
         axutil_array_list_add(ack_ranges, env, ack_range);
         completed = AXIS2_TRUE;
    }
    if(sorted_msg_no_list)
    {
        axutil_array_list_free(sorted_msg_no_list, env);
    }
    return ack_ranges;
}

static axutil_array_list_t *
get_sorted_msg_no_list(
    const axutil_env_t *env,
    axis2_char_t *msg_no_str,
    axis2_char_t *delim)
{
    axutil_array_list_t *msg_numbers = NULL;
    axutil_array_list_t *sorted_msg_no_list = NULL;
    axis2_char_t *dup_str = NULL;
    axis2_char_t *temp_str = NULL;

    dup_str = axutil_strdup(env, msg_no_str);
    msg_numbers = axutil_array_list_create(env, 0);
    temp_str = strtok(dup_str, delim);
    while(temp_str)
    {
        long *long_val = AXIS2_MALLOC(env->allocator, sizeof(long));

        *long_val = atol(temp_str);
        axutil_array_list_add(msg_numbers, env, long_val);
        temp_str = strtok(NULL, delim);
    }
    sorted_msg_no_list = sandesha2_utils_sort(env, msg_numbers);
    if(msg_numbers)
    {
        int i = 0;
        int size = 0;

        size = axutil_array_list_size(msg_numbers, env);
        for(i = 0; i < size; i++)
        {
            long *temp_long = NULL;

            temp_long = (long *) axutil_array_list_get(msg_numbers, env, i);
            AXIS2_FREE(env->allocator, temp_long);
        }
        axutil_array_list_free(msg_numbers, env);
    }
    AXIS2_FREE(env->allocator, dup_str);
    return sorted_msg_no_list;
}

static axutil_array_list_t *
sandesha2_utils_sort(
    const axutil_env_t *env,
    axutil_array_list_t *list)
{
    axutil_array_list_t *sorted_list = NULL;
    long max = 0;
    int i = 0, size = 0;
    long j = 0;
    
    sorted_list = axutil_array_list_create(env, 0);
    if(list)
    {
        size = axutil_array_list_size(list, env);
    }

    for(i = 0; i < size; i++)
    {
        long *temp_long = NULL;

        temp_long = (long *) axutil_array_list_get(list, env, i);
        if(*temp_long > max)
        {
            max = *temp_long;
        }
    }

    for(j = 1; j <= max; j++)
    {
        long *temp = AXIS2_MALLOC(env->allocator, sizeof(long));
        axis2_bool_t contains = AXIS2_FALSE;
        
        *temp = j;
        for(i = 0; i < size; i++)
        {
            long *value = NULL;
            value = axutil_array_list_get(list, env, i);
            if(*value == *temp)
            {
                contains = AXIS2_TRUE;
                break;
            }
        }

        if(contains)
        {
            axutil_array_list_add(sorted_list, env, temp);
        }
    }
    return sorted_list;    
}

axis2_bool_t AXIS2_CALL
sandesha2_utils_is_all_msgs_acked_upto(
    const axutil_env_t *env,
    long highest_in_msg_no,
    axis2_char_t *internal_seq_id,
    sandesha2_seq_property_mgr_t *seq_prop_mgr)
{
    axis2_char_t *client_completed_msgs = NULL;
    axutil_array_list_t *acked_msgs_list = NULL;
    long smallest_msg_no = 1;
    long temp_msg_no = 0;
    axis2_bool_t ret = AXIS2_TRUE;

    client_completed_msgs = sandesha2_utils_get_seq_property(env, internal_seq_id, 
            SANDESHA2_SEQ_PROP_CLIENT_COMPLETED_MESSAGES, seq_prop_mgr);

    if(client_completed_msgs)
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] Client_completed_msgs:%s", 
            client_completed_msgs);

        acked_msgs_list = sandesha2_utils_get_array_list_from_string(env, client_completed_msgs);
        AXIS2_FREE(env->allocator, client_completed_msgs);
    }

    if(!acked_msgs_list)
    {
        return AXIS2_FALSE;
    }

    for(temp_msg_no = smallest_msg_no; temp_msg_no <= highest_in_msg_no; temp_msg_no++)
    {
        axis2_char_t str_msg_no[32];

        sprintf(str_msg_no, "%ld", temp_msg_no);
        if(!sandesha2_utils_array_list_contains(env, acked_msgs_list, str_msg_no))
        {
            ret = AXIS2_FALSE;
            break;
        }
    }
    
    axutil_array_list_free(acked_msgs_list, env);

    return ret; /* All messages upto the highest have been acked */
}

axis2_status_t AXIS2_CALL
sandesha2_utils_execute_and_store(
    const axutil_env_t *env,
    sandesha2_msg_ctx_t *rm_msg_ctx,
    axis2_char_t *storage_key)
{
    axis2_msg_ctx_t *msg_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_transport_out_desc_t *transport_out = NULL;
    axis2_transport_out_desc_t *sandesha2_transport_out = NULL;
    axutil_property_t *property = NULL;
    axis2_engine_t *engine = NULL;
    axis2_status_t status = AXIS2_FAILURE;

    msg_ctx = sandesha2_msg_ctx_get_msg_ctx(rm_msg_ctx, env);
    if(msg_ctx)
    {
        conf_ctx = axis2_msg_ctx_get_conf_ctx(msg_ctx, env);
    }

    sandesha2_msg_ctx_set_msg_type(rm_msg_ctx, env, SANDESHA2_MSG_TYPE_CREATE_SEQ);
    /* Message will be stored in the sandesha2_transport_sender */
    property = axutil_property_create_with_args(env, AXIS2_SCOPE_REQUEST, AXIS2_TRUE, 0, storage_key);
    axis2_msg_ctx_set_property(msg_ctx, env, SANDESHA2_MESSAGE_STORE_KEY, property);
    
    transport_out = axis2_msg_ctx_get_transport_out_desc(msg_ctx, env);
    property = axutil_property_create_with_args(env, 3, 0, 
        axis2_transport_out_desc_free_void_arg, transport_out);
    axis2_msg_ctx_set_property(msg_ctx, env, SANDESHA2_ORIGINAL_TRANSPORT_OUT_DESC, property);
    
    /*property = axutil_property_create_with_args(env, 0, 0, 0, AXIS2_VALUE_TRUE);
    axis2_msg_ctx_set_property(msg_ctx, env, SANDESHA2_SET_SEND_TO_TRUE, property);*/
    sandesha2_transport_out = sandesha2_utils_get_transport_out(env);
    axis2_msg_ctx_set_transport_out_desc(msg_ctx, env, sandesha2_transport_out);
    /*Sending the message once through the sandesha2_transport_sender */
    engine = axis2_engine_create(env, conf_ctx);
    if(axis2_msg_ctx_is_paused(msg_ctx, env))
    {
        axis2_msg_ctx_set_current_handler_index(msg_ctx, env, 
            axis2_msg_ctx_get_current_handler_index(msg_ctx, env) + 1);
        status = axis2_engine_resume_send(engine, env, msg_ctx);
    }
    else
    {
        status = axis2_engine_send(engine, env, msg_ctx);
    }

    if(engine)
    {
        axis2_engine_free(engine, env);
    }

    return status;
}

axis2_bool_t AXIS2_CALL
sandesha2_utils_is_wsrm_anon_reply_to(
    const axutil_env_t *env,
    const axis2_char_t *reply_to)
{
    if (reply_to && axutil_strstr(reply_to, "anonymous"))
        return AXIS2_TRUE;
    if (reply_to && axutil_strstr(reply_to, AXIS2_WS_RM_ANONYMOUS_URL))
        return AXIS2_TRUE;
    else
        return AXIS2_FALSE;
}

axis2_bool_t AXIS2_CALL
sandesha2_utils_is_anon_uri(
    const axutil_env_t *env,
    const axis2_char_t *address)
{
    axis2_bool_t ret = AXIS2_FALSE;

    axis2_char_t *address_l = NULL;
    if(!address)
    {
        return AXIS2_TRUE;
    }

    address_l = axutil_strtrim(env, address, NULL);

    if(!axutil_strcmp(AXIS2_WSA_ANONYMOUS_URL, address_l))
    {
        ret = AXIS2_TRUE;
    }

    if(!axutil_strcmp(AXIS2_WSA_ANONYMOUS_URL_SUBMISSION, address_l))
    {
        ret = AXIS2_TRUE;
    }
    else if (sandesha2_utils_is_wsrm_anon_reply_to(env, (axis2_char_t *) address))
    {
        ret = AXIS2_TRUE;
    }

    AXIS2_FREE(env->allocator, address_l);

    return ret;
}

axutil_array_list_t *AXIS2_CALL
sandesha2_utils_split(
    const axutil_env_t *env,
    axis2_char_t *str,
    axis2_char_t *pattern)
{
    axutil_array_list_t *list = axutil_array_list_create(env, 0);
    axis2_char_t *ptr = NULL;
    axis2_char_t *value = NULL;
    ptr = axutil_strstr(str, pattern);

    while(ptr)
    {
        ptr[0] = AXIS2_EOLN;
        /*value = axutil_strdup(env, str);*/
        value = str;
        if(value && axutil_strcmp(value, ""))
        {
            axutil_array_list_add(list, env, value);
        }

        str = ptr + 3;
        ptr = axutil_strstr(str, pattern);
    }

    /*value = axutil_strdup(env, str);*/
    value = str;
    if(value && axutil_strcmp(value, ""))
    {
        axutil_array_list_add(list, env, value);
    }

    return list;
}

axis2_bool_t AXIS2_CALL
sandesha2_utils_is_rm_1_0_anonymous_acks_to(
    const axutil_env_t *env,
    const axis2_char_t *rm_version,
    const axis2_char_t *acks_to_addr)
{
    if(sandesha2_utils_is_anon_uri(env, acks_to_addr) &&
        (!axutil_strcmp(SANDESHA2_SPEC_VERSION_1_0, rm_version)))
    {
        return AXIS2_TRUE;
    }

    else return AXIS2_FALSE;
}

AXIS2_EXTERN axis2_msg_ctx_t * AXIS2_CALL
sandesha2_utils_create_out_msg_ctx(
    const axutil_env_t *env,
    axis2_msg_ctx_t *in_msg_ctx)
{
    axis2_ctx_t *ctx = NULL;
    axis2_msg_ctx_t *new_msg_ctx = NULL;
    axis2_conf_ctx_t *conf_ctx = NULL;
    axis2_transport_in_desc_t *transport_in = NULL;
    axis2_transport_out_desc_t *transport_out = NULL;
    axis2_msg_info_headers_t *old_msg_info_headers = NULL;
    axis2_msg_info_headers_t *msg_info_headers = NULL;
    axis2_endpoint_ref_t *reply_to = NULL;
    axis2_endpoint_ref_t *fault_to = NULL;
    axis2_endpoint_ref_t *to = NULL;
    const axis2_char_t *msg_id = NULL;
    axis2_relates_to_t *relates_to = NULL;
    const axis2_char_t *action = NULL;
    axis2_op_ctx_t *op_ctx = NULL;
    axis2_svc_ctx_t *svc_ctx = NULL;
    axis2_bool_t doing_rest = AXIS2_FALSE;
    axis2_bool_t doing_mtom = AXIS2_FALSE;
    axis2_bool_t server_side = AXIS2_FALSE;
    axis2_svc_grp_ctx_t *svc_grp_ctx = NULL;
    axis2_char_t *msg_uuid = NULL;
    axutil_stream_t *out_stream = NULL;

    AXIS2_PARAM_CHECK(env->error, in_msg_ctx, NULL);

    conf_ctx =  axis2_msg_ctx_get_conf_ctx(in_msg_ctx, env);
    transport_in =  axis2_msg_ctx_get_transport_in_desc(in_msg_ctx, env);
    transport_out =  axis2_msg_ctx_get_transport_out_desc(in_msg_ctx, env);

    new_msg_ctx = axis2_msg_ctx_create(env, conf_ctx, transport_in, transport_out);
    if (!new_msg_ctx)
    {
        return NULL;
    }
    old_msg_info_headers =  axis2_msg_ctx_get_msg_info_headers(in_msg_ctx, env);
    if (!old_msg_info_headers)
    {
        return NULL;
    }
    msg_info_headers =  axis2_msg_ctx_get_msg_info_headers(new_msg_ctx, env);
    if (!msg_info_headers)
    {
        /* if there is no msg info header in ew msg ctx, then create one */
        msg_info_headers = axis2_msg_info_headers_create(env, NULL, NULL);
        if (!msg_info_headers)
            return NULL;
         axis2_msg_ctx_set_msg_info_headers(new_msg_ctx, env, msg_info_headers);
    }

    msg_uuid =  axutil_uuid_gen(env);
    axis2_msg_info_headers_set_message_id(msg_info_headers, env, msg_uuid);
    if (msg_uuid)
    {
        AXIS2_FREE(env->allocator, msg_uuid);
        msg_uuid = NULL;
    }

    reply_to = axis2_msg_info_headers_get_reply_to(old_msg_info_headers, env);
    axis2_msg_info_headers_set_to(msg_info_headers, env, reply_to);

    fault_to = axis2_msg_info_headers_get_fault_to(old_msg_info_headers, env);
    axis2_msg_info_headers_set_fault_to(msg_info_headers, env, sandesha2_util_endpoint_ref_clone(
                env, fault_to));

    to = axis2_msg_info_headers_get_to(old_msg_info_headers, env);
    axis2_msg_info_headers_set_from(msg_info_headers, env, to);

    msg_id = axis2_msg_info_headers_get_message_id(old_msg_info_headers, env);
    relates_to = axis2_relates_to_create(env, msg_id, NULL
            /*AXIS2_WSA_RELATES_TO_RELATIONSHIP_TYPE_DEFAULT_VALUE*/);
    axis2_msg_info_headers_set_relates_to(msg_info_headers, env, relates_to);

    action = axis2_msg_info_headers_get_action(old_msg_info_headers, env);
    axis2_msg_info_headers_set_action(msg_info_headers, env, action);

    op_ctx =  axis2_msg_ctx_get_op_ctx(in_msg_ctx, env);
    axis2_msg_ctx_set_op_ctx(new_msg_ctx, env, op_ctx);

    svc_ctx =  axis2_msg_ctx_get_svc_ctx(in_msg_ctx, env);
     axis2_msg_ctx_set_svc_ctx(new_msg_ctx, env, svc_ctx);

    ctx = axis2_msg_ctx_get_base(in_msg_ctx, env);
    if (ctx)
    {
        axis2_ctx_t *new_ctx = axis2_msg_ctx_get_base(new_msg_ctx, env);
        if (new_ctx)
        {
            axis2_ctx_set_property_map(new_ctx, env, axis2_ctx_get_property_map(ctx, env));
        }
    }

    out_stream = axis2_msg_ctx_get_transport_out_stream(in_msg_ctx, env);
    axis2_msg_ctx_set_transport_out_stream(new_msg_ctx, env, out_stream);
    axis2_msg_ctx_set_out_transport_info(new_msg_ctx, env,
        axis2_msg_ctx_get_out_transport_info(in_msg_ctx, env));

    /* Setting the charater set encoding */
    doing_rest =  axis2_msg_ctx_get_doing_rest(in_msg_ctx, env);
    axis2_msg_ctx_set_doing_rest(new_msg_ctx, env, doing_rest);

    doing_mtom =  axis2_msg_ctx_get_doing_mtom(in_msg_ctx, env);
    axis2_msg_ctx_set_doing_mtom(new_msg_ctx, env, doing_mtom);

    server_side =  axis2_msg_ctx_get_server_side(in_msg_ctx, env);
    axis2_msg_ctx_set_server_side(new_msg_ctx, env, server_side);

    svc_grp_ctx =  axis2_msg_ctx_get_svc_grp_ctx(in_msg_ctx, env);
    axis2_msg_ctx_set_svc_grp_ctx(new_msg_ctx, env, svc_grp_ctx);

     axis2_msg_ctx_set_is_soap_11(new_msg_ctx, env,
             axis2_msg_ctx_get_is_soap_11(in_msg_ctx, env));
     /*axis2_msg_ctx_set_keep_alive(new_msg_ctx, env,
             axis2_msg_ctx_is_keep_alive(in_msg_ctx, env));*/

    axis2_msg_ctx_set_charset_encoding(new_msg_ctx, env,
        axis2_msg_ctx_get_charset_encoding(in_msg_ctx, env));
    return new_msg_ctx;
}

AXIS2_EXTERN void AXIS2_CALL
sandesha2_util_dummy_prop_free()
{
    return;
}

AXIS2_EXTERN axis2_char_t *AXIS2_CALL
sandesha2_util_get_dbname(
    const axutil_env_t *env,
    axis2_conf_ctx_t *conf_ctx)
{
    axis2_conf_t *conf = NULL;
    axis2_module_desc_t *module_desc = NULL;
    axutil_qname_t *qname = NULL;
    axis2_char_t *dbname = NULL;
    if(conf_ctx)
        conf = axis2_conf_ctx_get_conf((const axis2_conf_ctx_t *) conf_ctx, env);
    else
    {
        return NULL;
    }
    qname = axutil_qname_create(env, SANDESHA2_MODULE, NULL, NULL);
    module_desc = axis2_conf_get_module(conf, env, qname);
    if(module_desc)
    {
        axutil_param_t *dbparam = NULL;
        dbparam = axis2_module_desc_get_param(module_desc, env, SANDESHA2_DB);
        if(dbparam)
        {
            dbname = axutil_param_get_value(dbparam, env);
        }
    }

    if(!dbname)
    {
        axis2_char_t *home = NULL;
        home = AXIS2_GETENV("AXIS2C_HOME");
        if(home)
        {
            dbname = axutil_stracat(env, home, "/sandesha2_db");
        }
        else
        {
            dbname = "./sandesha2_db";
        }
    }
    if(qname)
        axutil_qname_free(qname, env);
    /*AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "dbname:%s", dbname);*/
    return dbname;
}

axis2_bool_t AXIS2_CALL
sandesha2_util_is_fault_envelope(
    const axutil_env_t *env, 
    axiom_soap_envelope_t *soap_envelope)
{
    axiom_soap_fault_t *fault = NULL;

    AXIS2_PARAM_CHECK(env->error, soap_envelope, AXIS2_FAILURE);
    
    fault = axiom_soap_body_get_fault(axiom_soap_envelope_get_body(soap_envelope, env), env);
    if(fault)
    {
        return AXIS2_TRUE;
    }
        
    return AXIS2_FALSE;
}

axis2_bool_t AXIS2_CALL
sandesha2_util_is_ack_already_piggybacked(
    const axutil_env_t *env, 
    sandesha2_msg_ctx_t *rm_msg_ctx)
{
    AXIS2_PARAM_CHECK(env->error, rm_msg_ctx, AXIS2_FAILURE);
    
    if(sandesha2_msg_ctx_get_seq_ack(rm_msg_ctx, env))
    {
        return AXIS2_TRUE;
    }
    
    return AXIS2_FALSE;
}

axis2_bool_t AXIS2_CALL
sandesha2_util_is_piggybackable_msg_type(
    const axutil_env_t *env, 
    int msg_type)
{
    if(SANDESHA2_MSG_TYPE_ACK == msg_type)
    {
        return AXIS2_FALSE;
    }

    return AXIS2_TRUE;
}

axutil_property_t *AXIS2_CALL
sandesha2_util_property_clone(
    const axutil_env_t * env,
    axutil_property_t * property)
{
    axutil_property_t *new_property = NULL;

    new_property = axutil_property_clone(property, env);
    axutil_property_set_own_value(new_property, env, 0);

    return new_property;
}

axis2_endpoint_ref_t *AXIS2_CALL
sandesha2_util_endpoint_ref_clone(
    const axutil_env_t * env,
    axis2_endpoint_ref_t * endpoint_ref)
{
    axis2_endpoint_ref_t *new_endpoint_ref = NULL;
    const axis2_char_t *address = NULL;

    if(endpoint_ref)
    {
        address = axis2_endpoint_ref_get_address(endpoint_ref, env);
        new_endpoint_ref = axis2_endpoint_ref_create(env, address);
    }

    return new_endpoint_ref;
}


axis2_rm_assertion_t *AXIS2_CALL
sandesha2_util_get_rm_assertion(
    const axutil_env_t * env,
    axis2_svc_t * svc)
{
    axis2_desc_t *desc = NULL;
    axis2_policy_include_t *policy_include = NULL;
    neethi_policy_t *service_policy = NULL;
    
    desc = axis2_svc_get_base(svc, env);
    if(!desc)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[sandesha][sandesha_util] Cannot find policy. Axis2 description is NULL.");
        return NULL;
    }

    policy_include = axis2_desc_get_policy_include(desc, env);
    if(!policy_include)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[sandesha][sandesha_util] Policy include is NULL.");
        return NULL;
    }

    service_policy = axis2_policy_include_get_effective_policy(policy_include, env);
    if(!service_policy)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[sandesha][sandesha_util] Policy is NULL.");
        return NULL;
    }

    return axis2_rm_assertion_get_from_policy(env, service_policy);
}

axis2_char_t *AXIS2_CALL
sandesha2_util_get_string_from_node_list(
    const axutil_env_t *env,
    axutil_array_list_t *node_list)
{
    axis2_char_t *node_list_str = NULL;
    int i = 0, size = 0;

    size = axutil_array_list_size(node_list, env);
    for(i = 0; i < size; i++)
    {
        axiom_node_t *node = NULL;
        axis2_char_t *node_str = NULL;
        axis2_char_t *temp_str = NULL;

        node = axutil_array_list_get(node_list, env, i);
        node_str = axiom_node_to_string(node, env);

        temp_str = node_list_str;

        if(i == 0)
        {
            node_list_str = axutil_strcat(env, node_str, SANDESHA2_PERSISTANT_PROPERTY_SEPERATOR, NULL);
        }
        else if(i == (--size))
        {
            node_list_str = axutil_strcat(env, temp_str, node_str, NULL);
        }
        else
        {
            node_list_str = axutil_strcat(env, temp_str, 
                node_str, SANDESHA2_PERSISTANT_PROPERTY_SEPERATOR, NULL);
        }

        if(node_str)
        {
            AXIS2_FREE(env->allocator, node_str);
        }

        if(temp_str && axutil_strlen(temp_str) > 0)
        {
            AXIS2_FREE(env->allocator, temp_str);
            temp_str = NULL;
        }
    }

    return node_list_str;
}

axutil_array_list_t *AXIS2_CALL
sandesha2_util_get_node_list_from_string(
    const axutil_env_t *env,
    axis2_char_t *node_list_str)
{
    axutil_array_list_t *value_list = NULL;
    int i = 0, size = 0;
    axutil_array_list_t *node_list = axutil_array_list_create(env, 0);

    value_list = sandesha2_utils_split(env, node_list_str, SANDESHA2_PERSISTANT_PROPERTY_SEPERATOR);
    if(value_list)
    {
        size = axutil_array_list_size(value_list, env);
        for(i = 0; i < size; i++)
        {
            axiom_stax_builder_t *om_builder = NULL;
            axiom_xml_reader_t *reader = NULL;
            axiom_document_t *document = NULL;
            axis2_char_t *value = NULL;
            axiom_node_t *node = NULL;
            
            value = axutil_array_list_get(value_list, env, i);
            reader = axiom_xml_reader_create_for_memory(env, value, axutil_strlen(value), NULL, 
                    AXIS2_XML_PARSER_TYPE_BUFFER);

            om_builder = axiom_stax_builder_create(env, reader);
            document = axiom_stax_builder_get_document(om_builder, env);
            axiom_document_build_all(document, env);
            node = axiom_document_get_root_element(document, env);
            axutil_array_list_add(node_list, env, node);

            /* Since we have built the document we can free the builder */
            axiom_stax_builder_free_self(om_builder, env);
        }

        axutil_array_list_free(value_list, env);
    }

    return node_list;
}


axis2_bool_t AXIS2_CALL
sandesha2_util_is_rstr_msg(
    const axutil_env_t *env, 
    axis2_msg_ctx_t *msg_ctx)
{
    axis2_char_t *action = NULL;    

    AXIS2_PARAM_CHECK(env->error, msg_ctx, AXIS2_FAILURE);

    action = (axis2_char_t *)axis2_msg_ctx_get_wsa_action(msg_ctx, env);

    if(!action)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,
            "[sandesha] WSA action is NULL.");
        return AXIS2_FALSE;
    }
    
    if(!axutil_strcmp(action, SECCONV_200502_REPLY_ISSUE_ACTION))
    {
        return AXIS2_TRUE;
    }
    else if(!axutil_strcmp(action, SECCONV_200502_REPLY_CANCEL_ACTION))
    {
        return AXIS2_TRUE;
    }
    else if(!axutil_strcmp(action, SECCONV_200512_REPLY_ISSUE_ACTION))
    {
        return AXIS2_TRUE;
    }
    else if(!axutil_strcmp(action, SECCONV_200512_REPLY_CANCEL_ACTION))
    {
        return AXIS2_TRUE;
    }
    else
    {
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI,
            "[sandesha] Not a RSTR message.");
        return AXIS2_FALSE;
    }
}

void AXIS2_CALL
sandesha2_util_clone_property_map(
    const axutil_env_t * env,
    axis2_msg_ctx_t *ref_msg_ctx,
    axis2_msg_ctx_t *new_msg_ctx)
{
    axis2_ctx_t *ctx = NULL;
    axis2_ctx_t *new_ctx = NULL;
    axutil_hash_t *property_map = NULL;

    ctx = axis2_msg_ctx_get_base(ref_msg_ctx, env);
    new_ctx = axis2_msg_ctx_get_base(new_msg_ctx, env);
    property_map = axis2_ctx_get_property_map(ctx, env);
    
    if (ctx)
    {
        axutil_hash_index_t *index = NULL;

        for (index = axutil_hash_first(property_map, env); index; index = axutil_hash_next(env, 
                    index))
        {
            axutil_property_t *new_property = NULL;
            void *v = NULL;
            const void *k = NULL;
            axis2_char_t *key = NULL;
            axutil_property_t *property = NULL;

            axutil_hash_this(index, &k, NULL, &v);
            key = (axis2_char_t *) k;
            property = (axutil_property_t *) v;
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[sandesha2] property:%s", key);
            new_property = sandesha2_util_property_clone(env, property);
            axis2_msg_ctx_set_property(new_msg_ctx, env, key, new_property);
        }
    }
}


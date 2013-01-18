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


#include <axis2_rm_assertion.h>
#include <sandesha2_property_mgr.h>
#include <sys/timeb.h>
#include <axutil_param.h>
#include <sandesha2_constants.h>
#include <sandesha2_error.h>
#include <axutil_string.h>
#include <axis2_conf.h>
#include <axutil_property.h>
#include <axiom_soap_body.h>
#include <axis2_options.h>
#include <axis2_msg_ctx.h>
#include <axis2_transport_out_desc.h>
#include <axis2_transport_in_desc.h>
#include <axutil_qname.h>
#include <sandesha2_utils.h>
#include <axutil_param.h>
#include <stdlib.h>

#include <axutil_types.h>


AXIS2_EXTERN  axis2_status_t AXIS2_CALL
sandesha2_property_mgr_load_exp_backoff(
    const axutil_env_t *env, 
    axis2_char_t *value, 
    sandesha2_property_bean_t *property_bean);
                        
AXIS2_EXTERN  axis2_status_t AXIS2_CALL
sandesha2_property_mgr_load_retrans_int(
    const axutil_env_t *env, 
    axis2_char_t *value, 
    sandesha2_property_bean_t *property_bean);
                        
AXIS2_EXTERN  axis2_status_t AXIS2_CALL                        
sandesha2_property_mgr_load_ack_int(
    const axutil_env_t *env, 
    axis2_char_t *value, 
    sandesha2_property_bean_t *property_bean);

AXIS2_EXTERN  axis2_status_t AXIS2_CALL
sandesha2_property_mgr_load_inactive_timeout(
    const axutil_env_t *env, 
    axis2_char_t *value,
    axis2_char_t *measure,                        
    sandesha2_property_bean_t *property_bean);

AXIS2_EXTERN  axis2_status_t AXIS2_CALL
sandesha2_property_mgr_load_in_order_invocation(
    const axutil_env_t *env, 
    axis2_char_t *value, 
    sandesha2_property_bean_t *property_bean);

AXIS2_EXTERN  axis2_status_t AXIS2_CALL
sandesha2_property_mgr_load_msg_types_to_drop(
    const axutil_env_t *env, 
    axis2_char_t *value, 
    sandesha2_property_bean_t *property_bean);
                        
AXIS2_EXTERN  sandesha2_property_bean_t* AXIS2_CALL
sandesha2_property_mgr_load_properties_from_def_values(
    const axutil_env_t *env)
{
    sandesha2_property_bean_t *property_bean = NULL;

    property_bean = sandesha2_property_bean_create(env);

    sandesha2_property_bean_set_exp_backoff(property_bean, env, SANDESHA2_DEF_VAL_EXP_BACKOFF);
    sandesha2_property_bean_set_retrans_interval(property_bean, env, SANDESHA2_DEF_VAL_RETR_COUNT);
    sandesha2_property_bean_set_ack_interval(property_bean, env, SANDESHA2_DEF_VAL_ACK_INTERVAL);
    sandesha2_property_bean_set_inactive_timeout_interval_with_units(property_bean, env, 
            SANDESHA2_DEF_VAL_INACTIVETIMEOUT, SANDESHA2_DEF_VAL_INACTIVETIMEOUT_MEASURE);

    sandesha2_property_bean_set_in_order(property_bean, env, SANDESHA2_DEF_VAL_INORDER_INVOCATION);
    sandesha2_property_bean_set_msg_types_to_drop(property_bean, env, NULL);

    /* will be useful when we are loading libraries */
    sandesha2_property_bean_set_max_retrans_count(property_bean, env, 
            SANDESHA2_DEF_VAL_MAX_RETR_COUNT);

    sandesha2_property_mgr_load_msg_types_to_drop(env, SANDESHA2_DEF_VAL_MSG_TYPES_TO_DROP, 
            property_bean);

    sandesha2_property_bean_set_terminate_delay(property_bean, env, SANDESHA2_TERMINATE_DELAY);
    
    sandesha2_property_bean_set_polling_delay(property_bean, env, SANDESHA2_POLLING_DELAY);

    return property_bean;
}

AXIS2_EXTERN  sandesha2_property_bean_t* AXIS2_CALL
sandesha2_property_mgr_load_properties_from_module_desc(
    const axutil_env_t *env,
    axis2_module_desc_t *module_desc)
{
    sandesha2_property_bean_t *property_bean = NULL;
    axutil_param_t *param = NULL;
    axis2_char_t *exp_backoff_str = NULL;
    axis2_char_t *retrans_int_str = NULL;
    axis2_char_t *ack_int_str = NULL;
    axis2_char_t *inactive_timeout_str = NULL;
    axis2_char_t *in_order_invoker_str = NULL;
    axis2_char_t *msg_types_str = NULL;
    
    AXIS2_PARAM_CHECK(env->error, module_desc, NULL);
    
    property_bean = sandesha2_property_bean_create(env);

    param = axis2_module_desc_get_param(module_desc, env, SANDESHA2_PROPERTIES_EXP_BACKOFF);
    if(param)
    {
        exp_backoff_str = axutil_param_get_value(param, env);
        sandesha2_property_mgr_load_exp_backoff(env, exp_backoff_str, property_bean);
    }

    param = axis2_module_desc_get_param(module_desc, env, 
            SANDESHA2_PROPERTIES_RETRANSMISSION_INTERVAL);

    if(param)
    {
        retrans_int_str = axutil_param_get_value(param, env);
        sandesha2_property_mgr_load_retrans_int(env, retrans_int_str, property_bean);
    }

    param = axis2_module_desc_get_param(module_desc, env, SANDESHA2_PROPERTIES_ACK_INTERVAL);
    if(param)
    {
        ack_int_str = axutil_param_get_value(param, env);
        sandesha2_property_mgr_load_ack_int(env, ack_int_str, property_bean);
    }

    param = axis2_module_desc_get_param(module_desc, env, SANDESHA2_PROPERTIES_INACTIVETIMEOUT);
    if(param)
    {
        axis2_char_t *inactive_to_measure_str = NULL;
        
        inactive_timeout_str = axutil_param_get_value(param, env);
        param = axis2_module_desc_get_param(module_desc, env, 
            SANDESHA2_PROPERTIES_INACTIVETIMEOUT_MEASURE);
        if(param)
        {
            inactive_to_measure_str = axutil_param_get_value(param, env);
        }

        if(!inactive_to_measure_str)
        {
            inactive_to_measure_str = SANDESHA2_DEF_VAL_INACTIVETIMEOUT_MEASURE;
        }
        
        sandesha2_property_mgr_load_inactive_timeout(env, inactive_timeout_str, 
                inactive_to_measure_str, property_bean);
    }

    param = axis2_module_desc_get_param(module_desc, env, SANDESHA2_PROPERTIES_INORDER_INVOCATION);
    if(param)
    {
        in_order_invoker_str = axutil_param_get_value(param, env);
        sandesha2_property_mgr_load_in_order_invocation(env, in_order_invoker_str, property_bean);        
    }

    param = axis2_module_desc_get_param(module_desc, env, SANDESHA2_PROPERTIES_MSG_TYPES_TO_DROP);
    if(param)
    {
        msg_types_str = axutil_param_get_value(param, env);
        sandesha2_property_mgr_load_msg_types_to_drop(env, msg_types_str, property_bean);        
    }
    
    param = axis2_module_desc_get_param(module_desc, env, SANDESHA2_PROPERTIES_STORAGE_MGR);
    if(param)
    {
        axis2_char_t *storage_mgr = NULL;
        storage_mgr = axutil_param_get_value(param, env);
        sandesha2_property_bean_set_storage_mgr(property_bean, env, storage_mgr);        
    }
    
    param = axis2_module_desc_get_param(module_desc, env, SANDESHA2_PROPERTIES_MAX_RETRANS_COUNT);
    if(param)
    {
        int max_retrans_count = -1;
        axis2_char_t *max_retrans_count_str = axutil_param_get_value(param, env);
        axis2_char_t *str = sandesha2_utils_trim_string(env, max_retrans_count_str);
        if(str)
        {
            max_retrans_count = atoi(str);
        }

        if(0 < max_retrans_count)
        {
            sandesha2_property_bean_set_max_retrans_count(property_bean, env, max_retrans_count);
        }

        if(str)
        {
            AXIS2_FREE(env->allocator, str);
        }
    }

    param = axis2_module_desc_get_param(module_desc, env, SANDESHA2_PROPERTIES_TERMINATE_DELAY);
    if(param)
    {
        int terminate_delay = -1;

        axis2_char_t *terminate_delay_str = axutil_param_get_value(param, env);
        axis2_char_t *str = sandesha2_utils_trim_string(env, terminate_delay_str);
        if(str)
        {
            terminate_delay = atoi(str);
        }
        else
        {
            terminate_delay = SANDESHA2_TERMINATE_DELAY;
        }

        if(0 < terminate_delay)
        {
            sandesha2_property_bean_set_terminate_delay(property_bean, env, terminate_delay);
        }

        if(str)
        {
            AXIS2_FREE(env->allocator, str);
        }
    }

    param = axis2_module_desc_get_param(module_desc, env, SANDESHA2_PROPERTIES_POLLING_DELAY);
    if(param)
    {
        int polling_delay = -1;

        axis2_char_t *polling_delay_str = axutil_param_get_value(param, env);
        axis2_char_t *str = sandesha2_utils_trim_string(env, polling_delay_str);
        if(str)
        {
            polling_delay = axutil_atoi(str);
        }
        else
        {
            polling_delay = SANDESHA2_POLLING_DELAY;
        }

        if(0 < polling_delay)
        {
            sandesha2_property_bean_set_polling_delay(property_bean, env, polling_delay);
        }

        if(str)
        {
            AXIS2_FREE(env->allocator, str);
        }
    }

    return property_bean;
}


AXIS2_EXTERN sandesha2_property_bean_t* AXIS2_CALL
sandesha2_property_mgr_load_properties_from_policy(
    const axutil_env_t *env,
    axis2_rm_assertion_t *rm_assertion)
{
    sandesha2_property_bean_t *property_bean = NULL;
    axis2_char_t *retrans_int_str = NULL;
    axis2_char_t *ack_int_str = NULL;
    axis2_char_t *inactive_timeout_str = NULL;
    axis2_char_t *msg_types_str = NULL;
    axis2_char_t *inactive_to_measure_str = NULL;   
    int max_retrans_count = -1;
    axis2_char_t *storage_mgr = NULL;
    axis2_char_t *max_retrans_count_str = NULL;
    axis2_char_t *terminate_delay_str = NULL;
    int terminate_delay = -1;
    int polling_delay = -1;
    axis2_char_t *polling_delay_str = NULL; 
    axis2_char_t *spec_version = NULL; 

    AXIS2_PARAM_CHECK(env->error, rm_assertion, NULL);
    
    property_bean = sandesha2_property_bean_create(env);

    sandesha2_property_bean_set_exp_backoff(property_bean, env, 
        axis2_rm_assertion_get_is_exp_backoff(rm_assertion, env));   

    sandesha2_property_bean_set_in_order(property_bean, env ,
        axis2_rm_assertion_get_is_inorder(rm_assertion, env));

    retrans_int_str = axis2_rm_assertion_get_retrans_interval(rm_assertion, env);
    if(retrans_int_str)
    {
        sandesha2_property_mgr_load_retrans_int(env, retrans_int_str, property_bean);
    }
        
    ack_int_str = axis2_rm_assertion_get_ack_interval(rm_assertion, env);
    if(ack_int_str)
    {
        sandesha2_property_mgr_load_ack_int(env, ack_int_str, property_bean);
    }

    inactive_timeout_str = axis2_rm_assertion_get_inactivity_timeout(rm_assertion, env);
    if(inactive_timeout_str)
    {
        inactive_to_measure_str = SANDESHA2_DEF_VAL_INACTIVETIMEOUT_MEASURE;
        
        sandesha2_property_mgr_load_inactive_timeout(env, inactive_timeout_str, 
                inactive_to_measure_str, property_bean);
    }

    msg_types_str = axis2_rm_assertion_get_message_types_to_drop(rm_assertion, env);
    if(msg_types_str)
    {
        sandesha2_property_mgr_load_msg_types_to_drop(env, msg_types_str, property_bean);        
    }
    
    storage_mgr = axis2_rm_assertion_get_storage_mgr(rm_assertion, env);
    if(storage_mgr)
    {
        sandesha2_property_bean_set_storage_mgr(property_bean, env, storage_mgr);        
    }
    
    max_retrans_count_str = axis2_rm_assertion_get_max_retrans_count(
        rm_assertion, env);
    if(max_retrans_count_str)
    {
        axis2_char_t *str = sandesha2_utils_trim_string(env, max_retrans_count_str);
        if(str)
        {
            max_retrans_count = atoi(str);
        }

        if(0 < max_retrans_count)
        {
            sandesha2_property_bean_set_max_retrans_count(property_bean, env, max_retrans_count);
        }

        if(str)
        {
            AXIS2_FREE(env->allocator, str);
        }
    }


    terminate_delay_str = axis2_rm_assertion_get_terminate_delay(
        rm_assertion, env);

    if(terminate_delay_str)
    {
        axis2_char_t *str = sandesha2_utils_trim_string(env, terminate_delay_str);
        if(str)
        {
            terminate_delay = atoi(str);
        }
        else
        {
            terminate_delay = SANDESHA2_TERMINATE_DELAY;
        }

        if(0 < terminate_delay)
        {
            sandesha2_property_bean_set_terminate_delay(property_bean, env, terminate_delay);
        }

        if(str)
        {
            AXIS2_FREE(env->allocator, str);
        }
    }

    polling_delay_str = axis2_rm_assertion_get_polling_wait_time(rm_assertion, env);
    if(polling_delay_str)
    {
        axis2_char_t *str = sandesha2_utils_trim_string(env, polling_delay_str);
        if(str)
        {
            polling_delay = axutil_atoi(str);
        }
        else
        {
            polling_delay = SANDESHA2_POLLING_DELAY;
        }

        if(0 < polling_delay)
        {
            sandesha2_property_bean_set_polling_delay(property_bean, env, polling_delay);
        }

        if(str)
        {
            AXIS2_FREE(env->allocator, str);
        }
    }
    
    spec_version = axis2_rm_assertion_get_spec_version(rm_assertion, env);
    if(spec_version)
    {
        sandesha2_property_bean_set_spec_version(property_bean, env, spec_version);        
    }
	
    return property_bean;
}



AXIS2_EXTERN  axis2_status_t AXIS2_CALL
sandesha2_property_mgr_load_exp_backoff(
    const axutil_env_t *env, 
    axis2_char_t *value, 
    sandesha2_property_bean_t *property_bean)
{
    axis2_char_t *str = NULL;
    
    AXIS2_PARAM_CHECK(env->error, value, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, property_bean, AXIS2_FAILURE);
    
    str = sandesha2_utils_trim_string(env, value);
    if(!axutil_strcmp(str, AXIS2_VALUE_TRUE))
    {
        sandesha2_property_bean_set_exp_backoff(property_bean, env, AXIS2_TRUE);
    }
    else
    {
        sandesha2_property_bean_set_exp_backoff(property_bean, env, AXIS2_FALSE);
    }

    if(str)
    {
        AXIS2_FREE(env->allocator, str);
    }

    return AXIS2_SUCCESS;
}
                        
AXIS2_EXTERN  axis2_status_t AXIS2_CALL
sandesha2_property_mgr_load_retrans_int(
    const axutil_env_t *env, 
    axis2_char_t *value, 
    sandesha2_property_bean_t *property_bean)
{
    axis2_char_t *str = NULL;
    int retrans_int = -1;
    
    AXIS2_PARAM_CHECK(env->error, value, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, property_bean, AXIS2_FAILURE);
    
    str = sandesha2_utils_trim_string(env, value);

    if(str)
    {
        retrans_int = atoi(str);
    }

    if(0 < retrans_int)
    {
        sandesha2_property_bean_set_retrans_interval(property_bean, env, retrans_int);
    }

    if(str)
    {
        AXIS2_FREE(env->allocator, str);
    }

    return AXIS2_SUCCESS;
}
                        
AXIS2_EXTERN  axis2_status_t AXIS2_CALL                        
sandesha2_property_mgr_load_ack_int(
    const axutil_env_t *env, 
    axis2_char_t *value, 
    sandesha2_property_bean_t *property_bean)
{
    axis2_char_t *str = NULL;
    int ack_int = -1;
    
    AXIS2_PARAM_CHECK(env->error, value, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, property_bean, AXIS2_FAILURE);
    
    str = sandesha2_utils_trim_string(env, value);
    if(str)
    {
        ack_int = atoi(str);
    }

    if(0 < ack_int)
    {
        sandesha2_property_bean_set_ack_interval(property_bean, env, ack_int);
    }

    if(str)
    {
        AXIS2_FREE(env->allocator, str);
    }

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN  axis2_status_t AXIS2_CALL
sandesha2_property_mgr_load_inactive_timeout(
    const axutil_env_t *env, 
    axis2_char_t *value,
    axis2_char_t *measure,                        
    sandesha2_property_bean_t *property_bean)
{
    axis2_char_t *str = NULL;
    axis2_char_t *str2 = NULL;
    int timeout = -1;
    
    AXIS2_PARAM_CHECK(env->error, value, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, measure, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, property_bean, AXIS2_FAILURE);
    
    str = sandesha2_utils_trim_string(env, value);
    str2 = sandesha2_utils_trim_string(env, measure);
    
    if(str)
    {
        timeout = axutil_atoi(str);
    }

    if(0 < timeout)
    {
        if(str2)
        {
            sandesha2_property_bean_set_inactive_timeout_interval_with_units(property_bean, env, 
                    timeout, str2);
        }
        else
        {
            sandesha2_property_bean_set_inactive_timeout_interval(property_bean, env, timeout);
        }
    }

    if(str)
    {
        AXIS2_FREE(env->allocator, str);
    }

    if(str2)
    {
        AXIS2_FREE(env->allocator, str2);
    }

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN  axis2_status_t AXIS2_CALL
sandesha2_property_mgr_load_in_order_invocation(
    const axutil_env_t *env, 
    axis2_char_t *value, 
    sandesha2_property_bean_t *property_bean)
{
    axis2_char_t *str = NULL;
    
    AXIS2_PARAM_CHECK(env->error, value, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, property_bean, AXIS2_FAILURE);
    
    str = sandesha2_utils_trim_string(env, value);
    if(!axutil_strcmp(str, AXIS2_VALUE_TRUE))
    {
        sandesha2_property_bean_set_in_order(property_bean, env, AXIS2_TRUE);
    }
    else
    {
        sandesha2_property_bean_set_in_order(property_bean, env, AXIS2_FALSE);
    }

    if(str)
    {
        AXIS2_FREE(env->allocator, str);
    }

    return AXIS2_SUCCESS;
}

AXIS2_EXTERN  axis2_status_t AXIS2_CALL
sandesha2_property_mgr_load_msg_types_to_drop(
    const axutil_env_t *env, 
    axis2_char_t *value, 
    sandesha2_property_bean_t *property_bean)
{
    axis2_char_t *str = NULL;
    
    AXIS2_PARAM_CHECK(env->error, value, AXIS2_FAILURE);
    AXIS2_PARAM_CHECK(env->error, property_bean, AXIS2_FAILURE);
    
    str = sandesha2_utils_trim_string(env, value);
    if(str && axutil_strcmp(str, SANDESHA2_VALUE_NONE))
    {
        axis2_char_t *str2 = NULL;
        axutil_array_list_t *list = NULL;
        
        str2 = axutil_strcat(env, "[", str, "]", NULL);
        list = sandesha2_utils_get_array_list_from_string(env, str2);
        if(list)
        {
            int i = 0;

            for(i = 0; i < axutil_array_list_size(list, env); i++)
            {
                axis2_char_t *val = NULL;
                val = axutil_array_list_get(list, env, i);
                sandesha2_property_bean_add_msg_type_to_drop(property_bean, env, axutil_atoi(val));
            }
        }
    }

    if(str)
    {
        AXIS2_FREE(env->allocator, str);
    }

    return AXIS2_SUCCESS;
}


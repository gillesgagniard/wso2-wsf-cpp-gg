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
#include <axutil_utils.h>
#include <axutil_linked_list.h>
#include <rampart_replay_detector.h>
#include <axutil_property.h>
#include <rampart_constants.h>
#include <rampart_sec_processed_result.h>
#include <rampart_util.h>
#include <stdlib.h>

#define BUFFER_LEN 10000
#define DELIMIT 16
#define INDICATOR_FILE "/indicator"
#define REPLAY_FILE "/replay.content"

static axis2_char_t *
rampart_replay_detector_file_dir(
    const axutil_env_t* env)
{
#ifdef WIN32
	char* axis_home = getenv("AXIS2C_HOME");
	if (axis_home)
		return axutil_strdup(env, axis_home);
	else
		return axutil_strdup(env, "c:\\logs\\");
#else
	return axutil_strdup(env, "/tmp/");
#endif 
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_replay_detector_free(
    rampart_replay_detector_t *rrd,
	const axutil_env_t* env)
{
	if (rrd)
	{
		if (rrd->ops)
		{
			AXIS2_FREE(env->allocator, rrd->ops);
		}
		AXIS2_FREE(env->allocator, rrd);
	}
	return AXIS2_SUCCESS;
}

static axis2_status_t
rampart_replay_detector_read_file(
    const axutil_env_t *env,
    axutil_linked_list_t* ll)
{
	FILE* temp_file = NULL;
	FILE* file = NULL;
	axis2_char_t buffer[sizeof(axis2_char_t) * (BUFFER_LEN + 1)];
	int ch_read = 0;
	char* key = NULL;
	axis2_char_t *file_dir = NULL;
	axis2_char_t *file_name = NULL;

	char dilim[2];
	dilim[0] = DELIMIT;
	dilim[1] = 0;
	

	/*
	 * check whether some other threads are using the file. In that case, the indicator file will 
     * not be empty. If no other threads are using it, then the file will not available
	 */
	file_dir = rampart_replay_detector_file_dir(env);
	file_name = axutil_stracat(env, file_dir, INDICATOR_FILE);
	temp_file = fopen(file_name, "r");
	while (temp_file)
	{
		fclose (temp_file);
#ifdef WIN32
		Sleep (5000);
#else
		sleep (5);
#endif
		temp_file = fopen(file_name, "r");
	}

	temp_file = fopen(file_name, "w+");
	AXIS2_FREE(env->allocator, file_name);
	if (!temp_file)
	{
		AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Creating indicator file failed" );
		AXIS2_FREE(env->allocator, file_dir);
		return AXIS2_FAILURE;
	}
	fclose (temp_file);

	/*
	 * now we can safely read the actual replay content file
	 */
	file_name = axutil_stracat(env, file_dir, REPLAY_FILE);
	file = fopen (file_name, "r");
	AXIS2_FREE(env->allocator, file_dir);
	AXIS2_FREE(env->allocator, file_name);
	if (file)
	{
		axis2_char_t* whole_buffer = NULL;
		do
		{
			ch_read = fread (buffer, sizeof(axis2_char_t), BUFFER_LEN, file);
			buffer[ch_read] = 0;
			if (!ch_read)
				break;

			if (whole_buffer)
			{
				axis2_char_t* temp_str = whole_buffer;
				whole_buffer = axutil_stracat(env, temp_str, buffer);
				AXIS2_FREE(env->allocator, temp_str);
			}
			else
			{
				whole_buffer = axutil_strdup(env, buffer);
			}
		}while (!feof(file));
		fclose(file);

		if (whole_buffer)
		{
			key = strtok(whole_buffer, dilim);
			while (key)
			{
				axutil_linked_list_add(ll, env, (void*)axutil_strdup(env,key));
				key = strtok(NULL, dilim);
			}
			AXIS2_FREE(env->allocator, whole_buffer);
		}
	}

	return AXIS2_SUCCESS;
}


static axis2_status_t
rampart_replay_detector_write_file(
    const axutil_env_t *env,
    axutil_linked_list_t* ll,
    axis2_bool_t write_content)
{
	FILE* file = NULL;
	axis2_char_t *file_dir = NULL;
	axis2_char_t *file_name = NULL;

	file_dir = rampart_replay_detector_file_dir(env);
	if (write_content)
	{
		file_name = axutil_stracat(env, file_dir, REPLAY_FILE);
		file = fopen (file_name, "w+");
		if (!file)
		{
			AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Creating replay file failed" );
			AXIS2_FREE(env->allocator, file_name);
			file_name = axutil_stracat(env, file_dir, INDICATOR_FILE);
			remove(file_name);
			AXIS2_FREE(env->allocator, file_name);
			AXIS2_FREE(env->allocator, file_dir);
			return AXIS2_FAILURE;
		}
#ifndef WIN32
		else
		{
			axis2_char_t *command = NULL;
			command = axutil_stracat(env, "chmod 666 ", file_name);
			system(command);
			AXIS2_FREE(env->allocator, command);
		}
#endif
		AXIS2_FREE(env->allocator, file_name);
		
	}

	while(axutil_linked_list_size(ll, env) > 0)
	{
		axis2_char_t *tmp_msg_id = NULL;
		tmp_msg_id = (axis2_char_t*)axutil_linked_list_remove_first(ll, env);

		if (file)
		{
			fwrite(tmp_msg_id, sizeof(axis2_char_t), axutil_strlen(tmp_msg_id), file);
			fputc(DELIMIT, file);
		}

		AXIS2_FREE(env->allocator, tmp_msg_id);
		tmp_msg_id = NULL;
	}

	if (file)
	{
		fclose(file);
	}

	file_name = axutil_stracat(env, file_dir, INDICATOR_FILE);
	remove(file_name);
	AXIS2_FREE(env->allocator, file_name);
	AXIS2_FREE(env->allocator, file_dir);
	return AXIS2_SUCCESS;
}

static axis2_bool_t
rampart_replay_detector_check_in_linked_list(
    axutil_linked_list_t *linked_list,
    const axutil_env_t *env,
    axis2_char_t *id)
{
    int count = 0;
    int i = 0;

    count = axutil_linked_list_size(linked_list, env);
    for(i=0; i<count; i++)
    {
        axis2_char_t *tmp_id = NULL;

        tmp_id = (axis2_char_t*)axutil_linked_list_get(linked_list, env, i);
        if(0 == axutil_strcmp(id, tmp_id))
        {
            return AXIS2_TRUE;
        }
    }
    return AXIS2_FALSE;
}

AXIS2_EXTERN axis2_status_t AXIS2_CALL
rampart_replay_detector_with_flat_file(
    rampart_replay_detector_t *rrd,
	const axutil_env_t *env,
    axis2_msg_ctx_t* msg_ctx,
    rampart_context_t *rampart_context)
{
    axutil_linked_list_t *ll = NULL;
    const axis2_char_t *msg_id = NULL;
    const axis2_char_t *ts = NULL;
    const axis2_char_t *addr_msg_id = NULL;
    int max_rcds = RAMPART_RD_DEF_MAX_RCDS;
    axis2_status_t status = AXIS2_FAILURE;
    axutil_hash_t *sec_process_result = NULL;

    /*Get timestamp from security processed results */
    sec_process_result = rampart_get_all_security_processed_results(env, msg_ctx);
    ts = axutil_hash_get(sec_process_result, RAMPART_SPR_TS_CREATED, AXIS2_HASH_KEY_STRING);

    /* get message id from addressing headers */
    addr_msg_id = axis2_msg_ctx_get_wsa_message_id(msg_ctx, env);

    if(!ts && addr_msg_id)
	{
        msg_id = addr_msg_id;
    }
	else if(ts && !addr_msg_id)
	{
        msg_id = ts;
    }
	else if(ts && addr_msg_id)
	{
        msg_id = axutil_strcat(env, addr_msg_id, ts, NULL);
    }
	else
	{
        msg_id = NULL;
    }

    if(!msg_id)
	{
        /* using default msg id */
        msg_id = "RAMPART-DEFAULT-TS";
        AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
            "[rampart]No msg_id specified, using default = %s", msg_id);
    }


    ll = axutil_linked_list_create(env);
    if(!ll)
	{
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]Linked list creation failed.");
        return AXIS2_FAILURE;
    }

	status = rampart_replay_detector_read_file(env, ll);
	if(status != AXIS2_SUCCESS)
	{
        /* we have to clear linked list. We don't need to write the contents. So pass false to 
         * denote whether to write the content */
		rampart_replay_detector_write_file(env, ll, AXIS2_FALSE);
        return AXIS2_FAILURE;
    }
	else
	{
        /* Get the number of records to be kept */
        if(rampart_context_get_rd_val(rampart_context, env))
		{
            max_rcds = axutil_atoi(rampart_context_get_rd_val(rampart_context, env));
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                "[rampart]Using the specified max_rcds  %d\n", max_rcds );
        }
		else
		{
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
                "[rampart]Using the default max_rcds  %d\n", max_rcds );
        }

        /* If the table already have the same key it's a replay */
        if(rampart_replay_detector_check_in_linked_list(ll, env, (void*)msg_id))
		{
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, "[rampart]For ID=%s, a replay detected", msg_id);
			rampart_replay_detector_write_file(env, ll, AXIS2_FALSE);
            return AXIS2_FAILURE;
        }

        /* if number of records saved are more than allowed, we have to remove them */
        while(axutil_linked_list_size(ll, env) >= max_rcds)
		{
            axis2_char_t *tmp_msg_id = NULL;
            tmp_msg_id = (axis2_char_t*)axutil_linked_list_remove_first(ll, env);
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart]Deleting record  %s\n", tmp_msg_id );
            AXIS2_FREE(env->allocator, tmp_msg_id);
            tmp_msg_id = NULL;
        }

        /* Add current record */
        status = axutil_linked_list_add(ll, env, (void*)axutil_strdup(env,msg_id));
        if(status == AXIS2_SUCCESS)
		{
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart]Adding record  %s\n", msg_id );
        }
		else
		{
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart]Cannot add record %s\n", msg_id);
			rampart_replay_detector_write_file(env, ll, AXIS2_FALSE);
            return AXIS2_FAILURE;
        }
		status =  rampart_replay_detector_write_file(env, ll, AXIS2_TRUE);
		axutil_linked_list_free(ll, env);
        if(status == AXIS2_SUCCESS)
		{
            AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, "[rampart]Writing records to file succeed." );
			return AXIS2_SUCCESS;
        }
		else
		{
            AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI,"[rampart]Writing records to file failed");
            return AXIS2_FAILURE;
        }
    }
}


/**
 * Following block distinguish the exposed part of the dll.
 */
AXIS2_EXPORT int
axis2_get_instance(
    rampart_replay_detector_t **inst,
    const axutil_env_t *env)
{
    rampart_replay_detector_t* rd = NULL;

    rd = AXIS2_MALLOC(env->allocator, sizeof(rampart_replay_detector_t));
    if (!rd)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot create replay detector module. Insufficient memory.");
        return AXIS2_FAILURE;
    }

    rd->ops = AXIS2_MALLOC(env->allocator, sizeof(rampart_replay_detector_ops_t));
    if (!rd->ops)
    {
        AXIS2_LOG_ERROR(env->log, AXIS2_LOG_SI, 
            "[rampart]Cannot create replay detector module operations. Insufficient memory.");
        return AXIS2_FAILURE;
    }

    /* assign function pointers */
    rd->ops->is_replayed = rampart_replay_detector_with_flat_file;
    rd->ops->free = rampart_replay_detector_free;

    *inst = rd;

    return AXIS2_SUCCESS;
}

AXIS2_EXPORT int
axis2_remove_instance(
    rampart_replay_detector_t *inst,
    const axutil_env_t *env)
{
    axis2_status_t status = AXIS2_FAILURE;
    if (inst)
    {
        status = RAMPART_REPLAY_DETECTOR_FREE(inst, env);
    }
    return status;
}


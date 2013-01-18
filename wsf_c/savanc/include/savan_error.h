/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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
 
#ifndef SAVAN_ERROR_H
#define SAVAN_ERROR_H

#include <axutil_error.h>

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @defgroup savan_error
 * @ingroup Savan Error
 * @{
 */
   /**
    * Since we use the same env->error from Axis2 we need to start from
    * a AXIS2_ERROR_LAST + some number to prevent ambiguity 
    */  
	/**
    * \brief Savan error codes
    *
    * Set of error codes for Savan
    */
    typedef enum savan_error_codes
    { 
        /* No error */
        SAVAN_ERROR_NONE = SAVAN_ERROR_CODES_START,
   
        /* The soap action of an eventing message was missing */    
        SAVAN_ERROR_SOAP_ACTION_NULL,
        /* Failed to create an instance of subscriber */
        SAVAN_ERROR_FAILED_TO_CREATE_SUBSCRIBER,
        /* Unhandled message type */
        SAVAN_ERROR_UNHANDLED_MSG_TYPE,
        /* Failed to build a default soap envelope */
        SAVAN_ERROR_FAILED_TO_BUILD_SOAP_ENV,
	    /* Requested delivery mode is not supported */
        SAVAN_ERROR_REQUESTED_DELIVERY_MODE_NOT_SUPPORTED,
	    /* Expiration time requested is invalid */
        SAVAN_ERROR_EXPIRATION_TIME_REQUESTED_IS_INVALID,
	    /* Only expiration durations are supported */
        SAVAN_ERROR_ONLY_EXPIRATION_DURATIONS_ARE_SUPPORTED,
	    /* Filtering is not supported */
        SAVAN_ERROR_FILTERING_IS_NOT_SUPPORTED,
	    /* Requested filter dialect is not supported */
        SAVAN_ERROR_REQUESTED_FILTER_DIALECT_IS_NOT_SUPPORTED,
	    /* Messsage is not valid and cannot be processed */
        SAVAN_ERROR_MESSAGE_IS_NOT_VALID_AND_CANNOT_BE_PROCESSED,
        /* Message cannot be processed by the event source */
        SAVAN_ERROR_MESSAGE_CANNOT_BE_PROCESSED_BY_EVENT_SOURCE,
        /* Unable to Renew */
        SAVAN_ERROR_UNABLE_TO_RENEW,
        /* Subscriber is not found */
        SAVAN_ERROR_SUBSCRIBER_NOT_FOUND,
        /* Could not populate Topic */
        SAVAN_ERROR_COULD_NOT_POPULATE_TOPIC,
        /* Parsing subsriber node failed */
        SAVAN_ERROR_PARSING_SUBSCRIBER_NODE_FAILED,
        /* Applying filter failed */
        SAVAN_ERROR_APPLYING_FILTER_FAILED,
        /* Memory allocation failed for Savan Storage Manager */
        SAVAN_ERROR_STORAGE_MANAGER_CREATION_FAILED,
        /* Could not retrieve subscriber from storage */
        SAVAN_ERROR_SUBSCRIBER_RETRIEVE_ERROR,
        /* Could not remove subscriber from storage */
        SAVAN_ERROR_SUBSCRIBER_REMOVE_ERROR,
        /* Could not update subscriber to storage */
        SAVAN_ERROR_SUBSCRIBER_UPDATE_ERROR,
        /* Could not insert subscriber into storage */
        SAVAN_ERROR_SUBSCRIBER_INSERT_ERROR,
        /* Could not insert topic into storage */
        SAVAN_ERROR_TOPIC_INSERT_ERROR,
        /* Could not create database table */
        SAVAN_ERROR_DATABASE_TABLE_CREATION_ERROR,
        /* Could not create database */
        SAVAN_ERROR_DATABASE_CREATION_ERROR,
        /* Could create the filter */
        SAVAN_ERROR_FILTER_CREATION_FAILED,
        /* Could not create the filter module */
        SAVAN_ERROR_FILTER_MODULE_COULD_NOT_BE_RETRIEVED,
        
        SAVAN_ERROR_LAST
    
    } savan_error_codes_t;

    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    savan_error_init();


	#define SAVAN_FAULT_DMRU_CODE "s12:Sender"
	#define SAVAN_FAULT_DMRU_SUB_CODE "wse:DeliveryModeRequestedUnavailable."
	#define SAVAN_FAULT_DMRU_DETAIL ""

	#define SAVAN_FAULT_IET_CODE "s12:Sender"
	#define SAVAN_FAULT_IET_SUB_CODE "wse:InvalidExpirationTime"
	#define SAVAN_FAULT_IET_DETAIL ""

	#define SAVAN_FAULT_UET_CODE "s12:Sender"
	#define SAVAN_FAULT_UET_SUB_CODE "wse:UnsupportedExpirationTime"
	#define SAVAN_FAULT_UET_DETAIL ""

	#define SAVAN_FAULT_FNS_CODE "s12:Sender"
	#define SAVAN_FAULT_FNS_SUB_CODE "wse:FilteringNotSupported"
	#define SAVAN_FAULT_FNS_DETAIL "Server doesn't support filtering"

	#define SAVAN_FAULT_FRU_CODE "s12:Sender"
	#define SAVAN_FAULT_FRU_SUB_CODE "wse:FilteringRequestedUnavailable"
	#define SAVAN_FAULT_FRU_DETAIL "Server does not support the dialect"

	#define SAVAN_FAULT_IM_CODE "s12:Sender"
	#define SAVAN_FAULT_IM_SUB_CODE "wse:InvalidMessages"
	#define SAVAN_FAULT_IM_DETAIL "Invalid message."

	#define SAVAN_FAULT_ESUP_CODE "s12:Receiver"
	#define SAVAN_FAULT_ESUP_SUB_CODE "wse:EventSourceUnableToProcess"
	#define SAVAN_FAULT_ESUP_DETAIL ""
	
	#define SAVAN_FAULT_UTR_CODE "s12:Receiver"
	#define SAVAN_FAULT_UTR_SUB_CODE "wse:UnableToRenew"
	#define SAVAN_FAULT_UTR_DETAIL1 "Could not find the subscriber"
	#define SAVAN_FAULT_UTR_DETAIL2 "Subscription can not be renewed"
        
	/*typedef enum savan_fault_types
	{
    	SAVAN_FAULT_DMRU = 0,
    	SAVAN_FAULT_IET,
    	SAVAN_FAULT_UET,
    	SAVAN_FAULT_FNS,
    	SAVAN_FAULT_FRU,
    	SAVAN_FAULT_ESUP,
    	SAVAN_FAULT_UTR,
    	SAVAN_FAULT_IM
	}savan_fault_types_t;*/

/** @} */
#ifdef __cplusplus
}
#endif
 
#endif /*SAVAN_ERROR_H*/

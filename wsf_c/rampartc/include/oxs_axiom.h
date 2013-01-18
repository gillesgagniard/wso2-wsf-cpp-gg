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

#ifndef OXS_AXIOM_H
#define OXS_AXIOM_H

/**
  * @file oxs_axiom.h
  * @brief Utility functions related to AXIOM. A place for common code.
  */

#include <axis2_defines.h>
#include <axutil_env.h>
#include <axis2_util.h>
#include <axiom_node.h>

#ifdef __cplusplus
extern "C"
{
#endif
    /** @defgroup oxs_axiom OXS Axiom
      * @ingroup oxs
      * @{
      */

    /**
     * Adds an attribute to a particular node
     * @param env Environment. MUST NOT be NULL
     * @param node the node where the attibute will be added
     * @param attribute_ns the the ns_prefix of the attribute
     * @param attribute_ns_uri the uri of the attribute
     * @param attribute the localname  of the attribute
     * @param value the value of the attribute
     * @return  AXIS2_SUCCESS on success, else AXIS2_FAILURE
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    oxs_axiom_add_attribute(
        const axutil_env_t *env,
        axiom_node_t* node,
        axis2_char_t* attribute_ns,
        axis2_char_t* attribute_ns_uri,
        axis2_char_t* attribute,
        axis2_char_t* value);

    /**
     * Finds the number of childern with given qname
     * @param env Environment. MUST NOT be NULL,
     * @param parent the root element defining start of the search
     * @param localname the local part of the qname
     * @param ns_uri uri part of the qname
     * @param prefix the prefix part of the qname
     * @return the number of children found
     */
    AXIS2_EXTERN int AXIS2_CALL
    oxs_axiom_get_number_of_children_with_qname(
        const axutil_env_t *env,
        axiom_node_t* parent,
        axis2_char_t* local_name,
        axis2_char_t* ns_uri,
        axis2_char_t* prefix);

    /**
     * Traverse thru the node and its descendents. Check if the localname is equal to the given name
     * @param env Environment. MUST NOT be NULL,
     * @param node the node to be searched
     * @param localname the local name of the node to be searched
     * @return the node if found, else NULL
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    oxs_axiom_get_node_by_local_name(
        const axutil_env_t *env,
        axiom_node_t *node,
        axis2_char_t *local_name);

    /**
     * Traverse thru the node and its descendents. Check if the node has a particular attibure 
     * value, whose attribute name as in @attr and value as in @val
     * @param env Environment. MUST NOT be NULL,
     * @param node the node to be searched
     * @param attr the attribute name of the node
     * @param val the attribute value of the node
     * @param ns namespace of the attribute
     * @return the node if found, else NULL
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    oxs_axiom_get_node_by_id(
        const axutil_env_t *env,
        axiom_node_t *node,
        axis2_char_t *attr,
        axis2_char_t *val,
        axis2_char_t *ns);

    /**
     * Traverse thru the node and its descendents. Check if the node has a particular attribute with 
     * name as in @attr and namespace as in @ns. Returns the attribute value.
     * @param env Environment. MUST NOT be NULL,
     * @param node the node to be searched
     * @param attribute_name the attribute name of the node
     * @param ns namespace of the attribute
     * @return the attribute value if found, else NULL
     */
    AXIS2_EXTERN axis2_char_t* AXIS2_CALL
    oxs_axiom_get_attribute_value_of_node_by_name(
        const axutil_env_t *env,
        axiom_node_t *node,
        axis2_char_t *attribute_name,
        axis2_char_t *ns);

    /**
     * Traverse thru the node and its descendents. Check if the node has a particular attribute with 
     * qname as in @qname. Returns the attribute value.
     * @param env Environment. MUST NOT be NULL,
     * @param node the node to be searched
     * @param qname the qname of the attribute
     * @return the attribute value if found, else NULL
     */
    AXIS2_EXTERN axis2_char_t* AXIS2_CALL
    oxs_axiom_get_attribute_val_of_node_by_qname(
        const axutil_env_t *env,
        axiom_node_t *node,
        axutil_qname_t *qname);

    /**
     * Check the node and its children. Check if the localname is equal to the given name
     * Note: You may pass the prefix=NULL as the prefix may be different depending on the impl
     * @param env Environment. MUST NOT be NULL,
     * @param parent the node to be searched
     * @param local_name the local name of the node to be searched
     * @ns_uri namespace uri of the node to be searched
     * @prefix prefix of the node to be searched. If NULL, node with any prefix will be considered
     * @return the node if found, else NULL
     */
    AXIS2_EXTERN axiom_node_t* AXIS2_CALL
    oxs_axiom_get_first_child_node_by_name(
        const axutil_env_t *env,
        axiom_node_t* parent,
        axis2_char_t* local_name,
        axis2_char_t* ns_uri,
        axis2_char_t* prefix);

    /**
     * Returns content of a node
     * @param env Environment. MUST NOT be NULL,
     * @param node the node whose content should be retrieved
     * @return the content of the node if found, else NULL
     */
    AXIS2_EXTERN axis2_char_t* AXIS2_CALL
    oxs_axiom_get_node_content(
        const axutil_env_t *env, 
        axiom_node_t* node);

    /**
     * Deserialises given buffer and creates the axiom node 
     * @param env Environment. Must not be NULL
     * @param buffer representation of serialised node
     * @return deserialised node if success. NULL otherwise.
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    oxs_axiom_deserialize_node(
        const axutil_env_t *env,  
        axis2_char_t* buffer);

    /**
     * Checks whether given node is having same name and namespace as given
     * @param env Environment. Must not be null
     * @param node node to be checked for name and namespace
     * @param name local name to be checked against given node
     * @param ns namespace to be checked against given node. Can be null. If null, will be omitted
     * @return AXIS2_TRUE if given name/ns is same as in the node. AXIS2_FALSE otherwise.
     */
    AXIS2_EXTERN axis2_bool_t AXIS2_CALL
    oxs_axiom_check_node_name(
        const axutil_env_t *env, 
        axiom_node_t* node, 
        axis2_char_t* name, 
        axis2_char_t* ns);

    /**
     * moves the given node before second node.
     * @param env Environment. Must not be null
     * @param node_to_move node to be moved
     * @param node_before node_to_move will be moved before this node
     * @return status of the operation
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    oxs_axiom_interchange_nodes(
        const axutil_env_t *env,
        axiom_node_t *node_to_move,
        axiom_node_t *node_before); 
    
    /**
     * Adds @child as the first child of @parent
     * @param env Environment. Must not be null
     * @param parent parent node
     * @param child child node which has to be the first child of parent
     * @return status of the operation
     */
    AXIS2_EXTERN axis2_status_t AXIS2_CALL
    oxs_axiom_add_as_the_first_child(
        const axutil_env_t *env,
        axiom_node_t *parent,
        axiom_node_t *child);

    /**
	 * Traverse thru the node and its children. Check if the element has the 
	 * given qname and has a id attribute equal to the given value.
	 * @param env Environment. MUST NOT be NULL,
     * @param node the node to be searched
	 * @param e_name element name
	 * @param e_ns element namespace. If NULL doesn't consider the namespaces
     * @param attr_name the attribute name of the node
     * @param attr_val the attribute value of the node
	 * @param attr_ns the attribute namespace. If NULL doesn't consider namespaces.
     * @return the node if found, else NULL
     */
	AXIS2_EXTERN axiom_node_t* AXIS2_CALL
	oxs_axiom_get_first_node_by_name_and_attr_val(
        const axutil_env_t *env,
        axiom_node_t *node,
        axis2_char_t *e_name,
        axis2_char_t *e_ns,
        axis2_char_t *attr_name,
        axis2_char_t *attr_val,
        axis2_char_t *attr_ns);

	/**
	 * First find the root of the scope node. Traverse thru the root node and its 
	 * children. Check if the element has the given qname and has a attribute 
	 * equal to the given values.
	 * @param env Environment. MUST NOT be NULL,
     * @param node the node to be searched
	 * @param e_name element name
	 * @param e_ns element namespace. If NULL doesn't consider the namespaces
     * @param attr_name the attribute name of the node
     * @param attr_val the attribute value of the node
	 * @param attr_ns the attribute namespace. If NULL doesn't consider namespaces.
     * @return the node if found, else NULL
     */	 
	AXIS2_EXTERN axiom_node_t * AXIS2_CALL
	oxs_axiom_get_first_node_by_name_and_attr_val_from_xml_doc(
        const axutil_env_t *env,
        axiom_node_t *node,
        axis2_char_t *e_name,
        axis2_char_t *e_ns,
        axis2_char_t *attr_name,
        axis2_char_t *attr_val,
        axis2_char_t *attr_ns);

    /**
     * Clones the given node. 
     * @param env Environment. Must not be null
     * @param node node to be cloned
     * @return cloned node if success. NULL otherwise
     */
    AXIS2_EXTERN axiom_node_t *AXIS2_CALL
    oxs_axiom_clone_node(
        const axutil_env_t *env,
        axiom_node_t *node);
                          
    /** @} */
#ifdef __cplusplus
}
#endif

#endif                          /* OXS_AXIOM_H */

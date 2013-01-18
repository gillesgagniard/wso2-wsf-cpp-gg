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

#include <oxs_axiom.h>
#include <axiom.h>
#include <axiom_util.h>

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
    axis2_char_t* value)
{
    axiom_attribute_t *attr = NULL;
    axiom_element_t *ele = NULL;
    axis2_status_t status = AXIS2_FAILURE;
    axiom_namespace_t *ns = NULL;

    if(attribute_ns_uri)
    {    
        ns =  axiom_namespace_create(env, attribute_ns_uri, attribute_ns);
    }    

    ele =  axiom_node_get_data_element(node, env);
    attr =  axiom_attribute_create(env, attribute , value, ns);
	if((!attr) && ns)
	{
		axiom_namespace_free(ns, env);
	}
    status = axiom_element_add_attribute(ele, env, attr, node);
    return status;
}

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
    axis2_char_t* prefix)
{
    axutil_qname_t *qname = NULL;
    axiom_element_t *parent_ele = NULL;
    axiom_children_qname_iterator_t *qname_iter = NULL;
    int counter = 0;

    parent_ele = axiom_node_get_data_element(parent, env);
    if(!parent_ele)
    {
        return -1;
    }

    qname = axutil_qname_create(env, local_name, ns_uri, prefix);
    qname_iter = axiom_element_get_children_with_qname(parent_ele, env, qname, parent);
    while (axiom_children_qname_iterator_has_next(qname_iter , env))
    {
        axiom_node_t *temp_node = NULL;
        counter++;
        temp_node = axiom_children_qname_iterator_next(qname_iter, env);
    }
    axutil_qname_free(qname, env);
    qname = NULL;

    return counter;
}

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
    axis2_char_t *local_name)
{
    axis2_char_t *temp_name = NULL;

    if(!node)
    {
        return NULL;
    }

    if(axiom_node_get_node_type(node, env) != AXIOM_ELEMENT)
    {
        return NULL;
    }

    temp_name = axiom_util_get_localname(node, env);
    AXIS2_LOG_DEBUG(env->log, AXIS2_LOG_SI, 
        "[rampart]Checking node %s for %s", temp_name, local_name );

    if(!axutil_strcmp(temp_name, local_name))
    {
        /* Gottcha.. return this node */
        return node;
    }
    else
    {
        /* Doesn't match? Get the children and search for them */
        axiom_node_t *temp_node = NULL;

        temp_node = axiom_node_get_first_element(node, env);
        while(temp_node)
        {
            axiom_node_t *res_node = NULL;
            res_node = oxs_axiom_get_node_by_local_name(env, temp_node, local_name);
            if(res_node)
            {
                return res_node;
            }
            temp_node = axiom_node_get_next_sibling(temp_node, env);
        }
    }
    return NULL;
}

/**
 * Traverse thru the node and its descendents. Check if the node has a particular attibure value, 
 * whose attribute name as in @attr and value as in @val
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
    axis2_char_t *ns)
{
    axis2_char_t *attribute_value = NULL;

    if(!node)
    {
        return NULL;
    }

    if(axiom_node_get_node_type(node, env) != AXIOM_ELEMENT)
    {
        return NULL;
    }

    attribute_value = oxs_axiom_get_attribute_value_of_node_by_name(env, node, attr, ns);
    
    if(!axutil_strcmp(val, attribute_value))
    {
        /* Gottcha.. return this node */
        return node;
    }
    else
    {
        /* Doesn't match? Get the children and search recursively. */
        axiom_node_t *temp_node = NULL;
        temp_node = axiom_node_get_first_element(node, env);
        while (temp_node)
        {
            axiom_node_t *res_node = NULL;
            res_node = oxs_axiom_get_node_by_id(env, temp_node, attr, val, ns);
            if(res_node)
            {
                return res_node;
            }
            temp_node = axiom_node_get_next_sibling(temp_node, env);
        }
    }

    return NULL;
}

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
    axis2_char_t *ns_uri)
{
    axis2_char_t *found_val = NULL;
    axiom_element_t *ele = NULL;
    axutil_hash_t *attr_list = NULL;
    axutil_hash_index_t *hi = NULL;
    
    ele = axiom_node_get_data_element(node, env);

    /* Get attribute list of the element */
    attr_list = axiom_element_extract_attributes(ele, env, node);
    if(!attr_list)
    {
        return NULL;
    }

    /* namespace uri can be NULL. In that case, use empty string */
    if(!ns_uri)
    {
        ns_uri = "";
    }

    /* Traverse thru all the attributes. If both localname and the nsuri matches return the val */
    for (hi = axutil_hash_first(attr_list, env); hi; hi = axutil_hash_next(env, hi))
    {
        void *attr = NULL;
        axiom_attribute_t *om_attr = NULL;
        axutil_hash_this(hi, NULL, NULL, &attr);
        if (attr)
        {
            axis2_char_t *this_attr_name = NULL;
            axis2_char_t *this_attr_ns_uri = NULL;
            axiom_namespace_t *attr_ns = NULL;

            om_attr = (axiom_attribute_t*)attr;
            this_attr_name = axiom_attribute_get_localname(om_attr, env);
            attr_ns = axiom_attribute_get_namespace(om_attr, env);
            if(attr_ns)
            {
                this_attr_ns_uri = axiom_namespace_get_uri(attr_ns, env);
            }
            else
            {
                this_attr_ns_uri = "";
            }
            
            if((!axutil_strcmp(attribute_name, this_attr_name)) && 
                (!axutil_strcmp(ns_uri, this_attr_ns_uri)))
            {
                /* Got it !!! */
                found_val = axiom_attribute_get_value(om_attr, env);
				AXIS2_FREE(env->allocator, hi);
                break;
            }
        }
    }

    for(hi = axutil_hash_first(attr_list, env); hi; hi = axutil_hash_next(env, hi))
    {
        void *val = NULL;
        axutil_hash_this(hi, NULL, NULL, &val);
        if (val)
        {
            axiom_attribute_free((axiom_attribute_t *)val, env);
            val = NULL;
        }
    }
    axutil_hash_free(attr_list, env);
    attr_list = NULL;

    return found_val;
}

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
    axutil_qname_t *qname)
{
    axis2_char_t *local_name = NULL;
    axis2_char_t *ns_uri = NULL;

    /* Get localname of the qname */
    local_name =  axutil_qname_get_localpart(qname, env);
    
    /* Get namespace uri of the qname */
    ns_uri = axutil_qname_get_uri(qname, env);

    return oxs_axiom_get_attribute_value_of_node_by_name(env, node, local_name, ns_uri);
}

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
    axis2_char_t* prefix)
{
    axutil_qname_t *qname = NULL;
    axiom_node_t *node = NULL;
    axiom_element_t *parent_ele = NULL;
    axiom_element_t *ele = NULL;

    qname = axutil_qname_create(env, local_name, ns_uri, prefix);
    parent_ele = axiom_node_get_data_element(parent, env);
    if (!parent_ele)
    {
        return NULL;
    }

    /*Get the child*/
    ele = axiom_element_get_first_child_with_qname(parent_ele, env, qname, parent, &node);
    axutil_qname_free(qname, env);
    qname = NULL;
    return node;
}

/**
 * Returns content of a node
 * @param env Environment. MUST NOT be NULL,
 * @param node the node whose content should be retrieved
 * @return the content of the node if found, else NULL
 */
AXIS2_EXTERN axis2_char_t* AXIS2_CALL
oxs_axiom_get_node_content(
    const axutil_env_t *env, 
    axiom_node_t* node)
{
    axiom_element_t *ele = NULL;
    axis2_char_t *content = NULL;

    ele = axiom_node_get_data_element(node, env);
    if(!ele) 
    {
        return NULL;
    }

    content = axiom_element_get_text(ele, env, node);
    return content;
}

/**
 * Deserialises given buffer and creates the axiom node 
 * @param env Environment. Must not be NULL
 * @param buffer representation of serialised node
 * @return deserialised node if success. NULL otherwise.
 */
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
oxs_axiom_deserialize_node(
    const axutil_env_t *env,  
    axis2_char_t* buffer)
{
    return axiom_node_create_from_buffer(env, buffer);
}

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
    axis2_char_t* ns)
{
    axiom_element_t * ele = NULL;
    axis2_char_t* namestr = NULL;
    axis2_char_t* ns_str = NULL;
    axutil_qname_t* qname = NULL;

    ele = axiom_node_get_data_element(node, env);
    qname = axiom_element_get_qname(ele, env, node);
    namestr = axutil_qname_get_localpart(qname, env);
    
    if(axutil_strcmp(namestr, name))
    {
        return AXIS2_FALSE;
    }

    if(ns)
    {
        ns_str = axutil_qname_get_uri(qname, env);
        if(axutil_strcmp(ns_str, ns))
        {
            return AXIS2_FALSE;
        }
    }

    return AXIS2_TRUE;
}

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
    axiom_node_t *node_before)
{
    axis2_status_t status = AXIS2_FAILURE;
    axiom_node_t *temp_node = NULL;

    temp_node = axiom_node_detach_without_namespaces(node_to_move,env);
    status = axiom_node_insert_sibling_before(node_before, env, temp_node);
    return status;
}

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
    axiom_node_t *child)
{
    axis2_status_t status = AXIS2_FAILURE;
    axiom_node_t *first_child = NULL;
    
    first_child = axiom_node_get_first_child(parent, env);
    status = axiom_node_insert_sibling_before(first_child, env, child);
    return status;
}

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
    axis2_char_t *attr_ns)
{
	axiom_node_t *p = NULL;	
	axiom_node_t *root = NULL;

    /* find the root node */
	p = node;
	do 
	{
		root = p;
		p = axiom_node_get_parent(root, env);	
	} while (p);

    /* from the root node, find the node with name and attribute value */
	return oxs_axiom_get_first_node_by_name_and_attr_val(
        env, root, e_name, e_ns, attr_name, attr_val, attr_ns);
}

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
    axis2_char_t *attr_ns)
{
    axis2_char_t *attribute_value = NULL;
    axis2_char_t *localname = NULL;    
	axiom_namespace_t *nmsp = NULL;
	axiom_element_t *element = NULL;
    axis2_bool_t element_match = AXIS2_FALSE;
	axiom_node_t *temp_node = NULL;

	if(axiom_node_get_node_type(node, env) != AXIOM_ELEMENT)
    {
        return NULL;
    }
	
    element = axiom_node_get_data_element(node, env);
	localname = axiom_element_get_localname(element, env);   
	if(localname && !axutil_strcmp(localname, e_name))
	{
		element_match = AXIS2_TRUE;
		if(e_ns)
		{
			nmsp = axiom_element_get_namespace(element, env, node);
			if(nmsp)
			{
                axis2_char_t *namespacea = NULL;
				namespacea = axiom_namespace_get_uri(nmsp, env);
				if(axutil_strcmp(e_ns, namespacea))
				{
					element_match = AXIS2_FALSE;
				}
			}
		}

        /* element is ok. So, we have to check the attribute value */
		if(element_match)
		{
			if(attr_ns)
			{
				axiom_attribute_t *attr = NULL;
				axutil_qname_t *qname = axutil_qname_create(env, attr_name, attr_ns, NULL);
				attr = axiom_element_get_attribute(element, env, qname);
                if(attr)
                {
				    attribute_value = axiom_attribute_get_value(attr, env);
                }
				axutil_qname_free(qname, env);
			}
			else
			{
				attribute_value = axiom_element_get_attribute_value_by_name(
                    element, env, attr_name);
			}
		}
		if (attribute_value && !axutil_strcmp(attribute_value, attr_val))
		{
			return node;
		}
	}

    /* Doesn't match? Get the children and search */    
    temp_node = axiom_node_get_first_element(node, env);
    while (temp_node)
    {
        axiom_node_t *res_node = NULL;
        res_node = oxs_axiom_get_first_node_by_name_and_attr_val(
            env, temp_node, e_name, e_ns, attr_name, attr_val, attr_ns);
        if (res_node)
		{
            return res_node;
        }
        temp_node = axiom_node_get_next_sibling(temp_node, env);
    }
    return NULL;
}

/**
 * Clones the given node. 
 * @param env Environment. Must not be null
 * @param node node to be cloned
 * @return cloned node if success. NULL otherwise
 */
AXIS2_EXTERN axiom_node_t *AXIS2_CALL
oxs_axiom_clone_node(
    const axutil_env_t *env,
    axiom_node_t *node)
{
    return axiom_util_clone_node(env, node);
}

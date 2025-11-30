# src/rule4.py

import re
from tree_builder import QueryNode

def apply_rule4(root, alias_map=None):
    # Combine cross-products followed by join conditions into a single join

    def extract_alias_from_relation(relation_str):
        # Extract alias from relation string like "table (alias)"
        match = re.search(r'\(([^)]+)\)', relation_str)
        if match:
            return match.group(1).strip()
        return relation_str.strip()
    
    def get_relations_in_subtree(node, relations_set):
        # Collect all relation aliases in a subtree
        if node.op_type == "relation":
            alias = extract_alias_from_relation(node.relation)
            relations_set.add(alias)
        for child in node.children:
            get_relations_in_subtree(child, relations_set)

    def get_relations_in_condition(condition, alias_map):
        # Extract relation aliases from condition string
        involved = set()
        condition_lower = condition.lower()
        
        if alias_map:
            for alias in alias_map.keys():
                alias_lower = alias.lower()
                pattern = r'\b' + re.escape(alias_lower) + r'\.'
                if re.search(pattern, condition_lower):
                    involved.add(alias)
        else:
            # Try to extract aliases from condition directly
            matches = re.findall(r'\b(\w+)\.\w+', condition_lower)
            involved.update(matches)
        
        return list(involved)

    def is_join_condition(condition, left_subtree, right_subtree, alias_map):
        # Check if condition involves attributes from both subtrees
        involved_relations = get_relations_in_condition(condition, alias_map)
        
        if len(involved_relations) < 2:
            return False
        
        # Get relations in each subtree
        left_relations = set()
        right_relations = set()
        get_relations_in_subtree(left_subtree, left_relations)
        get_relations_in_subtree(right_subtree, right_relations)
        
        # Check if condition involves relations from both subtrees
        involved_set = set(involved_relations)
        has_left = bool(involved_set & left_relations)
        has_right = bool(involved_set & right_relations)
        
        return has_left and has_right

    def collect_all_selections_above(node, product_node, selections_list):
        # Recursively collect all selection nodes that are ancestors of product_node
        # and could potentially be join conditions for that product
        if node is product_node:
            return
        
        if node.op_type == "select" and node.condition:
            selections_list.append(node)
        
        for child in node.children:
            collect_all_selections_above(child, product_node, selections_list)

    def find_join_conditions_for_product(product_node, ancestor_node, alias_map):
        # Find all join conditions in the ancestor tree that apply to this product
        if product_node.op_type != "product" or len(product_node.children) != 2:
            return []
        
        join_conditions = []
        
        # Collect all selections in the ancestor tree
        all_selections = []
        collect_all_selections_above(ancestor_node, product_node, all_selections)
        
        # Check each selection to see if it's a join condition for this product
        for sel in all_selections:
            if is_join_condition(sel.condition, product_node.children[0], 
                                product_node.children[1], alias_map):
                join_conditions.append(sel.condition)
        
        return join_conditions

    def convert_product_to_join(product_node, join_condition):
        # Convert a product node with a join condition to a join node
        if product_node.op_type != "product" or len(product_node.children) != 2:
            return product_node
        
        return QueryNode(
            op_type="join",
            condition=join_condition,
            children=product_node.children
        )

    def remove_join_conditions_from_tree(node, join_conditions_to_remove):
        # Remove specific join condition selections from the tree
        if node.op_type == "select" and node.condition:
            if node.condition in join_conditions_to_remove:
                # This selection should be removed
                if node.children:
                    return node.children[0], [node.condition]
                else:
                    return None, [node.condition]
            else:
                # Keep this selection, process children
                new_children = []
                removed = []
                for child in node.children:
                    new_child, child_removed = remove_join_conditions_from_tree(child, join_conditions_to_remove)
                    if new_child is not None:
                        new_children.append(new_child)
                    removed.extend(child_removed)
                
                if new_children:
                    return QueryNode(
                        op_type=node.op_type,
                        condition=node.condition,
                        attrs=node.attrs.copy() if node.attrs else None,
                        relation=node.relation,
                        children=new_children
                    ), removed
                else:
                    return None, removed
            
        # Process children
        new_children = []
        removed = []
        for child in node.children:
            new_child, child_removed = remove_join_conditions_from_tree(child, join_conditions_to_remove)
            if new_child is not None:
                new_children.append(new_child)
            removed.extend(child_removed)
        
        return QueryNode(
            op_type=node.op_type,
            condition=node.condition,
            attrs=node.attrs.copy() if node.attrs else None,
            relation=node.relation,
            children=new_children
        ), removed

    def process_node(node, parent=None):
        # Process children first (bottom-up)
        new_children = [process_node(child, node) for child in node.children]
        node.children = new_children
        
        # If this is a product node, try to convert it to a join
        if node.op_type == "product" and len(node.children) == 2:
            # Find join conditions that apply to this product
            join_conditions = find_join_conditions_for_product(node, root, alias_map)
            
            if join_conditions:
                # Convert product to join
                combined_join_condition = " AND ".join(join_conditions)
                join_node = convert_product_to_join(node, combined_join_condition)
                
                # Remove the join conditions from the tree above
                # We'll handle this by returning a marker and processing at a higher level
                return join_node
        
        return node

    def process_tree_bottom_up(node):
        # First process all children
        new_children = []
        for child in node.children:
            new_children.append(process_tree_bottom_up(child))
        node.children = new_children
        
        # Now check if this node is a product that can be converted
        if node.op_type == "product" and len(node.children) == 2:
            # Search for join conditions in the entire tree above this product
            # We need to search from root down to find selections that apply
            join_conditions = []
            
            # Search the entire tree for selections that are join conditions for this product
            def search_for_join_conditions(search_node, target_product):
                found = []
                if search_node is target_product:
                    return found
                
                if search_node.op_type == "select" and search_node.condition:
                    if is_join_condition(search_node.condition, target_product.children[0],
                                      target_product.children[1], alias_map):
                        found.append(search_node.condition)
                
                for child in search_node.children:
                    found.extend(search_for_join_conditions(child, target_product))
                
                return found
            
            # Search from root
            join_conditions = search_for_join_conditions(root, node)

            if join_conditions:
                # Convert to join
                combined_condition = " AND ".join(join_conditions)
                return QueryNode(
                    op_type="join",
                    condition=combined_condition,
                    children=node.children
                )
        
        return node

    # First pass: convert products to joins
    root = process_tree_bottom_up(root)
    
    # Second pass: remove the join condition selections that are now part of joins
    def remove_redundant_join_selections(node):
        new_children = [remove_redundant_join_selections(child) for child in node.children]
        node.children = new_children
        
        # If this is a selection and its child is a join with the same condition, remove it
        if node.op_type == "select" and node.condition and len(node.children) == 1:
            child = node.children[0]
            if child.op_type == "join" and child.condition == node.condition:
                return child
            # Check if condition is part of join condition
            if child.op_type == "join" and child.condition:
                # Check if this selection's condition is in the join condition
                if node.condition in child.condition or child.condition.find(node.condition) != -1:
                    # The condition might be embedded, need to check more carefully
                    join_parts = [p.strip() for p in child.condition.split(" AND ")]
                    if node.condition.strip() in join_parts:
                        return child
        
        return node

    root = remove_redundant_join_selections(root)
        
    return process_node(root)
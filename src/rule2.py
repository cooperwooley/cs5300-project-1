# src/rule2.py

import re
from tree_builder import QueryNode

def apply_rule2(root, alias_map):
    # Move selections down as far as possible

    def get_relations_in_condition(condition, alias_map):
        # Extract relation aliases from condition string
        # Look for patterns like "alias.attribute" or just "alias" 
        involved = set()
        condition_lower = condition.lower()
        
        for alias in alias_map.keys():
            alias_lower = alias.lower()
            # Check if alias appears as "alias." or "alias " or at start/end
            pattern = r'\b' + re.escape(alias_lower) + r'\.'
            if re.search(pattern, condition_lower):
                involved.add(alias)
        
        return list(involved)

    def extract_alias_from_relation(relation_str):
        match = re.search(r'\(([^)]+)\)', relation_str)
        if match:
            return match.group(1).strip()
        return relation_str.trip()

    def subtree_contains_relation(node, target_alias):
        # Check if this subtree contains the target relation
        if node.op_type == "relation":
            # Extract alias from relation string
            relation_alias = extract_alias_from_relation(node.relation)
            if relation_alias.lower() == target_alias.lower():
                return True
        for child in node.children:
            if subtree_contains_relation(child, target_alias):
                return True
        return False

    def push_selection_into_subtree(node, selection_condition, target_alias):
        # Recursively push selection down into the subtree containing target_alias
        if node.op_type == "relation":
            # Place selection right above it
            return QueryNode(op_type="select", condition=selection_condition, children=[node])
        
        # If selection node, push through
        if node.op_type == "select":
            child = node.children[0]
            pushed_child = push_selection_into_subtree(child, selection_condition, target_alias)
            return QueryNode(op_type="select", condition=node.condition, children=[pushed_child])

        # Process children first
        new_children = []
        for child in node.children:
            if subtree_contains_relation(child, target_alias):
                # Push selection into it
                new_children.append(push_selection_into_subtree(child, selection_condition, target_alias))
            else:
                new_children.append(push_down(child))
        
        # Reconstruct node with processed children
        return QueryNode(
            op_type=node.op_type,
            condition=node.condition,
            attrs=node.attrs.copy() if node.attrs else None,
            relation=node.relation,
            children=new_children
        )

    def push_down(node):
        # Process children first (bottom-up)
        new_children = [push_down(child) for child in node.children]
        node.children = new_children

        # If this is a selection node, try to push it down
        if node.op_type == "select" and node.condition:
            involved_relations = get_relations_in_condition(node.condition, alias_map)
            
            if len(involved_relations) == 1:
                # Selection applies to only one relation
                target_alias = involved_relations[0]
                child = node.children[0]
                
                # Check if we can push past the child
                # Can push past: product, join, project, select
                # Cannot push past: groupby, orderby
                if child.op_type in ["product", "join", "project", "select"]:
                    # Push the selection into the child's subtree
                    return push_selection_into_subtree(child, node.condition, target_alias)
                elif child.op_type == "select":
                    # Already a selection
                    return push_selection_into_subtree(child, node.condition, target_alias)
                elif child.op_type == "relation":
                    # Already at relation
                    return node
                else:
                    return node
            else:
                return node
        
        return node

    return push_down(root)
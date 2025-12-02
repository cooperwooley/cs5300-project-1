# src/rule5.py 

import re
from tree_builder import QueryNode

def apply_rule5(root, parsed, schema=None, alias_map=None):
    # Push projections down using schema information
    
    # Build attribute mapping
    alias_to_attrs = {}
    from_clause = parsed.get('from', {})
    tables = from_clause.get('tables', []) if isinstance(from_clause, dict) else from_clause
    
    for table_info in tables:
        table_name = table_info['table']
        alias = table_info['alias']
        if schema:
            # Try exact match first, then case-insensitive
            schema_key = None
            for key in schema.keys():
                if key.upper() == table_name.upper():
                    schema_key = key
                    break
            
            if schema_key:
                # Get attributes with alias prefix and without
                attrs = schema[schema_key]['attrs']  # FIX: use schema_key not table_name
                prefixed_attrs = {f"{alias}.{attr}" for attr in attrs}
                alias_to_attrs[alias] = prefixed_attrs | set(attrs)
            else:
                alias_to_attrs[alias] = set()
        else:
            alias_to_attrs[alias] = set()
        
    
    def extract_attrs_from_condition(condition):
        # Extract all attribute references from a condition
        attrs = set()
        if not condition:
            return attrs
        # Match attribute patterns
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)\b'
        matches = re.findall(pattern, condition)
        for match in matches:
            # Skip constants
            if not (match.startswith(('"', "'")) or re.match(r'^-?\d+\.?\d*$', match)):
                attrs.add(match.strip())
        return attrs
    
    def extract_alias_from_relation(relation_str):
        # Extract alias from relation string
        match = re.search(r'\(([^)]+)\)', relation_str)
        if match:
            return match.group(1).strip()
        return relation_str.strip()
    
    def get_attrs_from_subtree(node):
        # Get all attributes that can come from this subtree
        attrs = set()
        
        if node.op_type == "relation":
            # Get alias from relation string and return its attributes
            alias = extract_alias_from_relation(node.relation)
            if alias in alias_to_attrs:
                attrs.update(alias_to_attrs[alias])
        
        elif node.op_type == "project" and node.attrs:
            # Attributes available are those projected
            attrs.update(a.strip() for a in node.attrs)
        
        else:
            # Recurse through children and union
            for child in node.children:
                attrs.update(get_attrs_from_subtree(child))
        
        return attrs
    
    def get_attrs_needed(node):
        # Compute attributes needed by this node
        needed = set()
        
        if node.op_type == "project" and node.attrs:
            needed.update(a.strip() for a in node.attrs)
        
        if node.op_type == "select" and node.condition:
            needed.update(extract_attrs_from_condition(node.condition))
        
        if node.op_type == "join" and node.condition:
            needed.update(extract_attrs_from_condition(node.condition))
        
        if node.op_type in ("groupby", "orderby") and node.attrs:
            for a in node.attrs:
                needed.add(a.split()[0].strip())
        
        return needed
    
    def push_projection_down(node, needed_attrs_above):
        # Recursively push projections down the tree
        # Determine what this node needs
        node_needs = get_attrs_needed(node)
        all_needed = needed_attrs_above | node_needs
        
        if node.op_type == "relation":
            # At a base relation - can't push further
            return node
        
        elif node.op_type == "project":
            # CRITICAL FIX: This node projects, so push those requirements down to children
            project_attrs = set(node.attrs) if node.attrs else set()
            all_needed = project_attrs | node_needs
            
            # Process children with the needed attributes
            if node.children:
                child = node.children[0]
                child_attrs = get_attrs_from_subtree(child)
                child_needed = all_needed & child_attrs  # Intersection
                
                # Recursively push down child
                new_child = push_projection_down(child, child_needed)
                
                # If child doesn't already project what we need, add projection
                if new_child.op_type != "project" or not (set(new_child.attrs) if new_child.attrs else set()) == child_needed:
                    if child_needed:  # Only add projection if we know what we need
                        new_child = QueryNode(
                            op_type="project",
                            attrs=sorted(list(child_needed)),
                            children=[new_child]
                        )
                
                node.children = [new_child]
        
        elif node.op_type == "select":
            # Push needed attributes to child
            if node.children:
                child = node.children[0]
                child_attrs = get_attrs_from_subtree(child)
                child_needed = all_needed & child_attrs  # Intersection
                
                # Recursively push down child
                new_child = push_projection_down(child, child_needed)
                
                # If child doesn't already project what we need, add projection
                if new_child.op_type != "project" or not (set(new_child.attrs) if new_child.attrs else set()) == child_needed:
                    if child_needed:  # Only add projection if we know what we need
                        new_child = QueryNode(
                            op_type="project",
                            attrs=sorted(list(child_needed)),
                            children=[new_child]
                        )
                
                node.children = [new_child]
        
        elif node.op_type == "join":
            # Split needed attributes between left and right
            if len(node.children) == 2:
                left_child, right_child = node.children
                
                left_attrs = get_attrs_from_subtree(left_child)
                right_attrs = get_attrs_from_subtree(right_child)
                
                # Attributes needed from each side
                left_needed = (all_needed & left_attrs)
                right_needed = (all_needed & right_attrs)
                
                # Also need join condition attributes
                join_attrs = extract_attrs_from_condition(node.condition or "")
                left_needed.update(join_attrs & left_attrs)
                right_needed.update(join_attrs & right_attrs)
                
                # Recursively push down
                new_left = push_projection_down(left_child, left_needed)
                new_right = push_projection_down(right_child, right_needed)
                
                # Add projections if needed
                if new_left.op_type != "project" or not (set(new_left.attrs) if new_left.attrs else set()) == left_needed:
                    if left_needed:  # Only if we know what we need
                        new_left = QueryNode(
                            op_type="project",
                            attrs=sorted(list(left_needed)),
                            children=[new_left]
                        )
                
                if new_right.op_type != "project" or not (set(new_right.attrs) if new_right.attrs else set()) == right_needed:
                    if right_needed:  # Only if we know what we need
                        new_right = QueryNode(
                            op_type="project",
                            attrs=sorted(list(right_needed)),
                            children=[new_right]
                        )
                
                node.children = [new_left, new_right]
        
        elif node.op_type == "product":
            # Similar to join but no join condition
            if len(node.children) == 2:
                left_child, right_child = node.children
                
                left_attrs = get_attrs_from_subtree(left_child)
                right_attrs = get_attrs_from_subtree(right_child)
                
                left_needed = (all_needed & left_attrs)
                right_needed = (all_needed & right_attrs)
                
                new_left = push_projection_down(left_child, left_needed)
                new_right = push_projection_down(right_child, right_needed)
                
                if new_left.op_type != "project" or not (set(new_left.attrs) if new_left.attrs else set()) == left_needed:
                    if left_needed:
                        new_left = QueryNode(
                            op_type="project",
                            attrs=sorted(list(left_needed)),
                            children=[new_left]
                        )
                
                if new_right.op_type != "project" or not (set(new_right.attrs) if new_right.attrs else set()) == right_needed:
                    if right_needed:
                        new_right = QueryNode(
                            op_type="project",
                            attrs=sorted(list(right_needed)),
                            children=[new_right]
                        )
                
                node.children = [new_left, new_right]
        
        elif node.op_type in ("groupby", "orderby"):
            if node.children:
                child = node.children[0]
                child_attrs = get_attrs_from_subtree(child)
                child_needed = all_needed & child_attrs
                
                new_child = push_projection_down(child, child_needed)
                
                if new_child.op_type != "project" or not (set(new_child.attrs) if new_child.attrs else set()) == child_needed:
                    if child_needed:
                        new_child = QueryNode(
                            op_type="project",
                            attrs=sorted(list(child_needed)),
                            children=[new_child]
                        )
                
                node.children = [new_child]
        
        else:
            # Process children for other node types
            new_children = []
            for child in node.children:
                child_attrs = get_attrs_from_subtree(child)
                child_needed = all_needed & child_attrs
                new_child = push_projection_down(child, child_needed)
                new_children.append(new_child)
            node.children = new_children
        
        return node
    
    # Start at root
    root_needs = get_attrs_needed(root)
    return push_projection_down(root, root_needs)
# src/rule5.py 

import re
from tree_builder import QueryNode

def apply_rule5(root, parsed, schema=None, alias_map=None):
    """Push projections down the tree to reduce data size early."""
    
    # Build attribute mapping from schema
    alias_to_attrs = {}
    from_clause = parsed.get('from', {})
    tables = from_clause.get('tables', []) if isinstance(from_clause, dict) else from_clause
    
    for table_info in tables:
        table_name = table_info['table']
        alias = table_info['alias']
        if schema:
            # Find matching schema table (case-insensitive)
            schema_key = None
            for key in schema.keys():
                if key.lower() == table_name.lower():
                    schema_key = key
                    break
            
            if schema_key:
                attrs = schema[schema_key]['attrs']
                # Store attributes with alias prefix and without
                all_variants = set()
                for attr in attrs:
                    all_variants.add(attr)  # Lname
                    all_variants.add(attr.lower())  # lname
                    all_variants.add(f"{alias}.{attr}")  # E.Lname
                    all_variants.add(f"{alias.lower()}.{attr}")  # e.Lname
                    all_variants.add(f"{alias}.{attr.lower()}")  # E.lname
                alias_to_attrs[alias] = all_variants
                alias_to_attrs[alias.lower()] = all_variants
        else:
            alias_to_attrs[alias] = set()
            alias_to_attrs[alias.lower()] = set()
    
    def extract_attrs_from_expr(expr):
        """Extract attribute references from an expression."""
        attrs = set()
        if not expr:
            return attrs
        # Match patterns like "E.Lname", "Lname", etc.
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)\b'
        matches = re.findall(pattern, str(expr))
        for match in matches:
            # Skip constants
            if not (match.startswith(('"', "'")) or re.match(r'^-?\d+\.?\d*$', match)):
                attrs.add(match.strip())
                attrs.add(match.strip().lower())
        return attrs
    
    def get_alias_from_relation(node):
        """Extract alias from relation node."""
        if node.op_type != "relation":
            return None
        match = re.search(r'\(([^)]+)\)', node.relation)
        if match:
            return match.group(1).strip()
        return None
    
    def get_available_attrs_from_node(node):
        """Get all attributes available from this node."""
        attrs = set()
        
        if node.op_type == "relation":
            alias = get_alias_from_relation(node)
            if alias and alias in alias_to_attrs:
                attrs.update(alias_to_attrs[alias])
            elif alias and alias.lower() in alias_to_attrs:
                attrs.update(alias_to_attrs[alias.lower()])
        
        elif node.op_type == "project" and node.attrs:
            # What's projected is what's available
            for attr in node.attrs:
                attrs.add(attr)
                attrs.add(attr.lower())
        
        else:
            # Recursively collect from children
            for child in node.children:
                attrs.update(get_available_attrs_from_node(child))
        
        return attrs
    
    def normalize_attr_for_matching(attr):
        """Normalize attribute for comparison."""
        return attr.strip().lower()
    
    def attributes_equal(attrs1, attrs2):
        """Check if two attribute lists are equivalent (case-insensitive)."""
        if not attrs1 or not attrs2:
            return False
        set1 = {normalize_attr_for_matching(a) for a in attrs1}
        set2 = {normalize_attr_for_matching(a) for a in attrs2}
        return set1 == set2
    
    def push_down(node, required_attrs):
        """Push projections down, keeping only required attributes."""
        if not required_attrs:
            # Nothing required, return node as-is
            return node
        
        # Determine what this node needs
        node_requires = set()
        
        if node.op_type == "project" and node.attrs:
            node_requires.update(a.strip() for a in node.attrs)
            node_requires.update(a.strip().lower() for a in node.attrs)
        
        if node.op_type == "select" and node.condition:
            node_requires.update(extract_attrs_from_expr(node.condition))
        
        if node.op_type == "join" and node.condition:
            node_requires.update(extract_attrs_from_expr(node.condition))
        
        if node.op_type in ("groupby", "orderby") and node.attrs:
            for a in node.attrs:
                base_attr = a.split()[0].strip()
                node_requires.add(base_attr)
                node_requires.add(base_attr.lower())
        
        # Combine requirements
        all_required = required_attrs | node_requires
        
        # Handle different node types
        if node.op_type == "relation":
            return node  # Can't push further
        
        elif node.op_type == "project":
            # This node projects specific attributes
            # Push those requirements down
            if node.children:
                child = node.children[0]
                available = get_available_attrs_from_node(child)
                
                # What we need from child: intersection of required and available
                needed_from_child = set()
                for req in all_required:
                    req_normalized = normalize_attr_for_matching(req)
                    for avail in available:
                        if normalize_attr_for_matching(avail) == req_normalized:
                            needed_from_child.add(avail)
                            needed_from_child.add(avail.lower())
                
                # If no schema info, try to extract attributes from required set
                if not available and schema:
                    # We have schema but no match - try direct matching
                    for req in all_required:
                        needed_from_child.add(req)
                
                # Recursively push down
                new_child = push_down(child, needed_from_child)
                
                # Check if child already projects exactly what we need
                child_projects_needed = False
                if new_child.op_type == "project" and new_child.attrs:
                    child_attrs_normalized = {normalize_attr_for_matching(a) for a in new_child.attrs}
                    needed_normalized = {normalize_attr_for_matching(a) for a in needed_from_child}
                    if child_attrs_normalized == needed_normalized:
                        child_projects_needed = True
                
                # Check if parent and child project the same attributes
                parent_projects_same = False
                if new_child.op_type == "project" and new_child.attrs:
                    if attributes_equal(node.attrs, new_child.attrs):
                        parent_projects_same = True
                
                # If parent and child project the same, skip adding another projection
                if parent_projects_same:
                    node.children = [new_child.children[0] if new_child.children else new_child]
                    return node
                
                # Add projection if needed and not redundant
                if needed_from_child and not child_projects_needed:
                    # Create new projection with needed attributes
                    attrs_list = []
                    seen = set()
                    for attr in needed_from_child:
                        norm = normalize_attr_for_matching(attr)
                        if norm not in seen:
                            attrs_list.append(attr)
                            seen.add(norm)
                    
                    if attrs_list:  # Only create if we have attributes
                        new_child = QueryNode(
                            op_type="project",
                            attrs=attrs_list,
                            children=[new_child]
                        )
                
                node.children = [new_child]
            
            return node
        
        elif node.op_type == "select":
            # Push requirements to child
            if node.children:
                child = node.children[0]
                available = get_available_attrs_from_node(child)
                
                needed_from_child = set()
                for req in all_required:
                    req_norm = normalize_attr_for_matching(req)
                    for avail in available:
                        if normalize_attr_for_matching(avail) == req_norm:
                            needed_from_child.add(avail)
                            needed_from_child.add(avail.lower())
                
                if not available and schema:
                    for req in all_required:
                        needed_from_child.add(req)
                
                new_child = push_down(child, needed_from_child)
                
                if needed_from_child and (new_child.op_type != "project" or 
                    not attributes_equal(new_child.attrs, needed_from_child)):
                    attrs_list = []
                    seen = set()
                    for attr in needed_from_child:
                        norm = normalize_attr_for_matching(attr)
                        if norm not in seen:
                            attrs_list.append(attr)
                            seen.add(norm)
                    
                    if attrs_list:
                        new_child = QueryNode(
                            op_type="project",
                            attrs=attrs_list,
                            children=[new_child]
                        )
                
                node.children = [new_child]
            
            return node
        
        elif node.op_type == "join":
            # Split requirements between left and right children
            if len(node.children) == 2:
                left_child, right_child = node.children
                
                # Get available attributes from each side
                left_available = get_available_attrs_from_node(left_child)
                right_available = get_available_attrs_from_node(right_child)
                
                # Also need join condition attributes
                join_attrs = extract_attrs_from_expr(node.condition)
                
                # Determine what's needed from each side
                left_needed = set()
                right_needed = set()
                
                all_with_join = all_required | join_attrs
                
                for req in all_with_join:
                    req_norm = normalize_attr_for_matching(req)
                    
                    # Try to match on left
                    for avail in left_available:
                        if normalize_attr_for_matching(avail) == req_norm:
                            left_needed.add(avail)
                            left_needed.add(avail.lower())
                    
                    # Try to match on right
                    for avail in right_available:
                        if normalize_attr_for_matching(avail) == req_norm:
                            right_needed.add(avail)
                            right_needed.add(avail.lower())
                    
                    # If no schema info, add to both sides
                    if not left_available and not right_available:
                        left_needed.add(req)
                        right_needed.add(req)
                
                # Recursively push down
                new_left = push_down(left_child, left_needed)
                new_right = push_down(right_child, right_needed)
                
                # Add projections if needed
                if left_needed and (new_left.op_type != "project" or 
                    not attributes_equal(new_left.attrs, left_needed)):
                    attrs_list = []
                    seen = set()
                    for attr in left_needed:
                        norm = normalize_attr_for_matching(attr)
                        if norm not in seen:
                            attrs_list.append(attr)
                            seen.add(norm)
                    if attrs_list:
                        new_left = QueryNode(op_type="project", attrs=attrs_list, children=[new_left])
                
                if right_needed and (new_right.op_type != "project" or 
                    not attributes_equal(new_right.attrs, right_needed)):
                    attrs_list = []
                    seen = set()
                    for attr in right_needed:
                        norm = normalize_attr_for_matching(attr)
                        if norm not in seen:
                            attrs_list.append(attr)
                            seen.add(norm)
                    if attrs_list:
                        new_right = QueryNode(op_type="project", attrs=attrs_list, children=[new_right])
                
                node.children = [new_left, new_right]
            
            return node
        
        elif node.op_type == "product":
            # Similar to join
            if len(node.children) == 2:
                left_child, right_child = node.children
                left_available = get_available_attrs_from_node(left_child)
                right_available = get_available_attrs_from_node(right_child)
                
                left_needed = set()
                right_needed = set()
                
                for req in all_required:
                    req_norm = normalize_attr_for_matching(req)
                    
                    for avail in left_available:
                        if normalize_attr_for_matching(avail) == req_norm:
                            left_needed.add(avail)
                            left_needed.add(avail.lower())
                    
                    for avail in right_available:
                        if normalize_attr_for_matching(avail) == req_norm:
                            right_needed.add(avail)
                            right_needed.add(avail.lower())
                
                new_left = push_down(left_child, left_needed)
                new_right = push_down(right_child, right_needed)
                
                if left_needed and (new_left.op_type != "project" or 
                    not attributes_equal(new_left.attrs, left_needed)):
                    attrs_list = []
                    seen = set()
                    for attr in left_needed:
                        norm = normalize_attr_for_matching(attr)
                        if norm not in seen:
                            attrs_list.append(attr)
                            seen.add(norm)
                    if attrs_list:
                        new_left = QueryNode(op_type="project", attrs=attrs_list, children=[new_left])
                
                if right_needed and (new_right.op_type != "project" or 
                    not attributes_equal(new_right.attrs, right_needed)):
                    attrs_list = []
                    seen = set()
                    for attr in right_needed:
                        norm = normalize_attr_for_matching(attr)
                        if norm not in seen:
                            attrs_list.append(attr)
                            seen.add(norm)
                    if attrs_list:
                        new_right = QueryNode(op_type="project", attrs=attrs_list, children=[new_right])
                
                node.children = [new_left, new_right]
            
            return node
        
        else:
            # For other node types, just recurse
            new_children = []
            for child in node.children:
                new_children.append(push_down(child, all_required))
            node.children = new_children
            return node
    
    # Start: determine what's needed at root
    root_needs = set()
    if root.op_type == "project" and root.attrs:
        for attr in root.attrs:
            root_needs.add(attr)
            root_needs.add(attr.lower())
    
    result = push_down(root, root_needs)
    
    # Final cleanup: remove redundant consecutive projections
    def remove_redundant_projections(node):
        """Remove consecutive projection nodes that project the same attributes."""
        # Process children first (bottom-up)
        new_children = []
        for child in node.children:
            new_children.append(remove_redundant_projections(child))
        node.children = new_children
        
        # Check if this node is a projection with a projection child
        if node.op_type == "project" and node.children:
            child = node.children[0]
            if child.op_type == "project" and child.attrs:
                # If they project the same attributes, remove the child projection
                if attributes_equal(node.attrs, child.attrs):
                    # Replace this node with child's subtree (remove redundant parent)
                    if child.children:
                        # Keep child but remove parent
                        return child
                    else:
                        # Both are leaves, just keep child
                        return child
        
        return node
    
    return remove_redundant_projections(result)
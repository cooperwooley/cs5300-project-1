# heuristic_query_optimizer.py

import sys
import re
from graphviz import Digraph

def parse_query(query):
    # split query into tokens by clauses
    tokens = re.split(r'\b(select|from|where|group by|having|order by)', query, flags=re.IGNORECASE)
    tokens = [token.strip().lower() for token in tokens[1:]]
    token_dict = {tokens[i]: tokens[i+1] for i in range(0, len(tokens), 2)}

    # parse each clause
    parsed = {}
    if 'select' in token_dict:
        parsed['select'] = parse_select_clause(token_dict['select'])
    if 'from' in token_dict:
        parsed['from'] = parse_from_clause(token_dict['from'])
    if 'where' in token_dict:
        parsed['where'] = parse_where_clause(token_dict['where'])
    if 'group by' in token_dict:
        parsed['group by'] = parse_group_by_clause(token_dict['group by'])
    if 'having' in token_dict:
        parsed['having'] = parse_having_clause(token_dict['having'])
    if 'order by' in token_dict:
        parsed['order by'] = parse_order_by_clause(token_dict['order by'])

    return parsed


def parse_select_clause(select_str):
    attrs = []
    for attr in select_str.split(','):
        attr = attr.strip()
        alias = None
        agg = None

        # Detect alias
        if re.search(r'\bAS\b', attr, flags=re.IGNORECASE):
            expr, alias = re.split(r'\bAS\b', attr, flags=re.IGNORECASE)
            expr, alias = expr.strip(), alias.strip()
        else:
            expr = attr

        # Detect aggregations
        match = re.match(r'(SUM|COUNT|AVG|MAX|MIN)\((.*)\)', expr, flags=re.IGNORECASE)
        if match:
            agg, expr = match.groups()

        attrs.append({'expr': expr, 'alias': alias, 'agg': agg})
    return attrs


def parse_from_clause(from_str):
    tables = []
    for part in from_str.split(','):
        part = part.strip()
        components = part.split()
        if len(components) == 1:
            tables.append({'table': components[0], 'alias': components[0]}) # alias is the same as table name if not specified
        elif len(components) == 2:
            tables.append({'table': components[0], 'alias': components[1]})
        else:
            raise ValueError(f"Invalid FROM clause: {from_str}")
    return tables


def parse_where_clause(where_str):
    predicates = []
    # Split by AND for simplicity
    for cond in re.split(r'\bAND\b', where_str, flags=re.IGNORECASE):
        cond = cond.strip()
        match = re.match(r'(.*)\s*(=|!=|<|>|<=|>=)\s*(.*)', cond, flags=re.IGNORECASE)
        if match:
            left, op, right = match.groups()
            predicates.append({'left': left, 'op': op, 'right': right})
        else:
            print(f"Warning: Invalid WHERE condition: {cond}")
    return predicates


def parse_group_by_clause(group_by_str):
    return [attr.strip() for attr in group_by_str.split(',')]


def parse_having_clause(having_str):
    pass


def parse_order_by_clause(order_by_str):
    attrs = []
    for part in order_by_str.split(','):
        part = part.strip()
        tokens = part.split()
        if len(tokens) == 1:
            attrs.append({'attr': tokens[0], 'order': 'asc'})
        elif len(tokens) == 2:
            attrs.append({'attr': tokens[0], 'order': tokens[1].lower()})
        else:
            raise ValueError(f"Invalid ORDER BY clause: {order_by_str}")
    return attrs


class QueryNode:
    def __init__(self, op_type, condition=None, attrs=None, relation=None, children=None):
        self.op_type = op_type
        self.condition = condition # string condition
        self.attrs = attrs # list of attributes
        self.relation = relation # only for base tables
        self.children = children or [] # list of QueryNodes


    def __repr__(self):
        return f"{self.op_type({self. condition or self.attrs or self.relation})}"


    def copy(self):
        # Creates a deep copy of a node
        new_node = QueryNode(
            op_type = self.op_type,
            condition = self.condition,
            attrs = self.attrs.copy() if self.attrs else None,
            relation = self.relation,
            children = [child.copy() for child in self.children]
        )
        return new_node


def build_from_nodes(from_clause):
    nodes = []
    for table in from_clause:
        nodes.append(QueryNode(
            op_type="relation",
            relation=f"{table['table']} ({table['alias']})"
        )) 
    return nodes


def classify_predicates(predicates, alias_map):
    selections = {}
    joins = []

    for pred in predicates:
        left_alias = pred['left'].split('.')[0] if '.' in pred['left'] else None
        right_alias = pred['right'].split('.')[0] if '.' in pred['right'] else None

        if left_alias and right_alias and left_alias in alias_map and right_alias in alias_map and left_alias != right_alias:
            joins.append(pred)
        elif left_alias and left_alias in alias_map:
            selections.setdefault(left_alias, []).append(pred)
        elif right_alias and right_alias in alias_map:
            selections.setdefault(right_alias, []).append(pred)

    return selections, joins


def build_canonical_tree(parsed):
    base_nodes = build_from_nodes(parsed['from'])

    # Build cartesian product
    root = base_nodes[0]
    for i in range(1, len(base_nodes)):
        root = QueryNode(op_type="product", children=[root, base_nodes[i]])

    # Apply combined selection if WHERE
    if 'where' in parsed and parsed['where']:
        all_conditions = []
        for pred in parsed['where']:
            all_conditions.append(f"{pred['left']} {pred['op']} {pred['right']}")
        combined_condition = " AND ".join(all_conditions)
        root = QueryNode(op_type="select", condition=combined_condition, children=[root])

    # Apply projection
    if 'select' in parsed:
        attrs = [a['expr'] for a in parsed['select']]
        root = QueryNode('project', attrs=attrs, children=[root])

    # Apply group by
    if 'group by' in parsed:
        root = QueryNode("groupby", attrs=parsed['group by'], children=[root])

    # Apply order by
    if 'order by' in parsed:
        order_attrs = [f"{a['attr']} {a['order']}" for a in parsed['order by']]
        root = QueryNode('orderyby', attrs=order_attrs, children=[root])

    return root


def rule1_break_selections(root):
    # Break conjunctive selection conditions into a sequence of single condition selections
    if root.op_type == "select" and root.condition and " AND " in root.condition:
        # Split the condition
        conditions = [c.strip() for c in root.condition.split(" AND ")]
        # Build chain of selections
        child = root.children[0]
        for cond in reversed(conditions):
            child = QueryNode(op_type="select", condition=cond, children=[child])
        return child
    return root


def apply_rule1(node):
    # Apply rule 1 recursively
    new_children = [apply_rule1(child) for child in node.children]
    node.children = new_children

    # Apply rule 1 to this node
    if node.op_type == "select" and node.condition and " AND " in node.condition:
        conditions = [c.strip() for c in node.condition.split(" AND ")]
        child = node.children[0]
        for cond in reversed(conditions):
            child = QueryNode(op_type="select", condition=cond, children=[child])
        return child
    return node


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


def rule3_estimate_selectivity(condition, alias_map):
    # Estimate selectivity qualitatively
    match = re.match(r'(.*?)\s*(=|!=|<|>|<=|>=)\s*(.*)', condition.strip(), flags=re.IGNORECASE)
    if not match:
        return 0.5

    left, op, right = match.groups()
    left = left.strip()
    right = right.strip()
    op = op.strip()

    # Check if right side is a constant (quoted string or number)
    is_constant = False
    if re.match(r'^["\'].*["\']$', right) or re.match(r'^-?\d+\.?\d*$', right):
        is_constant = True

    # Check if right side is another attribute (contains a dot or is a known alias)
    is_attribute = False
    if '.' in right or right in alias_map:
        is_attribute = True

    if op == '=':
        if is_constant:
            return 0.1
        else:
            return 0.5
    elif op in ['<', '>', '<=', '>=']:
        if is_constant:
            return 0.3
        else:
            return 0.6
    elif op == '!=':
        if is_constant:
            return 0.7
        else:
            return 0.9
    else:
        return 0.5


def apply_rule3(root, alias_map):
    # Reorder selections so most restrictive filters are applied earliest
    
    def collect_selection_chain(node):
        # Collect a chian of consecutive selection nodes
        selections = []
        current = node
        while current.op_type == "select" and current.condition:
            selections.append(current)
            if current.children and len(current.children) == 1:
                current = current.children[0]
            else:
                break
        return selections, current

    def reorder_selection_chain(selections, bottom_node):
        # Sort selections by selectivity
        selection_with_selectivity = []
        for sel in selections:
            selectivity = rule3_estimate_selectivity(sel.condition, alias_map)
            selection_with_selectivity.append((selectivity, sel))

        selection_with_selectivity.sort(key=lambda x: x[0])

        # Rebuild the chain with most selective first
        current = bottom_node
        for _, sel in selection_with_selectivity:
            current = QueryNode(op_type="select", condition=sel.condition, children=[current])

        return current

    def process_node(node):
        # Process children first
        new_children = [process_node(child) for child in node.children]
        node.children = new_children

        if node.op_type == "select" and node.children:
            selections, bottom_node = collect_selection_chain(node)

            if len(selections) > 1:
                # Found a chain, reorder it
                return reorder_selection_chain(selections, bottom_node)
            else:
                return node

        return node
    
    return process_node(root)
            


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


def rule5_get_attributes_used(node, used_attrs):
    # Collect all attributes used in the tree
    # If this is a projection, these are the final attributes needed
    if node.op_type == "project" and node.attrs:
        for attr in node.attrs:
            used_attrs.add(attr.strip())
    
    # If this is a selection, extract attributes from condition
    if node.op_type == "select" and node.condition:
        condition = node.condition
        attr_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)\b'
        matches = re.findall(attr_pattern, condition)
        for match in matches:
            if not (match.startswith('"') or match.startswith("'") or 
                   re.match(r'^-?\d+\.?\d*$', match)):
                used_attrs.add(match.strip())
    
    # If this is a join, extract attributes from join condition
    if node.op_type == "join" and node.condition:
        attr_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)\b'
        matches = re.findall(attr_pattern, node.condition)
        for match in matches:
            if not (match.startswith('"') or match.startswith("'") or 
                   re.match(r'^-?\d+\.?\d*$', match)):
                used_attrs.add(match.strip())
    
    # If this is groupby, these attributes are needed
    if node.op_type == "groupby" and node.attrs:
        for attr in node.attrs:
            used_attrs.add(attr.strip())
    
    # If this is orderby, extract attributes
    if node.op_type == "orderby" and node.attrs:
        for attr_expr in node.attrs:
            attr = attr_expr.split()[0].strip()
            used_attrs.add(attr)
    
    # Recursively process children
    for child in node.children:
        rule5_get_attributes_used(child, used_attrs)


def apply_rule5(root, parsed):
    # Apply projections early - push projections down to reduce data size
    # Simple top-down approach: determine what each node needs, push projections down
    
    def extract_attributes_from_condition(condition):
        # Extract attribute references from a condition string
        attrs = set()
        if not condition:
            return attrs
        
        attr_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)\b'
        matches = re.findall(attr_pattern, condition)
        for match in matches:
            # Skip constants
            if not (match.startswith('"') or match.startswith("'") or 
                   re.match(r'^-?\d+\.?\d*$', match)):
                attrs.add(match.strip())
        return attrs
    
    def get_attributes_used_in_subtree(node):
        # Get all attributes that are used/defined in a subtree
        # This helps determine which attributes come from which side
        attrs = set()
        
        # If there's a projection, those are the attributes available
        def collect_from_node(n):
            if n.op_type == "project" and n.attrs:
                for attr in n.attrs:
                    attrs.add(attr.strip())
            elif n.op_type == "select" and n.condition:
                attrs.update(extract_attributes_from_condition(n.condition))
            elif n.op_type == "join" and n.condition:
                attrs.update(extract_attributes_from_condition(n.condition))
            elif n.op_type == "relation":
                # For base relations, we can't know all attributes
                # But we can infer from conditions above
                pass
            
            for child in n.children:
                collect_from_node(child)
        
        collect_from_node(node)
        return attrs
    
    def split_join_condition(condition):
        # Split a join condition into left and right attributes
        # Returns (left_attrs, right_attrs)
        left_attrs = set()
        right_attrs = set()
        
        if not condition:
            return left_attrs, right_attrs
        
        # Split by operators
        parts = re.split(r'\s*(=|!=|<|>|<=|>=)\s*', condition)
        if len(parts) >= 3:
            left_expr = parts[0].strip()
            right_expr = parts[2].strip()
            left_attrs = extract_attributes_from_condition(left_expr)
            right_attrs = extract_attributes_from_condition(right_expr)
        
        return left_attrs, right_attrs
    
    def push_projections_down(node, attributes_needed_above):
        # Top-down: push projections based on what's needed above
        # attributes_needed_above: attributes needed by parent operations
        
        # Determine what this node needs
        node_needs = set()
        
        if node.op_type == "project" and node.attrs:
            # Projection defines what's available above
            for attr in node.attrs:
                node_needs.add(attr.strip())
            # Update what's needed above to match what this projection provides
            attributes_needed_above = set(node.attrs)
        
        if node.op_type == "select" and node.condition:
            # Selection needs attributes from condition
            node_needs.update(extract_attributes_from_condition(node.condition))
        
        if node.op_type == "join" and node.condition:
            # Join needs attributes from join condition
            node_needs.update(extract_attributes_from_condition(node.condition))
        
        if node.op_type == "groupby" and node.attrs:
            for attr in node.attrs:
                node_needs.add(attr.strip())
        
        if node.op_type == "orderby" and node.attrs:
            for attr_expr in node.attrs:
                attr = attr_expr.split()[0].strip()
                node_needs.add(attr)
        
        # Total attributes needed from children
        all_needed = attributes_needed_above | node_needs
        
        # Handle different node types
        if node.op_type == "select":
            # Selection: child needs to provide all attributes
            if node.children:
                child = node.children[0]
                child_needs = all_needed
                
                # Add projection if needed
                if child.op_type != "project" or not child.attrs or set(child.attrs) != child_needs:
                    if child.op_type in ["relation", "select", "join", "product"]:
                        child = QueryNode(
                            op_type="project",
                            attrs=sorted(list(child_needs)),
                            children=[child]
                        )
                        node.children = [child]
                
                # Process child
                push_projections_down(child, child_needs)
        
        elif node.op_type == "join":
            # Join: split attributes between left and right
            if len(node.children) == 2:
                left_child, right_child = node.children
                
                # Split join condition attributes
                left_join_attrs, right_join_attrs = split_join_condition(node.condition)
                
                # Determine which attributes needed above come from which side
                # Strategy: 
                # 1. Attributes in join condition are already split
                # 2. For other attributes, check which subtree they appear in
                left_subtree_attrs = get_attributes_used_in_subtree(left_child)
                right_subtree_attrs = get_attributes_used_in_subtree(right_child)
                
                # Build sets of attributes needed from each side
                left_needs = left_join_attrs.copy()
                right_needs = right_join_attrs.copy()
                
                # Add attributes needed above
                for attr in all_needed:
                    if attr in left_join_attrs or attr in left_subtree_attrs:
                        left_needs.add(attr)
                    elif attr in right_join_attrs or attr in right_subtree_attrs:
                        right_needs.add(attr)
                    # If we can't determine, don't add to either (be conservative)
                
                # Add projections if needed
                if left_child.op_type != "project" or not left_child.attrs or set(left_child.attrs) != left_needs:
                    if left_child.op_type in ["relation", "select", "join", "product"]:
                        left_child = QueryNode(
                            op_type="project",
                            attrs=sorted(list(left_needs)),
                            children=[left_child]
                        )
                
                if right_child.op_type != "project" or not right_child.attrs or set(right_child.attrs) != right_needs:
                    if right_child.op_type in ["relation", "select", "join", "product"]:
                        right_child = QueryNode(
                            op_type="project",
                            attrs=sorted(list(right_needs)),
                            children=[right_child]
                        )
                
                node.children = [left_child, right_child]
                
                # Process children
                push_projections_down(left_child, left_needs)
                push_projections_down(right_child, right_needs)
        
        elif node.op_type == "product":
            # Product: similar to join but no join condition to split by
            if len(node.children) == 2:
                left_child, right_child = node.children
                
                # Try to determine which attributes come from which side
                left_subtree_attrs = get_attributes_used_in_subtree(left_child)
                right_subtree_attrs = get_attributes_used_in_subtree(right_child)
                
                left_needs = set()
                right_needs = set()
                
                # Split attributes based on which subtree they appear in
                for attr in all_needed:
                    if attr in left_subtree_attrs:
                        left_needs.add(attr)
                    elif attr in right_subtree_attrs:
                        right_needs.add(attr)
                    # If unknown, don't add (conservative)
                
                # Add projections if needed
                if left_needs and (left_child.op_type != "project" or not left_child.attrs or set(left_child.attrs) != left_needs):
                    if left_child.op_type in ["relation", "select", "join", "product"]:
                        left_child = QueryNode(
                            op_type="project",
                            attrs=sorted(list(left_needs)),
                            children=[left_child]
                        )
                
                if right_needs and (right_child.op_type != "project" or not right_child.attrs or set(right_child.attrs) != right_needs):
                    if right_child.op_type in ["relation", "select", "join", "product"]:
                        right_child = QueryNode(
                            op_type="project",
                            attrs=sorted(list(right_needs)),
                            children=[right_child]
                        )
                
                node.children = [left_child, right_child]
                
                push_projections_down(left_child, left_needs)
                push_projections_down(right_child, right_needs)
        
        elif node.op_type == "project":
            # Already a projection - process children with what this projection provides
            for child in node.children:
                push_projections_down(child, all_needed)
        
        elif node.op_type in ["groupby", "orderby"]:
            # Can't push past these, but can push to child
            if node.children:
                child = node.children[0]
                child_needs = all_needed
                
                if child.op_type != "project" or not child.attrs or set(child.attrs) != child_needs:
                    if child.op_type in ["relation", "select", "join", "product"]:
                        child = QueryNode(
                            op_type="project",
                            attrs=sorted(list(child_needs)),
                            children=[child]
                        )
                        node.children = [child]
                
                push_projections_down(child, child_needs)
        
        else:
            # Other node types - process children
            for child in node.children:
                push_projections_down(child, all_needed)
    
    # Start from root
    root_needs = set()
    if root.op_type == "project" and root.attrs:
        for attr in root.attrs:
            root_needs.add(attr.strip())
    
    # Push projections down
    push_projections_down(root, root_needs)
    
    return root


def optimize_query(root, parsed, alias_map):
    trees = []

    trees.append(("canonical", root.copy()))

    # Rule 1
    root = apply_rule1(root.copy())
    trees.append(("rule1", root.copy()))

    # Rule 2
    root = apply_rule2(root.copy(), alias_map)
    trees.append(("rule2", root.copy()))

    # Rule 3
    root = apply_rule3(root.copy(), alias_map)
    trees.append(("rule3", root.copy()))

    # Rule 4
    root = apply_rule4(root.copy(), alias_map)
    trees.append(("rule4", root.copy()))

    # Rule 5
    root = apply_rule5(root.copy(), parsed)
    trees.append(("rule5", root.copy()))

    return trees


def render_tree(node, graph=None, parent=None):
    if graph is None:
        graph = Digraph()
        graph.attr(randir='TB')
        graph.attr('node', shape='box')

    if node.op_type == "relation":
        label = node.relation
    elif node.op_type == "product":
        label = "x"
    elif node.op_type == "select":
        label = f"σ\n[{node.condition}]"
    elif node.op_type == "project":
        attrs_str = ", ".join(node.attrs)
        label = f"π\n{attrs_str}"
    elif node.op_type == "join":
        label = f"⋈\n[{node.condition}]"
    elif node.op_type == "groupby":
        label = f"GROUP BY\n{', '.join(node.attrs)}"
    elif node.op_type == "orderby":
        label = f"ORDER BY\n{', '.join(node.attrs)}"
    else:
        label = node.op_type
        if node.condition:
            label += f"\n[{node.condition}]"
        elif node.attrs:
            label += f"\n({', '.join(node.attrs)})"

    graph.node(str(id(node)), label)

    if parent:
        graph.edge(str(id(parent)), str(id(node)))

    for child in node.children:
        render_tree(child, graph, node)

    return graph


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python heuristic_query_optimizer.py <query_file>")
        sys.exit(1)
    query_file = sys.argv[1]
    with open(query_file, 'r') as file:
        content = file.read()

    # Find the start of the SQL query
    select_match = re.search(r'\bSELECT\b', content, flags=re.IGNORECASE)
    if select_match:
        query = content[select_match.start():].strip()
    else:
        query = content.strip()
        print("Warning: No SELECT statement found in file, using entire content")

    parsed = parse_query(query)
    alias_map = {t['alias']: t['table'] for t in parsed['from']}

    canonical_root = build_canonical_tree(parsed)

    trees = optimize_query(canonical_root, parsed, alias_map)

    # Render each tree
    for step_name, tree_root in trees:
        graph = render_tree(tree_root)
        output_path = f"outputs/{step_name}"
        graph.render(output_path, format='png')
        print(f"Generated {output_path}.png")
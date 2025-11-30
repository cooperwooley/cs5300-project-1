# src/rule3.py

import re
from tree_builder import QueryNode

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
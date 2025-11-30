# src/rule1.py

from tree_builder import QueryNode

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
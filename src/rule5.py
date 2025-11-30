# src/rule5.py 

import re
from tree_builder import QueryNode

def apply_rule5(root, parsed):
    def extract_attributes_from_condition(condition):
        attrs = set()
        if not condition:
            return attrs
        attr_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)?)\b'
        matches = re.findall(attr_pattern, condition)
        for match in matches:
            # skip obvious constants/numbers
            if not (match.startswith('"') or match.startswith("'") or re.match(r'^-?\d+\.?\d*$', match)):
                attrs.add(match.strip())
        return attrs

    def get_attributes_used_in_subtree(node):
        attrs = set()
        def collect(n):
            if n.op_type == "project" and n.attrs:
                for a in n.attrs:
                    attrs.add(a.strip())
            if n.op_type in ("select", "join") and getattr(n, "condition", None):
                attrs.update(extract_attributes_from_condition(n.condition))
            if n.op_type in ("orderby", "groupby") and getattr(n, "attrs", None):
                for a in n.attrs:
                    attrs.add(a.split()[0].strip())
            for c in n.children:
                collect(c)
        collect(node)
        return attrs

    def split_join_condition(condition):
        left_attrs = set()
        right_attrs = set()
        if not condition:
            return left_attrs, right_attrs
        parts = re.split(r'\s*(=|!=|<|>|<=|>=)\s*', condition, maxsplit=1)
        if len(parts) >= 3:
            left_expr, _, right_expr = parts
            left_attrs = extract_attributes_from_condition(left_expr)
            right_attrs = extract_attributes_from_condition(right_expr)
        return left_attrs, right_attrs

    def push_projections_down(node, attributes_needed_above):
        node_needs = set()

        if node.op_type == "project" and node.attrs:
            node_needs.update(a.strip() for a in node.attrs)
            attributes_needed_above = set(node.attrs)

        if node.op_type == "select" and getattr(node, "condition", None):
            node_needs.update(extract_attributes_from_condition(node.condition))

        if node.op_type == "join" and getattr(node, "condition", None):
            node_needs.update(extract_attributes_from_condition(node.condition))

        if node.op_type == "groupby" and getattr(node, "attrs", None):
            node_needs.update(a.strip() for a in node.attrs)

        if node.op_type == "orderby" and getattr(node, "attrs", None):
            for a in node.attrs:
                node_needs.add(a.split()[0].strip())

        # everything needed from children
        all_needed = attributes_needed_above | node_needs

        # Helper to decide whether to insert a projection for a child
        def maybe_project_child(child, needed_attrs):
            child_attrs_available = get_attributes_used_in_subtree(child)

            # If we can't determine any attributes from the child (empty set),
            # be conservative and DO NOT insert a projection (we don't know schema).
            if not child_attrs_available:
                return child, False

            # Attributes we can safely ask from this child are intersection:
            child_needs = set(needed_attrs) & child_attrs_available

            # If intersection is empty, don't project (nothing to push)
            if not child_needs:
                return child, False

            # If child is already a project with exact attrs, keep it
            if child.op_type == "project" and child.attrs and set(child.attrs) == child_needs:
                return child, False

            # Otherwise create a project node that requests exactly child_needs
            proj = QueryNode(
                op_type="project",
                attrs=sorted(list(child_needs)),
                children=[child]
            )
            return proj, True

        if node.op_type == "select":
            if node.children:
                child = node.children[0]
                # child needs to supply all attributes used above and used in select's condition
                child_needed = all_needed
                new_child, inserted = maybe_project_child(child, child_needed)
                if inserted:
                    node.children = [new_child]
                    child = new_child
                push_projections_down(child, child_needed)

        elif node.op_type == "join":
            if len(node.children) == 2:
                left_child, right_child = node.children
                left_join_attrs, right_join_attrs = split_join_condition(node.condition or "")

                # gather attributes that actually live in each subtree
                left_subtree_attrs = get_attributes_used_in_subtree(left_child)
                right_subtree_attrs = get_attributes_used_in_subtree(right_child)

                # decide needed attrs for each side conservatively
                left_needs = set(left_join_attrs)
                right_needs = set(right_join_attrs)

                for attr in all_needed:
                    if attr in left_subtree_attrs:
                        left_needs.add(attr)
                    elif attr in right_subtree_attrs:
                        right_needs.add(attr)
                    else:
                        left_needs.add(attr)
                        right_needs.add(attr)

                # try to insert project on left
                new_left, left_ins = maybe_project_child(left_child, left_needs)
                if left_ins:
                    left_child = new_left

                # try to insert project on right
                new_right, right_ins = maybe_project_child(right_child, right_needs)
                if right_ins:
                    right_child = new_right

                node.children = [left_child, right_child]

                # recurse
                push_projections_down(left_child, left_needs)
                push_projections_down(right_child, right_needs)

        elif node.op_type == "product":
            if len(node.children) == 2:
                left_child, right_child = node.children
                left_subtree_attrs = get_attributes_used_in_subtree(left_child)
                right_subtree_attrs = get_attributes_used_in_subtree(right_child)

                left_needs = set()
                right_needs = set()
                for attr in all_needed:
                    if attr in left_subtree_attrs:
                        left_needs.add(attr)
                    elif attr in right_subtree_attrs:
                        right_needs.add(attr)
                    else:
                        left_needs.add(attr)
                        right_needs.add(attr)

                new_left, left_ins = maybe_project_child(left_child, left_needs)
                if left_ins:
                    left_child = new_left

                new_right, right_ins = maybe_project_child(right_child, right_needs)
                if right_ins:
                    right_child = new_right

                node.children = [left_child, right_child]
                push_projections_down(left_child, left_needs)
                push_projections_down(right_child, right_needs)

        elif node.op_type == "project":
            for child in node.children:
                push_projections_down(child, set(node.attrs) if node.attrs else all_needed)

        elif node.op_type in ("groupby", "orderby"):
            if node.children:
                child = node.children[0]
                child_needed = all_needed
                new_child, inserted = maybe_project_child(child, child_needed)
                if inserted:
                    node.children = [new_child]
                    child = new_child
                push_projections_down(child, child_needed)

        else:
            # other nodes, just recurse with same required set
            for child in node.children:
                push_projections_down(child, all_needed)

    # start
    root_needs = set()
    if root.op_type == "project" and root.attrs:
        root_needs.update(a.strip() for a in root.attrs)

    push_projections_down(root, root_needs)
    return root
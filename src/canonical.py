# src/canonical.py

from tree_builder import QueryNode, build_from_nodes

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
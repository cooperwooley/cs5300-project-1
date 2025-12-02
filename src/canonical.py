# src/canonical.py

from tree_builder import QueryNode, build_from_nodes

def build_canonical_tree(parsed):
    from_clause = parsed['from']
    
    # Handle new format with joins
    if isinstance(from_clause, dict) and 'joins' in from_clause:
        # Build tree with explicit joins
        base_nodes = build_from_nodes(from_clause)
        
        if not base_nodes:
            raise ValueError("No tables found in FROM clause")
        
        # Start with first table
        root = base_nodes[0]
        
        # Build joins in order
        joins = from_clause.get('joins', [])
        for i, join_info in enumerate(joins):
            right_table = base_nodes[i + 1]
            
            # Create join node
            root = QueryNode(
                op_type="join",
                condition=join_info['condition'],
                join_type=join_info['type'],
                children=[root, right_table]
            )
        
        # If there are tables without explicit joins, make them products
        if len(base_nodes) > len(joins) + 1:
            for i in range(len(joins) + 1, len(base_nodes)):
                root = QueryNode(op_type="product", children=[root, base_nodes[i]])
    else:
        # Old format: comma-separated tables -> cartesian product
        base_nodes = build_from_nodes(from_clause)
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
        root = QueryNode('orderby', attrs=order_attrs, children=[root])

    return root
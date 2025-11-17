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


def optimize_query(root, parsed, alias_map):
    trees = []

    trees.append(("canonical", root.copy()))

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
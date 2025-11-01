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
        left_alias = pred['left'].split('.')[0]
        right_alias = pred['right'].split('.')[0] if '.' in pred['right'] else None

        if right_alias and right_alias in alias_map: # join condition
            joins.append(pred)
        else: # selection condition
            selections.setdefault(left_alias, []).append(pred)

    return selections, joins


def apply_selections(base_nodes, selections):
    new_nodes = []
    for node in base_nodes:
        alias = node.relation.split('(')[1].strip(')')
        if alias in selections:
            for pred in selections[alias]:
                node = QueryNode(
                    op_type="select",
                    condition=f"{pred['left']} {pred['op']} {pred['right']}",
                    children=[node]
                )
        new_nodes.append(node)
    return new_nodes


def combine_relations_with_joins(nodes, joins):
    if not joins:
        # Cartesian prduct of all tables
        while len(nodes) > 1:
            right = nodes.pop()
            left = nodes.pop()
            nodes.append(QueryNode(op_type="product", children=[left, right]))
        return nodes[0]
    else:
        # Apply each join
        current = nodes[0]
        for i in range(1, len(nodes)):
            right = nodes[i]
            cond = joins[i-1]
            join_cond = f"{cond['left']} {cond['op']} {cond['right']}"
            current = QueryNode(op_type='join', condition=join_cond, children=[current, right])
        return current


def build_higher_nodes(root, parsed):
    if 'group by' in parsed:
        root = QueryNode("groupby", attrs=parsed['group by'], children=[root])

    if 'select' in parsed:
        attrs = [a['expr'] for a in parsed['select']]
        root = QueryNode('project', attrs=attrs, children=[root])

    if 'order by' in parsed:
        order_attrs = [f"{a['attr']} {a['order']}" for a in parsed['order by']]
        root = QueryNode('orderby', attrs=order_attrs, children=[root])

    return root


def build_canonical_tree(parsed):
    base_nodes = build_from_nodes(parsed['from'])
    alias_map = {t['alias']: t['table'] for t in parsed['from']}

    selections, joins = classify_predicates(parsed.get('where', []), alias_map)
    selected_nodes = apply_selections(base_nodes, selections)
    root = combine_relations_with_joins(selected_nodes, joins)

    root = build_higher_nodes(root, parsed)

    return root


def render_tree(node, graph=None, parent=None):
    if graph is None:
        graph = Digraph()

    label = node.op_type
    if node.condition:
        label += f" [{node.condition}]"
    elif node.attrs:
        label += f" ({', '.join(node.attrs)})"
    elif node.relation:
        label += f" [{node.relation}]"

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
        query = file.read()

    parsed = parse_query(query)

    root = build_canonical_tree(parsed)

    graph = render_tree(root)
    graph.render('outputs/canonical_tree', format='png')
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


def rule3_estimate_selectivity(predicate, alias_map):
    # Estimate selectivity qualitatively
    pass


def apply_rule3(root, alias_map):
    # Reorder selections so most restrictive filters are applied earliest
    pass


def apply_rule4(root):
    # Combine cross-products followed by join conditions into a single join
    pass


def rule5_get_attributes_used(node, used_attrs):
    # Collect all atrributes used in the tree
    pass


def apply_rule5(root, parsed):
    # Apply projections early
    pass


def optimize_query(root, parsed, alias_map):
    trees = []

    trees.append(("canonical", root.copy()))

    # Rule 1
    root = apply_rule1(root.copy())
    trees.append(("rule1", root.copy()))

    # Rule 2
    root = apply_rule2(root.copy(), alias_map)
    trees.append(("rule2", root.copy()))

    # # Rule 3
    # root = apply_rule3(root.copy(), alias_map)
    # trees.append(("rule3", root.copy()))

    # # Rule 4
    # root = apply_rule4(root.copy())
    # trees.append(("rule4", root.copy()))

    # # Rule 5
    # root = apply_rule5(root.copy(), parsed)
    # trees.append(("rule5", root.copy()))

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
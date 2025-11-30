# src/main.py

import sys
import re
from graphviz import Digraph

from parse_query import parse_query
from canonical import build_canonical_tree
from rule1 import apply_rule1
from rule2 import apply_rule2
from rule3 import apply_rule3
from rule4 import apply_rule4
from rule5 import apply_rule5


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
        print("Usage: python3 src/main.py <query_file>")
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
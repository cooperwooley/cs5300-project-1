# src/tree_builder.py

class QueryNode:
    def __init__(self, op_type, condition=None, attrs=None, relation=None, children=None, join_type=None):
        self.op_type = op_type
        self.condition = condition # string condition
        self.attrs = attrs # list of attributes
        self.relation = relation # only for base tables
        self.children = children or [] # list of QueryNodes
        self.join_type = join_type # 'INNER', 'LEFT OUTER', 'RIGHT OUTER', 'FULL OUTER', None


    def __repr__(self):
        return f"{self.op_type({self. condition or self.attrs or self.relation})}"


    def copy(self):
        # Creates a deep copy of a node
        new_node = QueryNode(
            op_type = self.op_type,
            condition = self.condition,
            attrs = self.attrs.copy() if self.attrs else None,
            relation = self.relation,
            children = [child.copy() for child in self.children],
            join_type = self.join_type
        )
        return new_node


def build_from_nodes(from_clause):
    nodes = []
    # Handle both old format (list) and new format (dict with 'tables')
    tables = from_clause if isinstance(from_clause, list) else from_clause.get('tables', [])
    for table in tables:
        nodes.append(QueryNode(
            op_type="relation",
            relation=f"{table['table']} ({table['alias']})"
        )) 
    return nodes
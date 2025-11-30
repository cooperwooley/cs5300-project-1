# src/tree_builder.py

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
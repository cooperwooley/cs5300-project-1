# src/parse_query.py

import re


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
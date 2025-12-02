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
    joins = []

    # Check if uses JOIN syntax
    if re.search(r'\b(INNER|LEFT|RIGHT|FULL)\s+(OUTER\s+)?JOIN\b', from_str, re.IGNORECASE):

        # Split JOIN by keywords
        parts = re.split(r'\b((?:INNER|LEFT|RIGHT|FULL)\s+(?:OUTER\s+)?JOIN)\b', from_str, flags=re.IGNORECASE)

        # First part is the base table
        base_table_str = parts[0].strip()
        base_table = parse_table_reference(base_table_str)
        tables.append(base_table)

        # Process remaining JOIN clauses
        i = 1
        while i < len(parts):
            join_type_str = parts[i].strip()
            join_table_str = parts[i+1].strip() if i+1 < len(parts) else ""

            # Extract join type
            if 'FULL' in join_type_str.upper():
                join_type = 'FULL OUTER'
            elif 'RIGHT' in join_type_str.upper():
                join_type = 'RIGHT OUTER'
            elif 'LEFT' in join_type_str.upper():
                join_type = 'LEFT OUTER'
            elif 'INNER' in join_type_str.upper():
                join_type = 'INNER'
            else:
                join_type = 'INNER'

            # Parse the table and ON condition
            on_match = re.search(r'\bON\b(.*)', join_table_str, re.IGNORECASE)
            if on_match:
                table_part = join_table_str[:on_match.start()].strip()
                condition = on_match.group(1).strip()
                join_table = parse_table_reference(table_part)
                tables.append(join_table)
                joins.append({
                    'type': join_type,
                    'left_table': tables[-2]['alias'],
                    'right_table': join_table['alias'],
                    'condition': condition
                })

            i += 2
    else:
        for part in from_str.split(','):
            part = part.strip()
            tables.append(parse_table_reference(part))

    return {'tables': tables, 'joins': joins}


def parse_table_reference(table_str):
    # Parse a single table reference
    parts = table_str.split()
    if len(parts) == 1:
        return {'table': parts[0], 'alias': parts[0]}
    elif len(parts) == 2:
        return {'table': parts[0], 'alias': parts[1]}
    else:
        raise ValueError(f"Invalid table reference: {table_str}")


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
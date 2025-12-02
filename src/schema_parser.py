# src/schema_parser.py

import re

def parse_schema(content):
    # Parse schema definitions from input file
    schema = {}

    # Find schema section assuming "-- Schema Definitions --" is in the file and capture everything before query
    schema_match = re.search(r'-- Schema Definitions --(.*?)(?:-- SQL Query --|\bSELECT\b)', content, re.DOTALL | re.IGNORECASE)
    if not schema_match:
        return schema

    schema_text = schema_match.group(1)

    # Pattern to match table definitions
    table_pattern = r'(\w+)\s*\(\s*(.*?)\s*\);'

    for match in re.finditer(table_pattern, schema_text, re.DOTALL):
        table_name = match.group(1)
        table_def = match.group(2)

        # Extract attrs
        lines = [line.strip() for line in table_def.split('\n') if line.strip()]
        attrs = []
        primary_key = []
        unique = []

        for line in lines:
            # Check for primary key
            pk_match = re.search(r'PRIMARY\s+KEY\s*\(([^)]+)\)', line, re.IGNORECASE)
            if pk_match:
                primary_key = [a.strip() for a in pk_match.group(1).split(',')]
                continue

            # Check for unique constraints
            unique_match = re.search(r'UNIQUE\s*\(([^)]+)\)', line, re.IGNORECASE)
            if unique_match:
                unique = [a.strip() for a in unique_match.group(1).split(',')]
                continue

            # Otherwise, its an attr
            if ',' in line:
                attrs.extend([a.strip() for a in line.split(',')])

        # Clean up attrs
        attrs = [a for a in attrs if a]

        schema[table_name] = {
            'attrs': attrs,
            'primary_key': primary_key,
            'unique': unique
        }

    return schema


def get_table_attrs(schema, table_name):
    # Get all attributes for a given table
    if table_name not in schema:
        return set()
    return set(schema[table_name]['attrs'])
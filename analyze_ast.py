import ast
import json
from collections import defaultdict

with open('app.py', 'r') as f:
    source = f.read()

tree = ast.parse(source)

routes = defaultdict(list)
models = []
functions = []
other = []

for node in tree.body:
    if isinstance(node, ast.ClassDef):
        models.append(node.name)
    elif isinstance(node, ast.FunctionDef):
        is_route = False
        route_path = None
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and getattr(dec.func, 'attr', '') == 'route':
                is_route = True
                route_path = dec.args[0].value
                break
        
        if is_route:
            category = route_path.strip('/').split('/')[0]
            if category == '': category = 'core'
            routes[category].append(node.name)
        else:
            functions.append(node.name)

print("Models:", models)
print("Functions:", functions)
print("Route Categories:", {k: len(v) for k, v in routes.items()})

import ast

def safe():
    user_input = input("Enter a number: ")
    # SAFE: use literal_eval for simple literals
    result = ast.literal_eval(user_input)

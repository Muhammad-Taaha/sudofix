import ast

def safe():
    user_input = input("Enter a number: ")
    result = ast.literal_eval(user_input)  # SAFE

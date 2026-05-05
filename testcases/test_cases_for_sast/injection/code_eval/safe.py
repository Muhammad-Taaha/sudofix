import ast
def safe():
    user_input = input("Enter a number: ")
    # Only literal evaluation, safe
    result = ast.literal_eval(user_input)

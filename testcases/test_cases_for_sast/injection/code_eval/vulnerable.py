def vulnerable():
    user_code = input("Enter Python expression: ")
    result = eval(user_code)  # DANGEROUS: arbitrary code execution
    print(result)

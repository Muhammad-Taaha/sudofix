def vulnerable():
    user_code = input("Enter Python expression: ")
    result = eval(user_code)  # DANGEROUS
    print(result)

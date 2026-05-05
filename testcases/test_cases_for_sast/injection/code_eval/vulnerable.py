def vulnerable():
    user_code = input("Enter expression: ")
    result = eval(user_code)  # DANGEROUS
    print(result)

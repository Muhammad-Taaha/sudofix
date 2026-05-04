# Assume Django or SQLAlchemy in a real test
def vulnerable(request):
    user_input = request.GET.get('name')
    # Dangerous raw query with string formatting
    results = MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = '" + user_input + "'")

# Assume Django Model
def vulnerable(request):
    user_input = request.GET.get('name')
    # Raw query with concatenation
    return MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = '" + user_input + "'")

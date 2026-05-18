def safe(request):
    user_input = request.GET.get('name')
    # Parameterized raw query
    return MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = %s", [user_input])

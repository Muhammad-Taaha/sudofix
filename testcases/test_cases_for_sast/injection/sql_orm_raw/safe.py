def safe(request):
    user_input = request.GET.get('name')
    # Safe: parameterized raw query
    results = MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = %s", [user_input])

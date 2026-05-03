from django.db import models

def safe(request):
    user_input = request.GET.get('name')
    # SAFE: parameterized raw query
    results = MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = %s", [user_input])

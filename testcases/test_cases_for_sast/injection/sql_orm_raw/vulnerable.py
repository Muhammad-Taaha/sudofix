from django.db import models

def vulnerable(request):
    user_input = request.GET.get('name')
    # DANGEROUS: Django raw query with concatenation
    results = MyModel.objects.raw("SELECT * FROM myapp_mymodel WHERE name = '" + user_input + "'")

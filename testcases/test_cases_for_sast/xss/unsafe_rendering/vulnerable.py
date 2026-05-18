from django.utils.safestring import mark_safe
def show(request):
    user_input = request.GET.get('data')
    return mark_safe(user_input)  # DANGEROUS

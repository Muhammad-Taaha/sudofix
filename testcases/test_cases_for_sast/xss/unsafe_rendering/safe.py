from django.utils.html import escape
def show(request):
    user_input = request.GET.get('data')
    return escape(user_input)  # SAFE

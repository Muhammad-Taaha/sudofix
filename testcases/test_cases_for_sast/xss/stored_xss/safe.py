from django.utils.html import escape
def add_comment(request):
    safe_text = escape(request.POST['comment'])
    comment = Comment(text=safe_text)
    comment.save()

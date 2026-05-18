from django.db import models
class Comment(models.Model):
    text = models.TextField()
def add_comment(request):
    comment = Comment(text=request.POST['comment'])  # DANGEROUS
    comment.save()

from django.contrib.auth.models import User
from django.db import models

class UserProfile(models.Model):
    user= models.ForeignKey(User, on_delete=models.CASCADE)
    leetcode = models.CharField(max_length=100)
    github = models.CharField(max_length=100)
    dateJoined = models.DateTimeField(auto_now_add=True)
    photo = models.ImageField(upload_to='./user',blank=True,null=True)
    bio = models.TextField(blank=True,null=True)
    def __str__(self):
        return f'{self.user.username}'

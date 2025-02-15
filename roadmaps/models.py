from django.contrib.auth.models import User
from django.db import models

# Create your models here.
class RoadMaps(models.Model):
    name = models.CharField(max_length=20)
    desc = models.TextField()
class Progress(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    RoadMap = models.ForeignKey(RoadMaps,on_delete=models.CASCADE)
    level = models.IntegerField(default=0)
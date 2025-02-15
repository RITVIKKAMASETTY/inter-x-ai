from datetime import timezone
from enum import UNIQUE

from django.contrib.auth.models import User
from django.db import models

class organization(models.Model):
    org = models.ForeignKey(User, on_delete=models.CASCADE)
    orgname = models.CharField(max_length=100)
    address = models.TextField()
    photo = models.ImageField(upload_to='./orgs',null=True,blank=True)
    Description = models.TextField()
    def __str__(self):
        return self.orgname
class Custominterviews(models.Model):
    org = models.ForeignKey(organization,on_delete=models.CASCADE)
    desc = models.TextField()
    post = models.TextField()
    experience = models.CharField(max_length=10)
    submissionDeadline = models.DateTimeField()
    questions = models.TextField()
    startTime = models.DateTimeField()
    endTime = models.DateTimeField()
    DSA = models.IntegerField(blank=True,null=True)
    Dev = models.IntegerField(blank=True,null=True)

    def __str__(self):
        return f'{self.org.orgname}-{self.post}'
class Application(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    interview = models.ForeignKey(Custominterviews, on_delete=models.CASCADE)
    approved = models.BooleanField(default=False)
    resume = models.FileField(upload_to='./resume',blank=True,null=True)
    attempted = models.BooleanField(default=False)
    isCheated = models.BooleanField(default=False)
    extratedResume = models.TextField(blank=True,null=True)
    virtualResume = models.TextField(blank=True,null=True)
    standardized_resume = models.FileField(upload_to='std_resumes/',blank=True,null=True)
    score = models.IntegerField(default=0)
    def __str__(self):
        return f'{self.user.username}-{self.interview.org.orgname}'
class Customconversation(models.Model):
    Application = models.ForeignKey(Application, on_delete=models.CASCADE)
    time = models.DateTimeField(auto_now_add=True)
    confidence = models.IntegerField(blank=True,null=True)
    def __str__(self):
        return f'{self.Application.user.username}-{self.Application.interview.org.orgname}'
class Customquestions(models.Model):
    convo = models.ForeignKey(Customconversation, on_delete=models.CASCADE, db_index=True, default=1)
    user = models.CharField(max_length=100, default="user")
    question = models.TextField(default="Default question text")
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f'{self.convo.Application.user.username}-{self.id}'
class postings(models.Model):
    org = models.ForeignKey(organization, on_delete=models.CASCADE)
    desc = models.TextField()
    post = models.TextField()
    experience = models.CharField(max_length=10)
    deadline = models.DateTimeField()
    def __str__(self):
        return f'{self.org.orgname}-{self.post}'
class leaderBoard(models.Model):
    Application = models.ForeignKey(Application, on_delete=models.CASCADE)
    Score = models.DecimalField(max_digits=10,decimal_places=2)

    def __str__(self):
        return f'{self.Application.user.username}-{self.Score}'

class resumeconvo(models.Model):
    Application = models.ForeignKey(Application,on_delete=models.CASCADE)
    time = models.DateTimeField(auto_now_add=True)
class resquestions(models.Model):
    convo = models.ForeignKey(resumeconvo, on_delete=models.CASCADE, db_index=True, default=1)
    user = models.CharField(max_length=100, default="user")
    question = models.TextField(default="Default question text")
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f'{self.convo.Application.user.username}-{self.id}'
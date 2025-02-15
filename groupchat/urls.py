
from django.urls import path, include

from . import views

urlpatterns = [


    path('', views.public_chat,name='gc'),
    path('create/',views.createGroup,name='create_group')
]

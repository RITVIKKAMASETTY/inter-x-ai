from django.urls import path, include

from . import views

urlpatterns = [

    path('', views.index, name='ats'),
    path('analyze_resume/', views.analyze_resume, name='analyze_resume'),
]

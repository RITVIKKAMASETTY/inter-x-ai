from django.urls import path
from . import views

urlpatterns = [
    path('', views.maps, name='roadmaps'),
    path('roadmaps/<int:roadmap_id>/', views.roadmap_detail, name='roadmap_detail'),
    path('update-progress/', views.update_progress, name='update_progress'),
]
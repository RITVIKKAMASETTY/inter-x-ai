from django.urls import path, include

from . import views
from .views import apply_interview

urlpatterns = [

    path('postings/', views.getpostings,name= 'postings'),
    path('login', views.orglogin_view,name='complogin'),
    path('verify-email/', views.verify_email, name='compverify_email'),
    path('resend-code/', views.resend_code, name='compresend_code'),
    path('logout/', views.logoutView, name='complogout'),
    path('forgot-password/', views.forgot_password, name='compforgot_password'),
    path('verify-reset-code/', views.verify_reset_code, name='compverify_reset_code'),
    path('reset-password/', views.reset_password, name='compreset_password'),
    path('resend-reset-code/', views.resend_reset_code, name='compresend_reset_code'),
    path('createposting/',views.create_posting,name='createposting'),
    path('createinterview/',views.create_custom_interview,name='createcustominterview'),
    path('attempted/',views.Attempted,name='attempted'),
    path('cheated/',views.Cheated,name='cheated'),
    path('chat_create-<int:applicationid>', views.compchatcreate, name='compchatcreate'),
    path('chat-<str:convoid>/', views.compchat, name='compchat'),
    path('evaluate-<application_id>/',views.evaluate_interview,name='evaluate'),
    path('interviews/', views.available_interviews, name='available_interviews'),
    path('company/interviews/', views.company_interviews, name='company_interviews'),
    path('company/interviews/<int:interview_id>/applications/', views.company_applications,name='company_applications'),
    path('company/applications/approve/<int:application_id>/', views.approve_application, name='approve_application'),
    path('leaderboard/<int:interview_id>/', views.leaderboard_view, name='leaderboard'),
    path('edit',views.editCompanyProfile,name='editcompany'),
    path('compdash/',views.companyDashboard,name='compdash'),
    path('apply/<int:interview_id>/', apply_interview, name='apply_interview'),
    path('chat-history/<int:application_id>/', views.chat_history_view, name='chat_history'),

    # path('video_feed/', views.video_feed, name='video_feed'),
    # path('toggle_camera/', views.toggle_camera, name='toggle_camera'),
    # path('end_meeting/', views.end_meeting, name='end_meeting'),
    # path('confidence_scores/', views.get_confidence_scores, name='confidence_scores'),
]
from django.urls import path
from django.contrib.auth import views as auth_views
from django.views.generic import TemplateView
from . import views

urlpatterns = [
    path('login/', views.StepUpLoginView.as_view(template_name="account/login.html"), name="login"),
    path('logout/', auth_views.LogoutView.as_view(template_name="account/loggedout.html"), name='logout'),
    path('step-up-otp/', views.StepUpOTPView.as_view(), name='step-up-otp'),
    path('register/', views.signup, name='signup'),
    path('password/', views.change_password, name='account/change_password'),
    path('profile/', views.update_profile, name='profile'),
    path('update-security-question/', views.update_security_question, name='update-security-question'),
    path('addfile/', views.UploadCreate.as_view(), name='add-files'),
    path('contact/', views.ContactView.as_view(), name='contact-form-add'),
    path('filelist/', views.FileListView.as_view(), name='file-list'),
    path('deletefile/<pk>', views.FileDelete.as_view(), name='delete-file'),
    path('downloadfile/<pk>', views.DownloadFile.as_view(), name='download-file'),
    path('activity-log/', views.ActivityLogListView.as_view(), name='activity-log'),
    path('anomaly-dashboard/', views.anomaly_dashboard, name='anomaly-dashboard'),
    path('filetransfer_list/', views.TransferListView.as_view(), name='filetransfer-list'),
    path('filetransfer/', views.TransferFileCreate.as_view(), name='filetransfer'),
    path('chat/', views.ChatCreateListView.as_view(), name='chat'),
    path('deletechat/', views.delete_chat, name='deletechat'),
    path('ecc-keys/', views.ecc_key_view, name='ecc-keys'),
    path('overview/', views.overview, name='overview'),
    path('', views.home, name='home'),
    path('thanks/', TemplateView.as_view(template_name='thanks.html'), name='thanks'),
]
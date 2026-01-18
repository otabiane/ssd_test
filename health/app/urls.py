"""health URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from app import views
from logs import views as logView

urlpatterns = [
    # core
    path('', views.home, name='index'),

    # auth
    path('get_entry', views.get_entry, name='get_entry'),
    path('generate_challenge', views.generate_challenge, name='generate_challenge'),
    path('verify', views.verify, name='verify'),
    path('validate_otp', views.validate_otp, name='validate_otp'),
    path('logout', views.signout, name='logout'),
    path('forgot_password',views.forgot_password, name='forgot_password'),
    path('change_psw', views.change_psw, name='change_psw'),
    path('get_public_key', views.get_public_key, name='get_public_key'),
    path('get_current_user_data', views.get_current_user_data, name='get_current_user_data'),
    path('initiate_email_change', views.initiate_email_change, name='initiate_email_change'),
    path('verify_email_change', views.verify_email_change, name='verify_email_change'), 
    path('change_profile', views.change_profile, name='change_profile'),   
    path('dashboard', views.dashboard, name='dashboard'),
    path('settings', views.setting, name='profile'),
    path('notifications/', views.notifications, name='notification'),
    path('shared_dashboard',views.render_shared,name='shared_dashboard'),

    # MANAGE
    path('upload_files', views.upload_files, name='upload_files'),
    path('upload_files_doctor', views.upload_files_doctor, name='upload_files_doctor'),
    path('save_folder', views.save_folder, name='save_folder'),
    path('delete', views.delete_file, name='delete'),
    path('delete_file_doctor', views.delete_file_doctor, name='delete_file_doctor'),
    path('delete_folder',views.delete_folder, name='delete_folder'),
    path('delete_file_version', views.delete_file_version, name='delete_file_version'),

    # providers
    path('file_provider/', views.file_provider, name='file_provider'),
    path('folder_provider/',views.folder_provider, name='folder_provider'),
    path('shared_file_provider/',views.shared_file_provider,name='shared_file_provider'),
    path('shared_folder_provider/',views.shared_folder_provider,name='shared_folder_provider'),
    path('get_folder_metadata',views.get_folder_metadata,name='get_folder_metadata'),
    path('get_file_version',views.get_file_version,name='get_file_version'),

    # download
    path('file_download',views.file_download, name='file_download'),

    # sharing
    path('list_doctors', views.list_doctors, name='list_doctors'),
    path('get_shared',views.get_shared,name='get_shared'),
    path('check_share',views.check_share,name='check_share'),
    path('revoke_share',views.revoke_share,name="revoke_share"),

    # notifications
    path('mark_notification_read', views.mark_notification_read, name='mark_notification_read'),
    path('delete_notification', views.delete_notification, name='delete_notification'),

    # vault
    path('auth_vault', views.auth_vault, name='auth_vault'),
    path('vault', views.vault, name='vault'),

    # other
    path('audit_system', logView.integrity_check, name='audit_system')
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

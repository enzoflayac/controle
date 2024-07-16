from django.urls import path
from django.contrib.auth import views as auth_views
from .views import (CustomPasswordResetView, CustomPasswordResetDoneView,
                    CustomPasswordResetConfirmView, CustomPasswordResetCompleteView)
from . import views
from users.views import user_list

urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login_view'),
    path('logout/', views.logout_view, name='logout'),
    path('reset_password/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('reset_password/confirm/<uidb64>/<token>/', CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset_password/complete/', CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),
    path('reset_password/password_reset_done', CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('users/', user_list, name='user_list'),
    path('upload/<int:user_id>/', views.upload_page, name='upload_page'),
    path('delete_file/<int:user_id>/<path:file_name>/', views.delete_file, name='delete_file'),  # Mise à jour pour utiliser file_name
    path('download/<path:file_path>/', views.download, name='download'),
]
from django.urls import path

from user import views


app_name = 'user'

urlpatterns = [
    path('create/', views.CreateUserView.as_view(), name="create"),
    path('token/', views.CreateTokenView.as_view(), name="token"),
    path('me/', views.ManageUserView.as_view(), name="me"),
    path('email_verify/', views.VerifyEmailView.as_view(), name="email_verify"),
    path('reset_password/', views.ResetPasswordView.as_view(), name="reset_password"),
    path('password-reset/<uidb64>/<token>/',views.PasswordTokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete', views.SetNewPasswordAPIView.as_view(), name='password-reset-complete'),
]

from django.urls import path
from .views import UserRegistrationView,UserLoginView,GetAllUserView,ChangePasswordView,GenerateOTPView,ForgotPasswordView,DeleteUserView,UpdateUserView,GetUserProfile,BlackListTokenView,UserProfileView
from accounts import views
from rest_framework.urlpatterns import format_suffix_patterns

from rest_framework_simplejwt.views import TokenRefreshView
urlpatterns = [
    
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('getalluser/',GetAllUserView.as_view(),name='display'),
    path('changepassword/<int:pk>/', ChangePasswordView.as_view(), name='change_password'), 
    path('generateotp/', GenerateOTPView.as_view(), name='generateotp'),
    path('forgotpassword/', ForgotPasswordView.as_view(), name='forgotpassword'),
    path('deleteuser/<int:pk>/', DeleteUserView.as_view(), name='deleteuser'),
    path('updateuser/<int:pk>/',UpdateUserView.as_view(),name='updateuser'),
    path('profile/<int:pk>/',GetUserProfile.as_view(),name='profile'),
    path('tokenverify/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logout/', BlackListTokenView.as_view(), name='logout'),
    path('me/',UserProfileView.as_view(),name='me'),
    # path('filter/', ValidateUsers.as_view(), name='validate_users'),
    # path('generateotpupdate/', GenerateOtpForUpdate.as_view(), name='generateotpforupdate'),

    





    #path('logout/',BlacklistRefreshView.as_view(), name="logout"),



]
#urlpatterns = format_suffix_patterns(urlpatterns)


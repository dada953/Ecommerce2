import uuid
from django.shortcuts import render
from rest_framework import generics
from django.contrib.auth import get_user_model
from rest_framework import generics, status
from rest_framework.response import Response
from django.http import Http404
from rest_framework.filters import SearchFilter
from django_filters.rest_framework import DjangoFilterBackend
import django_filters.rest_framework
from rest_framework import filters
#from rest_framework.authentication import BaseAuthentication
#from .utils import generate_otp, send_otp_email
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
import random,re
import datetime
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from accounts.serializers import UserRegistrationSerializer,UserLoginSerializer,UserTokenSerializer,GetAllUserSerializer,serializers,ChangePasswordSerializer,ForgotPasswordSerilizer,CustomUserSerializerUpdate,CustomUserSerializerUpdateEmail
from rest_framework_simplejwt.tokens import RefreshToken
from .models import CustomUser,CustomUserLogs
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

# Create your views here.
class UserRegistrationView(generics.CreateAPIView):
    
    
    queryset = CustomUser.objects.all()
    serializer_class = UserRegistrationSerializer
    

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # code to save email and password of user.id
        #    serializer = self.get_serializer(data=request.data)
        #     serializer.is_valid(raise_exception=True)
        #     user2 = serializer.save()
        #     user3 = customeuser.object.get(id=user.id)
        #     user3.delete() 

        return Response({
            "user": UserRegistrationSerializer(user, context=self.get_serializer_context()).data,
            "message": "User created successfully. Now perform Login to get your token",
            "status":"Sucess",
        }, status=status.HTTP_201_CREATED)
    
class UserLoginView(APIView):
    serializer_class = UserLoginSerializer
    
    #authentication_classes=[BaseAuthentication]
   # permission_classes=[IsAuthenticated]

    def post(self, request, *args, **kwargs):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data
        refresh = RefreshToken.for_user(user)
        token_serializer = UserTokenSerializer(data={
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        })
        token_serializer.is_valid()
        return Response(token_serializer.data, status=status.HTTP_200_OK)
    
class GetAllUserView(generics.ListAPIView):
   # queryset=CustomUser.objects.all()
    queryset = CustomUser.objects.all()
    serializer_class = GetAllUserSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['^first_name', 'email']

class ChangePasswordView(generics.GenericAPIView):
    serializer_class = ChangePasswordSerializer
    


    def put(self, request, pk):
        password = request.data['password']
       # print(password)
       

        
        new_password = request.data['new_password']
        confirm_new_password = request.data['confirm_new_password']

        #print(password,new_password,email)
        obj = get_user_model().objects.get(id=pk)
        try:
            validate_password(password=new_password,user=obj)
        except ValidationError as err:
            raise serializers.ValidationError({'password':err.error_list})
        if not obj.check_password(raw_password=password):
            return Response({'error': 'old password not match'}, status=400)
        else:
            if new_password==confirm_new_password:
                obj.set_password(new_password)
                obj.save()
                return Response({'success': 'password changed successfully'}, status=200)
            raise serializers.ValidationError({"password": "Password fields didn't match."})

class GenerateOTPView(APIView):
    permission_classes=[]
    #print(emailotp)
    def post(self, request):
        email = request.data.get('email', '')
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)
        emailotp = random.randint(1000,10000)
        uid=uuid.uuid4()
        CustomUserLogs.objects.create(useremail=email,otp=emailotp,uid=uid)

        # user.otp = self.emailotp
        # user.save()
        print(emailotp,uid)
        def send_otp_email(email, otp):
            subject = 'Your OTP for Login'
            message = f'Your OTP is: {otp}'

            from_email = settings.EMAIL_HOST_USER
            recipient_list = [email]
            send_mail(subject, message, from_email, recipient_list)
            
        send_otp_email(email, emailotp)
        # send_otp_phone(phone_number, otp)

        return Response({'uuid':uid,'message': 'OTP has been sent to your email.'}, status=status.HTTP_200_OK)

class ForgotPasswordView(APIView):
    serilizer=ForgotPasswordSerilizer
    def put(self, request):
        email = request.data.get('email', '')
        otp = request.data.get('otp', '')
        new_password1=request.data.get('new_password1')
        new_password2=request.data.get('new_password2')
        uuid = request.data.get('uuid', '')

        
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)
        try:
            validate_password(password=new_password1,user=user)
        except ValidationError as err:
            raise serializers.ValidationError({'password':err.error_list})
        
        # objLoginWithotp=GenerateOTPView
        # emailotp=str(objLoginWithotp.emailotp)
        # email = request.data.get('email', '')
        # print(emailotp,otp,type(emailotp),type(otp))
        userlog = CustomUserLogs.objects.get(uid=uuid)
        #print(otp,userlog.otp,type(otp),type(userlog))
        print(type(userlog.uid),type(uuid))
        # if otp==userlog.otp and timezone.now()<userlog.password_changed_date+datetime.timedelta(minutes=1) and userlog.uid==uuid:
        if otp==userlog.otp  and userlog.uid==uuid:
        
            if new_password1==new_password2:
                user.set_password(new_password1)
                user.save()
                
                #CustomUserLogs.objects.create(useremail=email,otp=emailotp)
               # CustomUserLogs.objects.create(otp=emailotp)
                return Response({'sucessfuly changed':'corret otp'},status=status.HTTP_201_CREATED)
            return Response({'error':'password does not match'})
        else:
            return Response({'error':'incorrect otp'})

class DeleteUserView(APIView):
    """
    Retrieve, update or delete a snippet instance.
    """
    def get_object(self, pk):
        try:
            return CustomUser.objects.get(pk=pk)
        except CustomUser.DoesNotExist:
            raise Http404

   

    def delete(self, request, pk, format=None):
        snippet = self.get_object(pk)
        snippet.is_active=False
        snippet.save()
        
        serializer = UserRegistrationSerializer(snippet)
        #snippet.delete()
        return Response(data={'data':serializer.data,'message':'data deleted Successfully.','status':'Success'},status=status.HTTP_204_NO_CONTENT)

class UpdateUserView(APIView):#generic api view
   # queryset = CustomUser.objects.all()
   # serializer_class = CustomUserSerializerUpdate
   # lookup_field='email'
    def put(self, request, pk):
        email = request.data.get('email', '')
        
        
        # try:
        #     user = CustomUser.objects.get(email=email)
        # except CustomUser.DoesNotExist:
        #     return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_404_NOT_FOUND)
        user=CustomUser.objects.get(id=pk)
        if user.email==email:
            serializer=CustomUserSerializerUpdate(user,data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            otp = request.data.get('otp', '')

            userlog = CustomUserLogs.objects.last()

            if otp==userlog.otp and timezone.now()<userlog.password_changed_date+datetime.timedelta(seconds=55):
                serializer=CustomUserSerializerUpdate(user,data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'otp':'otp doesnt match'})
            


class GetUserProfile(APIView):
    def get_object(self, pk):
        try:
            return CustomUser.objects.get(id=pk)
        except CustomUser.DoesNotExist:
            raise Http404

    def get(self, request, pk, format=None):
        snippet = self.get_object(pk)
        serializer = UserRegistrationSerializer(snippet)
        return Response(serializer.data)


class BlackListTokenView(APIView):
    

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "Token blacklisted successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            
            
            "email": user.email,
            "address":user.address,
            "first_name":user.first_name,
            "last_name":user.last_name,
            "gender":user.gender,
            "mobileno":user.mobileno
        })
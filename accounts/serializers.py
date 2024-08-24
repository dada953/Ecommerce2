from rest_framework import serializers
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate  # Assuming it's from Django
from .models import CustomUser,CustomUserLogs
from rest_framework.response import Response
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import re
User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ['first_name','last_name','email','mobileno','address','gender','image','password','confirm_password']
    def validate_first_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("First name must contain only letters")
        return value
    def validate_last_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("Last name must contain only letters")
        return value
    def validate_mobileno(self, value):
        if not value.isdigit():
            raise serializers.ValidationError("Mobile no must be 10 digits")
        return value
    def validate_email(self, value):
        temp=re.findall('([A-Z])', value)
        if len(temp)>0:
            raise serializers.ValidationError("Email must be in lower case")
        return value


    def create(self, validated_data):
        # gender=validated_data['gender'],
        # first_name=validated_data['first_name'],
        # print(first_name)
        # print(gender)
        
        if validated_data['password']==validated_data['confirm_password']:
            user = CustomUser(
                first_name=validated_data['first_name'],
                last_name=validated_data['last_name'],
               # username=validated_data['username'],
                email=validated_data['email'],
                mobileno=validated_data['mobileno'],
                address=validated_data['address'],
                gender=validated_data['gender'],
                
                image=validated_data['image'],



            )
            
            user.set_password(validated_data['password'])
            try:
                validate_password(password=validated_data['password'],user=user)
            except ValidationError as err:
                raise serializers.ValidationError({'password':err.error_list})
            
            user.save()
            
            return user
        raise serializers.ValidationError({"password": "Password fields didn't match."})
class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    def validate(self, data):
        email=data['email']
        password=data['password']
        user = authenticate(email=email,password=password)
        print(user)
        if user and user.is_active:
            return user
        raise serializers.ValidationError("Invalid credentials")

class UserTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField()

class GetAllUserSerializer(serializers.ModelSerializer):
      class Meta:
        model = CustomUser
        exclude=('password','last_login','is_superuser','is_staff','is_active','groups','user_permissions')

class ChangePasswordSerializer(serializers.Serializer):
   # password = serializers.CharField(required=True)
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)
    class Meta:
  
        
        fields = ['password','new_password','confirm_new_password']


class ForgotPasswordSerilizer(serializers.ModelSerializer):
    new_password1 = serializers.CharField(required=True)
    new_password2 = serializers.CharField(required=True)
    uuid=serializers.UUIDField()

    class Meta:
         model=CustomUser
         fields=['otp','new_password1','new_password2','uuid']

class CustomUserSerializerUpdate(serializers.ModelSerializer):
   # otp=serializers.CharField(write_only=True)
    class Meta:
        model=CustomUser
        fields = ['email','first_name','last_name']

class CustomUserSerializerUpdateEmail(serializers.ModelSerializer):
    otp=serializers.CharField(write_only=True)
    class Meta:
        model=CustomUser
        fields = ['otp']



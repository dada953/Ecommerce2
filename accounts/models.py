from django.db import models

# Create your models here.
# myapp/models.py
from django.contrib.auth.models import AbstractUser
#from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.validators import RegexValidator


from django.db import models

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)
# class CustomUserManager(BaseUserManager):   

#     def create_superuser(self, email, password=None, **extra_fields):
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_superuser', True)
     
class CustomUser(AbstractUser):
    username=None
    GENDER_CHOICES = (
        ('Male', 'Male'),
        ('Female', 'Female'),
    )
    
    first_name=models.CharField(max_length=15)
    last_name=models.CharField(max_length=15)
    #password=models.CharField(max_length=15)
    mobileno=models.CharField(max_length=10,validators=[RegexValidator(regex=r"^\d{10}", message="Phone number must be 10 digits only.")])
    email=models.EmailField(unique=True)
    gender = models.CharField(null=True,choices=GENDER_CHOICES,max_length=6)
    address=models.CharField(max_length=200)
    image=models.ImageField(upload_to="image1")
    #confirm_password=models.CharField(max_length=20)
    #otp = models.CharField(max_length=6, null=True, blank=True)  # Add the otp field here

    USERNAME_FIELD='email'
    REQUIRED_FIELDS=[]
    objects = CustomUserManager()


class CustomUserLogs(models.Model):
    useremail=models.EmailField(unique=False)
    otp = models.CharField(max_length=6, null=True, blank=True)  # Add the otp field here=
    password_changed_date=models.DateTimeField(auto_now_add=True)
    uid=models.CharField(max_length=300,default="khskfhskfhfh")
# def set_otp(self):
#         self.otp = str(random.randint(100000, 999999))
#         self.otp_created_at = timezone.now()  # Use timezone-aware datetime
#         self.save()
        
#         return self.otp
      
#     def is_otp_valid(self, otp):
#         if self.otp == otp and timezone.now() < self.otp_created_at + timedelta(minutes=5):
#             return True
#         return False
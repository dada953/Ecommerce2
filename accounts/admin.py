from django.contrib import admin

from .models import CustomUser
# Register your models here.
class MemberAdmin(admin.ModelAdmin):
    list_display=('id','first_name','last_name','email','mobileno','address','gender','image',)

admin.site.register(CustomUser,MemberAdmin)
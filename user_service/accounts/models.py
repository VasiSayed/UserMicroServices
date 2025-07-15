from django.contrib.auth.models import AbstractUser
from django.db import models

USER_ROLE_CHOICES = (
    ('ADMIN', 'Admin'),
    ('Intializer','Intializer'),
    ('SUPERVISOR', 'Supervisor'),
    ('CHECKER', 'Checker'),
    ('MAKER', 'Maker'),
    # ('INSPECTOR', 'Inspector'),
)

class User(AbstractUser):
    phone_number = models.CharField(max_length=15, blank=True)
    has_access = models.BooleanField(default=True)
    is_client = models.BooleanField(default=False)
    is_manager=models.BooleanField(default=False)
    org=models.IntegerField(null=True,blank=True)
    company=models.IntegerField(null=True,blank=True)
    entity=models.IntegerField(null=True,blank=True)
    created_by = models.ForeignKey('self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='created_users'
    )

    def __str__(self):
        return self.username


class UserAccess(models.Model):
    user = models.ForeignKey('accounts.User', on_delete=models.CASCADE, related_name='accesses')
    project_id = models.IntegerField(null=True,blank=True) 
    building_id = models.IntegerField(null=True, blank=True)
    zone_id = models.IntegerField(null=True, blank=True)
    flat_id = models.IntegerField(null=True, blank=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    category=models.IntegerField(null=True,blank=True)

    CategoryLevel1=models.IntegerField(null=True,blank=True)
    CategoryLevel2=models.IntegerField(null=True,blank=True)
    CategoryLevel3=models.IntegerField(null=True,blank=True)
    CategoryLevel4=models.IntegerField(null=True,blank=True)
    CategoryLevel5=models.IntegerField(null=True,blank=True)
    CategoryLevel6=models.IntegerField(null=True,blank=True)


    def __str__(self):
        return f"{self.user.username} Access to Project {self.project_id}"


class UserAccessRole(models.Model):
    user_access = models.ForeignKey(UserAccess, on_delete=models.CASCADE, related_name='roles')
    role = models.CharField(max_length=50, choices=USER_ROLE_CHOICES)
    assigned_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user_access', 'role')

    # def __str__(self):
    #     return f"{self.user_access.user.username} - {self.get_role_display()} (Project {self.user_access.project_id})
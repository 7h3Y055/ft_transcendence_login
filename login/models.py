from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.conf import settings
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError
# Create your models here.

STATUS_CHOICES = (
    ('ON', 'online'),
    ('OF', 'offline'),
    ('IG', 'in-game'),
)

class PlayerManager(BaseUserManager):
    def create_user(self, username, email, **extra_fields):
        if not username or not email:
            return ValueError('Invalid username or email')
        email = self.normalize_email(email)
        validator = EmailValidator()
        try:
            validator(email)
        except ValidationError:
            raise ValueError('Invalid email address')
        user = self.model(
            username=username,
            email=email,
            **extra_fields)

        user.save(using=self._db)
        return user

class Player(AbstractBaseUser):
    id = models.AutoField(primary_key=True, db_index=True)
    username = models.CharField(max_length=60, unique=True)
    email = models.EmailField(null=True, max_length=255, unique=True)
    first_name = models.CharField(null=True, max_length=30)
    last_name = models.CharField(null=True, max_length=30)
    avatar_url = models.URLField(default=settings.DEFAULT_PROFILE_IMAGE)
    status = models.CharField(max_length=2, choices=STATUS_CHOICES, default='ON')
    two_FA = models.BooleanField(default=False)
    created_at = models.DateTimeField(null=True , auto_now_add=True)


    password = None
    last_login = None

    objects = PlayerManager()
    
    def __str__(self):
        return self.username
    
    USERNAME_FIELD = 'username'
    

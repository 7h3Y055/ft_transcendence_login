from rest_framework import serializers
from ..models import Player

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Player
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'avatar_url', 'status', 'two_FA', 'created_at']


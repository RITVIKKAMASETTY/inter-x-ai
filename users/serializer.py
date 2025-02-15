from rest_framework import serializers



class loginSearializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
class sendCode(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField()
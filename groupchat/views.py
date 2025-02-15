import json

from django.http import JsonResponse
from django.shortcuts import render

from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_201_CREATED

from .models import *
from django.contrib.auth.decorators import login_required

@login_required
def public_chat(request):

    rooms = chatGroup.objects.all()
    messages = Messages.objects.all().order_by('createdAt')

    return render(request, 'groupchat/gc.html', {
        'messages': messages,
        'rooms': rooms,  # Pass the list of usernames
    })


def createGroup(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            group_name = data.get('group')

            # Check if 'group' is provided and not empty
            if not group_name:
                return JsonResponse({"error": "Group name is required."}, status=400)

            if chatGroup.objects.filter(roomName=group_name).exists():
                return JsonResponse({"error": "A group with this name already exists."}, status=400)

            obj = chatGroup.objects.create(roomName=group_name)
            return JsonResponse({"message": "Group created successfully.", "group_id": obj.id}, status=201)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data."}, status=400)

    return JsonResponse({"error": "Only POST method is allowed."}, status=405)
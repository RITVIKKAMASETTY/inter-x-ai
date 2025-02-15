import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render, get_object_or_404
from django.views.decorators.csrf import csrf_exempt

from .models import *
# Create your views here.
def maps(request):
    maap = RoadMaps.objects.all()
    return render(request, 'roadmaps/map.html',{'map' : maap})
def roadmap_detail(request, roadmap_id):
    roadmap = get_object_or_404(RoadMaps, id=roadmap_id)
    progress, _ = Progress.objects.get_or_create(RoadMap=roadmap, user=request.user)
    return render(request, f'roadmaps/{roadmap.name}.html', {'roadmap': roadmap, 'level': progress.level})
@csrf_exempt
@login_required
def update_progress(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            topic_id = data.get('topic_id')
            roadmap_id = data.get('roadmap_id')

            if topic_id is None or roadmap_id is None:
                return JsonResponse({'error': 'Invalid request, missing topic ID or roadmap ID'}, status=400)

            # Fetch the progress object for the user and roadmap
            progress, created = Progress.objects.get_or_create(user=request.user, roadmap_id=roadmap_id)

            # Update level
            progress.level = topic_id  # Assuming topic_id represents the completion level
            progress.save()

            return JsonResponse({'message': 'Progress updated successfully', 'new_level': progress.level, 'roadmap_id': roadmap_id})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

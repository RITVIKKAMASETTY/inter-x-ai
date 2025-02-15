9
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from groq import Groq
from PyPDF2 import PdfReader

groq_api_key = "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"
client = Groq(
    api_key=  groq_api_key
)
@login_required()
def index(request):

    return render(request, "index.html")

def extract_text_from_pdf(pdf_file):

    try:
        pdf_reader = PdfReader(pdf_file)
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text() + "\n"
        return text.strip()
    except Exception:
        return None

@csrf_exempt
def analyze_resume(request):

    if request.method == "POST" and request.FILES.get("resume"):
        try:
            # Extract job role and company from request
            job_role = request.POST.get("job_role", "")
            company = request.POST.get("company", "")

            # Read uploaded PDF and extract text
            pdf_file = request.FILES["resume"]
            resume_text = extract_text_from_pdf(pdf_file)

            if not resume_text:
                return JsonResponse({"success": False, "error": "Unable to extract text from the uploaded resume."})

            # Prepare Groq request
            prompt = (
                f"Analyze the following resume for the job role '{job_role}' at the company '{company}'. "
                f"Provide a score out of 100, a brief description, and suggestions for improvement.\n\n"
                f"Resume Text:\n{resume_text}"
            )

            chat_completion = client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are an AI resume analysis assistant."},
                    {"role": "user", "content": prompt},
                ],
                model="llama-3.3-70b-versatile",
            )

            response_text = chat_completion.choices[0].message.content


            return JsonResponse(
                {
                    "success": True,
                    "data": response_text
                }
            )
        except Exception:
            return JsonResponse({"success": False, "error": "An error occurred during analysis."})

    return JsonResponse({"success": False, "error": "Invalid request"})

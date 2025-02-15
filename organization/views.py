import datetime
from users.models import *
import groq
import requests
from bs4 import BeautifulSoup

from datetime import datetime, timedelta
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

from .forms import *
from .utils import *
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.http import JsonResponse, HttpResponseForbidden
from django.utils import timezone
import json
from django.contrib import messages


def getpostings(request):
    jobs = postings.objects.all().order_by('-id')
    return render(request, 'organization/postings.html', {'jobs': jobs})


def verify_email(request):
    # Check if we have pending registration
    pending_user = request.session.get('pending_user')
    if not pending_user:
        return redirect('reg')

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            submitted_code = data.get('verification_code')
            stored_code = request.session.get('verification_code')
            code_generated_at = request.session.get('code_generated_at')

            current_time = timezone.now().timestamp()
            is_expired = (current_time - code_generated_at) > 30

            if stored_code and submitted_code == stored_code and not is_expired:
                # Create the user
                user = User.objects.create_user(
                    username=pending_user['username'],
                    email=pending_user['email'],
                    password=pending_user['password']
                )

                # Clean up session
                for key in ['pending_user', 'verification_code', 'code_generated_at']:
                    if key in request.session:
                        del request.session[key]

                # Authenticate and login the user
                authenticated_user = authenticate(
                    request,
                    username=pending_user['username'],
                    password=pending_user['password']
                )

                if authenticated_user is not None:
                    login(request, authenticated_user, backend='django.contrib.auth.backends.ModelBackend')
                    return JsonResponse({'success': True})
                else:
                    return JsonResponse({'success': False, 'error': 'Authentication failed'})
            else:
                error = 'Code expired' if is_expired else 'Invalid code'
                return JsonResponse({'success': False, 'error': error})

        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid request'})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})

    return render(request, 'users/verify_email.html')

def resend_code(request):
    if request.method == 'POST':
        pending_user = request.session.get('pending_user')
        if not pending_user:
            return JsonResponse({'success': False, 'error': 'No pending registration'})

        try:
            # Generate new code
            code = generate_verification_code()
            del request.session['verification_code']
            del request.session['code_generated_at']
            request.session['verification_code'] = code
            request.session['code_generated_at'] = timezone.now().timestamp()
            send_verification_email(pending_user['email'], code)
            return JsonResponse({'success': True})

        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})
def orglogin_view(request):
    if request.method == 'POST':
        # Extract data from the POST request
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Validate required fields
        if not all([username, password]):
            return render(request, 'organization/orglogin.html', {
                'error': 'Both username and password are required.'
            })

        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Check if the user belongs to an organization
            try:
                org = organization.objects.get(org=user)
                login(request, user)
                return redirect('home')  # Redirect to the home page or dashboard
            except organization.DoesNotExist:
                return render(request, 'organization/orglogin.html', {
                    'error': 'This user is not associated with any organization.'
                })
        else:
            # Invalid credentials
            return render(request, 'users/login.html', {
                'error': 'Invalid username or password.'
            })

    # Render the login form for GET requests
    return render(request, 'users/login.html')

def logoutView(request):
    logout(request)
    return redirect('login')

def forgot_password(request):
    if request.method == 'POST':
        username = request.POST.get('username')

        try:
            email = User.objects.get(username=username).email
            reset_code = generate_verification_code()
            request.session['reset_code'] = reset_code
            request.session['reset_email'] = email
            request.session['username'] = username
            request.session['code_generated_at'] = timezone.now().timestamp()

            # Send reset code email
            send_reset_code_email(email, reset_code)

            return redirect('verify_reset_code')

        except User.DoesNotExist:
            messages.error(request, 'No account found with this username.')

    return render(request, 'users/forgot_password.html')


def verify_reset_code(request):
    reset_email = request.session.get('reset_email')
    if not reset_email:
        return redirect('forgot_password')

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            submitted_code = data.get('verification_code')
            stored_code = request.session.get('reset_code')
            code_generated_at = request.session.get('code_generated_at')

            # Check if code is expired (30 seconds)
            current_time = timezone.now().timestamp()
            is_expired = (current_time - code_generated_at) > 30

            if stored_code and submitted_code == stored_code and not is_expired:
                request.session['reset_verified'] = True
                return JsonResponse({'success': True})
            else:
                error = 'Code expired' if is_expired else 'Invalid code'
                return JsonResponse({'success': False, 'error': error})

        except json.JSONDecodeError:
            return JsonResponse({'success': False, 'error': 'Invalid request'})

    return render(request, 'users/verify_reset_code.html')


def resend_reset_code(request):
    if request.method == 'POST':
        reset_email = request.session.get('reset_email')
        if not reset_email:
            return JsonResponse({'success': False, 'error': 'No pending reset request'})

        try:
            # Generate new code
            reset_code = send_reset_code_email()
            request.session['reset_code'] = reset_code
            request.session['code_generated_at'] = timezone.now().timestamp()

            # Send new code
            send_reset_code_email(reset_email, reset_code)
            return JsonResponse({'success': True})

        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})


def reset_password(request):
    if not request.session.get('reset_verified'):
        return redirect('forgot_password')

    if request.method == 'POST':
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'users/reset_password.html')

        if len(password1) < 8:
            messages.error(request, 'Password must be at least 8 characters long.')
            return render(request, 'users/reset_password.html')

        try:
            user = User.objects.get(username=request.session['username'])
            user.set_password(password1)
            user.save()

            # Clean up session
            for key in ['reset_email', 'reset_code', 'code_generated_at', 'reset_verified']:
                if key in request.session:
                    del request.session[key]

            messages.success(request, 'Password reset successful! Please login with your new password.')
            return redirect('login')

        except User.DoesNotExist:
            messages.error(request, 'An error occurred. Please try again.')

    return render(request, 'users/reset_password.html')
@login_required()
def create_posting(request):

    user_org = organization.objects.get(org=request.user)  # Get the user's organization


    if request.method == 'POST':
        form = postingsForm(request.POST)
        if form.is_valid():
            interview = form.save(commit=False)  # Don't save immediately
            interview.org = user_org  # Assign the organization
            interview.save()
            messages.success(request, 'Custom interview created successfully!')
            return redirect('compdash')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = postingsForm()

    return render(request, 'organization/createjobposting.html', {'form': form})
def create_custom_interview(request):
    user_org = organization.objects.get(org=request.user)  # Get the user's organization

    if request.method == 'POST':
        form = CustomInterviewsform(request.POST)
        if form.is_valid():
            interview = form.save(commit=False)  # Don't save immediately
            interview.org = user_org  # Assign the organization
            interview.save()
            messages.success(request, 'Custom interview created successfully!')
            return redirect('company_interviews')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = CustomInterviewsform()

    return render(request, 'organization/createcustominterview.html', {'form': form})


@login_required
@csrf_exempt
def Cheated(request):
    if request.method == 'POST':
        try:
            # Parse JSON data from request.body
            data = json.loads(request.body)
            application_id = data.get('id')

            if not application_id:
                return JsonResponse({'error': 'Application ID is required'}, status=400)

            try:
                application = Application.objects.get(id=application_id)

                # Check if user is authorized
                if request.user != application.user:
                    return JsonResponse({'error': 'Unauthorized'}, status=401)

                application.isCheated = True
                application.save()

                return JsonResponse({'success': True})

            except Application.DoesNotExist:
                return JsonResponse({'error': 'Application not found'}, status=404)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@login_required
def compchatcreate(request, applicationid):
    if Application.objects.get(id=applicationid) is None:
        messages.error(request,"Application Not found")
        return redirect('home')
    if not Application.objects.get(id=applicationid).approved :
        messages.error(request, "You are not approved")
        return redirect('home')
    cd = Application.objects.get(id=applicationid)
    cd.attempted = True
    cd.save()
    convo = Customconversation.objects.create(Application=Application.objects.get(id=applicationid))
    return redirect('compchat', convoid=convo.id)
@login_required
@csrf_exempt
def compchat(request, convoid):
    convo = get_object_or_404(Customconversation, id=convoid)

    if request.method == 'POST' and request.headers.get('Content-Type') == 'application/json':
        data = json.loads(request.body)
        user_response = data.get('response')
        if user_response:
            Customquestions.objects.create(convo=convo, question=user_response, user='user')
            questions_list = list(Customquestions.objects.filter(convo=convo).values_list('question', flat=True))

            ques = ques = convo.Application.interview.questions
            post_title = convo.Application.interview.post
            reply, next_question = llm(questions_list, convoid, user_response, post_title,ques)

            if reply:
                Customquestions.objects.create(convo=convo, question=reply, user='ai')
            if next_question:
                Customquestions.objects.create(convo=convo, question=next_question, user='ai')

            if "INTERVIEW_COMPLETE" in next_question:
                convo.Application.attempted = True
                convo.Application.completed = True
                convo.Application.save()
                messages.success(request,"You have successfully finished the interview")
                return redirect('home')

            return JsonResponse({
                "reply": reply,
                "next_question": next_question,
            })

        return JsonResponse({"error": "Invalid response"}, status=400)

    # Fetch all questions for this conversation
    questions_list = Customquestions.objects.filter(convo=convo)

    # Initialize with a default question if no questions exist
    if not questions_list.exists():
        first_question = "Welcome to the interview! Can you tell me about your experience in this field?"
        Customquestions.objects.create(convo=convo, question=first_question, user='ai')
        questions_list = Customquestions.objects.filter(convo=convo)
    is_cheated = convo.Application.isCheated
    return render(request, 'organization/i.html', {
        'convo': convo,
        'questions': questions_list,
        'applicationId': convo.Application.id,
        'is_cheated': is_cheated,

    })
    # Fetch all questions for this conversation
 

@login_required
def evaluate_interview(request, application_id):
    groq_client = groq.Groq(api_key="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")
    application = get_object_or_404(Application, id=application_id)
    application.completed = True
    if leaderBoard.objects.filter(Application=application).exists():
        messages.warning(request, 'This interview has already been evaluated.')
        return redirect('home')  # Replace 'home' with your home URL name
    # if application.isCheated:
    #     messages.warning(request, 'This interview has recorded malpractice.')
    #     return redirect('home')
    if not application.attempted:
        messages.warning(request, 'This interview has not been attempted.')
        return redirect('home')
    conversation = Customconversation.objects.filter(Application=application).first()
    interview = application.interview
    qa_pairs = Customquestions.objects.filter(convo=conversation).order_by('created_at')

    if not qa_pairs.exists():
        messages.error(request, 'No conversation found for evaluation.')
        return redirect('home')  # Replace 'home' with your home URL name

    # Extract questions and answers
    questions = []
    answers = []
    timestamps = []

    for i in range(0, len(qa_pairs), 2):  # Assuming alternating question-answer pairs
        if i + 1 < len(qa_pairs):  # Make sure we have both Q and A
            questions.append(qa_pairs[i].question)
            answers.append(qa_pairs[i + 1].question)  # Answer stored in question field
            timestamps.append((qa_pairs[i + 1].created_at - qa_pairs[i].created_at).total_seconds())

    try:
        # Initialize scores
        technical_scores = []

        # Evaluate each Q&A pair
        for q, a in zip(questions, answers):
            technical_score = evaluate_answer_quality(
                groq_client,
                q, a,
                f"Job Post: {interview.post}\nExperience Required: {interview.experience}\nDescription: {interview.desc}"
            )
            technical_scores.append(technical_score)
        # Evaluate corporate fit
        corporate_fit_score = evaluate_corporate_fit(
            groq_client,
            json.dumps(list(zip(questions, answers))),
            interview.desc
        )
        is_cheated = check_cheating(groq_client, json.dumps(list(zip(questions, answers))))
        technical_weight = 0.6  # 60% weight for technical evaluation
        corporate_fit_weight = 0.4  # 40% weight for corporate fit

        final_score = (
                (sum(technical_scores) / len(technical_scores) * technical_weight) +
                (corporate_fit_score * corporate_fit_weight)
        ) if technical_scores else 0

        application.attempted = True
        application.completed = True
        application.isCheated = is_cheated
        application.save()

        # Create leaderboard entry
        leaderBoard.objects.create(
            Application=application,
            Score=round(final_score, 2)
        )
        print("sucesss")
        messages.success(request, 'Interview evaluation completed successfully.')

    except Exception as e:
        print({str(e)})
        messages.error(request, f'Error during evaluation: {str(e)}')
        application.attempted = True
        application.completed = False
        application.save()
    return redirect('home')


@login_required
def Attempted(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        application_id = data.get('id')

        try:
            application = Application.objects.get(id=application_id)

            # Check if user is authorized
            if request.user != application.user:
                return JsonResponse({'error': 'Unauthorized'}, status=401)

            return JsonResponse({
                'isCheated': application.isCheated,
                'isCompleted': application.completed,
                'isAttempted': application.attempted
            })

        except Application.DoesNotExist:
            return JsonResponse({'error': 'Application not found'}, status=404)

    return JsonResponse({'error': 'Invalid request method'}, status=405)



@login_required
def available_interviews(request):
    current_time = timezone.now()
    # Get all interviews that haven't passed deadline
    interviews = Custominterviews.objects.filter(
        submissionDeadline__gt=current_time
    ).select_related('org')

    # Get user's applications
    user_applications = Application.objects.filter(
        user=request.user
    ).select_related('interview')

    # Create a dictionary with application status
    application_status = {}
    for application in user_applications:
        interview = application.interview
        can_start_interview = (
                application.approved and
                not application.attempted and
                interview.startTime <= current_time <= interview.endTime
        )

        application_status[application.interview_id] = {
            'resume_status': bool(application.resume),
            'is_approved': application.approved,
            'application_id': application.id,
            'can_start_interview': can_start_interview,
            'interview_start': interview.startTime,
            'interview_end': interview.endTime,
            'attempted': application.attempted
        }

    context = {
        'interviews': interviews,
        'application_status': application_status,
        'current_time': current_time,
    }
    return render(request, 'organization/available_interviews.html', context)

@login_required
def company_interviews(request):
    try:
        # Get the organization for current user
        org = organization.objects.get(org=request.user)

        # Get all interviews created by this organization
        interviews = Custominterviews.objects.filter(
            org=org
        ).order_by('-submissionDeadline')

        # Get application counts for each interview
        for interview in interviews:
            interview.application_count = Application.objects.filter(
                interview=interview
            ).count()

        return render(request, 'organization/company_interviews.html', {
            'interviews': interviews,
            'organization': org
        })
    except organization.DoesNotExist:
        messages.error(request, 'Unauthorized access. No organization profile found.')
        return redirect('home')


@login_required
def company_applications(request, interview_id):
    try:
        # Get the organization for current user
        org = organization.objects.get(org=request.user)

        # Get the specific interview and verify it belongs to this organization
        interview = get_object_or_404(Custominterviews, id=interview_id, org=org)

        # Get all applications for this interview
        applications = Application.objects.filter(
            interview=interview
        ).select_related('user')

        context = {
            'interview': interview,
            'applications': applications,
            'organization': org
        }

        return render(request, 'organization/company_applications.html', context)
    except organization.DoesNotExist:
        messages.error(request, 'Unauthorized access. No organization profile found.')
        return redirect('home')

@login_required
def approve_application(request, application_id):
    if request.method == 'POST':
        application = Application.objects.get(id=application_id)

        # Verify the user has permission to approve
        if request.user != application.interview.org.org:  # Modify based on your authorization logic
            messages.error(request, 'Unauthorized access.')
            return redirect('company_interviews')

        application.approved = True
        application.save()

        messages.success(request, f'Application approved for {application.user.username}')
        return redirect('company_applications',Application.objects.get(id=application_id).interview.id)

    return redirect('company_applications',Application.objects.get(id=application_id).interview.id)


@login_required
def leaderboard_view(request, interview_id):
    """View to show leaderboard for a specific interview"""
    try:
        org = organization.objects.get(org=request.user)
    except organization.DoesNotExist:
        return HttpResponseForbidden("Only company accounts can access the leaderboard")

    # Get the specific interview and verify it belongs to this organization
    interview = get_object_or_404(Custominterviews, id=interview_id, org=org)

    # Get leaderboard entries for this specific interview
    leaderboard_entries = leaderBoard.objects.filter(
        Application__interview=interview
    ).select_related(
        'Application__user',
        'Application__interview'
    ).order_by('-Score')

    context = {
        'leaderboard_entries': leaderboard_entries,
        'organization': org,
        'interview': interview
    }
    return render(request, 'organization/leaderboard.html', context)
@login_required(login_url='reg/')
def editCompanyProfile(request):
    user_profile= organization.objects.get(org=request.user)
    if user_profile is None:
        messages.error(request,'You are not an organization')
        return redirect('login')
    if request.method == 'POST':
        print("FILES:", request.FILES)  # Debug print
        form = EditCompanyForm(request.POST, request.FILES, instance=user_profile)
        if form.is_valid():
            profile = form.save(commit=False)
            profile.org = request.user

            if 'photo' in request.FILES:
                profile.photo = request.FILES['photo']

            profile.save()
            return redirect('home')
        else:
            print("Form errors:", form.errors)  # Debug print
    else:
        form = EditCompanyForm(instance=user_profile)

    # Add context to show current photo
    context = {
        'form': form,
        'current_photo': user_profile.photo if user_profile.photo else None
    }
    return render(request, 'organization/editCompany.html', {'form': form})
@login_required()
def companyDashboard(request):
    us = organization.objects.get(org=request.user)
    if us is None:
        messages.error(request,"Become a Organization first")
        return redirect('home')
    else :
        return render(request,'organization/companydashboard.html')


def fetch_leetcode_stats(username):
    """Fetch LeetCode statistics using public profile scraping"""
    if not username:
        return None

    url = f"https://leetcode.com/{username}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find the problems solved count
        solved_problems = soup.find('div', {'class': 'text-[24px]'})
        if solved_problems:
            return {
                'total_solved': int(solved_problems.text.strip()),
                'profile_url': url
            }
    except Exception as e:
        print(f"Error fetching LeetCode stats: {e}")
    return None


def fetch_github_stats(username):
    """Fetch GitHub statistics using public API endpoints"""
    if not username:
        return None

    try:
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Mozilla/5.0'
        }

        # Get basic profile info
        profile_response = requests.get(f"https://api.github.com/users/{username}", headers=headers)
        if profile_response.status_code != 200:
            return None
        profile_data = profile_response.json()

        # Get repositories
        repos_response = requests.get(f"https://api.github.com/users/{username}/repos", headers=headers)
        repos_data = repos_response.json() if repos_response.status_code == 200 else []

        # Get languages from repos
        languages = set()
        for repo in repos_data[:5]:  # Limit to first 5 repos
            if repo.get('language'):
                languages.add(repo.get('language'))

        # Estimate contributions
        contribution_count = sum(
            1 for repo in repos_data
            if repo.get('updated_at') and
            datetime.strptime(repo['updated_at'], '%Y-%m-%dT%H:%M:%SZ') > datetime.now() - timedelta(days=365)
        )

        return {
            'public_repos': profile_data.get('public_repos', 0),
            'contributions': contribution_count,
            'languages': list(languages),
            'profile_url': profile_data.get('html_url'),
            'followers': profile_data.get('followers', 0),
            'following': profile_data.get('following', 0)
        }
    except Exception as e:
        print(f"Error fetching GitHub stats: {e}")
    return None


def analyze_profile_with_groq(leetcode_stats, github_stats, job_role, job_description):
    """Analyze profile using Groq API"""
    try:
        client = groq.Client(api_key="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")

        # Prepare the analysis prompt
        prompt = f"""
        Analyze this candidate's technical profile:

        LeetCode Statistics:
        - Problems Solved: {leetcode_stats.get('total_solved') if leetcode_stats else 'No data'}

        GitHub Statistics:
        - Public Repositories: {github_stats.get('public_repos') if github_stats else 'No data'}
        - Programming Languages: {', '.join(github_stats.get('languages', [])) if github_stats else 'No data'}
        - Recent Contributions: {github_stats.get('contributions') if github_stats else 'No data'}

        For this job:
        Role: {job_role}
        Description: {job_description}

        Based on their technical profile, rate their fit for this role on a scale of 0-20.
        Consider:
        1. Problem-solving skills (LeetCode performance)
        2. Real-world coding experience (GitHub activity)
        3. Technology stack match (Languages used vs job requirements)
        4. Active coding practice (Recent contributions)

        Return only a numeric score between 0 and 20.
        """

        response = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model="mixtral-8x7b-32768",
            temperature=0.1,
        )

        # Extract and validate score
        try:
            score = float(response.choices[0].message.content.strip())
            return min(max(score, 0), 20)  # Ensure score is between 0 and 20
        except (ValueError, AttributeError):
            return 10  # Default score if parsing fails

    except Exception as e:
        print(f"Error in Groq analysis: {e}")
        return 10  # Default score if analysis fails


def calculate_profile_score(leetcode_stats, github_stats, job_role, job_description):
    """Calculate overall profile score"""
    score = 0

    # LeetCode scoring (max 40 points)
    if leetcode_stats:
        problems_solved = leetcode_stats.get('total_solved', 0)
        score += min(problems_solved / 5, 40)

    # GitHub scoring (max 40 points)
    if github_stats:
        repos = github_stats.get('public_repos', 0)
        contributions = github_stats.get('contributions', 0)
        languages = len(github_stats.get('languages', []))
        score += min((repos * 2) + (languages * 2) + (contributions / 100), 40)

    # Job relevance scoring from Groq (max 20 points)
    groq_score = analyze_profile_with_groq(leetcode_stats, github_stats, job_role, job_description)
    score += groq_score

    return min(round(score, 2), 100)


import PyPDF2
from docx import Document
from io import BytesIO

def extract_text_from_file(file):
    """
    Extracts text from an uploaded file (PDF or DOCX).
    """
    if file.content_type == 'application/pdf':
        # Handle PDF files
        pdf_reader = PyPDF2.PdfReader(BytesIO(file.read()))
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text()
        return text
    elif file.content_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
        # Handle DOCX files
        doc = Document(BytesIO(file.read()))
        text = "\n".join([paragraph.text for paragraph in doc.paragraphs])
        return text
    else:
        raise ValueError("Unsupported file format. Please upload a PDF or DOCX file.")

def apply_interview(request, interview_id):
    if request.method == 'POST':
        try:
            # Get interview
            interview = Custominterviews.objects.get(id=interview_id)
            # Check deadline
            if interview.submissionDeadline < timezone.now():
                messages.error(request, 'Application deadline has passed.')
                return redirect('available_interviews')
            # Check if already applied
            if Application.objects.filter(user=request.user, interview_id=interview_id).exists():
                messages.error(request, 'You have already applied for this interview.')
                return redirect('available_interviews')
            # Handle resume upload
            resume = request.FILES.get('resume')
            if not resume:
                messages.error(request, 'Please upload your resume.')
                return redirect('available_interviews')
            # Extract text from the uploaded resume
            try:
                extracted_resume_text = extract_text_from_file(resume)
            except ValueError as e:
                messages.error(request, str(e))
                return redirect('available_interviews')
            # Get user profile
            try:
                user_profile = UserProfile.objects.get(user=request.user)
            except UserProfile.DoesNotExist:
                messages.error(request, 'Please complete your profile first.')
                return redirect('profile_setup')
            # Fetch profile stats
            leetcode_stats = fetch_leetcode_stats(user_profile.leetcode)
            github_stats = fetch_github_stats(user_profile.github)
            # Calculate profile score
            profile_score = calculate_profile_score(
                leetcode_stats,
                github_stats,
                interview.post,
                interview.desc
            )
            # Create application
            application = Application.objects.create(
                user=request.user,
                interview=interview,
                resume=resume,
                extratedResume=extracted_resume_text,  # Store extracted text here
                score=profile_score,
            )
            messages.success(request, 'Application submitted successfully!')
            return redirect('application_status', application_id=application.id)
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')
            return redirect('available_interviews')
    return redirect('available_interviews')

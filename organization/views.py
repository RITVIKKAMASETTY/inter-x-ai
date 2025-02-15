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
            return redirect('company_interviews')
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

def calculate_profile_score(leetcode_stats, github_stats, job_role, job_description, dsa_weight, dev_weight):
    """
    Calculate overall profile score with DSA and Dev weightage, using stricter criteria
    
    Parameters:
    - leetcode_stats: dict with LeetCode statistics
    - github_stats: dict with GitHub statistics
    - job_role: str describing the role
    - job_description: str with detailed job description
    - dsa_weight: int percentage weight for DSA (0-100)
    - dev_weight: int percentage weight for Dev (0-100)
    """
    if dsa_weight + dev_weight != 100:
        raise ValueError("DSA and Dev weights must sum to 100")

    # DSA Score Calculation (based on LeetCode) - stricter scaling
    dsa_score = 0
    if leetcode_stats:
        problems_solved = leetcode_stats.get('total_solved', 0)
        # Scale problems solved with stricter requirement (1500 for max)
        dsa_score = min(problems_solved / 15, 100)

    # Dev Score Calculation (based on GitHub) - stricter and more nuanced
    dev_score = 0
    if github_stats:
        repos = github_stats.get('public_repos', 0)
        contributions = github_stats.get('contributions', 0)
        languages = len(github_stats.get('languages', []))
        followers = github_stats.get('followers', 0)
        following = max(github_stats.get('following', 1), 1)  # Prevent division by zero
        
        # Calculate components with stricter scales
        repo_score = min(repos * 5, 35)  # Max 35 points, stricter scaling
        contrib_score = min(contributions / 5, 25)  # Max 25 points, needs more contributions
        lang_score = min(languages * 5, 20)  # Max 20 points, harder to max out
        
        # Quality factor based on follower ratio (rewards popular accounts)
        follower_ratio = followers / following
        quality_factor = min(follower_ratio, 1)  # Cap at 1
        
        # Calculate initial dev score with quality consideration
        dev_score = (repo_score + contrib_score + lang_score) * (0.5 + 0.5 * quality_factor)
        
        # Adjust for job role relevance if information available
        if job_role and github_stats.get('languages'):
            # Simple heuristic: check if any languages match keywords in job role/description
            relevant_keywords = {
                'frontend': ['javascript', 'typescript', 'html', 'css', 'react', 'vue', 'angular'],
                'backend': ['python', 'java', 'c#', 'go', 'ruby', 'node', 'php'],
                'fullstack': ['javascript', 'typescript', 'python', 'java', 'ruby'],
                'mobile': ['swift', 'kotlin', 'java', 'objective-c', 'flutter', 'react native'],
                'data': ['python', 'r', 'sql', 'scala', 'julia']
            }
            
            role_keywords = []
            for role, keywords in relevant_keywords.items():
                if role.lower() in job_role.lower() or role.lower() in job_description.lower():
                    role_keywords.extend(keywords)
            
            if role_keywords:
                languages_list = [lang.lower() for lang in github_stats.get('languages', [])]
                matches = sum(1 for lang in languages_list if lang in role_keywords)
                relevance_factor = min(0.5 + (matches * 0.1), 1.0)  # 0.5 base + 0.1 per match, max 1.0
                dev_score *= relevance_factor

    # Apply weightage
    weighted_score = (
        (dsa_score * (dsa_weight / 100)) +
        (dev_score * (dev_weight / 100))
    )
    
    # Apply a curve to make high scores harder to achieve
    if weighted_score > 60:
        weighted_score = 60 + (weighted_score - 60) * 0.5  # Reduce growth rate above 60
    
    # Add final check to ensure scores are stricter overall
    final_score = min(round(weighted_score * 0.9, 2), 100)  # 10% overall reduction
    
    return final_score

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
import re
import uuid
from io import BytesIO
from django.http import HttpResponse
from django.shortcuts import redirect
from django.contrib import messages
from django.utils import timezone
from django.core.files.base import ContentFile
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import requests
import json



# Load environment variables
def extract_resume_with_groq(extracted_text):
    """
    Use Groq API to extract structured information from resume text
    """
    api_key = "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"
    if not api_key:
        raise ValueError("GROQ API key not found in environment variables")
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    prompt = f"""
    Extract the following information from this resume text and return it as a JSON object:
    
    1. Personal information: name, email, phone, LinkedIn profile if available
    2. Education: list of schools/universities with degree, field of study, and years
    3. Work experience: list of positions with company name, role, years, and key responsibilities
    4. Skills: list of technical skills, programming languages, tools, etc.
    5. Projects: list of projects with name, description, and technologies used
    
    Here's the resume text:
    {extracted_text}
    
    Also, calculate a resume score (0-100) based on:
    - Relevance of skills to software development/engineering (0-25)
    - Years of experience (0-25)
    - Education level (0-15)
    - Project complexity and relevance (0-25)
    - Overall presentation and completeness (0-10)
    
    Return ONLY a valid JSON object with these keys: personal_info, education, experience, skills, projects, resume_score. 
    Do not include any explanation text before or after the JSON.
    """
    
    data = {
        "model": "llama3-70b-8192",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "response_format": {"type": "json_object"}  # Request JSON response format
    }
    
    try:
        response = requests.post("https://api.groq.com/openai/v1/chat/completions", 
                               headers=headers, 
                               json=data)
        response.raise_for_status()
        result = response.json()
        
        # Extract the JSON content from the response
        content = result["choices"][0]["message"]["content"]
        
        # Clean and parse the JSON
        try:
            # First try direct parsing
            resume_data = json.loads(content)
        except json.JSONDecodeError:
            # Try to extract JSON if there's markdown or other text
            json_match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
            if json_match:
                json_str = json_match.group(1).strip()
                resume_data = json.loads(json_str)
            else:
                # Last resort: try to find anything that looks like JSON
                potential_json = re.search(r'\{.*\}', content, re.DOTALL)
                if potential_json:
                    json_str = potential_json.group(0)
                    resume_data = json.loads(json_str)
                else:
                    # If all else fails, create a minimal valid structure
                    resume_data = {
                        "personal_info": {"name": "Could not parse name"},
                        "education": [],
                        "experience": [],
                        "skills": [],
                        "projects": [],
                        "resume_score": 0
                    }
        
        # Validate the required keys exist
        required_keys = ["personal_info", "education", "experience", "skills", "projects", "resume_score"]
        for key in required_keys:
            if key not in resume_data:
                resume_data[key] = [] if key != "personal_info" and key != "resume_score" else ({} if key == "personal_info" else 0)
        
        return resume_data
        
    except requests.exceptions.RequestException as e:
        # Log the error and return a basic structure
        print(f"Error calling Groq API: {str(e)}")
        return {
            "personal_info": {"name": "API Error - Could not process resume"},
            "education": [],
            "experience": [],
            "skills": [],
            "projects": [],
            "resume_score": 0
        }
    except json.JSONDecodeError as e:
        # Log the error with the received content for debugging
        print(f"Error parsing Groq API response: {str(e)}")
        print(f"Received content: {content}")
        return {
            "personal_info": {"name": "JSON Error - Could not process resume"},
            "education": [],
            "experience": [],
            "skills": [],
            "projects": [],
            "resume_score": 0
        }
    except Exception as e:
        # Catch any other unexpected errors
        print(f"Unexpected error processing resume: {str(e)}")
        return {
            "personal_info": {"name": "Error - Could not process resume"},
            "education": [],
            "experience": [],
            "skills": [],
            "projects": [],
            "resume_score": 0
        }

def create_standardized_pdf(resume_data):
    """
    Create a standardized PDF resume with improved formatting and content display
    """
    buffer = BytesIO()
    
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Enhanced style definitions
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        spaceAfter=10,
        alignment=1,
        textColor=colors.HexColor('#2C3E50')
    )
    
    section_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=16,
        spaceAfter=10,
        textColor=colors.HexColor('#2C3E50')
    )
    
    subsection_style = ParagraphStyle(
        'SubSection',
        parent=styles['Normal'],
        fontSize=12,
        textColor=colors.HexColor('#34495E'),
        fontName='Helvetica-Bold'
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=11,
        textColor=colors.HexColor('#2C3E50'),
        leading=14
    )
    
    score_style = ParagraphStyle(
        'ScoreStyle',
        parent=styles['Normal'],
        fontSize=13,
        textColor=colors.HexColor('#2980B9'),
        fontName='Helvetica-Bold',
        alignment=1,
        spaceBefore=10,
        spaceAfter=10
    )
    
    # Resume Score
    if 'resume_score' in resume_data:
        score = resume_data['resume_score']
        # Handle different score formats (string or number)
        if isinstance(score, str):
            try:
                score = float(score)
            except ValueError:
                score = 0
        elements.append(Paragraph(f"Resume Score: {score}/100", score_style))
    
    # Personal Information
    personal_info = resume_data.get('personal_info', {})
    if not isinstance(personal_info, dict):
        personal_info = {"name": str(personal_info)}
    
    name = personal_info.get('name', 'N/A')
    elements.append(Paragraph(str(name), title_style))
    
    contact_info = []
    if 'email' in personal_info:
        contact_info.append(str(personal_info['email']))
    if 'phone' in personal_info:
        contact_info.append(str(personal_info['phone']))
    if 'linkedin' in personal_info:
        contact_info.append(str(personal_info['linkedin']))
    if contact_info:
        elements.append(Paragraph(' | '.join(contact_info), normal_style))
    elements.append(Spacer(1, 20))
    
    # Skills Section (Moved to top for quick review)
    if resume_data.get('skills'):
        elements.append(Paragraph('TECHNICAL SKILLS', section_style))
        skills = resume_data['skills']
        if isinstance(skills, list):
            skills_text = ', '.join(str(skill) for skill in skills)
        else:
            skills_text = str(skills)
        elements.append(Paragraph(skills_text, normal_style))
        elements.append(Spacer(1, 12))
    
    # Experience Section
    if resume_data.get('experience'):
        elements.append(Paragraph('PROFESSIONAL EXPERIENCE', section_style))
        experiences = resume_data['experience']
        if not isinstance(experiences, list):
            experiences = [experiences]
            
        for exp in experiences:
            if isinstance(exp, dict):
                company = exp.get('company', 'N/A')
                role = exp.get('role', 'N/A')
                years = exp.get('years', '')
                description = exp.get('description', '')
                
                elements.append(Paragraph(f"{company} - {role} ({years})", subsection_style))
                if description:
                    if isinstance(description, list):
                        for item in description:
                            elements.append(Paragraph(f"• {item}", normal_style))
                    else:
                        elements.append(Paragraph(str(description), normal_style))
                elements.append(Spacer(1, 8))
            else:
                elements.append(Paragraph(str(exp), normal_style))
                elements.append(Spacer(1, 8))
    
    # Education Section
    if resume_data.get('education'):
        elements.append(Paragraph('EDUCATION', section_style))
        educations = resume_data['education']
        if not isinstance(educations, list):
            educations = [educations]
            
        for edu in educations:
            if isinstance(edu, dict):
                institution = edu.get('institution', 'N/A')
                degree = edu.get('degree', '')
                field = edu.get('field', '')
                years = edu.get('years', '')
                
                elements.append(Paragraph(f"{institution}", subsection_style))
                edu_details = []
                if degree:
                    edu_details.append(str(degree))
                if field:
                    edu_details.append(str(field))
                if years:
                    edu_details.append(f"({years})")
                
                if edu_details:
                    elements.append(Paragraph(" - ".join(edu_details), normal_style))
                elements.append(Spacer(1, 8))
            else:
                elements.append(Paragraph(str(edu), normal_style))
                elements.append(Spacer(1, 8))
    
    # Projects Section
    if resume_data.get('projects'):
        elements.append(Paragraph('PROJECTS', section_style))
        projects = resume_data['projects']
        if not isinstance(projects, list):
            projects = [projects]
            
        for project in projects:
            if isinstance(project, dict):
                name = project.get('name', 'N/A')
                description = project.get('description', '')
                technologies = project.get('technologies', '')
                
                elements.append(Paragraph(str(name), subsection_style))
                if description:
                    elements.append(Paragraph(str(description), normal_style))
                if technologies:
                    if isinstance(technologies, list):
                        tech_text = f"Technologies: {', '.join(str(tech) for tech in technologies)}"
                    else:
                        tech_text = f"Technologies: {technologies}"
                    elements.append(Paragraph(tech_text, normal_style))
                elements.append(Spacer(1, 8))
            else:
                elements.append(Paragraph(str(project), normal_style))
                elements.append(Spacer(1, 8))
    
    try:
        doc.build(elements)
        buffer.seek(0)
        return buffer
    except Exception as e:
        # Handle PDF generation errors
        print(f"Error generating PDF: {str(e)}")
        # Create a simple error PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        elements = [
            Paragraph("Error Generating Resume", title_style),
            Spacer(1, 20),
            Paragraph(f"There was an error processing this resume: {str(e)}", normal_style)
        ]
        doc.build(elements)
        buffer.seek(0)
        return buffer

def generate_unique_filename(instance, filename):
    """Generate a unique, shortened filename"""
    ext = filename.split('.')[-1]
    unique_id = str(uuid.uuid4())[:8]  # Use first 8 chars of UUID
    return f"{unique_id}.{ext}"

def apply_interview(request, interview_id):
    if request.method == 'POST':
        try:
            # Get interview
            interview = Custominterviews.objects.get(id=interview_id)
            
            # Validation checks
            if interview.submissionDeadline < timezone.now():
                messages.error(request, 'Application deadline has passed.')
                return redirect('available_interviews')
                
            if Application.objects.filter(user=request.user, interview_id=interview_id).exists():
                messages.error(request, 'You have already applied for this interview.')
                return redirect('available_interviews')
            
            # Handle resume upload
            resume = request.FILES.get('resume')
            if not resume:
                messages.error(request, 'Please upload your resume.')
                return redirect('available_interviews')
            
            # Extract resume text
            try:
                extracted_resume_text = extract_text_from_file(resume)
                
                # Use Groq to extract structured data and calculate score
                resume_data = extract_resume_with_groq(extracted_resume_text)
                
                # Generate standardized PDF
                pdf_buffer = create_standardized_pdf(resume_data)
                
                # Generate unique, short filenames
                resume_filename = generate_unique_filename(None, resume.name)
                std_resume_filename = f"std_{resume_filename}"
                
                # Create ContentFile with filename
                standardized_pdf = ContentFile(
                    pdf_buffer.getvalue(), 
                    name=f'std_resumes/{std_resume_filename}'
                )
                
                # Get the calculated resume score
                resume_score = resume_data.get('resume_score', 0)
                if isinstance(resume_score, str):
                    try:
                        resume_score = float(resume_score)
                    except ValueError:
                        resume_score = 0
                
            except ValueError as e:
                messages.error(request, str(e))
                return redirect('available_interviews')
            except Exception as e:
                messages.error(request, f"Error processing resume: {str(e)}")
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
            
            # Calculate profile score with weightage - incorporate resume score as well
            profile_score = calculate_profile_score(
                leetcode_stats,
                github_stats,
                interview.post,
                interview.desc,
                interview.DSA or 50,
                interview.Dev or 50,
                
            )
            
            # Save extracted resume data as JSON
            try:
                resume_json = json.dumps(resume_data)
            except Exception as e:
                # Fallback if JSON serialization fails
                print(f"Error serializing resume data: {str(e)}")
                resume_json = json.dumps({
                    "error": f"Could not serialize resume data: {str(e)}",
                    "personal_info": {"name": "Error processing resume"}
                })
            
            # Create application with proper file handling
            application = Application.objects.create(
                user=request.user,
                interview=interview,
                resume=resume,
                standardized_resume=standardized_pdf,
                extratedResume=resume_json,  
                score=profile_score,
            )
            
            # Set the original resume filename
            application.resume.name = f'resumes/{resume_filename}'
            application.save()
            
            messages.success(request, 'Application submitted successfully!')
            return redirect('available_interviews')
            
        except Exception as e:
            messages.error(request, f'An error occurred: {str(e)}')
            return redirect('available_interviews')
            
    return redirect('available_interviews')
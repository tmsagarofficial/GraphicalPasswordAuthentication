from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from graphical_pwd_auth.settings import N, TBA, EMAIL_HOST_USER, ALLOWED_HOSTS
from .models import LoginInfo
import random, uuid
import os
from email.message import EmailMessage
import ssl
import smtplib
import hashlib
def encrypt_md5(string):
    md5_hasher = hashlib.md5()
    md5_hasher.update(string.encode())
    return md5_hasher.hexdigest()

def encrypt_sha256(string):
    sha256_hasher = hashlib.sha256()
    sha256_hasher.update(string.encode())
    return sha256_hasher.hexdigest()

def get_pwd_imgs():
    # These images are just to confuse the attacker
    images = random.sample(range(1, 39), N * N)
    print(images)
    p_images = []
    for i in range(0, N * N, N):
        p_images.append(images[i:i+N])
    print(p_images)
    return p_images
    

def update_login_info(user, didSuccess):
    if didSuccess:
        user.logininfo.fails = 0
    else:
        user.logininfo.fails += 1
    
    user.logininfo.save()
    print('{} Failed attempts: {}'.format(user.username, user.logininfo.fails))


def isBlocked(username):
    try:
        user = User.objects.get(username=username)
    except Exception:
        return None
    print('isBlocked: {} - {}'.format(user.logininfo, TBA))
    if user.logininfo.fails >= TBA:
        return True
    else:
        return False


def sendLoginLinkMailToUser(username):
    try:
        user = User.objects.get(username=username)
    except Exception:
        return False
    
    user_email=user.email
    email_sender = ''
    email_password=''
    email_receiver=user_email
    subject ='Account Blocked'
    body="""
         Your GPA (Graphical Password Authentication) account has been BLOCKED due to suspicious activity
        

         To login use this:  http://127.0.0.1:8000/blocklogin/ 

         
         Password reset link: http://127.0.0.1:8000/resetpass/

        """
    em=EmailMessage()
    em['From']=email_sender
    em['To']=email_receiver
    em['Subject']=subject
    em.set_content(body)

    context=ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com',465,context=context) as smtp:
            smtp.login(email_sender,email_password)
            smtp.sendmail(email_sender,email_receiver,em.as_string())
    print('PWD RESET LINK EMAIL SENT')
    return True

def sendPasswordResetLinkToUser(username):
    # send reset link everytime user requests
    try:
        user = User.objects.get(username=username)
    except Exception:
        return False
    
    user_email=user.email
    email_sender = ''
    email_password=''
    email_receiver=user_email
    subject ='Link to Reset your Password'
    body="""
         You have requested to reset your password.
        Click the Link to reset your password directly.
        The link is one-time clickable
        link: http://127.0.0.1:8000/resetpass/

        """
    em=EmailMessage()
    em['From']=email_sender
    em['To']=email_receiver
    em['Subject']=subject
    em.set_content(body)

    context=ssl.create_default_context()

    with smtplib.SMTP_SSL('smtp.gmail.com',465,context=context) as smtp:
            smtp.login(email_sender,email_password)
            smtp.sendmail(email_sender,email_receiver,em.as_string())
    print('PWD RESET LINK EMAIL SENT')
    return True


def home_page(request):
    return render(request, 'home.html')


def register_page(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        password= encrypt_md5(password)
        password = encrypt_sha256(password)
        print(username, password)
        try:
            # create user and loginInfo for him
            user = User.objects.create_user(email=email, username=username, password=password)
            login_info = LoginInfo(user=user, fails=0)
            login_info.save()
            messages.success(request, 'Account created successfully!')
        except Exception:
            messages.warning(request, 'Error while creating Account!')
        
        return redirect('home')
    else:
        data = {
            'p_images': get_pwd_imgs(),
        }
        return render(request, 'register.html', context=data)


def login_page(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print(username, password)

        block_status = isBlocked(username)
        if block_status is None:
            # No user exists
            messages.warning(request, 'Account doesn\'t Exist')
            return redirect('login')

        elif block_status == True:
            # Blocked - send login link to email
            # check if previously sent, if not send
            sendLoginLinkMailToUser(username)
            messages.warning(request, 'Your account is Blocked, please check your Email!')
            return redirect('login')
        else:
            # Not Blocked
            message=password
            password= encrypt_md5(password)
            password = encrypt_sha256(password)
            user = authenticate(username=username, password=password, request=request)
            if user is not None:
                login(request, user)
                update_login_info(user, True)
                
                md5_hashed_message = encrypt_md5(message)
                sha256_hashed_message = encrypt_sha256(md5_hashed_message)
                messages.success(request, 'Login successfull!')
                msg='BNMIT 👈🏼(This will be visible only once logged in)'
                link='https://bnmit.org'
                return render(request,'home.html',{'msg':msg,'link':link})
            else:
                user = User.objects.get(username=username)
                update_login_info(user, False)
                messages.warning(request, 'Login Failed!')
                return redirect('login')

    else:
        data = {
            'p_images': get_pwd_imgs(),
        }
        return render(request, 'login.html', context=data)


def login_from_uid(request, uid):
    try:
        # get user from the uid and reset the Link to 'NO_LINK' again
        login_info = LoginInfo.objects.get(login_link=uid)
        user = login_info.user
        login(request, user)
        update_login_info(user, True)
        login_info.login_link = None
        login_info.save()
        messages.success(request, 'Login successfull!')
    except Exception:
        messages.warning(request, 'Invalid Link. Please check again!')

    return redirect('home')


def reset_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        print(username)
        if sendPasswordResetLinkToUser(username):
            messages.success(request, 'Password Reset Link sent to you email!')
        else:
            messages.warning(request, 'User doesn\'t exist!')
        return redirect('home')
    else:
        return render(request, 'reset_request.html')


def reset_from_uid(request, uid):
    print('hello')
    if request.method == 'POST':
        print('hi-post')
        password = request.POST['password']
        try:
            # get user from the uid and reset the Link to 'NO_LINK' again
            login_info = LoginInfo.objects.get(reset_link=uid)
            user = login_info.user
            # reset pwd
            user.set_password(password)
            login_info.reset_link = None
            login_info.save()
            user.save()
            messages.success(request, 'Password Changed Successfully!')
        except Exception:
            messages.warning(request, 'Invalid Link. Please check again!')
        return redirect('home')
    else:
        print('hi-else')
        try:
            # To make sure the link is valid
            print(uid)
            login_info = LoginInfo.objects.get(reset_link=uid)
            data = {
                'p_images': get_pwd_imgs(),
            }
            return render(request, 'reset.html', context=data)
        except Exception:
            messages.warning(request, 'Invalid Link. Please check again!')
            return redirect('home')


def logout_page(request):
    logout(request)
    messages.warning(request, 'You\'ve been logged out!')
    return redirect('home')

def reset1(request):
    data = {
            'p_images': get_pwd_imgs(),
        }
    return render(request,'reset.html',context=data)

def login_page1(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print(username, password)

        block_status = isBlocked(username)
        

        if block_status == True:
            # Blocked - send login link to email
            # check if previously sent, if not send
            sendLoginLinkMailToUser(username)
            messages.warning(request, 'Your account is Blocked, please check your Email!')
            return redirect('login')
        else:
            # Not Blocked
            message=password
            password= encrypt_md5(password)
            password = encrypt_sha256(password)
            user = authenticate(username=username, password=password, request=request)
            if user is not None:
                login(request, user)
                update_login_info(user, True)
                
                md5_hashed_message = encrypt_md5(message)
                sha256_hashed_message = encrypt_sha256(md5_hashed_message)
                messages.success(request, 'Login successfull!')
                msg='BNMIT'
                link='https://bnmit.org'
                return render(request,'home.html',{'msg':msg,'link':link})
            else:
                user = User.objects.get(username=username)
                update_login_info(user, False)
                messages.warning(request, 'Login Failed!')
                return redirect('login')

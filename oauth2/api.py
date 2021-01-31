from django.shortcuts import render, redirect
from oauth2.otp import otp
import qrcode


def index(request):
    name = request.session['user']['name']
    token = request.session['token']
    context = {
        'name': name,
        'token': token,
    }
    return render(request, 'otp.html', context=context)


def send_otp(request):
    otp_four_digit = otp.generateOTP()

    request.session['otp'] = otp_four_digit
    email = request.session['user']['email']
    send_email_with_otp("gpapadopoulos864@gmail.com", email, "OTP PIN",
                        "OTP is: %s" % otp_four_digit)

    return render(request, 'authenticate.html', context={'session': request.session})


def send_email_with_otp(email, recipient, subject, message):
    from django.core.mail import send_mail
    from smtplib import SMTPException
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=email,
            recipient_list=[recipient],
        )
        return True
    except SMTPException:
        return False


def logout(request):
    from oauth2.auth import OAuthMiddleware
    OAuthMiddleware().clear_session(request)
    return redirect('/')


def code_qr(request):
    from PIL import Image
    import io
    import base64
    
    name = 'Welcome to'
    qr = qrcode.make('hello')
    qr.save('myqr.png')

    im = Image.open('/app/myqr.png', mode='r')
    buffer = io.BytesIO()
    im.save(buffer, format='PNG')
    buffer.seek(0)

    data_uri = base64.b64encode(buffer.read()).decode('ascii')

    html = "data:image/png;base64,{0}".format(data_uri)

    context = {
        'name': name,
        'image': html,
    }
    return render(request, 'qrcode.html', context)

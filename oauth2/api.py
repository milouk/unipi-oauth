from django.http import HttpResponse


def index(request):
    msg = "Hello %s, you're logged in with session token %s <a href=/otp><button>Click Me</button></a>" % (request.session['user']['name'], request.session['token'])
    return HttpResponse(msg)


def send_otp(request):
    from oauth2.otp import otp
    otp_four_digit = otp.generateOTP()

    # Maybe encode?
    plaintext = 'hello world'
    encrypt = otp.encryption(plaintext, otp_four_digit)
    encryptedText = encrypt.OTPencryption()

    request.session['otp'] = otp_four_digit
    msg = "Your 4 digit otp is: %s" % otp_four_digit
    send_email_with_otp("gpapadopoulos864@gmail.com", "OTP PIN",
                        "OTP is: %s" % otp_four_digit)
    return HttpResponse(msg)


def send_email_with_otp(email, subject, message):
    from django.core.mail import send_mail
    from smtplib import SMTPException
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=email,
            recipient_list=["mstauroy@gmail.com"],
        )
        return True
    except SMTPException:
        return False


def validate_otp(request):

    otp_input = request.POST['otp']

    #Maybe decryption
    # decrypt = decryption(otp_input, OTP)
    # recoveredText = decrypt.decryptCipher()
    # aesDecrypt = decrypt.decrypt(aesEncrypt)

    if otp_input == request.session['otp']:
        msg = "Success"
        return HttpResponse(msg)
    msg = "Wrong OTP"
    return HttpResponse(msg)

from django.http import HttpResponse


def index(request):
    msg = "Hello %s, you're logged in with session token %s" % (request.session['user']['name'], request.session['token'])
    return HttpResponse(msg)

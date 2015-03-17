"""
Utilities for all views

Ben Adida (12-30-2008)
"""

from django.template import Context, Template, loader, RequestContext
from django.http import HttpResponse, Http404
from django.shortcuts import render_to_response

import re

import utils

from helios import datatypes

# nicely update the wrapper function
from functools import update_wrapper

from helios_auth.security import get_user

import helios

from django.conf import settings

from helios.models import ElectionOfficer
##
## BASICS
##

SUCCESS = HttpResponse("SUCCESS")

# FIXME: error code
FAILURE = HttpResponse("FAILURE")

##
## template abstraction
##
def prepare_vars(request, vars):
  vars_with_user = vars.copy()
  vars_with_user['user'] = get_user(request)
  
  # csrf protection
  if request.session.has_key('csrf_token'):
    vars_with_user['csrf_token'] = request.session['csrf_token']
    
  vars_with_user['utils'] = utils
  vars_with_user['settings'] = settings
  vars_with_user['HELIOS_STATIC'] = '/static/helios/helios'
  vars_with_user['TEMPLATE_BASE'] = helios.TEMPLATE_BASE
  vars_with_user['CURRENT_URL'] = request.path
  vars_with_user['SECURE_URL_HOST'] = settings.SECURE_URL_HOST
  
  if 'election' in vars and get_user(request):
      try:
          vars_with_user['officer'] = ElectionOfficer.get_by_election_and_user(election=vars['election'], user=get_user(request))
      except:
          pass
      
  return vars_with_user

def render_template(request, template_name, vars = {}, include_user=True):
  t = loader.get_template(template_name + '.html')
  
  vars_with_user = prepare_vars(request, vars)
  
  if not include_user:
    del vars_with_user['user']
  
  return render_to_response('helios/templates/%s.html' % template_name, vars_with_user, context_instance=RequestContext(request))
  
def render_template_raw(request, template_name, vars={}):
  t = loader.get_template(template_name)
  
  # if there's a request, prep the vars, otherwise can't do it.
  if request:
    full_vars = prepare_vars(request, vars)
  else:
    full_vars = vars

  c = Context(full_vars)  
  return t.render(c)


def render_json(json_txt):
  return HttpResponse(json_txt, "application/json")

# decorator
def json(func):
    """
    A decorator that serializes the output to JSON before returning to the
    web client.
    """
    def convert_to_json(self, *args, **kwargs):
      return_val = func(self, *args, **kwargs)
      try:
        return render_json(utils.to_json(return_val))
      except Exception, e:
        import logging
        logging.error("problem with serialization: " + str(return_val) + " / " + str(e))
        raise e

    return update_wrapper(convert_to_json,func)
    
def get_referer_view(request, default=None):
    ''' 
    Copyright (c) 2009 Arthur Furlan <arthur.furlan@gmail.com>
    
    Return the referer view of the current request

    Example:

        def some_view(request):
            ...
            referer_view = get_referer_view(request)
            return HttpResponseRedirect(referer_view, '/accounts/login/')
    '''

    # if the user typed the url directly in the browser's address bar
    referer = request.META.get('HTTP_REFERER')
    print referer
    if not referer:
        return default

    # remove the protocol and split the url at the slashes
    referer = re.sub('^https?:\/\/', '', referer).split('/')
    
    #strip port number from domain name?
    server_name = referer[0]
    try:
        server_name = server_name[:server_name.index(':')]
    except:
        pass
    
    if server_name != request.META.get('SERVER_NAME'):
        return default

    # add the slash at the relative path's view and finished
    referer = u'/' + u'/'.join(referer[1:])
    print referer
    return referer
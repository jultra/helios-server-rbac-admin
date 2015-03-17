"""
Helios Security -- mostly access control

Ben Adida (ben@adida.net)
"""

# nicely update the wrapper function
from functools import update_wrapper

from django.core.urlresolvers import reverse
from django.core.exceptions import *
from django.http import *
from django.conf import settings

from models import *
from helios_auth.security import get_user

from helios_auth.models import PermissionDoesNotExist, Permission

from django.http import HttpResponseRedirect
import urllib

import helios

#added by john 
import messages
from helios.view_utils import get_referer_view

# current voter
def get_voter(request, user, election):
  """
  return the current voter
  """
  voter = None
  if request.session.has_key('CURRENT_VOTER'):
    voter = request.session['CURRENT_VOTER']
    if voter.election != election:
      voter = None

  if not voter:
    if user:
      voter = Voter.get_by_election_and_user(election, user)
      
  return voter

# a function to check if the current user is a trustee
HELIOS_TRUSTEE_UUID = 'helios_trustee_uuid'
def get_logged_in_trustee(request):
  if request.session.has_key(HELIOS_TRUSTEE_UUID):
    return Trustee.get_by_uuid(request.session[HELIOS_TRUSTEE_UUID])
  else:
    return None

def set_logged_in_trustee(request, trustee):
  request.session[HELIOS_TRUSTEE_UUID] = trustee.uuid

#
# some common election checks
#
def do_election_checks(election, props, request=None):
  # frozen
  if props.has_key('frozen'):
    frozen = props['frozen']
  else:
    frozen = None
  
  # newvoters (open for registration)
  if props.has_key('newvoters'):
    newvoters = props['newvoters']
  else:
    newvoters = None
  
  # frozen check
  if frozen != None:
    if frozen and not election.frozen_at:
      messages.error(request, "You can only perform this when the election has started.")
      return False
      #raise PermissionDenied("You can only perform this when the election has started.")
    if not frozen and election.frozen_at:
      messages.error(request, "The election has already started. You are no longer allowed to perform this activity.")
      return False
      #raise PermissionDenied("The election has already started. You are no longer allowed to perform this activity.")
    
  # open for new voters check
  if newvoters != None:
    # where is this can_add_voter?
    if election.can_add_voters() != newvoters:
      raise PermissionDenied()
  
  #everything alright
  return True

  
def get_election_by_uuid(uuid):
  if not uuid:
    raise Exception("no election ID")
      
  return Election.get_by_uuid(uuid)
  
# decorator for views that pertain to an election
# takes parameters:
# frozen - is the election frozen
# newvoters - does the election accept new voters
# perm_needed - permission required by the election view, values should be one of codename in Permissions
def election_view(**checks):
  
  def election_view_decorator(func):
    def election_view_wrapper(request, election_uuid=None, *args, **kw):
      
      #add content of checks to kw
      #kw = checks
      
      
      election = get_election_by_uuid(election_uuid)
      
      if not election:
        raise Http404

      # do checks
      ok = do_election_checks(election, checks, request)
      
      if not ok:
          return HttpResponseRedirect(get_referer_view(request))
      
      # if private election, only logged in voters
      if election.private_p and not checks.get('allow_logins',False):
        from views import password_voter_login
        if not user_can_see_election(request, election):
          return_url = request.get_full_path()
          if 'admin' in return_url:
              from server_ui.views import home_m
              return HttpResponseRedirect("%s?%s" % (reverse(home_m), urllib.urlencode({'return_url' : return_url})))
          else:
              return HttpResponseRedirect("%s?%s" % (reverse(password_voter_login, args=[election.uuid]), urllib.urlencode({
                  'return_url' : return_url})))
      
      return func(request, election, *args, **kw)

    return update_wrapper(election_view_wrapper, func)
    
  return election_view_decorator

def user_can_admin_election(user, election):
  if not user:
    return False
  
  #added by John Ultra
  #check  if user is one of the election administrators
  #using filter, instead of get, to avoid dealing with DoesNotExist exception
  election_admin = ElectionOfficer.objects.filter(election=election, user=user, super_p=True)

  # election or site administrator
  return election.admin == user or election_admin or user.admin_p

#added by John Ultra

def user_has_perm(user, election, perm_n, request=None):
    if user_can_officiate_election(user):
              
        available_perms = Permission.all_codenames()
      
        if perm_n not in available_perms:
            raise PermissionDoesNotExist("You have supplied an invalid Permission codename. Please check the Permission table auth_permission for possible values.");
      
        #using filter to avoid dealing with DoesNotExist exception
        officer = ElectionOfficer.objects.filter(user=user, election=election)
        if officer:
            officer = officer[0]
        #assumption here is that, perm_needed is only present if an election view can be accessed
        #only by election officers
        if not officer:
            messages.error(request, "You are not an election officer of this election. You are not authorized to perform this operation.")
            return False
            #raise PermissionDenied()
      
        perms = officer.permissions

        if not perms:
            return False  
        if perm_n not in perms:
            return False
    
        return True
    
def user_can_officiate_election(user, election=None):
    if not user:
        return False
    
    #user is one of the election officers, not necessarily admin
    if election:
        election_officers = ElectionOfficer.objects.filter(election=election, user=user)
    else:
        election_officers = ElectionOfficer.objects.filter(user=user)
    return election_officers != []

def user_can_see_election(request, election):
  user = get_user(request)

  if not election.private_p:
    return True

  # election is private
  
  # but maybe this user is the administrator?
  if user_can_admin_election(user, election):
    return True
  
  #added by John Ultra
  #maybe this user is an election officer
  if user_can_officiate_election(user, election):
      return True
  
  # or maybe this is a trustee of the election?
  trustee = get_logged_in_trustee(request)
  if trustee and trustee.election.uuid == election.uuid:
    return True

  # then this user has to be a voter
  return (get_voter(request, user, election) != None)

def api_client_can_admin_election(api_client, election):
  return election.api_client == api_client and api_client != None
  
# decorator for checking election admin access, and some properties of the election
# frozen - is the election frozen
# newvoters - does the election accept new voters
def election_admin(**checks):
  
  def election_admin_decorator(func):
    def election_admin_wrapper(request, election_uuid=None, *args, **kw):
      election = get_election_by_uuid(election_uuid)
      
      user = get_user(request)
      
      if 'perm_needed' in checks:
          perm = Permission.objects.get(codename=checks['perm_needed'])
      
      #user is an Election Officer
      if not user_can_officiate_election(user, election):
          messages.error(request, "You don't have the required permission (%s) to execute that activity." % (perm))
          return HttpResponseRedirect(get_referer_view(request))
          #raise PermissionDenied()
      
      #user should at least have the required permission
      if 'perm_needed' in checks:
          kw['perm_needed'] = checks['perm_needed'] 
          if not user_has_perm(user, election, checks['perm_needed'], request=request):
              messages.error(request, "You don't have the required permission (%s) to execute that activity." % (perm))
              return HttpResponseRedirect(get_referer_view(request))
              #raise PermissionDenied()
      #if the view does not explicitly put any required permission,
      #then the view must have required an admin user by default
      #else:
      #    if not user_can_admin_election(user, election):
      #        raise PermissionDenied()
        
      # do checks, ok means it's alright to proceed with the action
      ok = do_election_checks(election, checks, request)
      if not ok:
          return HttpResponseRedirect(get_referer_view(request))
        
      return func(request, election, *args, **kw)

    return update_wrapper(election_admin_wrapper, func)
    
  return election_admin_decorator
  
def trustee_check(func):
  def trustee_check_wrapper(request, election_uuid, trustee_uuid, *args, **kwargs):
    election = get_election_by_uuid(election_uuid)
    
    trustee = Trustee.get_by_election_and_uuid(election, trustee_uuid)
    
    if trustee == get_logged_in_trustee(request):
      return func(request, election, trustee, *args, **kwargs)
    else:
      raise PermissionDenied()
  
  return update_wrapper(trustee_check_wrapper, func)

def can_create_election(request):
  user = get_user(request)
  if not user:
    return False
    
  if helios.ADMIN_ONLY:
    return user.admin_p
  else:
    return user != None
  
def user_can_feature_election(user, election):
  if not user:
    return False
    
  return user.admin_p

def get_officer(user, election):
    electionofficer = None
    try:
        electionofficer = ElectionOfficer.objects.get(user=user, election=election)
    except ObjectDoesNotExist:
        pass
    return electionofficer

# -*- coding: utf-8 -*-
"""
Helios Django Views

Ben Adida (ben@adida.net)
"""

from django.core.urlresolvers import reverse
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.http import *
from django.db import transaction

#added by john
import messages

from django.contrib.contenttypes.models import ContentType

from django.forms.formsets import formset_factory
from django.forms.models import modelformset_factory
from django.utils.functional import curry

from mimetypes import guess_type

import csv, urllib, os, base64

from crypto import algs, electionalgs, elgamal
from crypto import utils as cryptoutils
from workflows import homomorphic
from helios import utils as helios_utils
from view_utils import *

from helios_auth.security import *
from helios_auth.auth_systems import AUTH_SYSTEMS, can_list_categories
from helios_auth.models import AuthenticationExpired

from helios import security
from helios_auth import views as auth_views

import tasks

from security import *
from helios_auth.security import get_user, save_in_session_across_logouts

import uuid, datetime

from models import * 

import forms, signals

# Parameters for everything
ELGAMAL_PARAMS = elgamal.Cryptosystem()

# trying new ones from OlivierP
ELGAMAL_PARAMS.p = 16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071L
ELGAMAL_PARAMS.q = 61329566248342901292543872769978950870633559608669337131139375508370458778917L
ELGAMAL_PARAMS.g = 14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533L

# object ready for serialization
ELGAMAL_PARAMS_LD_OBJECT = datatypes.LDObject.instantiate(ELGAMAL_PARAMS, datatype='legacy/EGParams')

# single election server? Load the single electionfrom models import Election
from django.conf import settings

def get_election_url(election):
  return settings.URL_HOST + reverse(election_shortcut, args=[election.short_name])  

def get_election_badge_url(election):
  return settings.URL_HOST + reverse(election_badge, args=[election.uuid])  

def get_election_govote_url(election):
  return settings.URL_HOST + reverse(election_vote_shortcut, args=[election.short_name])  

def get_castvote_url(cast_vote):
  return settings.URL_HOST + reverse(castvote_shortcut, args=[cast_vote.vote_tinyhash])

# social buttons
def get_socialbuttons_url(url, text):
  if not text:
    return None
  
  return "%s%s?%s" % (settings.SOCIALBUTTONS_URL_HOST,
                      reverse(socialbuttons),
                      urllib.urlencode({
        'url' : url,
        'text': text.encode('utf-8')
        }))
  

##
## remote auth utils

def user_reauth(request, user):
  # FIXME: should we be wary of infinite redirects here, and
  # add a parameter to prevent it? Maybe.
  login_url = "%s%s?%s" % (settings.SECURE_URL_HOST,
                           reverse(auth_views.start, args=[user.user_type]),
                           urllib.urlencode({'return_url':
                                               request.get_full_path()}))
  return HttpResponseRedirect(login_url)

##

# simple static views
def home(request):
  user = get_user(request)
  if user:
    elections = Election.get_by_user_as_admin(user, archived_p = False)
  else:
    elections = []
  
  return render_template(request, "index", {'elections' : elections})
  
def stats(request):
  user = get_user(request)
  if not user or not user.admin_p:
    raise PermissionDenied()

  page = int(request.GET.get('page', 1))
  limit = int(request.GET.get('limit', 25))

  elections = Election.objects.all().order_by('-created_at')
  elections_paginator = Paginator(elections, limit)
  elections_page = elections_paginator.page(page)

  return render_template(request, "stats", {'elections' : elections_page.object_list, 'elections_page': elections_page,
                                            'limit' : limit})


## 
## simple admin for development
##
def admin_autologin(request):
  if "localhost" not in settings.URL_HOST and "127.0.0.1" not in settings.URL_HOST:
    raise Http404
  
  users = User.objects.filter(admin_p=True)
  if len(users) == 0:
    return HttpResponse("no admin users!")

  if len(users) == 0:
    return HttpResponse("no users!")

  user = users[0]
  request.session['user'] = {'type' : user.user_type, 'user_id' : user.user_id}
  return HttpResponseRedirect("/")

##
## General election features
##

@json
def election_params(request):
  return ELGAMAL_PARAMS_LD_OBJECT.toJSONDict()

def election_verifier(request):
  return render_template(request, "tally_verifier")

def election_single_ballot_verifier(request):
  return render_template(request, "ballot_verifier")

def election_shortcut(request, election_short_name):
  election = Election.get_by_short_name(election_short_name)
  if election:
    return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
  else:
    raise Http404

# a hidden view behind the shortcut that performs the actual perm check
@election_view()
def _election_vote_shortcut(request, election):
  vote_url = "%s/booth/vote.html?%s" % (settings.SECURE_URL_HOST, urllib.urlencode({'election_url' : reverse(one_election, args=[election.uuid])}))
  
  test_cookie_url = "%s?%s" % (reverse(test_cookie), urllib.urlencode({'continue_url' : vote_url}))

  return HttpResponseRedirect(test_cookie_url)
  
def election_vote_shortcut(request, election_short_name):
  election = Election.get_by_short_name(election_short_name)
  if election:
    return _election_vote_shortcut(request, election_uuid=election.uuid)
  else:
    raise Http404

@election_view()
def _castvote_shortcut_by_election(request, election, cast_vote):
  return render_template(request, 'castvote', {'cast_vote' : cast_vote, 'vote_content': cast_vote.vote.toJSON(), 'the_voter': cast_vote.voter, 'election': election})
  
def castvote_shortcut(request, vote_tinyhash):
  try:
    cast_vote = CastVote.objects.get(vote_tinyhash = vote_tinyhash)
  except CastVote.DoesNotExist:
    raise Http404

  return _castvote_shortcut_by_election(request, election_uuid = cast_vote.voter.election.uuid, cast_vote=cast_vote)

@trustee_check
def trustee_keygenerator(request, election, trustee):
  """
  A key generator with the current params, like the trustee home but without a specific election.
  """
  eg_params_json = utils.to_json(ELGAMAL_PARAMS_LD_OBJECT.toJSONDict())

  return render_template(request, "election_keygenerator", {'eg_params_json': eg_params_json, 'election': election, 'trustee': trustee})

@login_required
def elections_administered(request):
  #check modified by John Ultra
  user = get_user(request)
  
  #this will show elections where a user is an election officer, not necessarily admin 
  #if not can_create_election(request):
  if not user_can_officiate_election(user):
    return HttpResponseForbidden('only an administrator has elections to administer')
  
  #modified by John Ultra, now gets all election which the user is an officer
  #elections = Election.get_by_user_as_admin(user)
  elections = Election.get_by_user_as_officer(user)
  
  return render_template(request, "elections_administered", {'elections': elections})

@login_required
def elections_voted(request):
  user = get_user(request)
  elections = Election.get_by_user_as_voter(user)
  
  return render_template(request, "elections_voted", {'elections': elections})
    

@login_required
def election_new(request):
  if not can_create_election(request):
    return HttpResponseForbidden('only an administrator can create an election')
    
  error = None
  
  if request.method == "GET":
    election_form = forms.ElectionForm(initial={'private_p': settings.HELIOS_PRIVATE_DEFAULT})
  else:
    election_form = forms.ElectionForm(request.POST)
    
    if election_form.is_valid():
      # create the election obj
      election_params = dict(election_form.cleaned_data)
      
      # is the short name valid
      if helios_utils.urlencode(election_params['short_name']) == election_params['short_name']:      
        election_params['uuid'] = str(uuid.uuid1())
        election_params['cast_url'] = settings.SECURE_URL_HOST + reverse(one_election_cast, args=[election_params['uuid']])
      
        # registration starts closed
        election_params['openreg'] = False

        user = get_user(request)
        election_params['admin'] = user
        
        election, created_p = Election.get_or_create(**election_params)
        
        #TODO: I think it's much better that we create a default election role, Election Administrator
        #everytime we create a new election. Election Administrator role by default shall possess permissions 
        #such as, Can add election officer, Open Election, Close Election, Can Add Trustee
    
        #name = 'Election Administration'
        #election = election
        #e_admin = ElectionRole(name = name, election=election)
        
        #set the election creator as first election administrator
        #officer_role = 
        
        #since one of our goals is to distribute administration of election as much as possible, meaning not
        #execution of the different election activities is not performed by a minimum number of users.
        #critical election tasks such voters registration, election contest creation, should be performed by
        #another subset of users
        
        if created_p:
            # add Helios as a trustee by default
            election.generate_trustee(ELGAMAL_PARAMS)
                        
            #added code by John Ultra
            #add the current user, election creator as Election Admin by default
            election_officer = ElectionOfficer.objects.create(user=user, election=election, super_p = True )
            election_officer.save()
            
            #create default Election Administrator role for this election
            election_admin_role = ElectionRole.get_or_create_election_admin_role(election)
            
            #add Election Administrator role to roles of election creator.Assumes that he is an admin and He MUST be!
            election_officer.electionrole.add(election_admin_role)
        
            return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
        else:
          error = "An election with short name %s already exists" % election_params['short_name']
      else:
        error = "No special characters allowed in the short name."
    
  return render_template(request, "election_new", {'election_form': election_form, 'error': error})
  
@election_admin(frozen=False, perm_needed='change_election')
#@election_view(frozen=False, perm_needed='change_election')
def one_election_edit(request, election, **kw):

  error = None
  RELEVANT_FIELDS = ['short_name', 'name', 'description', 'use_voter_aliases', 'election_type', 'private_p']
  # RELEVANT_FIELDS += ['use_advanced_audit_features']
  
  if request.method == "GET":
    values = {}
    for attr_name in RELEVANT_FIELDS:
      values[attr_name] = getattr(election, attr_name)
    election_form = forms.ElectionForm(values)
  else:
    election_form = forms.ElectionForm(request.POST)
    
    if election_form.is_valid():
      clean_data = election_form.cleaned_data
      for attr_name in RELEVANT_FIELDS:
        setattr(election, attr_name, clean_data[attr_name])

      election.save()
        
      return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
  
  return render_template(request, "election_edit", {'election_form' : election_form, 'election' : election, 'error': error})

@election_admin(frozen=False, perm_needed='change_election')
def one_election_schedule(request, election):
  return HttpResponse("foo")

@election_view()
@json
def one_election(request, election, caller=None, vr_id=None):
  if not election:
    raise Http404

  #by default, we assume that this is called from a non-validation request page
  election_dict = election.toJSONDict(update=True)

  #FIXME  
  # we need to put questions_url, for ballot booth previewing.
  # adding it to election object, mess up its hash. so we 
  # add this additional info if we are on preview mode.
  # should find a better way to do this
  if not election.frozen_at: 
      election_dict['questions_url'] =  settings.SECURE_URL_HOST + reverse(one_election_questions, args=[election.uuid])
      
  #else we have no question, maybe this request comes from requests_ballot page preview link,    
  if caller == 'ballot_request' and vr_id:
      
      try:
          
          vr_ballot = ValidationRequest.objects.get(id=vr_id)
          election.questions = vr_ballot.data['input']['questions']
          election_dict = election.toJSONDict(update=True)
          election_dict['questions_url'] =  settings.SECURE_URL_HOST + reverse(requests_ballot, args=[election.uuid])
      except ObjectDoesNotExist:
          pass
  else:
      #check if the requesting user has Define Ballot permission
      perm_needed = 'define_ballot'
      user = get_user(request)
      admin_p = security.user_has_perm(user, election, perm_needed)
      
      if admin_p and not election.frozen_at:
          try:
              vr_ballot = ValidationRequest.objects.get(election_uuid = election.uuid, action = Election.DEFINE_BALLOT, terminated_at__isnull=True)
              election.questions = vr_ballot.data['input']['questions']    
              election_dict = election.toJSONDict(complete=True)
              election_dict['questions_url'] =  settings.SECURE_URL_HOST + reverse(one_election_questions, args=[election.uuid])  
          except ObjectDoesNotExist:
              pass
  return election_dict
  
@election_view()
def election_badge(request, election):
  election_url = get_election_url(election)
  params = {'election': election, 'election_url': election_url}
  for option_name in ['show_title', 'show_vote_link']:
    params[option_name] = (request.GET.get(option_name, '1') == '1')
  return render_template(request, "election_badge", params)

@election_view()
def one_election_view(request, election):

  user = get_user(request)
  #admin_p = security.user_can_admin_election(user, election)
  admin_p = security.user_can_officiate_election(user, election)
  can_feature_p = security.user_can_feature_election(user, election)
  
  notregistered = False
  eligible_p = True
  
  election_url = get_election_url(election)
  election_badge_url = get_election_badge_url(election)
  status_update_message = None

  vote_url = "%s/booth/vote.html?%s" % (settings.SECURE_URL_HOST, urllib.urlencode({'election_url' : reverse(one_election, args=[election.uuid])}))

  test_cookie_url = "%s?%s" % (reverse(test_cookie), urllib.urlencode({'continue_url' : vote_url}))
  
  if user:
    voter = Voter.get_by_election_and_user(election, user)
    
    if not voter:
      try:
        eligible_p = _check_eligibility(election, user)
      except AuthenticationExpired:
        return user_reauth(request, user)
      notregistered = True
  else:
    voter = get_voter(request, user, election)

  if voter:
    # cast any votes?
    votes = CastVote.get_by_voter(voter)
  else:
    votes = None

  # status update message?
  if election.openreg:
    if election.voting_has_started:
      status_update_message = u"Vote in %s" % election.name
    else:
      status_update_message = u"Register to vote in %s" % election.name

  # result!
  if election.result:
    status_update_message = u"Results are in for %s" % election.name
  
  # a URL for the social buttons
  socialbuttons_url = get_socialbuttons_url(election_url, status_update_message)

  trustees = Trustee.get_by_election(election)
  
  active_v_requests = ValidationRequest.get_active_requests_by_election(election)
  
  return render_template(request, 'election_view',
                         {'election' : election, 'trustees': trustees, 'admin_p': admin_p, 'user': user,
                          'voter': voter, 'votes': votes, 'notregistered': notregistered, 'eligible_p': eligible_p,
                          'can_feature_p': can_feature_p, 'election_url' : election_url, 
                          'vote_url': vote_url, 'election_badge_url' : election_badge_url,
                          'test_cookie_url': test_cookie_url, 'socialbuttons_url' : socialbuttons_url,
                          'no_active_v_requests':len(active_v_requests)})

def test_cookie(request):
  continue_url = request.GET['continue_url']
  request.session.set_test_cookie()
  next_url = "%s?%s" % (reverse(test_cookie_2), urllib.urlencode({'continue_url': continue_url}))
  return HttpResponseRedirect(next_url)  

def test_cookie_2(request):
  continue_url = request.GET['continue_url']

  if not request.session.test_cookie_worked():
    return HttpResponseRedirect("%s?%s" % (reverse(nocookies), urllib.urlencode({'continue_url': continue_url})))

  request.session.delete_test_cookie()
  return HttpResponseRedirect(continue_url)  

def nocookies(request):
  retest_url = "%s?%s" % (reverse(test_cookie), urllib.urlencode({'continue_url' : request.GET['continue_url']}))
  return render_template(request, 'nocookies', {'retest_url': retest_url})

def socialbuttons(request):
  """
  just render the social buttons for sharing a URL
  expecting "url" and "text" in request.GET
  """
  return render_template(request, 'socialbuttons',
                         {'url': request.GET['url'], 'text':request.GET['text']})

##
## Trustees and Public Key
##
## As of July 2009, there are always trustees for a Helios election: one trustee is acceptable, for simple elections.
##
@json
@election_view()
def list_trustees(request, election):
  trustees = Trustee.get_by_election(election)
  return [t.toJSONDict(complete=True) for t in trustees]
  
@election_view()
def list_trustees_view(request, election):
  trustees = Trustee.get_by_election(election)
  user = get_user(request)
  #admin_p = security.user_can_admin_election(user, election)
  
  admin_p = security.user_can_officiate_election(user, election)
  return render_template(request, 'list_trustees', {'election': election, 'trustees': trustees, 'admin_p':admin_p})
  
@election_admin(frozen=False, perm_needed='add_trustee')
def new_trustee(request, election):
  if request.method == "GET":
    return render_template(request, 'new_trustee', {'election' : election})
  else:
    # get the public key and the hash, and add it
    name = request.POST['name']
    email = request.POST['email']
    
    trustee = Trustee(uuid = str(uuid.uuid1()), election = election, name=name, email=email)
    trustee.save()
    return HttpResponseRedirect(reverse(list_trustees_view, args=[election.uuid]))

@election_admin(frozen=False, perm_needed='add_trustee')
def new_trustee_helios(request, election):
  """
  Make Helios a trustee of the election
  """
  election.generate_trustee(ELGAMAL_PARAMS)
  return HttpResponseRedirect(reverse(list_trustees_view, args=[election.uuid]))
  
@election_admin(frozen=False, perm_needed='delete_trustee')
def delete_trustee(request, election):
  trustee = Trustee.get_by_election_and_uuid(election, request.GET['uuid'])
  trustee.delete()
  return HttpResponseRedirect(reverse(list_trustees_view, args=[election.uuid]))
  
def trustee_login(request, election_short_name, trustee_email, trustee_secret):
  election = Election.get_by_short_name(election_short_name)
  if election:
    trustee = Trustee.get_by_election_and_email(election, trustee_email)
    
    if trustee:
      if trustee.secret == trustee_secret:
        set_logged_in_trustee(request, trustee)
        return HttpResponseRedirect(reverse(trustee_home, args=[election.uuid, trustee.uuid]))
      else:
        # bad secret, we'll let that redirect to the front page
        pass
    else:
      # no such trustee
      raise Http404

  return HttpResponseRedirect("/")

@election_admin(perm_needed='can_send_trustee_url')
def trustee_send_url(request, election, trustee_uuid):
  trustee = Trustee.get_by_election_and_uuid(election, trustee_uuid)
  
  url = settings.SECURE_URL_HOST + reverse(trustee_login, args=[election.short_name, trustee.email, trustee.secret])
  
  body = """

You are a trustee for %s.

Your trustee dashboard is at

  %s
  
--
Helios  
""" % (election.name, url)

  send_mail('your trustee homepage for %s' % election.name, body, settings.SERVER_EMAIL, ["%s <%s>" % (trustee.name, trustee.email)], fail_silently=True)

  logging.info("URL %s " % url)
  return HttpResponseRedirect(reverse(list_trustees_view, args = [election.uuid]))

@trustee_check
def trustee_home(request, election, trustee):
  return render_template(request, 'trustee_home', {'election': election, 'trustee':trustee})
  
@trustee_check
def trustee_check_sk(request, election, trustee):
  return render_template(request, 'trustee_check_sk', {'election': election, 'trustee':trustee})
  
@trustee_check
def trustee_upload_pk(request, election, trustee):
  if request.method == "POST":
    # get the public key and the hash, and add it
    public_key_and_proof = utils.from_json(request.POST['public_key_json'])
    trustee.public_key = algs.EGPublicKey.fromJSONDict(public_key_and_proof['public_key'])
    trustee.pok = algs.DLogProof.fromJSONDict(public_key_and_proof['pok'])
    
    # verify the pok
    if not trustee.public_key.verify_sk_proof(trustee.pok, algs.DLog_challenge_generator):
      raise Exception("bad pok for this public key")
    
    trustee.public_key_hash = utils.hash_b64(utils.to_json(trustee.public_key.toJSONDict()))

    trustee.save()
    
    # send a note to admin
    try:
      election.admin.send_message("%s - trustee pk upload" % election.name, "trustee %s (%s) uploaded a pk." % (trustee.name, trustee.email))
    except:
      # oh well, no message sent
      pass
    
  return HttpResponseRedirect(reverse(trustee_home, args=[election.uuid, trustee.uuid]))

##
## Ballot Management
##

@json
@election_view()
def get_randomness(request, election):
  """
  get some randomness to sprinkle into the sjcl entropy pool
  """
  return {
    # back to urandom, it's fine
    "randomness" : base64.b64encode(os.urandom(32))
    #"randomness" : base64.b64encode(uuid.uuid4().bytes + uuid.uuid4().bytes)
    }

@json
@election_view(frozen=True)
def encrypt_ballot(request, election):
  """
  perform the ballot encryption given answers_json, a JSON'ified list of list of answers
  (list of list because each question could have a list of answers if more than one.)
  """
  # FIXME: maybe make this just request.POST at some point?
  answers = utils.from_json(request.REQUEST['answers_json'])
  ev = homomorphic.EncryptedVote.fromElectionAndAnswers(election, answers)
  return ev.ld_object.includeRandomness().toJSONDict()
    
@election_view(frozen=True)
def post_audited_ballot(request, election):
  if request.method == "POST":
    raw_vote = request.POST['audited_ballot']
    encrypted_vote = electionalgs.EncryptedVote.fromJSONDict(utils.from_json(raw_vote))
    vote_hash = encrypted_vote.get_hash()
    audited_ballot = AuditedBallot(raw_vote = raw_vote, vote_hash = vote_hash, election = election)
    audited_ballot.save()
    
    return SUCCESS
    

@election_view(frozen=True)
def one_election_cast(request, election):
  """
  on a GET, this is a cancellation, on a POST it's a cast
  """
  if request.method == "GET":
    return HttpResponseRedirect("%s%s" % (settings.URL_HOST, reverse(one_election_view, args = [election.uuid])))
    
  user = get_user(request)    
  encrypted_vote = request.POST['encrypted_vote']

  save_in_session_across_logouts(request, 'encrypted_vote', encrypted_vote)

  return HttpResponseRedirect("%s%s" % (settings.SECURE_URL_HOST, reverse(one_election_cast_confirm, args=[election.uuid])))

@election_view(allow_logins=True)
def password_voter_login(request, election):
  """
  This is used to log in as a voter for a particular election
  """
  
  # the URL to send the user to after they've logged in
  return_url = request.REQUEST.get('return_url', reverse(one_election_cast_confirm, args=[election.uuid]))
  bad_voter_login = (request.GET.get('bad_voter_login', "0") == "1")

  if request.method == "GET":
    # if user logged in somehow in the interim, e.g. using the login link for administration,
    # then go!
    if user_can_see_election(request, election):
      return HttpResponseRedirect(reverse(one_election_view, args = [election.uuid]))

    password_login_form = forms.VoterPasswordForm()
    return render_template(request, 'password_voter_login',
                           {'election': election, 
                            'return_url' : return_url,
                            'password_login_form': password_login_form,
                            'bad_voter_login' : bad_voter_login})
  
  login_url = request.REQUEST.get('login_url', None)

  if not login_url:
    # login depending on whether this is a private election
    # cause if it's private the login is happening on the front page
    if election.private_p:
      login_url = reverse(password_voter_login, args=[election.uuid])
    else:
      login_url = reverse(one_election_cast_confirm, args=[election.uuid])

  password_login_form = forms.VoterPasswordForm(request.POST)

  if password_login_form.is_valid():
    try:
      voter = election.voter_set.get(voter_login_id = password_login_form.cleaned_data['voter_id'].strip(),
                                     voter_password = password_login_form.cleaned_data['password'].strip())

      request.session['CURRENT_VOTER'] = voter
    except Voter.DoesNotExist:
      redirect_url = login_url + "?" + urllib.urlencode({
          'bad_voter_login' : '1',
          'return_url' : return_url
          })

      return HttpResponseRedirect(redirect_url)
  
  return HttpResponseRedirect(return_url)

@election_view(frozen=True)
def one_election_cast_confirm(request, election):
  user = get_user(request)    

  # if no encrypted vote, the user is reloading this page or otherwise getting here in a bad way
  if not request.session.has_key('encrypted_vote'):
    return HttpResponseRedirect(settings.URL_HOST)

  voter = get_voter(request, user, election)

  # auto-register this person if the election is openreg
  if user and not voter and election.openreg:
    voter = _register_voter(election, user)
    
  # tallied election, no vote casting
  if election.encrypted_tally or election.result:
    return render_template(request, 'election_tallied', {'election': election})
    
  encrypted_vote = request.session['encrypted_vote']
  vote_fingerprint = cryptoutils.hash_b64(encrypted_vote)

  # if this user is a voter, prepare some stuff
  if voter:
    vote = datatypes.LDObject.fromDict(utils.from_json(encrypted_vote), type_hint='legacy/EncryptedVote').wrapped_obj

    # prepare the vote to cast
    cast_vote_params = {
      'vote' : vote,
      'voter' : voter,
      'vote_hash': vote_fingerprint,
      'cast_at': datetime.datetime.utcnow()
    }

    cast_vote = CastVote(**cast_vote_params)
  else:
    cast_vote = None
    
  if request.method == "GET":
    if voter:
      past_votes = CastVote.get_by_voter(voter)
      if len(past_votes) == 0:
        past_votes = None
    else:
      past_votes = None

    if cast_vote:
      # check for issues
      issues = cast_vote.issues(election)
    else:
      issues = None

    bad_voter_login = (request.GET.get('bad_voter_login', "0") == "1")

    # status update this vote
    if voter and voter.user.can_update_status():
      status_update_label = voter.user.update_status_template() % "your smart ballot tracker"
      status_update_message = "I voted in %s - my smart tracker is %s.. #heliosvoting" % (get_election_url(election),cast_vote.vote_hash[:10])
    else:
      status_update_label = None
      status_update_message = None

    # do we need to constrain the auth_systems?
    if election.eligibility:
      auth_systems = [e['auth_system'] for e in election.eligibility]
    else:
      auth_systems = None

    password_only = False

    if auth_systems == None or 'password' in auth_systems:
      show_password = True
      password_login_form = forms.VoterPasswordForm()

      if auth_systems == ['password']:
        password_only = True
    else:
      show_password = False
      password_login_form = None

    return_url = reverse(one_election_cast_confirm, args=[election.uuid])
    login_box = auth_views.login_box_raw(request, return_url=return_url, auth_systems = auth_systems)

    return render_template(request, 'election_cast_confirm', {
        'login_box': login_box, 'election' : election, 'vote_fingerprint': vote_fingerprint,
        'past_votes': past_votes, 'issues': issues, 'voter' : voter,
        'return_url': return_url,
        'status_update_label': status_update_label, 'status_update_message': status_update_message,
        'show_password': show_password, 'password_only': password_only, 'password_login_form': password_login_form,
        'bad_voter_login': bad_voter_login})
      
  if request.method == "POST":
    check_csrf(request)
    
    # voting has not started or has ended
    if (not election.voting_has_started()) or election.voting_has_stopped():
      return HttpResponseRedirect(settings.URL_HOST)
            
    # if user is not logged in
    # bring back to the confirmation page to let him know
    if not voter:
      return HttpResponseRedirect(reverse(one_election_cast_confirm, args=[election.uuid]))
    
    # don't store the vote in the voter's data structure until verification
    cast_vote.save()

    # status update?
    if request.POST.get('status_update', False):
      status_update_message = request.POST.get('status_update_message')
    else:
      status_update_message = None

    # launch the verification task
    tasks.cast_vote_verify_and_store.delay(
      cast_vote_id = cast_vote.id,
      status_update_message = status_update_message)
    
    # remove the vote from the store
    del request.session['encrypted_vote']
    
    return HttpResponseRedirect("%s%s" % (settings.URL_HOST, reverse(one_election_cast_done, args=[election.uuid])))
  
@election_view()
def one_election_cast_done(request, election):
  """
  This view needs to be loaded because of the IFRAME, but then this causes 
  problems if someone clicks "reload". So we need a strategy.
  We store the ballot hash in the session
  """
  user = get_user(request)
  voter = get_voter(request, user, election)

  if voter:
    votes = CastVote.get_by_voter(voter)
    vote_hash = votes[0].vote_hash
    cv_url = get_castvote_url(votes[0])

    # only log out if the setting says so *and* we're dealing
    # with a site-wide voter. Definitely remove current_voter
    if voter.user == user:
      logout = settings.LOGOUT_ON_CONFIRMATION
    else:
      logout = False
      del request.session['CURRENT_VOTER']

    save_in_session_across_logouts(request, 'last_vote_hash', vote_hash)
    save_in_session_across_logouts(request, 'last_vote_cv_url', cv_url)
  else:
    vote_hash = request.session['last_vote_hash']
    cv_url = request.session['last_vote_cv_url']
    logout = False
  
  # local logout ensures that there's no more
  # user locally
  # WHY DO WE COMMENT THIS OUT? because we want to force a full logout via the iframe, including
  # from remote systems, just in case, i.e. CAS
  # if logout:
  #   auth_views.do_local_logout(request)
  
  # tweet/fb your vote
  socialbuttons_url = get_socialbuttons_url(cv_url, 'I cast a vote in %s' % election.name) 
  
  # remote logout is happening asynchronously in an iframe to be modular given the logout mechanism
  # include_user is set to False if logout is happening
  return render_template(request, 'cast_done', {'election': election,
                                                'vote_hash': vote_hash, 'logout': logout,
                                                'socialbuttons_url': socialbuttons_url},
                         include_user=(not logout))

@election_view()
@json
def one_election_result(request, election):
  return election.result

@election_view()
@json
def one_election_result_proof(request, election):
  return election.result_proof
  
@election_view(frozen=True)
def one_election_bboard(request, election):
  """
  UI to show election bboard
  """
  after = request.GET.get('after', None)
  offset= int(request.GET.get('offset', 0))
  limit = int(request.GET.get('limit', 50))
  
  order_by = 'voter_id'
  
  # unless it's by alias, in which case we better go by UUID
  if election.use_voter_aliases:
    order_by = 'alias'

  # if there's a specific voter
  if request.GET.has_key('q'):
    # FIXME: figure out the voter by voter_id
    voters = []
  else:
    # load a bunch of voters
    voters = Voter.get_by_election(election, after=after, limit=limit+1, order_by=order_by)
    
  more_p = len(voters) > limit
  if more_p:
    voters = voters[0:limit]
    next_after = getattr(voters[limit-1], order_by)
  else:
    next_after = None
    
  return render_template(request, 'election_bboard', {'election': election, 'voters': voters, 'next_after': next_after,
                'offset': offset, 'limit': limit, 'offset_plus_one': offset+1, 'offset_plus_limit': offset+limit,
                'voter_id': request.GET.get('voter_id', '')})

@election_view(frozen=True)
def one_election_audited_ballots(request, election):
  """
  UI to show election audited ballots
  """
  
  if request.GET.has_key('vote_hash'):
    b = AuditedBallot.get(election, request.GET['vote_hash'])
    return HttpResponse(b.raw_vote, mimetype="text/plain")
    
  after = request.GET.get('after', None)
  offset= int(request.GET.get('offset', 0))
  limit = int(request.GET.get('limit', 50))
  
  audited_ballots = AuditedBallot.get_by_election(election, after=after, limit=limit+1)
    
  more_p = len(audited_ballots) > limit
  if more_p:
    audited_ballots = audited_ballots[0:limit]
    next_after = audited_ballots[limit-1].vote_hash
  else:
    next_after = None
    
  return render_template(request, 'election_audited_ballots', {'election': election, 'audited_ballots': audited_ballots, 'next_after': next_after,
                'offset': offset, 'limit': limit, 'offset_plus_one': offset+1, 'offset_plus_limit': offset+limit})

@election_admin(perm_needed='delete_voter')
def voter_delete(request, election, voter_uuid, **kw):
  """
  Two conditions under which a voter can be deleted:
  - election is not frozen or
  - election is open reg
  """
  ## FOR NOW we allow this to see if we can redefine the meaning of "closed reg" to be more flexible
  # if election is frozen and has closed registration
  #if election.frozen_at and (not election.openreg):
  #  raise PermissionDenied()

  if election.encrypted_tally:
    raise PermissionDenied()

  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  if voter:
    data = {'old_obj': voter.toJSONDict(update=True),
            'input':{},
            'output':{}}
    try:
        v_policy = ValidationPolicy.get_by_election_and_perm(election, perm_codename=kw['perm_needed'])
        req_data = {'uuid':voter.uuid,
                    'data':data,
                    'action':Voter.DELETE,
                    'modeltype':helios.VOTER,
                    'vp':v_policy}
        ValidationRequest.create(get_user(request), election, req_data)
        messages.info(request, "Your request to remove %s from the list of voters has been filed." % (voter.voter_name))
    except:
        req_data = {'uuid':voter.uuid,
                    'data':data,
                    'action':Voter.DELETE,
                    'modeltype':helios.VOTER,
                    'vp':None}
        v_request = ValidationRequest.create(get_user(request), election, req_data)
        voter.delete()
        v_request.commit()

        if election.frozen_at:
            # log it
            election.append_log("Voter %s/%s removed after election frozen" % (voter.voter_type,voter.voter_id))
    
  return HttpResponseRedirect(reverse(voters_list_pretty, args=[election.uuid]))

@election_admin(frozen=False, perm_needed='change_election')
def one_election_set_reg(request, election):
  """
  Set whether this is open registration or not
  """
  # only allow this for public elections
  if not election.private_p:
    open_p = bool(int(request.GET['open_p']))
    election.openreg = open_p
    election.save()
  
  return HttpResponseRedirect(reverse(voters_list_pretty, args=[election.uuid]))

@election_admin(perm_needed='change_election')
def one_election_set_featured(request, election):
  """
  Set whether this is a featured election or not
  """

  user = get_user(request)
  if not security.user_can_feature_election(user, election):
    raise PermissionDenied()

  featured_p = bool(int(request.GET['featured_p']))
  election.featured_p = featured_p
  election.save()
  
  return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))

@election_admin(perm_needed='change_election')
def one_election_archive(request, election):
  
  archive_p = request.GET.get('archive_p', True)
  
  if bool(int(archive_p)):
    election.archived_at = datetime.datetime.utcnow()
  else:
    election.archived_at = None
    
  election.save()

  return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))

# changed from admin to view because 
# anyone can see the questions, the administration aspect is now
# built into the page
@election_view()
def one_election_questions(request, election, **kw):
  perm_needed = 'define_ballot'
  
  questions_json = utils.to_json(election.questions)
  
  #print questions_json
  user = get_user(request)
  
  #added by John Ultra
  #allow ballot booth preview viewing
  #set ballot booth url
  urls_json = {
          'questions': settings.SECURE_URL_HOST + reverse(one_election_questions, args=[election.uuid]),
          'vote' : "%s/booth/vote.html?%s" % (settings.SECURE_URL_HOST, urllib.urlencode({'election_url' : reverse(one_election, args=[election.uuid])}))
         }
  #admin_p = security.user_can_admin_election(user, election)
  #admin_p = security.user_can_officiate_election(user, election)
  
  admin_p = security.user_has_perm(user, election, perm_needed)
    
  #if user can define election ballot, then he must be here to do so.
  if admin_p:
      # questions is still empty
      #if not election.questions:
      #check if a validation request for a ballot been made already      
      try:
          v_request = ValidationRequest.objects.get(election_uuid=election.uuid, action=Election.DEFINE_BALLOT, terminated_at__isnull=True, committed_at__isnull=True)          
          questions_json = utils.to_json(v_request.data['input']['questions'])
          messages.info(request, "There is a PENDING ballot design request that is being processed.")
          messages.error(request, "Modifying the ballot design displayed on this page will invalidate its current progress and will reset its validation process.", extra_tags='pending_ballot')
      except ObjectDoesNotExist:
          pass
      
  return render_template(request, 'election_questions', {'election': election, 'questions_json' : questions_json, 
                                                         'admin_p': admin_p,
                                                         'urls_json':utils.to_json(urls_json)})

@election_admin(frozen=False, perm_needed='define_ballot')
def one_election_save_questions(request, election, **kw):

  vp = None
  check_csrf(request)
  
  election.questions = utils.from_json(request.POST['questions_json'])
  
  #prepare the data
  old_obj = Election.objects.get(id=election.id).toJSONDict(update=True)
  input = {'questions':election.questions}
  output = {}
  
  data = {'old_obj':old_obj,
         'input':input,
         'output':output # new object, if input is saved
         }

  try:
      #get validation policy for permission of this task
      v_policy = ValidationPolicy.get_by_election_and_perm(election, perm_codename=kw['perm_needed'])
      req_data = { 'uuid' : election.uuid,
                'data': data, 
                'action' : Election.DEFINE_BALLOT,
                'modeltype': helios.ELECTION,
                'vp' : v_policy
              }
      #ValidationRequest.update_or_create(get_user(request), election, req_data=req_data)
      ValidationRequest.update_or_create(get_user(request), election, req_data=req_data)
      
  except:
      #Oh, permission does not have validation policy so continue with its usual processing.
      req_data = { 'uuid' : election.uuid,
                'data': data,
                'action' : Election.DEFINE_BALLOT,
                'modeltype': helios.ELECTION,
                'vp' : None
              }
      v_request = ValidationRequest.update_or_create(get_user(request), election, req_data=req_data)
      election.save()
      v_request.data['output'] = election.toJSONDict(update=True)
      v_request.save()
      v_request.commit()
  # always a machine API
  return SUCCESS

def _check_eligibility(election, user):
  # prevent password-users from signing up willy-nilly for other elections, doesn't make sense
  if user.user_type == 'password':
    return False

  return election.user_eligible_p(user)

def _register_voter(election, user):
  if not _check_eligibility(election, user):
    return None
    
  return Voter.register_user_in_election(user, election)
    
@election_view()
def one_election_register(request, election):
  if not election.openreg:
    return HttpResponseForbidden('registration is closed for this election')
    
  check_csrf(request)
    
  user = get_user(request)
  voter = Voter.get_by_election_and_user(election, user)
  
  if not voter:
    voter = _register_voter(election, user)
    
  return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))

#@transaction.commit_on_success
@election_admin(frozen=False, perm_needed='open_election')
def one_election_freeze(request, election, **kw):
  # figure out the number of questions and trustees
    
  issues = election.issues_before_freeze

  if request.method == "GET":
    return render_template(request, 'election_freeze', {'election': election, 'issues' : issues, 'issues_p' : len(issues) > 0})
  else:
    check_csrf(request)
    
    
    try:
        pending_request = ValidationRequest.objects.get(election_uuid=election.uuid, action=Election.OPEN, committed_at__isnull=True, terminated_at__isnull=True)
        messages.error(request, "There is currently a PENDING request to OPEN this election. " + 
                        "Please wait for its processing to terminate first.", extra_tags='pending_request')
    
    except:
        #prepare data
        old_obj = election.toJSONDict(update=True)
        input = {}
        output = {}
        
        data = {'old_obj':old_obj,
                'input':input,
                'output':output}
        try: 
            v_policy = ValidationPolicy.get_by_election_and_perm(election, perm_codename=kw['perm_needed'])
            req_data = {'uuid': election.uuid,
                        'data': data,
                        'action': Election.OPEN,
                        'modeltype':helios.ELECTION,
                        'vp':v_policy,
                        }
            ValidationRequest.create(get_user(request), election, req_data)
            messages.info(request, "Your request to open the election has been filed.")
        except:
            req_data = {'uuid': election.uuid,
                        'data': data,
                        'action': Election.OPEN,
                        'modeltype':helios.ELECTION,
                        'vp':None,
                        }
            v_request = ValidationRequest.create(get_user(request), election, req_data)
            election.freeze()
            election.append_log(ElectionLog.FROZEN)
            election.save()
            v_request.data['output'] = election.toJSONDict(update=True)
            v_request.save()
            v_request.commit()
            messages.success(request, "The election is now officially open.")
    if get_user(request):
      return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
    else:
      return SUCCESS    

def _check_election_tally_type(election):
  for q in election.questions:
    if q['tally_type'] != "homomorphic":
      return False
  return True

@election_admin(frozen=True, perm_needed='close_election')
def one_election_compute_tally(request, election, **kw):
  """
  tallying is done all at a time now
  """
  if not _check_election_tally_type(election):
    return HttpResponseRedirect(reverse(one_election_view,args=[election.election_id]))

  if request.method == "GET":
    return render_template(request, 'election_compute_tally', {'election': election})
  
  check_csrf(request)

  try:
      pending_request = ValidationRequest.objects.get(election_uuid=election.uuid,action=Election.CLOSE, committed_at__isnull=True, terminate_at__isnull=True)
      messages.error(request, "There is currently a PENDING request to CLOSE this election. " + 
                        "Please wait for its processing to terminate first." , extra_tags="pending_request")
  except:
      data = {'old_obj':election.toJSONDict(update=True),
              'input':{},
              'output':{}}
      try:
          v_policy = ValidationPolicy.get_by_election_and_perm(election, perm_codename=kw['perm_needed'])
          req_data = {'uuid': election.uuid,
                        'data': data,
                        'action': Election.CLOSE,
                        'modeltype':helios.ELECTION,
                        'vp':v_policy,
                        }
          ValidationRequest.create(get_user(request), election, req_data)
          messages.info(request, "Your request to close the election has been filed.")
      except:
          if not election.voting_ended_at:
            election.voting_ended_at = datetime.datetime.utcnow()
        
          req_data = {'uuid': election.uuid,
                        'data': data,
                        'action': Election.CLOSE,
                        'modeltype':helios.ELECTION,
                        'vp':None,
                        }
          v_request = ValidationRequest.create(get_user(request), election, req_data)
          
          election.tallying_started_at = datetime.datetime.utcnow()
          election.save()
          tasks.election_compute_tally.delay(election_id = election.id)
          v_request.data['output'] = election.toJSONDict(update=True)
          v_request.save()
          v_request.commit()
          messages.success(request, "The tallying of votes have started.")
  return HttpResponseRedirect(reverse(one_election_view,args=[election.uuid]))

@trustee_check
def trustee_decrypt_and_prove(request, election, trustee):
  if not _check_election_tally_type(election) or election.encrypted_tally == None:
    return HttpResponseRedirect(reverse(one_election_view,args=[election.uuid]))
    
  return render_template(request, 'trustee_decrypt_and_prove', {'election': election, 'trustee': trustee})
  
@election_view(frozen=True)
def trustee_upload_decryption(request, election, trustee_uuid):
  if not _check_election_tally_type(election) or election.encrypted_tally == None:
    return FAILURE

  trustee = Trustee.get_by_election_and_uuid(election, trustee_uuid)

  factors_and_proofs = utils.from_json(request.POST['factors_and_proofs'])

  # verify the decryption factors
  trustee.decryption_factors = [[datatypes.LDObject.fromDict(factor, type_hint='core/BigInteger').wrapped_obj for factor in one_q_factors] for one_q_factors in factors_and_proofs['decryption_factors']]

  # each proof needs to be deserialized
  trustee.decryption_proofs = [[datatypes.LDObject.fromDict(proof, type_hint='legacy/EGZKProof').wrapped_obj for proof in one_q_proofs] for one_q_proofs in factors_and_proofs['decryption_proofs']]

  if trustee.verify_decryption_proofs():
    trustee.save()
    
    try:
      # send a note to admin
      election.admin.send_message("%s - trustee partial decryption" % election.name, "trustee %s (%s) did their partial decryption." % (trustee.name, trustee.email))
    except:
      # ah well
      # LoL!!
      pass
    
    return SUCCESS
  else:
    return FAILURE
  
@election_admin(frozen=True, perm_needed='can_release_election_results')
def combine_decryptions(request, election, **kw):
  """
  combine trustee decryptions
  """
  #perm_needed = 'can_release_election_results'
  if not security.user_has_perm(get_user(request), election, kw['perm_needed']):
      raise PermissionDenied()

  election_url = get_election_url(election)
  
  if request.method == "POST":
    check_csrf(request)
    
    try:
        pending_request = ValidationRequest.objects.get(election_uuid=election.uuid, action=Election.RELEASE, committed_at__isnull=True, terminated_at__isnull=True)
        messages.error(request, "There is currently a PENDING request to OPEN this election. " + 
                        "Please wait for its processing to terminate first.", extra_tags="pending_request")
        
        return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
    except:
        
        data = {'old_obj': election.toJSONDict(update=True),
                'input':{},
                'output':{}}
        try:
            v_policy = ValidationPolicy.get_by_election_and_perm(election, perm_codename=kw['perm_needed'])
            req_data = {'uuid': election.uuid,
                        'data': data,
                        'action': Election.RELEASE,
                        'modeltype':helios.ELECTION,
                        'vp':v_policy,
                        }
            ValidationRequest.create(get_user(request), election, req_data)
            messages.info(request, "Your request to release the election results has been filed.")
        except:
            req_data = {'uuid': election.uuid,
                        'data': data,
                        'action': Election.RELEASE,
                        'modeltype':helios.ELECTION,
                        'vp':None,
                        }
            v_request = ValidationRequest.create(get_user(request), election, req_data)        
            election.combine_decryptions()
            election.save()
            v_request.data['output'] = election.toJSONDict(update=True)
            v_request.save()
            v_request.commit()
            messages.info(request, "The results of the election is now officially released.")
            return HttpResponseRedirect("%s?%s" % (reverse(voters_email, args=[election.uuid]), urllib.urlencode({'template': 'result'})))

  # if just viewing the form or the form is not valid
  return render_template(request, 'combine_decryptions', {'election': election})

@election_admin(frozen=True)
def one_election_set_result_and_proof(request, election):
  if election.tally_type != "homomorphic" or election.encrypted_tally == None:
    return HttpResponseRedirect(reverse(one_election_view,args=[election.election_id]))

  # FIXME: check csrf
  
  election.result = utils.from_json(request.POST['result'])
  election.result_proof = utils.from_json(request.POST['result_proof'])
  election.save()

  if get_user(request):
    return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
  else:
    return SUCCESS
  
  
@election_view()
def voters_list_pretty(request, election):
  """
  Show the list of voters
  now using Django pagination
  """

  # for django pagination support
  page = int(request.GET.get('page', 1))
  limit = int(request.GET.get('limit', 50))
  q = request.GET.get('q','')
  
  order_by = 'user__user_id'

  # unless it's by alias, in which case we better go by UUID
  if election.use_voter_aliases:
    order_by = 'alias'

  user = get_user(request)
  #admin_p = security.user_can_admin_election(user, election)
  admin_p = security.user_can_officiate_election(user, election)

  categories = None
  eligibility_category_id = None

  try:
    if admin_p and can_list_categories(user.user_type):
      categories = AUTH_SYSTEMS[user.user_type].list_categories(user)
      eligibility_category_id = election.eligibility_category_id(user.user_type)
  except AuthenticationExpired:
    return user_reauth(request, user)
  
  # files being processed
  voter_files = election.voterfile_set.all()

  # load a bunch of voters
  # voters = Voter.get_by_election(election, order_by=order_by)
  voters = Voter.objects.filter(election = election).order_by(order_by).defer('vote')

  if q != '':
    if election.use_voter_aliases:
      voters = voters.filter(alias__icontains = q)
    else:
      voters = voters.filter(voter_name__icontains = q)

  voter_paginator = Paginator(voters, limit)
  voters_page = voter_paginator.page(page)

  total_voters = voter_paginator.count
    
  return render_template(request, 'voters_list', 
                         {'election': election, 'voters_page': voters_page,
                          'voters': voters_page.object_list, 'admin_p': admin_p, 
                          'email_voters': helios.VOTERS_EMAIL,
                          'limit': limit, 'total_voters': total_voters,
                          'upload_p': helios.VOTERS_UPLOAD, 'q' : q,
                          'voter_files': voter_files,
                          'categories': categories,
                          'eligibility_category_id' : eligibility_category_id})

@election_admin(perm_needed='change_election')
def voters_eligibility(request, election):
  """
  set eligibility for voters
  """
  user = get_user(request)

  if request.method == "GET":
    # this shouldn't happen, only POSTs
    return HttpResponseRedirect("/")

  # for now, private elections cannot change eligibility
  if election.private_p:
    return HttpResponseRedirect(reverse(voters_list_pretty, args=[election.uuid]))

  # eligibility
  eligibility = request.POST['eligibility']

  if eligibility in ['openreg', 'limitedreg']:
    election.openreg= True

  if eligibility == 'closedreg':
    election.openreg= False

  if eligibility == 'limitedreg':
    # now process the constraint
    category_id = request.POST['category_id']

    constraint = AUTH_SYSTEMS[user.user_type].generate_constraint(category_id, user)
    election.eligibility = [{'auth_system': user.user_type, 'constraint': [constraint]}]
  else:
    election.eligibility = None

  election.save()
  return HttpResponseRedirect(reverse(voters_list_pretty, args=[election.uuid]))
  
@election_admin(perm_needed='upload_voterfile')
def voters_upload(request, election, **kw):
  """
  Upload a CSV of password-based voters with
  voter_id, email, name
  
  name and email are needed only if voter_type is static
  """

  ## TRYING this: allowing voters upload by admin when election is frozen
  #if election.frozen_at and not election.openreg:
  #  raise PermissionDenied()

  if request.method == "GET":
    return render_template(request, 'voters_upload', {'election': election, 'error': request.GET.get('e',None)})
    
  if request.method == "POST":
    if bool(request.POST.get('confirm_p', 0)):
      
      
      try:
          v_policy = ValidationPolicy.get_by_election_and_perm(election, perm_codename=kw['perm_needed'])
          tasks.voter_file_process.delay(request=request, voter_file_id = request.session['voter_file_id'], v_policy = v_policy)
      except:
          # launch the background task to parse that file
          tasks.voter_file_process.delay(request=request, voter_file_id = request.session['voter_file_id'])
      
      del request.session['voter_file_id']
      messages.info(request, "Entries in the voter file which might cause duplicates voter registration were automatically removed.")
      return HttpResponseRedirect(reverse(voters_list_pretty, args=[election.uuid]))
    else:
      # we need to confirm
      if request.FILES.has_key('voters_file'):
        voters_file = request.FILES['voters_file']
        voter_file_obj = election.add_voters_file(voters_file)

        request.session['voter_file_id'] = voter_file_obj.id
        
        # import the first few lines to check
        voters = [v for v in voter_file_obj.itervoters()][:5]

        return render_template(request, 'voters_upload_confirm', {'election': election, 'voters': voters})
      else:
        return HttpResponseRedirect("%s?%s" % (reverse(voters_upload, args=[election.uuid]), urllib.urlencode({'e':'no voter file specified, try again'})))

@election_admin()
def voters_upload_cancel(request, election):
  """
  cancel upload of CSV file
  """
  voter_file_id = request.session.get('voter_file_id', None)
  if voter_file_id:
    vf = VoterFile.objects.get(id = voter_file_id)
    vf.delete()
  del request.session['voter_file_id']

  return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))

@election_admin(frozen=True)
def voters_email(request, election):
  
  if not helios.VOTERS_EMAIL:
    return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
  TEMPLATES = [
    ('vote', 'Time to Vote'),
    ('info', 'Additional Info'),
    ('result', 'Election Result')
    ]

  template = request.REQUEST.get('template', 'vote')
  if not template in [t[0] for t in TEMPLATES]:
    raise Exception("bad template")

  voter_id = request.REQUEST.get('voter_id', None)

  if voter_id:
    voter = Voter.get_by_election_and_voter_id(election, voter_id)
  else:
    voter = None
  
  election_url = get_election_url(election)
  election_vote_url = get_election_govote_url(election)

  default_subject = render_template_raw(None, 'email/%s_subject.txt' % template, {
      'custom_subject': "&lt;SUBJECT&gt;"
})
  default_body = render_template_raw(None, 'email/%s_body.txt' % template, {
      'election' : election,
      'election_url' : election_url,
      'election_vote_url' : election_vote_url,
      'custom_subject' : default_subject,
      'custom_message': '&lt;BODY&gt;',
      'voter': {'vote_hash' : '<SMART_TRACKER>',
                'name': '<VOTER_NAME>',
                'voter_login_id': '<VOTER_LOGIN_ID>',
                'voter_password': '<VOTER_PASSWORD>',
                'voter_type' : election.voter_set.all()[0].voter_type,
                'election' : election}
      })

  if request.method == "GET":
    email_form = forms.EmailVotersForm()
    if voter:
      email_form.fields['send_to'].widget = email_form.fields['send_to'].hidden_widget()
  else:
    email_form = forms.EmailVotersForm(request.POST)
    
    if email_form.is_valid():
      
      # the client knows to submit only once with a specific voter_id
      subject_template = 'email/%s_subject.txt' % template
      body_template = 'email/%s_body.txt' % template

      extra_vars = {
        'custom_subject' : email_form.cleaned_data['subject'],
        'custom_message' : email_form.cleaned_data['body'],
        'election_vote_url' : election_vote_url,
        'election_url' : election_url,
        'election' : election
        }
        
      voter_constraints_include = None
      voter_constraints_exclude = None

      if voter:
        tasks.single_voter_email.delay(voter_uuid = voter.uuid, subject_template = subject_template, body_template = body_template, extra_vars = extra_vars)
      else:
        # exclude those who have not voted
        if email_form.cleaned_data['send_to'] == 'voted':
          voter_constraints_exclude = {'vote_hash' : None}
          
        # include only those who have not voted
        if email_form.cleaned_data['send_to'] == 'not-voted':
          voter_constraints_include = {'vote_hash': None}
          
        print "Hiasas"
        tasks.voters_email.delay(election_id = election.id, subject_template = subject_template, body_template = body_template, extra_vars = extra_vars, voter_constraints_include = voter_constraints_include, voter_constraints_exclude = voter_constraints_exclude)
        print "Hi"
      # this batch process is all async, so we can return a nice note
      return HttpResponseRedirect(reverse(one_election_view, args=[election.uuid]))
    
  return render_template(request, "voters_email", {
      'email_form': email_form, 'election': election,
      'voter': voter,
      'default_subject': default_subject,
      'default_body' : default_body,
      'template' : template,
      'templates' : TEMPLATES})    

# Individual Voters
@election_view()
@json
def voter_list(request, election):
  # normalize limit
  limit = int(request.GET.get('limit', 500))
  if limit > 500: limit = 500
    
  voters = Voter.get_by_election(election, order_by='uuid', after=request.GET.get('after',None), limit= limit)
  return [v.ld_object.toDict() for v in voters]
  
@election_view()
@json
def one_voter(request, election, voter_uuid):
  """
  View a single voter's info as JSON.
  """
  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  if not voter:
    raise Http404
  return voter.toJSONDict()  

@election_view()
@json
def voter_votes(request, election, voter_uuid):
  """
  all cast votes by a voter
  """
  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  votes = CastVote.get_by_voter(voter)
  return [v.toJSONDict()  for v in votes]

@election_view()
@json
def voter_last_vote(request, election, voter_uuid):
  """
  all cast votes by a voter
  """
  voter = Voter.get_by_election_and_uuid(election, voter_uuid)
  return voter.last_cast_vote().toJSONDict()

##
## cast ballots
##

@election_view()
@json
def ballot_list(request, election):
  """
  this will order the ballots from most recent to oldest.
  and optionally take a after parameter.
  """
  limit = after = None
  if request.GET.has_key('limit'):
    limit = int(request.GET['limit'])
  if request.GET.has_key('after'):
    after = datetime.datetime.strptime(request.GET['after'], '%Y-%m-%d %H:%M:%S')
    
  voters = Voter.get_by_election(election, cast=True, order_by='cast_at', limit=limit, after=after)

  # we explicitly cast this to a short cast vote
  return [v.last_cast_vote().ld_object.short.toDict(complete=True) for v in voters]


#added views for election administration features

#home view of the admin page
@election_view()
def one_election_admin(request, election):    
    return render_template(request, 'admin/election_admin', {'election':election})

#page listing all officers of an election
@election_view()
def one_election_officers_list(request, election):
    """
    this list all election officers of the given election
    """
    #url of referer view
    referer_view = get_referer_view(request)
    #url of a certain view
    view_url = reverse(one_election_view,args=[election.uuid])

    if referer_view == view_url:
        unassigned_roles = ElectionRole.get_unassigned_roles_by_election(election)
    
        messages.info(request, "The following roles has not been assigned to any election officer yet:")
        
        for role in unassigned_roles:
            messages.error(request, role)
            
    officers = ElectionOfficer.objects.filter(election=election)
    
    return render_template(request, 'admin/officers_list', {
        'election':election, 'officers':officers})

#page for creating/adding new election officer
#@election_view(perm_needed='add_electionofficer')
@election_admin(frozen=False, perm_needed='add_electionofficer')
def user_new(request, election, **kw):
    
    error = None
                
    if request.method == "GET":
        officer_form = forms.OfficerForm(election=election)
    else:
        officer_form = forms.OfficerForm(request.POST, election=election)
        
        if officer_form.is_valid():
            perm = kw.pop('perm_needed', 'add_electionofficer')
            
            
            user_params = dict(officer_form.cleaned_data)
            
            #process officer for User object
            
            #create random password for officer
            password = helios_utils.random_string(length=10)
            
            info = {'email':user_params['email'], 'password':password}
            
            #create and save user info to database
            user = User.update_or_create(user_type='password', user_id=user_params['user_id'], 
                            name=user_params['name'] , info=info)
            
            #create ElectionOfficer object and save to database
            officer = officer_form.save(commit=False)
            officer.election = election
            officer.user = user
            officer.save()
            
            #save values of the role many to many field
            officer_form.save_m2m()
            
            #if super_p field is True for user, add Election Admin role to user roles
            if officer.super_p:
                officer.electionrole.add(ElectionRole.get_or_create_election_admin_role(election))
            
            default_subject = render_template_raw(None, 'email/officer_subject.txt', {})
            
            election_url = settings.URL_HOST + reverse(one_election_officers_list, args=[election.uuid])
            
            default_body = render_template_raw(None, 'email/officer_body.txt', {
                'election' : election,
                'election_url' : election_url,
                'user': officer.user
            })
                
            tasks.election_notify_an_officer.delay(officer, election.id, default_subject, default_body)
            
            messages.success(request, "%s was successfully added to the election officers of this election." % (officer.user.name))
            return HttpResponseRedirect(reverse(one_election_officers_list, args=[election.uuid]))
    
    return render_template(request, 'admin/user_new', {
        'election':election, 'officer_form':officer_form,
        'error':error})

#@election_view(perm_needed='change_electionofficer')
@election_admin(frozen=False, perm_needed='change_electionofficer')
def user_edit(request, election, officer_id, **kw):
    
    error = None

    officer = ElectionOfficer.objects.filter(id=officer_id)
    
    if not officer:
        raise Http404
    
    officer = officer[0]
    
    if request.method == "GET":
        user = User.objects.filter(id=officer.user.id)[0]
        officer_form = forms.OfficerEditForm(election=election, 
                            initial={'user_id':user.user_id, 'name':user.name,
                                     'email':user.info['email']}, instance=officer)
        #officer_form.fields['user_id'] = user.user_id
        #officer_form.fields['name'] = user.name
        #officer_form.fields['email'] = user.info['email']
    else:
        officer_form = forms.OfficerEditForm(request.POST, instance=officer, election=election)
        
        if officer_form.is_valid():
            user_params = dict(officer_form.cleaned_data)
            
            #process officer for User object
            
            #create random password for officer
            password = helios_utils.random_string(length=10)
            
            info = {'email':user_params['email'], 'password':password}
            
            
            #create and save user info to database
            user = User.update_or_create(user_type='password', user_id=user_params['user_id'], 
                            name=user_params['name'] , info=info)
            
            #create ElectionOfficer object and save to database
            officer = officer_form.save(commit=False)
            officer.election = election
            officer.user = user
            officer.save()
            #save values of the role many to many field
            officer_form.save_m2m()
            
            if officer.super_p:
                officer.electionrole.add(ElectionRole.get_or_create_election_admin_role(election))
            #election_officer = ElectionOfficer.objects.create(user=user, election=election, 
            #                        super_p = user_params['super_p'])
            
            messages.success(request, "Election Officer %s details was successfully updated." % (officer))
            return HttpResponseRedirect(reverse(one_election_officers_list, args=[election.uuid]))
    
    return render_template(request, 'admin/user_edit', {
        'election':election, 'officer_form':officer_form,
        'error':error})
    
@election_admin(frozen=False, perm_needed='delete_electionofficer')
def user_delete(request, election, officer_id, **kw):
    
    #check for conditions before delete
    #but for now, allow deletion
    officer = ElectionOfficer.objects.filter(election=election, id=officer_id)
    
    if officer:
        v_policies = ValidationPolicy.get_by_election_and_officer(election, officer[0], delete=True)
        if v_policies:
            messages.error(request, "Officer %s cannot be deleted. Officer is needed on the following validation policies:" %(officer[0].user.name))
            for v in v_policies:
                messages.error(request, v.description)
                
        else:
            admins = ElectionOfficer.objects.filter(election=election, super_p=True).exclude(id=officer[0].id)
            if not admins:
                messages.error(request, "Officer %s is the lone Election Administrator of this election." % officer[0].user.name)
            else:
                officer[0].delete()
                messages.success(request, "Officer %s was successfully deleted from this election." % (officer[0].user.name))
        
    return HttpResponseRedirect(reverse(one_election_officers_list, args=[election.uuid]))
    
#page for creating election roles
@election_view()
def one_election_roles_list(request, election, **kw):
    #url of referer view
    referer_view = get_referer_view(request)
    #url of a certain view
    view_url = reverse(one_election_view,args=[election.uuid])

    if referer_view == view_url:
        unassigned_perms = Permission.get_unassigned_permissions_by_election(election)
        messages.info(request, "The following permissions has not been assigned to any role yet.")
        for perm in unassigned_perms:
            messages.error(request, perm)
    election_roles = ElectionRole.objects.filter(election=election).exclude(name=helios.ELECTION_ADMIN_ROLE)
    
    
    return render_template(request, 'admin/roles_list',{
                            'election':election, 'e_roles':election_roles})
@election_admin(frozen=False, perm_needed='add_electionrole')
def role_new(request, election, **kw):
    
    error = None
    
    if request.method == "GET":
        role_form = forms.RoleForm()
    else:
        role_form = forms.RoleForm(request.POST)
        if role_form.is_valid():
            #since election field was not included in the form, we have to manually set its value here
            role = role_form.save(commit=False)
            role.election = election
            role.save()
            
            #save the values of the many-to-many field permissions
            role_form.save_m2m()
            
            #role_params = dict(role_form.cleaned_data)
            #ElectionRole.objects.create(name=role_params['name'], election=election)
            messages.success(request, "Role %s was successfully added." % (role))
            
            return HttpResponseRedirect(reverse(one_election_roles_list, args=[election.uuid]))
    
    return render_template(request, 'admin/role_new', {
                            'election':election, 'role_form':role_form})

@election_admin(frozen=False, perm_needed='change_electionrole')
def role_edit(request, election, role_id, **kw):
    
    role = ElectionRole.objects.filter(id=role_id)[0]
    #do some check here
    if not role:
        raise Http404
    
    if request.method == "GET":
        #get instance of the election role, using role_id
        role = ElectionRole.objects.get(id=role_id)
        role_form = forms.RoleForm(instance=role)
    else:
        role_form = forms.RoleForm(request.POST, instance=role)
        if role_form.is_valid():
            #since election field was not included in the form, we have to manually set its value here
            role = role_form.save(commit=False)
            role.election = election
            role.save()
            
            #save the values of the many-to-many field permissions
            role_form.save_m2m()
            
            #role_params = dict(role_form.cleaned_data)
            #ElectionRole.objects.create(name=role_params['name'], election=election)
            messages.success(request, "Role %s was successfully updated." % (role))
            return HttpResponseRedirect(reverse(one_election_roles_list, args=[election.uuid]))
        
    return render_template(request, 'admin/role_edit', {
                            'election':election, 'role_form':role_form})

@election_admin(frozen=False, perm_needed='delete_electionrole')
def role_delete(request, election, role_id, **kw):
    
    #check for conditions before delete
    #but for now, allow deletion
    role = ElectionRole.objects.filter(election=election, id=role_id)
    
    if role:
        #get all validation policies where role is used
        v_policies = ValidationPolicy.get_by_election_and_role(election, election_role=role[0])
        if v_policies:
            messages.error(request, "Role %s cannot be deleted. It used on the following validation policies:" %(role[0]))
            for v in v_policies:
                messages.error(request, v.description)
                
        else:    
            role[0].delete()
            messages.success(request, "Role %s was successfully deleted." % (role[0]))
    return HttpResponseRedirect(reverse(one_election_roles_list, args=[election.uuid]))
    
@election_view()
def one_validations_list(request, election, **kw):

    perms = Permission.objects.all().exclude(codename__in=settings.ELECTION_ADMIN_PERMS)
    for perm in perms:
        #a separate validation policy can be defined for per permission per election
        perm_policies = perm.validationpolicy_set.filter(election=election, status=ValidationPolicy.ACTIVE)
        if perm_policies:
            setattr(perm, 'policy', perm_policies[0])
            
    return render_template(request, 'admin/validations_list', {
                            'election':election, 'perms':perms})

@election_admin(frozen=False, perm_needed='add_policy')
def policy_new(request, election, perm_id, **kw):
    error = None
    
    if not perm_id:
        raise Http404()
    
    EntryFormSet = modelformset_factory(ValidationEntry, form=forms.PolicyEntryForm, formset=forms.BaseEntryFormSet, can_delete=True)
    EntryFormSet.form = staticmethod(curry(forms.PolicyEntryForm, election=election))
    
    perm = Permission.objects.get(id=perm_id)
    policy = ValidationPolicy(permission=perm)
        
    if request.method == "GET":    
        policy_form = forms.PolicyForm(initial= {'description':ValidationPolicy.DESCRIPTION[perm.codename]}, 
                                       perm_id=perm_id, instance=policy)            
        formset = EntryFormSet(prefix='pentries', queryset=ValidationEntry.objects.none())
    elif 'add' in request.POST:
        policy_form = forms.PolicyForm(request.POST)
        cp = request.POST.copy()
        cp['pentries-TOTAL_FORMS'] = int(cp['pentries-TOTAL_FORMS']) + 1
        formset = EntryFormSet(cp, prefix='pentries')
    else:
        policy_form = forms.PolicyForm(request.POST)
        formset = EntryFormSet(request.POST, prefix='pentries')
        
        if policy_form.is_valid() and formset.is_valid():     
            instances = formset.save(commit=False)
            if instances:
                policy = policy_form.save(commit=False)
                policy.election = election
                policy.save()
                            
                for instance in instances:
                    instance.validation_policy = policy
                    instance.save()
                
            messages.success(request, "validation policy, %s was successfully added for permission %s" % (policy, policy.permission))    
            return HttpResponseRedirect(reverse(one_validations_list, args=[election.uuid]))
    return render_template(request, 'admin/policy_new', {
                            'election':election, 'policy_form':policy_form,
                            'formset':formset, 'error':error})

@election_view()
def policy_details(request, election, val_id, **kw):
    
    policy = ValidationPolicy.objects.filter(id=val_id, status='active')[0]
    entries = policy.validationentry_set.all().order_by('order')
    
    return render_template(request, 'admin/policy_details', {
                            'election':election, 'policy':policy,
                            'entries':entries})

@election_admin(frozen=False, perm_needed='change_policy')
def policy_edit(request, election, val_id, **kw):
    error = None
    policy = ValidationPolicy.objects.filter(id=val_id, status='active')[0]
    EntryFormSet = modelformset_factory(ValidationEntry, form=forms.PolicyEntryForm, can_delete=True, formset=forms.BaseEntryFormSet)
    EntryFormSet.form = staticmethod(curry(forms.PolicyEntryForm, election=election))
    
    if not policy:
        raise Http404()
    
    if request.method == "GET":    
        policy_form = forms.PolicyForm(perm_id=policy.permission.id, instance=policy)
        formset = EntryFormSet(prefix='pentries', queryset=ValidationEntry.objects.filter(validation_policy=policy).order_by('order'))        
    elif 'add' in request.POST:
        policy_form = forms.PolicyForm(request.POST)
        cp = request.POST.copy()
        cp['pentries-TOTAL_FORMS'] = int(cp['pentries-TOTAL_FORMS']) + 1
        formset = EntryFormSet(cp, prefix='pentries')
    else:
        
        policy_form = forms.PolicyForm(request.POST, instance=policy)
        formset = EntryFormSet(request.POST, prefix='pentries')
        
        if policy_form.is_valid() and formset.is_valid():
            
            all_instances = []
            for form in formset.forms:
#an error happens at form.cleaned_data
                if form.is_valid():
                    instance = form.cleaned_data
                    if instance:
                        if not instance['DELETE']:
                            all_instances.append(instance)
            
            if all_instances:
                #create a new validation policy instead
                policy = policy_form.save(commit=False)
                p = ValidationPolicy.create(policy_old=policy, v_entries=all_instances)
                
                messages.success(request, "validation policy, %s was successfully updated." % (p))
                return HttpResponseRedirect(reverse(one_validations_list, args=[election.uuid]))
            
    return render_template(request, 'admin/policy_edit', {
                            'election':election, 'policy_form':policy_form,
                            'formset':formset, 'error':error})

@election_admin(frozen=False, perm_needed='delete_policy')
def policy_delete(request, election, val_id, **kw):
    policy = ValidationPolicy.objects.filter(id=val_id)
    #print policy
    if policy:
        #don't delete it, just override it. 
        policy[0].override()
        messages.success(request, "The validation policy was successfuly deactivated.")
        
    return HttpResponseRedirect(reverse(one_validations_list, args=[election.uuid]))

@election_view()
def requests_list(request, election, **kw):
    all_v_requests = ValidationRequest.get_active_requests_by_election(election)
    voter_v_requests = ValidationRequest.get_active_voter_requests_by_election(election)
    other_v_requests = ValidationRequest.get_active_other_requests_by_election(election)
    return render_template(request, 'admin/requests', {
                                    'election' : election, 'no_active_voter_requests':len(voter_v_requests),
                                    'no_active_other_requests':len(other_v_requests),  
                                    'no_active_ballot_requests':len(all_v_requests) - len(voter_v_requests)-len(other_v_requests)})
  
@election_view()
def requests_ballot(request, election, **kw):
    
    #ballot preview url
    
    try:
        ballot_requests = ValidationRequest.objects.filter(election_uuid=election.uuid,modeltype=helios.ELECTION, action=Election.DEFINE_BALLOT).order_by('-terminated_at')
        for r in ballot_requests:
            r.set_user(get_user(request), request)
    except ObjectDoesNotExist:
        ballot_requests = None
        #return HttpResponseRedirect(reverse(requests_list, args=[election.uuid]))
        
    return render_template(request, 'admin/requests_ballot', {
                                    'election' : election, 'ballot_requests':ballot_requests})

@election_view()
def ballot_req_details(request, election, vr_id, **kw):
    #ballot preview url
    p_url = None
    try:
        #get the ballot definition validation request being currently processed
        v_request = ValidationRequest.objects.get(id=vr_id, modeltype=helios.ELECTION)
        v_request.set_user(get_user(request), request)
        v_history = v_request.validationentrymonitor_set.all().order_by('validation_entry__order')
        p_url = "%s/booth/vote.html?%s" % (settings.SECURE_URL_HOST, urllib.urlencode({'election_url' : reverse(one_election, args=[election.uuid, 'ballot_request', v_request.id])}))
    except ObjectDoesNotExist:
        v_request = None
        v_history = None
        #return HttpResponseRedirect(reverse(requests_list, args=[election.uuid]))
        
    return render_template(request, 'admin/ballot_req_details', {
                                    'election' : election, 'v_request': v_request,
                                    'v_history': v_history, 'p_url': p_url})
@election_view()
def requests_voters(request, election, **kw):
    
    registrants_vr = ValidationRequest.objects.filter(election_uuid = election.uuid, modeltype=helios.VOTER).order_by('-terminated_at')
    
    for r in registrants_vr:
        r.set_user(get_user(request), request)
    #if not registrants_vr:
    #    messages.error(request, "NO NEW voter registration has been uploaded yet!")
    #    return HttpResponseRedirect(get_referer_view(request))
        
    return render_template(request, 'admin/requests_voters', {
                                    'election' : election, 'registrants':registrants_vr})

@election_view()
def voter_req_details(request, election, vr_id, **kw):
    try:
        v_request = ValidationRequest.objects.get(id=vr_id, modeltype=helios.VOTER)
        v_request.set_user(get_user(request), request)
        v_history = v_request.validationentrymonitor_set.all().order_by('validation_entry__order')
        
    except:
        v_request = None
        v_history = None
        messages.error(request, "Validation Request does not exist!")
        
    return render_template(request, 'admin/voter_request_details', {
                                    'election' : election, 'v_request':v_request,
                                    'v_history':v_history})
@election_view()
def request_details(request, election, vr_id, **kw):
    try:
        v_request = ValidationRequest.objects.get(id=vr_id, modeltype=helios.ELECTION)
        v_request.set_user(get_user(request), request)
        v_history = v_request.validationentrymonitor_set.all().order_by('validation_entry__order')
    except:
        v_request = None
        v_history = None
        messages.error(request, "Validation Request does not exist!")
    return render_template(request, 'admin/request_details', {
                                    'election' : election, 'v_request':v_request,
                                    'v_history':v_history})
    
@election_view()
def requests_trustees(request, election, **kw):
    return render_template(request, 'admin/requests_trustee', {
                                    'election' : election })

@election_view()
def other_requests(request, election, **kw):
    
    proc_requests = list(ValidationRequest.objects.filter(object_uuid=election.uuid).exclude(action=Election.DEFINE_BALLOT).order_by('-terminated_at'))
    
    for r in proc_requests:
        r.set_user(get_user(request), request)
    return render_template(request, 'admin/other_requests', {
                                    'election':election, 'proc_requests':proc_requests})
@election_view()
def approve_request(request, election, vr_id, **kw):
    prompt = None
    try:
        v_request = ValidationRequest.objects.get(id=vr_id)
        e_officer = get_officer(get_user(request), election)
        print "hi approve ako"
        
        if e_officer.approve(v_request, request):
            #FIXME:
            #code for committing the action on the validation request
            #need to do this in a more clean manner
            # need to check the difference in semantics of valid and satisfied!
            
            if v_request.satisfied:
                commit_request(election, v_request, request)
            else:
                messages.success(request, "Your decision on the validation request has been recorded successfully.")
        
        #return HttpResponseRedirect(reverse(requests_list, args=[election.uuid]))
        return HttpResponseRedirect(get_referer_view(request))
        
    except ObjectDoesNotExist:
        raise Http404("The validation request does not exist in the records.")

def commit_request(election, v_request, request=None):
    obj = None
    if v_request.satisfied:
        if v_request.action == Election.DEFINE_BALLOT and v_request.modeltype==helios.ELECTION:
            data = v_request.data
            model_type = v_request.modeltype
            election_type = ContentType.objects.get(model=model_type)
            #election_class = election_type.model_class()
            obj = election_type.get_object_for_this_type(uuid=data['old_obj']['uuid'])
            for attr in data['input']:
                if hasattr(obj, attr):
                    setattr(obj, attr, data['input'][attr]) 
            obj.save()
            v_request.data['output'] = obj.toJSONDict(update=True)
            v_request.save()
            v_request.commit()
            messages.success(request, "Ballot design has been successfully committed.")
        elif v_request.action == Voter.ADD and v_request.modeltype == helios.VOTER:
            obj = Voter.create_from_vrequest(v_request)
            v_request.data['output'] = obj.toJSONDict(update=True)
            v_request.save()
            v_request.commit()
            messages.success(request, "%s has been added to the official list of voters!" % (obj.voter_name))
        elif v_request.action == Voter.DELETE and v_request.modeltype == helios.VOTER:
            data = v_request.data
            model_type = v_request.modeltype
            voter_type = ContentType.objects.get(model=model_type)
            obj = voter_type.get_object_for_this_type(uuid=data['old_obj']['uuid'])
            messages.success(request, "%s has now been removed from the official list of voters." % (obj.voter_name))
            obj.delete()
            v_request.data['output'] = {}
            v_request.save()
            v_request.commit()
        elif v_request.action == Election.OPEN and v_request.modeltype == helios.ELECTION:
            data = v_request.data
            model_type = v_request.modeltype
            election_type = ContentType.objects.get(model=model_type)
            obj = election_type.get_object_for_this_type(uuid=data['old_obj']['uuid'])
            for attr in data['input']:
                if hasattr(obj, attr):
                    setattr(obj, attr, data['input'][attr])
            obj.freeze() 
            v_request.commit()
            obj.frozen_at = v_request.committed_at
            obj.save()
            v_request.data['output'] = obj.toJSONDict(update=True)
            v_request.save()
            messages.success(request, "Voting is now officially open!")
        elif v_request.action == Election.RELEASE and v_request.modeltype == helios.ELECTION:
            data = v_request.data
            model_type = v_request.modeltype
            election_type = ContentType.objects.get(model=model_type)
            obj = election_type.get_object_for_this_type(uuid=data['old_obj']['uuid'])
            for attr in data['input']:
                if hasattr(obj, attr):
                    setattr(obj, attr, data['input'][attr])
            obj.combine_decryptions()
            obj.save()
            v_request.data['output'] = obj.toJSONDict(update=True)
            v_request.save()
            v_request.commit()
            messages.success(request, "The results of the election is now officially released!")
        elif v_request.action == Election.CLOSE and v_request.modeltype == helios.ELECTION:
            data = v_request.data
            model_type = v_request.modeltype
            election_type = ContentType.objects.get(model=model_type)
            obj = election_type.get_object_for_this_type(uuid=data['old_obj']['uuid'])
            for attr in data['input']:
                if hasattr(obj, attr):
                    setattr(obj, attr, data['input'][attr])
            obj.tallying_started_at = datetime.datetime.utcnow()
            obj.save()
            tasks.election_compute_tally.delay(election_id = obj.id)
            v_request.data['output'] = obj.toJSONDict(update=True)
            v_request.save()
            v_request.commit()
            messages.success(request, "Tallying of the votes has begun!")
        return obj

@election_view()
def reject_request(request, election, vr_id, **kw):
    prompt = None
    try:
        v_request = ValidationRequest.objects.get(id=vr_id)
        e_officer = get_officer(get_user(request), election)
        
        #election officer reject request
        if e_officer.reject(v_request, request):
            messages.success(request, "Your decision on the validation request has been recorded successfully.")
        
        return HttpResponseRedirect(get_referer_view(request))
        
    except ObjectDoesNotExist:
        raise Http404("The validation request does not exist in the records.")

@election_view()
def ignore_request(request, election, vr_id, **kw):
    prompt = None
    try:
        v_request = ValidationRequest.objects.get(id=vr_id)
        e_officer = get_officer(get_user(request), election)
        
        #election officer abstain request
        if e_officer.ignore(v_request, request):
            messages.success(request, "Your decision on the validation request has been recorded successfully.")
            
        return HttpResponseRedirect(get_referer_view(request))
        
    except ObjectDoesNotExist:
        raise Http404("The validation request does not exist in the records.")

@election_view()
@json
def verify_object_by_uuid(request, election, uuid):
    validity = None
    #must be an election object uuid
    if election.uuid == uuid:
        validity = election.check_validity_on_vrequests()
    else:
        voter = Voter.get_by_election_and_uuid(election, uuid)
        validity = voter.check_validity_on_vrequests()
        
    return {'validity': validity}

@election_view()
@json
def election_questions(request, election, **kw):
    return utils.hash_b64(utils.to_json(election.questions))



    
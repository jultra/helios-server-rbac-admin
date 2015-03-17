# -*- coding: utf-8 -*-
"""
Data Objects for Helios.

Ben Adida
(ben@adida.net)
"""

from django.db import models, transaction
from django.utils import simplejson
from django.conf import settings
from django.core.mail import send_mail
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied

#added by John Ultra
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.http import *
import messages

import datetime, logging, uuid, random, StringIO

from crypto import electionalgs, algs, utils
from helios import utils as heliosutils
import helios.views

from helios import datatypes 

# useful stuff in auth
from helios_auth.models import User, AUTH_SYSTEMS, Permission
from helios_auth.jsonfield import JSONField
from helios.datatypes.djangofield import LDObjectField

import csv, copy

  
class HeliosModel(models.Model, datatypes.LDObjectContainer):
  class Meta:
    abstract = True

  #enumerate the field names of a model
  @classmethod
  def field_names(cls):
    fields = cls._meta.fields + cls._meta.many_to_many
    field_names = []
    
    for field in fields:
        field_names.append(field.name)
    return field_names  
  
  def check_validity_on_vrequests(self):
      
      if isinstance(self, Election):
          election = self
    
      if hasattr(self, 'election'):
          election = self.election
            
      v_requests = ValidationRequest.get_by_object_uuid_and_election(object_uuid=self.uuid, election=election)
      #convert to list
      vr_list = list(v_requests)
      cleaned_vr_list = []
      for r in vr_list:
          if r.satisfied:
              #consider only satisfied validation request 
              cleaned_vr_list.append(r)
      
      cur_obj = self.toJSONDict(update=True)
      length = len(cleaned_vr_list)
      
      #firstly, check if the 'output' of the latest validation request 
      #is THE SAME as the current state of the object
      if len(cleaned_vr_list) > 1: 
          if not cur_obj == cleaned_vr_list[length-1].data['output']:
              return False
      
      #traverse the cleaned vr list, checking if the 'output' of a validation request 
      #is THE SAME as 'old_obj' of the validation request succeeding it.  
      for i in xrange(length-1):
          if not cleaned_vr_list[i].data['output'] == cleaned_vr_list[i+1].data['old_obj']:
              return False
      
      return True
  
class Election(HeliosModel):

  OPEN = 'open election'
  CLOSE = 'close election and start tallying votes'
  RELEASE = 'release results'
  DEFINE_BALLOT = 'define ballot'
  
  #election creator
  admin = models.ForeignKey(User, related_name='elections')
  
  #other election administrators and officers  
  election_officers = models.ManyToManyField(User, through='ElectionOfficer')
  
  
  uuid = models.CharField(max_length=50, null=False, unique=True)

  # keep track of the type and version of election, which will help dispatch to the right
  # code, both for crypto and serialization
  # v3 and prior have a datatype of "legacy/Election"
  # v3.1 will still use legacy/Election
  # later versions, at some point will upgrade to "2011/01/Election"
  datatype = models.CharField(max_length=250, null=False, default="legacy/Election")
  
  short_name = models.CharField(max_length=100)
  name = models.CharField(max_length=250)
  
  ELECTION_TYPES = (
    ('election', 'Election'),
    ('referendum', 'Referendum')
    )

  election_type = models.CharField(max_length=250, null=False, default='election', choices = ELECTION_TYPES)
  private_p = models.BooleanField(default=False, null=False)

  description = models.TextField()
  public_key = LDObjectField(type_hint = 'legacy/EGPublicKey',
                             null=True)
  private_key = LDObjectField(type_hint = 'legacy/EGSecretKey',
                              null=True)
  
  questions = LDObjectField(type_hint = 'legacy/Questions',
                            null=True)
  
  # eligibility is a JSON field, which lists auth_systems and eligibility details for that auth_system, e.g.
  # [{'auth_system': 'cas', 'constraint': [{'year': 'u12'}, {'year':'u13'}]}, {'auth_system' : 'password'}, {'auth_system' : 'openid', 'constraint': [{'host':'http://myopenid.com'}]}]
  eligibility = LDObjectField(type_hint = 'legacy/Eligibility',
                              null=True)

  # open registration?
  # this is now used to indicate the state of registration,
  # whether or not the election is frozen
  openreg = models.BooleanField(default=False)
  
  # featured election?
  featured_p = models.BooleanField(default=False)
    
  # voter aliases?
  use_voter_aliases = models.BooleanField(default=False)
  use_advanced_audit_features = models.BooleanField(default=True, null=False)
  
  # where votes should be cast
  cast_url = models.CharField(max_length = 500)

  # dates at which this was touched
  created_at = models.DateTimeField(auto_now_add=True)
  modified_at = models.DateTimeField(auto_now_add=True)
  
  # dates at which things happen for the election
  frozen_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  archived_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  
  # dates for the election steps, as scheduled
  # these are always UTC
  registration_starts_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  voting_starts_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  voting_ends_at = models.DateTimeField(auto_now_add=False, default=None, null=True)

  # if this is non-null, then a complaint period, where people can cast a quarantined ballot.
  # we do NOT call this a "provisional" ballot, since provisional implies that the voter has not
  # been qualified. We may eventually add this, but it can't be in the same CastVote table, which
  # is tied to a voter.
  complaint_period_ends_at = models.DateTimeField(auto_now_add=False, default=None, null=True)

  tallying_starts_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  
  # dates when things were forced to be performed
  voting_started_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  voting_extended_until = models.DateTimeField(auto_now_add=False, default=None, null=True)
  voting_ended_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  tallying_started_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  tallying_finished_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
  tallies_combined_at = models.DateTimeField(auto_now_add=False, default=None, null=True)

  # the hash of all voters (stored for large numbers)
  voters_hash = models.CharField(max_length=100, null=True)
  
  # encrypted tally, each a JSON string
  # used only for homomorphic tallies
  encrypted_tally = LDObjectField(type_hint = 'legacy/Tally',
                                  null=True)

  # results of the election
  result = LDObjectField(type_hint = 'legacy/Result',
                         null=True)

  # decryption proof, a JSON object
  # no longer needed since it's all trustees
  result_proof = JSONField(null=True)

  @property
  def pretty_type(self):
    return dict(self.ELECTION_TYPES)[self.election_type]

  @property
  def num_cast_votes(self):
    return self.voter_set.exclude(vote=None).count()

  @property
  def num_voters(self):
    return self.voter_set.count()

  @property
  def num_trustees(self):
    return self.trustee_set.count()

  @property
  def last_alias_num(self):
    """
    FIXME: we should be tracking alias number, not the V* alias which then
    makes things a lot harder
    """
    if not self.use_voter_aliases:
      return None
    
    return heliosutils.one_val_raw_sql("select max(cast(substring(alias, 2) as integer)) from " + Voter._meta.db_table + " where election_id = %s", [self.id]) or 0

  @property
  def encrypted_tally_hash(self):
    if not self.encrypted_tally:
      return None

    return utils.hash_b64(self.encrypted_tally.toJSON())

  @property
  def is_archived(self):
    return self.archived_at != None

  @classmethod
  def get_featured(cls):
    return cls.objects.filter(featured_p = True).order_by('short_name')
    
  @classmethod
  def get_or_create(cls, **kwargs):
    return cls.objects.get_or_create(short_name = kwargs['short_name'], defaults=kwargs)

  @classmethod
  def get_by_user_as_admin(cls, user, archived_p=None, limit=None):
    query = cls.objects.filter(admin = user)
    if archived_p == True:
      query = query.exclude(archived_at= None)
    if archived_p == False:
      query = query.filter(archived_at= None)
    query = query.order_by('-created_at')
    if limit:
      return query[:limit]
    else:
      return query

  #added by John Utra
  #gets all elections where a user is an officer, not necessarily an admin
  
  @classmethod
  def get_by_user_as_officer(cls, user, archived_p=None, limit=None):
      query = cls.objects.filter(election_officers=user)
      query = query.order_by('-created_at')
      if not query:
          return None
      return query
  
  @classmethod
  def get_by_user_as_voter(cls, user, archived_p=None, limit=None):
    query = cls.objects.filter(voter__user = user)
    if archived_p == True:
      query = query.exclude(archived_at= None)
    if archived_p == False:
      query = query.filter(archived_at= None)
    query = query.order_by('-created_at')
    if limit:
      return query[:limit]
    else:
      return query
    
  @classmethod
  def get_by_uuid(cls, uuid):
    try:
      return cls.objects.select_related().get(uuid=uuid)
    except cls.DoesNotExist:
      return None
  
  @classmethod
  def get_by_short_name(cls, short_name):
    try:
      return cls.objects.get(short_name=short_name)
    except cls.DoesNotExist:
      return None

  def add_voters_file(self, uploaded_file):
    """
    expects a django uploaded_file data structure, which has filename, content, size...
    """
    # now we're just storing the content
    # random_filename = str(uuid.uuid4())
    # new_voter_file.voter_file.save(random_filename, uploaded_file)

    new_voter_file = VoterFile(election = self, voter_file_content = uploaded_file.read())
    new_voter_file.save()
    
    self.append_log(ElectionLog.VOTER_FILE_ADDED)
    return new_voter_file
  
  def user_eligible_p(self, user):
    """
    Checks if a user is eligible for this election.
    """
    # registration closed, then eligibility doesn't come into play
    if not self.openreg:
      return False
    
    if self.eligibility == None:
      return True
      
    # is the user eligible for one of these cases?
    for eligibility_case in self.eligibility:
      if user.is_eligible_for(eligibility_case):
        return True
        
    return False

  def eligibility_constraint_for(self, user_type):
    if not self.eligibility:
      return []

    # constraints that are relevant
    relevant_constraints = [constraint['constraint'] for constraint in self.eligibility if constraint['auth_system'] == user_type]
    if len(relevant_constraints) > 0:
      return relevant_constraints[0]
    else:
      return []

  def eligibility_category_id(self, user_type):
    "when eligibility is by category, this returns the category_id"
    if not self.eligibility:
      return None
    
    constraint_for = self.eligibility_constraint_for(user_type)
    if len(constraint_for) > 0:
      constraint = constraint_for[0]
      return AUTH_SYSTEMS[user_type].eligibility_category_id(constraint)
    else:
      return None
    
  @property
  def pretty_eligibility(self):
    if not self.eligibility:
      return "Anyone can vote."
    else:
      return_val = "<ul>"
      
      for constraint in self.eligibility:
        if constraint.has_key('constraint'):
          for one_constraint in constraint['constraint']:
            return_val += "<li>%s</li>" % AUTH_SYSTEMS[constraint['auth_system']].pretty_eligibility(one_constraint)
        else:
          return_val += "<li> any %s user</li>" % constraint['auth_system']

      return_val += "</ul>"

      return return_val
  
  def voting_has_started(self):
    """
    has voting begun? voting begins if the election is frozen, at the prescribed date or at the date that voting was forced to start
    """
    return self.frozen_at != None and (self.voting_starts_at == None or (datetime.datetime.utcnow() >= (self.voting_started_at or self.voting_starts_at)))
    
  def voting_has_stopped(self):
    """
    has voting stopped? if tally computed, yes, otherwise if we have passed the date voting was manually stopped at,
    or failing that the date voting was extended until, or failing that the date voting is scheduled to end at.
    """
    voting_end = self.voting_ended_at or self.voting_extended_until or self.voting_ends_at
    return (voting_end != None and datetime.datetime.utcnow() >= voting_end) or self.encrypted_tally

  @property
  def issues_before_freeze(self):
    issues = []
    
    unassigned_perms = Permission.get_unassigned_permissions_by_election(self) 
    if unassigned_perms:
        issues.append(
            {'type':'permission',
             'action': 'assign permissions to election roles'
             }
            )
    unassigned_roles = ElectionRole.get_unassigned_roles_by_election(self)
    if unassigned_roles:
        issues.append(
            {'type':'election role',
             'action': 'assign election roles to election officers'
             }
            )
    if self.questions == None or len(self.questions) == 0:
      issues.append(
        {'type': 'questions',
         'action': "add questions to the ballot"}
        )
  
    trustees = Trustee.get_by_election(self)
    if len(trustees) == 0:
      issues.append({
          'type': 'trustees',
          'action': "add at least one trustee"
          })

    for t in trustees:
      if t.public_key == None:
        issues.append({
            'type': 'trustee keypairs',
            'action': 'have trustee %s generate a keypair' % t.name
            })

    if self.voter_set.count() == 0 and not self.openreg:
      issues.append({
          "type" : "voters",
          "action" : 'enter your voter list (or open registration to the public)'
          })

    return issues    

  def ready_for_tallying(self):
    return datetime.datetime.utcnow() >= self.tallying_starts_at

  def compute_tally(self):
    """
    tally the election, assuming votes already verified
    """
    tally = self.init_tally()
    for voter in self.voter_set.all():
      if voter.vote:
        tally.add_vote(voter.vote, verify_p=False)

    self.encrypted_tally = tally
    self.save()    
  
  def ready_for_decryption(self):
    return self.encrypted_tally != None
    
  def ready_for_decryption_combination(self):
    """
    do we have a tally from all trustees?
    """
    for t in Trustee.get_by_election(self):
      if not t.decryption_factors:
        return False
    
    return True
    
  def combine_decryptions(self):
    """
    combine all of the decryption results
    """
    
    # gather the decryption factors
    trustees = Trustee.get_by_election(self)
    decryption_factors = [t.decryption_factors for t in trustees]
    
    self.result = self.encrypted_tally.decrypt_from_factors(decryption_factors, self.public_key)

    self.append_log(ElectionLog.DECRYPTIONS_COMBINED)

    self.save()
  
  def generate_voters_hash(self):
    """
    look up the list of voters, make a big file, and hash it
    """

    ## FIXME: for now we don't generate this voters hash:
    #return

    if self.openreg:
      self.voters_hash = None
    else:
      voters = Voter.get_by_election(self)
      voters_json = utils.to_json([v.toJSONDict() for v in voters])
      self.voters_hash = utils.hash_b64(voters_json)
    
  def increment_voters(self):
    ## FIXME
    return 0
    
  def increment_cast_votes(self):
    ## FIXME
    return 0
        
  def set_eligibility(self):
    """
    if registration is closed and eligibility has not been
    already set, then this call sets the eligibility criteria
    based on the actual list of voters who are already there.

    This helps ensure that the login box shows the proper options.

    If registration is open but no voters have been added with password,
    then that option is also canceled out to prevent confusion, since
    those elections usually just use the existing login systems.
    """

    # don't override existing eligibility
    if self.eligibility != None:
      return

    # enable this ONLY once the cast_confirm screen makes sense
    #if self.voter_set.count() == 0:
    #  return

    auth_systems = copy.copy(settings.AUTH_ENABLED_AUTH_SYSTEMS)
    voter_types = [r['user__user_type'] for r in self.voter_set.values('user__user_type').distinct() if r['user__user_type'] != None]

    # password is now separate, not an explicit voter type
    if self.voter_set.filter(user=None).count() > 0:
      voter_types.append('password')
    else:
      # no password users, remove password from the possible auth systems
      if 'password' in auth_systems:
        auth_systems.remove('password')        

    # closed registration: limit the auth_systems to just the ones
    # that have registered voters
    if not self.openreg:
      auth_systems = [vt for vt in voter_types if vt in auth_systems]

    self.eligibility = [{'auth_system': auth_system} for auth_system in auth_systems]
    
    #bewate in calling self.save
    #self.save()    
    
  def freeze(self):
    """
    election is frozen when the voter registration, questions, and trustees are finalized
    """
    if len(self.issues_before_freeze) > 0:
      raise Exception("cannot freeze an election that has issues")

    self.frozen_at = datetime.datetime.utcnow()
    
    # voters hash
    self.generate_voters_hash()

    self.set_eligibility()
    
    # public key for trustees
    trustees = Trustee.get_by_election(self)
    combined_pk = trustees[0].public_key
    for t in trustees[1:]:
      combined_pk = combined_pk * t.public_key
      
    self.public_key = combined_pk
    
    # log it
    self.append_log(ElectionLog.FROZEN)

    #remove by John
    #self.save()

  def generate_trustee(self, params):
    """
    generate a trustee including the secret key,
    thus a helios-based trustee
    """
    # FIXME: generate the keypair
    keypair = params.generate_keypair()

    # create the trustee
    trustee = Trustee(election = self)
    trustee.uuid = str(uuid.uuid4())
    trustee.name = settings.DEFAULT_FROM_NAME
    trustee.email = settings.DEFAULT_FROM_EMAIL
    trustee.public_key = keypair.pk
    trustee.secret_key = keypair.sk
    
    # FIXME: is this at the right level of abstraction?
    trustee.public_key_hash = datatypes.LDObject.instantiate(trustee.public_key, datatype='legacy/EGPublicKey').hash

    trustee.pok = trustee.secret_key.prove_sk(algs.DLog_challenge_generator)

    trustee.save()

  def get_helios_trustee(self):
    trustees_with_sk = self.trustee_set.exclude(secret_key = None)
    if len(trustees_with_sk) > 0:
      return trustees_with_sk[0]
    else:
      return None
    
  def has_helios_trustee(self):
    return self.get_helios_trustee() != None

  def helios_trustee_decrypt(self):
    tally = self.encrypted_tally
    tally.init_election(self)

    trustee = self.get_helios_trustee()
    factors, proof = tally.decryption_factors_and_proofs(trustee.secret_key)

    trustee.decryption_factors = factors
    trustee.decryption_proofs = proof
    trustee.save()

  def append_log(self, text):
    item = ElectionLog(election = self, log=text, at=datetime.datetime.utcnow())
    item.save()
    return item

  def get_log(self):
    return self.electionlog_set.order_by('-at')

  @property
  def url(self):
    return helios.views.get_election_url(self)

  def init_tally(self):
    # FIXME: create the right kind of tally
    from helios.workflows import homomorphic
    return homomorphic.Tally(election=self)
        
  @property
  def registration_status_pretty(self):
    if self.openreg:
      return "Open"
    else:
      return "Closed"

  @classmethod
  def one_question_winner(cls, question, result, num_cast_votes):
    """
    determining the winner for one question
    """
    # sort the answers , keep track of the index
    counts = sorted(enumerate(result), key=lambda(x): x[1])
    counts.reverse()
    
    the_max = question['max'] or 1
    the_min = question['min'] or 0

    # if there's a max > 1, we assume that the top MAX win
    if the_max > 1:
      return [c[0] for c in counts[:the_max]]

    # if max = 1, then depends on absolute or relative
    if question['result_type'] == 'absolute':
      if counts[0][1] >=  (num_cast_votes/2 + 1):
        return [counts[0][0]]
      else:
        return []
    else:
      # assumes that anything non-absolute is relative
      return [counts[0][0]]    

  @property
  def winners(self):
    """
    Depending on the type of each question, determine the winners
    returns an array of winners for each question, aka an array of arrays.
    assumes that if there is a max to the question, that's how many winners there are.
    """
    return [self.one_question_winner(self.questions[i], self.result[i], self.num_cast_votes) for i in range(len(self.questions))]
    
  @property
  def pretty_result(self):
    if not self.result:
      return None
    
    # get the winners
    winners = self.winners

    raw_result = self.result
    prettified_result = []

    # loop through questions
    for i in range(len(self.questions)):
      q = self.questions[i]
      pretty_question = []
      
      # go through answers
      for j in range(len(q['answers'])):
        a = q['answers'][j]
        count = raw_result[i][j]
        pretty_question.append({'answer': a, 'count': count, 'winner': (j in winners[i])})
        
      prettified_result.append({'question': q['short_name'], 'answers': pretty_question})

    return prettified_result
  
    
  
class ElectionLog(models.Model):
  """
  a log of events for an election
  """

  FROZEN = "frozen"
  VOTER_FILE_ADDED = "voter file added"
  DECRYPTIONS_COMBINED = "decryptions combined"
  
  VOTER_ADDED = "voter added"
  VOTER_DELETED = "voter deleted"
  
  election = models.ForeignKey(Election)
  log = models.CharField(max_length=500)
  at = models.DateTimeField(auto_now_add=True)
  #who = models.ForeignKey(ElectionOfficer) 

##
## UTF8 craziness for CSV
##

def unicode_csv_reader(unicode_csv_data, dialect=csv.excel, **kwargs):
    # csv.py doesn't do Unicode; encode temporarily as UTF-8:
    csv_reader = csv.reader(utf_8_encoder(unicode_csv_data),
                            dialect=dialect, **kwargs)
    for row in csv_reader:
      # decode UTF-8 back to Unicode, cell by cell:
      try:
        yield [unicode(cell, 'utf-8') for cell in row]
      except:
        yield [unicode(cell, 'latin-1') for cell in row]        

def utf_8_encoder(unicode_csv_data):
    for line in unicode_csv_data:
      # FIXME: this used to be line.encode('utf-8'),
      # need to figure out why this isn't consistent
      yield line
  
class VoterFile(models.Model):
  """
  A model to store files that are lists of voters to be processed
  """
  # path where we store voter upload 
  PATH = settings.VOTER_UPLOAD_REL_PATH

  election = models.ForeignKey(Election)

  # we move to storing the content in the DB
  voter_file = models.FileField(upload_to=PATH, max_length=250,null=True)
  voter_file_content = models.TextField(null=True)

  uploaded_at = models.DateTimeField(auto_now_add=True)
  processing_started_at = models.DateTimeField(auto_now_add=False, null=True)
  processing_finished_at = models.DateTimeField(auto_now_add=False, null=True)
  num_voters = models.IntegerField(null=True)

  def itervoters(self):
    if self.voter_file_content:
      voter_stream = StringIO.StringIO(self.voter_file_content)
    else:
      voter_stream = open(self.voter_file.path, "rU")

    reader = unicode_csv_reader(voter_stream)

    for voter_fields in reader:
      # bad line
      if len(voter_fields) < 1:
        continue
    
      return_dict = {'voter_id': voter_fields[0]}

      if len(voter_fields) > 1:
        return_dict['email'] = voter_fields[1]

      if len(voter_fields) > 2:
        return_dict['name'] = voter_fields[2]

      yield return_dict
     
  def process(self):
    self.processing_started_at = datetime.datetime.utcnow()
    self.save()

    election = self.election

    # now we're looking straight at the content
    if self.voter_file_content:
      voter_stream = StringIO.StringIO(self.voter_file_content)
    else:
      voter_stream = open(self.voter_file.path, "rU")

    reader = unicode_csv_reader(voter_stream)
    
    last_alias_num = election.last_alias_num

    num_voters = 0
    new_voters = []
    for voter in reader:
      # bad line
      if len(voter) < 1:
        continue
    
      num_voters += 1
      voter_id = voter[0].strip()
      name = voter_id
      email = voter_id
    
      if len(voter) > 1:
        email = voter[1].strip()
    
      if len(voter) > 2:
        name = voter[2].strip()
    
      # create the user -- NO MORE
      # user = User.update_or_create(user_type='password', user_id=email, info = {'name': name})
    
      # does voter for this user already exist
      voter = Voter.get_by_election_and_voter_id(election, voter_id)
    
      # create the voter
      if not voter:
        voter_uuid = str(uuid.uuid4())
        voter = Voter(uuid= voter_uuid, user = None, voter_login_id = voter_id,
                      voter_name = name, voter_email = email, election = election)
        voter.generate_password()
        new_voters.append(voter)
        voter.save()

    if election.use_voter_aliases:
      voter_alias_integers = range(last_alias_num+1, last_alias_num+1+num_voters)
      random.shuffle(voter_alias_integers)
      for i, voter in enumerate(new_voters):
        voter.alias = 'V%s' % voter_alias_integers[i]
        voter.save()

    self.num_voters = num_voters
    self.processing_finished_at = datetime.datetime.utcnow()
    self.save()

    return num_voters

  def registrants(self):
    #self.processing_started_at = datetime.datetime.utcnow()
    #self.save()

    election = self.election

    # now we're looking straight at the content
    if self.voter_file_content:
      voter_stream = StringIO.StringIO(self.voter_file_content)
    else:
      voter_stream = open(self.voter_file.path, "rU")

    reader = unicode_csv_reader(voter_stream)

    last_alias_num = election.last_alias_num

    num_voters = 0
    new_voters = []
    for voter in reader:
      # bad line
      if len(voter) < 1:
        continue
    
      num_voters += 1
      voter_id = voter[0].strip()
      name = voter_id
      email = voter_id
    
      if len(voter) > 1:
        email = voter[1].strip()
    
      if len(voter) > 2:
        name = voter[2].strip()
    
      # create the user -- NO MORE
      # user = User.update_or_create(user_type='password', user_id=email, info = {'name': name})
    
      # does voter for this user already exist
      voter = Voter.get_by_election_and_voter_id(election, voter_id)
    
      # create the voter
      if not voter:
        voter_uuid = str(uuid.uuid4())
        voter = Voter(uuid= voter_uuid, user = None, voter_login_id = voter_id,
                      voter_name = name, voter_email = email, election = election)
        new_voters.append(voter)
        
        #we just want to list the them....
        voter.generate_password()
        #voter.save()

    #what if, election which does not use alias is changed to use one?
    if election.use_voter_aliases:
      voter_alias_integers = range(last_alias_num+1, last_alias_num+1+num_voters)
      random.shuffle(voter_alias_integers)
      for i, voter in enumerate(new_voters):
        voter.alias = 'V%s' % voter_alias_integers[i]
        
        #voter.save()

    self.num_voters = num_voters
    
    #self.processing_finished_at = datetime.datetime.utcnow()
    #self.save()

    return new_voters

  def start_processing(self):
    self.processing_started_at = datetime.datetime.utcnow()
    self.save()
        
  def end_processing(self):
    self.processing_finished_at = datetime.datetime.utcnow()
    self.save()
    
class Voter(HeliosModel):
    
  DELETE = 'delete voter'
  ADD = 'add voter'
  
  election = models.ForeignKey(Election)
  
  # let's link directly to the user now
  # FIXME: delete this as soon as migrations are set up
  #name = models.CharField(max_length = 200, null=True)
  #voter_type = models.CharField(max_length = 100)
  #voter_id = models.CharField(max_length = 100)

  uuid = models.CharField(max_length = 50)
  
  # for users of type password, no user object is created
  # but a dynamic user object is created automatically
  user = models.ForeignKey('helios_auth.User', null=True)

  # if user is null, then you need a voter login ID and password
  voter_login_id = models.CharField(max_length = 100, null=True)
  voter_password = models.CharField(max_length = 100, null=True)
  voter_name = models.CharField(max_length = 200, null=True)
  voter_email = models.CharField(max_length = 250, null=True)
  
  # if election uses aliases
  alias = models.CharField(max_length = 100, null=True)
  
  # we keep a copy here for easy tallying
  vote = LDObjectField(type_hint = 'legacy/EncryptedVote',
                       null=True)
  vote_hash = models.CharField(max_length = 100, null=True)
  cast_at = models.DateTimeField(auto_now_add=False, null=True)

  
  
  class Meta:
    unique_together = (('election', 'voter_login_id'))

  def __init__(self, *args, **kwargs):
    super(Voter, self).__init__(*args, **kwargs)

    # stub the user so code is not full of IF statements
    if not self.user:
      self.user = User(user_type='password', user_id=self.voter_email, name=self.voter_name)

  @classmethod
  @transaction.commit_on_success
  def register_user_in_election(cls, user, election):
    voter_uuid = str(uuid.uuid4())
    voter = Voter(uuid= voter_uuid, user = user, election = election)

    # do we need to generate an alias?
    if election.use_voter_aliases:
      heliosutils.lock_row(Election, election.id)
      alias_num = election.last_alias_num + 1
      voter.alias = "V%s" % alias_num

    voter.save()
    return voter

  @classmethod
  def get_by_election(cls, election, cast=None, order_by='voter_login_id', after=None, limit=None):
    """
    FIXME: review this for non-GAE?
    """
    query = cls.objects.filter(election = election)
    
    # the boolean check is not stupid, this is ternary logic
    # none means don't care if it's cast or not
    if cast == True:
      query = query.exclude(cast_at = None)
    elif cast == False:
      query = query.filter(cast_at = None)

    # little trick to get around GAE limitation
    # order by uuid only when no inequality has been added
    if cast == None or order_by == 'cast_at' or order_by =='-cast_at':
      query = query.order_by(order_by)
      
      # if we want the list after a certain UUID, add the inequality here
      if after:
        if order_by[0] == '-':
          field_name = "%s__gt" % order_by[1:]
        else:
          field_name = "%s__gt" % order_by
        conditions = {field_name : after}
        query = query.filter (**conditions)
    
    if limit:
      query = query[:limit]
      
    return query
  
  @classmethod
  def get_all_by_election_in_chunks(cls, election, cast=None, chunk=100):
    return cls.get_by_election(election)

  @classmethod
  def get_by_election_and_voter_id(cls, election, voter_id):
    try:
      return cls.objects.get(election = election, voter_login_id = voter_id)
    except cls.DoesNotExist:
      return None
    
  @classmethod
  def get_by_election_and_user(cls, election, user):
    try:
      return cls.objects.get(election = election, user = user)
    except cls.DoesNotExist:
      return None
      
  @classmethod
  def get_by_election_and_uuid(cls, election, uuid):
    query = cls.objects.filter(election = election, uuid = uuid)

    try:
      return query[0]
    except:
      return None

  @classmethod
  def get_by_user(cls, user):
    return cls.objects.select_related().filter(user = user).order_by('-cast_at')

  @property
  def datatype(self):
    return self.election.datatype.replace('Election', 'Voter')

  @property
  def vote_tinyhash(self):
    """
    get the tinyhash of the latest castvote
    """
    if not self.vote_hash:
      return None
    
    return CastVote.objects.get(vote_hash = self.vote_hash).vote_tinyhash

  @property
  def election_uuid(self):
    return self.election.uuid

  @property
  def name(self):
    return self.user.name

  @property
  def voter_id(self):
    return self.user.user_id

  @property
  def voter_id_hash(self):
    if self.voter_login_id:
      # for backwards compatibility with v3.0, and since it doesn't matter
      # too much if we hash the email or the unique login ID here.
      value_to_hash = self.voter_login_id
    else:
      value_to_hash = self.voter_id

    try:
      return utils.hash_b64(value_to_hash)
    except:
      try:
        return utils.hash_b64(value_to_hash.encode('latin-1'))
      except:
        return utils.hash_b64(value_to_hash.encode('utf-8'))        

  @property
  def voter_type(self):
    return self.user.user_type

  @property
  def display_html_big(self):
    return self.user.display_html_big
      
  def send_message(self, subject, body):
    self.user.send_message(subject, body)

  def generate_password(self, length=10):
    if self.voter_password:
      raise Exception("password already exists")
    
    self.voter_password = heliosutils.random_string(length)

  def store_vote(self, cast_vote):
    # only store the vote if it's cast later than the current one
    if self.cast_at and cast_vote.cast_at < self.cast_at:
      return

    self.vote = cast_vote.vote
    self.vote_hash = cast_vote.vote_hash
    self.cast_at = cast_vote.cast_at
    self.save()
  
  def last_cast_vote(self):
    return CastVote(vote = self.vote, vote_hash = self.vote_hash, cast_at = self.cast_at, voter=self)
    
  @classmethod
  def create_from_vrequest(cls, v_request):
    election = Election.get_by_uuid(v_request.election_uuid) 
    data = v_request.data['input']
    
    #field_names = cls.field_names()
    #new_voter = cls()
    #for attr in data:
    #    if attr in field_names:
    #        setattr(new_voter, attr, data[attr])
    
    new_voter = cls(uuid=str(data['uuid']), voter_name=str(data['voter_name']), voter_login_id=str(data['voter_login_id']), 
                        voter_email=str(data['voter_email']), voter_password=str(data['voter_password']),
                        voter_type=str(data['voter_type']), election=election)
    new_voter.save()
    return new_voter

class CastVote(HeliosModel):
  # the reference to the voter provides the voter_uuid
  voter = models.ForeignKey(Voter)
  
  # the actual encrypted vote
  vote = LDObjectField(type_hint = 'legacy/EncryptedVote')

  # cache the hash of the vote
  vote_hash = models.CharField(max_length=100)

  # a tiny version of the hash to enable short URLs
  vote_tinyhash = models.CharField(max_length=50, null=True, unique=True)

  cast_at = models.DateTimeField(auto_now_add=True)

  # some ballots can be quarantined (this is not the same thing as provisional)
  quarantined_p = models.BooleanField(default=False, null=False)
  released_from_quarantine_at = models.DateTimeField(auto_now_add=False, null=True)

  # when is the vote verified?
  verified_at = models.DateTimeField(null=True)
  invalidated_at = models.DateTimeField(null=True)
  
  @property
  def datatype(self):
    return self.voter.datatype.replace('Voter', 'CastVote')

  @property
  def voter_uuid(self):
    return self.voter.uuid  
    
  @property
  def voter_hash(self):
    return self.voter.hash

  @property
  def is_quarantined(self):
    return self.quarantined_p and not self.released_from_quarantine_at

  def set_tinyhash(self):
    """
    find a tiny version of the hash for a URL slug.
    """
    safe_hash = self.vote_hash
    for c in ['/', '+']:
      safe_hash = safe_hash.replace(c,'')
    
    length = 8
    while True:
      vote_tinyhash = safe_hash[:length]
      if CastVote.objects.filter(vote_tinyhash = vote_tinyhash).count() == 0:
        break
      length += 1
      
    self.vote_tinyhash = vote_tinyhash

  def save(self, *args, **kwargs):
    """
    override this just to get a hook
    """
    # not saved yet? then we generate a tiny hash
    if not self.vote_tinyhash:
      self.set_tinyhash()

    super(CastVote, self).save(*args, **kwargs)
  
  @classmethod
  def get_by_voter(cls, voter):
    return cls.objects.filter(voter = voter).order_by('-cast_at')

  def verify_and_store(self):
    # if it's quarantined, don't let this go through
    if self.is_quarantined:
      raise Exception("cast vote is quarantined, verification and storage is delayed.")

    result = self.vote.verify(self.voter.election)
    print result
    
    if result:
      self.verified_at = datetime.datetime.utcnow()
    else:
      self.invalidated_at = datetime.datetime.utcnow()
      
    # save and store the vote as the voter's last cast vote
    self.save()

    if result:
      self.voter.store_vote(self)
    
    return result

  def issues(self, election):
    """
    Look for consistency problems
    """
    issues = []
    
    # check the election
    if self.vote.election_uuid != election.uuid:
      issues.append("the vote's election UUID does not match the election for which this vote is being cast")
    
    return issues
    
class AuditedBallot(models.Model):
  """
  ballots for auditing
  """
  election = models.ForeignKey(Election)
  raw_vote = models.TextField()
  vote_hash = models.CharField(max_length=100)
  added_at = models.DateTimeField(auto_now_add=True)

  @classmethod
  def get(cls, election, vote_hash):
    return cls.objects.get(election = election, vote_hash = vote_hash)

  @classmethod
  def get_by_election(cls, election, after=None, limit=None):
    query = cls.objects.filter(election = election).order_by('vote_hash')

    # if we want the list after a certain UUID, add the inequality here
    if after:
      query = query.filter(vote_hash__gt = after)

    if limit:
      query = query[:limit]

    return query
    
class Trustee(HeliosModel):
  election = models.ForeignKey(Election)
  
  uuid = models.CharField(max_length=50)
  name = models.CharField(max_length=200)
  email = models.EmailField()
  secret = models.CharField(max_length=100)
  
  # public key
  public_key = LDObjectField(type_hint = 'legacy/EGPublicKey',
                             null=True)
  public_key_hash = models.CharField(max_length=100)

  # secret key
  # if the secret key is present, this means
  # Helios is playing the role of the trustee.
  secret_key = LDObjectField(type_hint = 'legacy/EGSecretKey',
                             null=True)
  
  # proof of knowledge of secret key
  pok = LDObjectField(type_hint = 'legacy/DLogProof',
                      null=True)
  
  # decryption factors
  decryption_factors = LDObjectField(type_hint = datatypes.arrayOf(datatypes.arrayOf('core/BigInteger')),
                                     null=True)

  decryption_proofs = LDObjectField(type_hint = datatypes.arrayOf(datatypes.arrayOf('legacy/EGZKProof')),
                                    null=True)
  
  def save(self, *args, **kwargs):
    """
    override this just to get a hook
    """
    # not saved yet?
    if not self.secret:
      self.secret = heliosutils.random_string(12)
      self.election.append_log("Trustee %s added" % self.name)
      
    super(Trustee, self).save(*args, **kwargs)
  
  @classmethod
  def get_by_election(cls, election):
    return cls.objects.filter(election = election)

  @classmethod
  def get_by_uuid(cls, uuid):
    return cls.objects.get(uuid = uuid)
    
  @classmethod
  def get_by_election_and_uuid(cls, election, uuid):
    return cls.objects.get(election = election, uuid = uuid)

  @classmethod
  def get_by_election_and_email(cls, election, email):
    try:
      return cls.objects.get(election = election, email = email)
    except cls.DoesNotExist:
      return None

  @property
  def datatype(self):
    return self.election.datatype.replace('Election', 'Trustee')    
    
  def verify_decryption_proofs(self):
    """
    verify that the decryption proofs match the tally for the election
    """
    # verify_decryption_proofs(self, decryption_factors, decryption_proofs, public_key, challenge_generator):
    return self.election.encrypted_tally.verify_decryption_proofs(self.decryption_factors, self.decryption_proofs, self.public_key, algs.EG_fiatshamir_challenge_generator)
    
#added by John Utra

#code taken from Django 1.2.5 helios_auth.models
class ElectionRole(HeliosModel):
    """ElectionRole is a way for categorizing permissions to election officers. 
    """
    
    name = models.CharField(_('name'), max_length=80)
    election = models.ForeignKey(Election)
    permissions = models.ManyToManyField(Permission, verbose_name=_('permissions'), blank=True)

    class Meta:
        verbose_name = _('election role')
        verbose_name_plural = _('election roles')
        unique_together = ('election', 'name')
        
    def __unicode__(self):
        return self.name
    
    @classmethod
    def get_or_create_election_admin_role(cls, election):
        name = settings.ELECTION_ADMIN_ROLE
        
        #checks first if Election Admin role already exists, and return it
        election_admin_role = ElectionRole.objects.filter(name=name, election=election)
        if election_admin_role:
            return election_admin_role[0]
        
        #proceed into creation of ELECTION ADMIN role
        default_admin_perms = settings.ELECTION_ADMIN_PERMS
        
        permissions = Permission.objects.filter(codename__in=default_admin_perms)
        
        election_admin_role = ElectionRole(election=election, name=name)
        election_admin_role.save()
        for perm in permissions:
            election_admin_role.permissions.add(perm)
        
        return election_admin_role
    
    @classmethod
    def get_officers_per_roles(cls, role_ids):
        officers_per_role = {}
        
        for id in role_ids:
            try:
                role = cls.objects.get(id=id)
                officers_per_role[id] = role.electionofficer_set.all()          
            except:    
                continue
        return officers_per_role
    
    @classmethod
    def get_unassigned_roles_by_election(cls, election):
        all_election_roles = cls.objects.filter(election=election)
        unassigned_roles = []
        for role in all_election_roles:
            if not role.electionofficer_set.all():
                unassigned_roles.append(role)
        return unassigned_roles
    
class ElectionOfficer(HeliosModel):
    user =  models.ForeignKey(User)
    
    election = models.ForeignKey(Election)
    
    #is an Election Administrator or Super Administrator
    super_p = models.BooleanField(default=False)
    
    electionrole = models.ManyToManyField(ElectionRole, verbose_name=_('election roles'), blank=True)
    
    #user_permissions = models.ManyToManyField(Permission, verbose_name=_('user permissions'), blank=True)
    
    class Meta:
        unique_together = ('user', 'election')
    @property
    def permissions(self):
        roles = self.electionrole.all()
        perms = None
        for role in roles:
            role_p = role.permissions.all()
            if role_p and not perms:
                perms = []
                for p in role_p:
                    perms.append(str(p.codename))
            else:
                for p in role_p:
                    perms.append(str(p.codename))
        return perms
    
    @property
    def roles(self):
        #return the QuerySet
        return self.electionrole.all()

    def approve(self, v_request, request):
        return self.vote(v_request, request, decision='approved')
        
        
    def reject(self, v_request, request):
        return self.vote(v_request, request, decision='rejected')
        
    def ignore(self, v_request, request):
        return self.vote(v_request, request, decision='abstained')
        
    def vote(self, v_request, request, decision='abstained'):
        """
        conditions:
        
        1. check if election officer possess the right role, of the currently active validation entry
        2. check if the election officer, has not previously participated in validating another validation entry
            under the same validation request a.k.a enforcing separation of concern.
        """
        active_vm = v_request.active_vm
         
        if active_vm:
            
            ve_role = active_vm.validation_entry.election_role
            if ve_role in self.roles:
                if not self.has_prior_participation(v_request, request):
                    # add approval of election officer, and save to database
                    active_vm.validators.append([self.user.user_id, unicode(datetime.datetime.utcnow()), decision,'somesignature'])
                    active_vm.save()
                    v_request.do_checks()
                    if not v_request.satisfiable:
                        messages.error(request, "This validation request can no longer be SATISFIED/VALID so it was TERMINATED.")
                    return True
                else:
                    messages.error(request, "It's either you were the one who filed this validation request, so can you no longer participate for its approval,") 
                    messages.error(request, "Or you have already participated in deciding this request!")
                    return False
            else:
                messages.error(request, "You are not allowed to participate in deciding this validation request!")
                return False
        #else: validation entry or the whole policy is already terminated
        messages.error(request, "This validation request has already been decided.")
        return False
    
    def has_prior_participation(self, v_request, request):
        #assume this is user public key
        user_id = self.user.user_id
        
        #maybe officer is the requesting officer
        if user_id == v_request.user_id:
            #messages.error(request, "You created this request. So you can't participate in its approval!")
            return True
        
        #committed_vm = v_request.committed_vm
        for vm in v_request.validationentrymonitor_set.all():
            if user_id in vm.validator_ids:
                #messages.error(request, "You have already participated in deciding this request!")
                return True
        
        return False
    
    @classmethod
    def get_by_permission_and_election(cls, permission, election):
        return cls.objects.filter(electionrole__permissions__codename=permission.codename, election=election).distinct()

    def __unicode__(self):
        return self.user.name
    
    @classmethod
    def get_by_election_id(cls, election_id):
        return cls.objects.filter(election__id = election_id)
        
    @classmethod
    def get_by_election_and_user(cls, election, user):
        return cls.objects.get(election=election, user=user)
    
from helios.graph_utils.BipartiteMatching import matching as bi_matching

class ValidationPolicy(models.Model):
    
    ACTIVE = 'active'
    
    DESCRIPTION = {
        'upload_voterfile': 'Validation policy for uploading new voter registration',
        'define_ballot': 'Validation policy for defining the election ballot',
        'open_election':'Validation policy for opening the election',
        'close_election': 'Validation policy for closing the election',
        'delete_voter': 'Validation policy for removing a voter',
        'can_release_election_results':'Validation policy for releasing election results'
        }
    
    description = models.CharField(max_length=500)
    permission = models.ForeignKey(Permission)
    election = models.ForeignKey(Election)
    status = models.CharField(max_length=50, default='active')
    
    @classmethod
    def create(cls, policy_old, v_entries):
        policy_new = cls()
        policy_new.description = policy_old.description
        policy_new.permission = policy_old.permission
        policy_new.election = policy_old.election
        #take old's policy status which is presumably ACTIVE
        policy_new.status = policy_old.status
        #save as new policy
        policy_new.save()
        #override the old one, deactivate sort of. 
        policy_old.override()
        
        for entry_old in v_entries:
            entry_new = ValidationEntry()
            entry_new.description = entry_old['description']
            entry_new.validation_policy = policy_new
            entry_new.election_role = entry_old['election_role']
            entry_new.needed_signatures = entry_old['needed_signatures']
            entry_new.order = entry_old['order']
            entry_new.save()
            
        return policy_new
    
    #used in evaluating a persistent validation policy
    def is_satisfiable(self, officers_to_delete=[], delete_from_roles=[]):
        role_ids = []
        v_entries = self.validationentry_set.all()
        
        for entry in v_entries:
            if entry.election_role.id not in role_ids:
                role_ids.append(entry.election_role.id)
                
        #returnds a dictionary {'role_id':[officer_objects_list], ...}
        officers_per_role = ElectionRole.get_officers_per_roles(role_ids)
        
        delete_from_role_ids = [role.id for role in delete_from_roles]
        
        for role in officers_per_role:
            officer_ids = []
            for officer in officers_per_role[role]:
                if delete_from_roles:
                    #if this method is called from the edit officer view,
                    #then this code simulates the deletion of the officer 
                    #from each of the roles defined in delete_from_roles
                    if role in delete_from_role_ids:
                        if officer not in officers_to_delete:
                            officer_ids.append(officer.id)
                    else:
                        officer_ids.append(officer.id)
                else:
                    #if this method is called from the delete officer view,
                    #then this code simulates the deletion of the officer being removed
                    #officer is deleted from each of the roles where he is a member
                    if officer not in officers_to_delete:
                        officer_ids.append(officer.id)
            officers_per_role[role] = officer_ids
        
        #get the users who can execute the permission associated to this policy
        #include them in the matching
        #officers_of_perm = ElectionOfficer.get_by_permission_and_election(permission=self.permission, election=self.election).distinct()
        
        perm_officer_ids = []
        roles_of_perm = self.permission.electionrole_set.filter(election=self.election)
        role_ids_of_perm = [role.id for role in roles_of_perm]
        officers_per_role_of_perm = ElectionRole.get_officers_per_roles(role_ids_of_perm)
        for role in officers_per_role_of_perm:
            for officer in officers_per_role_of_perm[role]:
                if officer.id not in perm_officer_ids:
                    if delete_from_roles:
                        if role in delete_from_role_ids:
                            if officer not in officers_to_delete:
                                perm_officer_ids.append(officer.id)
                        else:
                            perm_officer_ids.append(officer.id)
                    else:
                        if officer not in officers_to_delete: 
                            perm_officer_ids.append(officer.id)     
                                    
        ve_user_mapping ={}
        ve_user_mapping['perm'] = perm_officer_ids
        
        for i, ve in enumerate(v_entries):
            for j in range(ve.needed_signatures):
                if ve.election_role.id in officers_per_role:
                    ve_user_mapping['ve'+str((i+1)+((j+1)*.1))] = officers_per_role[ve.election_role.id]
        
        
        
        M, A, B = bi_matching(ve_user_mapping)
        
        M2 = {}
        
        for u in M:
            M2[M[u]] = u
            
        errors = []
        for i, ve in enumerate(v_entries):
            errors.append([ve.needed_signatures, 0])
            for v in M2:
                if v.startswith("ve"+str(i+1)):
                    errors[i][1] += 1
        
        if 'perm' not in M2:
            errors.append(['perm', 0])
        
        if len(M) == len(ve_user_mapping):
            return [True, None]
        
        return [False, errors]
    
    
    #used to validate a validation policy raw data from a form
    @classmethod
    def validate(cls, v_entries, permission_id, election):
        
        
        role_ids = []
        for entry in v_entries:
            if entry['election_role'] not in role_ids:
                role_ids.append(entry['election_role'].id)
        
        officers_per_role = ElectionRole.get_officers_per_roles(role_ids)
        
        for role in officers_per_role:
            officer_ids = []
            for officer in officers_per_role[role]:
                officer_ids.append(officer.id)
            officers_per_role[role] = officer_ids
        
        permission = Permission.objects.get(id=permission_id)
        officers_of_perm = ElectionOfficer.get_by_permission_and_election(permission=permission, election=election)
        perm_officer_ids = []
        
        for officer in officers_of_perm:
            if officer.id not in perm_officer_ids:
                perm_officer_ids.append(officer.id)
        
        ve_user_mapping ={}
        
        for i, ve in enumerate(v_entries):
            for j in range(ve['needed_signatures']):
                if ve['election_role'].id in officers_per_role:
                    ve_user_mapping['ve'+str((i+1)+((j+1)*.1))] = officers_per_role[ve['election_role'].id]
                
        ve_user_mapping['perm'] = perm_officer_ids
                
        M, A, B = bi_matching(ve_user_mapping)
        
        M2 = {}
        
        for u in M:
            M2[M[u]] = u
            
        errors = []
        for i, ve in enumerate(v_entries):
            errors.append([ve['needed_signatures'], 0])
            for v in M2:
                if v.startswith("ve"+str(i+1)):
                    errors[i][1] += 1
        if 'perm' not in M2:
            errors.append(['perm', 0])
        
        if len(M) == len(ve_user_mapping):
            return [True, None]
        
        return [False, errors]
    
    def __unicode__(self):
        return self.description
    
    def override(self):
        self.status = 'over-ridden'
        self.save()
    
    
    @property
    def election_roles(self):
        roles =[]
        validation_entries = self.validationentry_set.all()
        for v in validation_entries:
            roles.append(v.role.name)
        return roles
    
    @classmethod
    def get_by_election_and_perm(cls, election, perm_codename):
        try:
            policy = cls.objects.get(election=election, permission__codename=perm_codename, status='active')
        except:
            raise ObjectDoesNotExist("Validation Policy matching query does not exist.")
        return policy
    
    @classmethod
    def get_by_election_and_role(cls, election, election_role):
        return cls.objects.filter(validationentry__election_role=election_role, election=election)
    
    @classmethod
    def get_by_election_and_officer(cls, election, officer, delete_from_roles=[], delete=False):
        #officer_roles = officer.electionrole.all()
        #officer_role_ids = [role.id for role in officer_roles]
        
        #officer_policies = cls.objects.filter(validationentry__election_role__in=officer_roles, election=election)
        officer_policies = cls.objects.filter( election=election, status='active') 
        
        if delete:
            officers_to_delete=[officer]
            
        affected_policies = []
        
        if officer_policies:
            for p in officer_policies:
                if not p.is_satisfiable(officers_to_delete, delete_from_roles)[0]:
                    affected_policies.append(p)
                    
        return affected_policies
    
class ValidationEntry(models.Model):
    description = models.CharField(max_length=100)
    validation_policy = models.ForeignKey(ValidationPolicy)
    election_role = models.ForeignKey(ElectionRole)
    needed_signatures = models.PositiveIntegerField()
    order = models.PositiveIntegerField()

    def __unicode__(self):
        return self.description
    
class ValidationRequest(HeliosModel):
    
    #the uuid of the object, this will be its default uuid value when it's actually committed
    object_uuid = models.CharField(max_length=50, null=False)
    
    #election refs uuid field
    election_uuid = models.CharField(max_length=50, null=False)
    
    #the id of the election officer
    election_officer = models.ForeignKey(ElectionOfficer)
    
    #user_id of election officer, for convenience?
    user_id = models.CharField(max_length=50, null=False)
    
    #date time this request was created
    requested_at = models.DateTimeField(auto_now_add=True)
    
    #date time this request's action was committed
    committed_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
    
    #date time this request was terminated, either since it was satisfied or ended prematurely
    terminated_at = models.DateTimeField(auto_now_add=False, default=None, null=True)
    
    #data type of object, based on __init__.py file
    modeltype = models.CharField(max_length=20, null=False)
    
    #dictionary representation of data of object
    data = LDObjectField(null=True, type_hint='legacy/Data')
    
    #action to be executed on the object of type datatype instantiated with data
    action = models.CharField(null=False, max_length=50)
    
    #hash of these request
    digest = models.CharField(null=False, max_length=50)
    
    #validation policy, assuming that it does not get changed. 
    #validation_policy = models.CharField(null=False, max_length=200)
    validation_policy = models.ForeignKey(ValidationPolicy, null=True)
    
    # start the validation process
    def start(self):
        if self.validation_policy:
            vp = self.validation_policy
            
            #start creation of ValidationEntry monitors from the 'back'
            ves = vp.validationentry_set.all().order_by('order')
            
            for ve in ves:
                vm =  ValidationEntryMonitor()
                vm.validation_entry = ve
                vm.validation_request = self
                vm.save()
                
            vm1 = self.validationentrymonitor_set.all().order_by('validation_entry__order')[0]
            vm1.start()
        else:
            #if there is no validation policy, just terminate it.
            self.terminate()
    # restart the validation process, called when a validation request is modified
    def reset(self):
        if self.validation_policy:
            #delete previous monitors
            prev_monitors = self.validationentrymonitor_set.all()
            for mon in prev_monitors:
                mon.delete()
                
            self.start()
    
    def terminate(self):
        self.terminated_at = datetime.datetime.utcnow()
        self.save() 
    
    def commit(self):
        self.terminate()
        self.committed_at = datetime.datetime.utcnow()
        self.save()
    #@property
    #def active(self):
    #    if self.active_vm:
    #        return True
    #    return False
    
    
    @property
    def terminated(self):
        return self.terminated_at != None
        """
        if not self.validation_policy:
            return True
        else:
            vms = self.validationentrymonitor_set.all()
            for vm in vms:
                if vm.active:
                    return False
            return True
        """
    @property
    def status(self):
        if self.terminated and self.satisfied:
            return u'Terminated-Valid'
        if self.terminated:
            return u'Terminated-Invalid'
        return u'Active-Invalid'
    
    @property
    def active_vm(self):
        vms = self.validationentrymonitor_set.all()
        for vm in vms:
            if vm.active:
                return vm
        return None
    
    @property
    def committed_vm(self):
        return self.validationentrymonitor_set.filter(start_time__isnull=False, end_time__isnull=False)
    
    @property
    def satisfied(self):
        #initially, test if a validation policy is defined, and
        #if there is none, the request is satisfied by default
        if not self.validation_policy:
            return True
        
        committed_vm = self.committed_vm
        
        if self.validationentrymonitor_set.all().count() == committed_vm.count():
            for vm in committed_vm:
                if not vm.satisfied:
                    return False
        else:
            return False
        
        return True
    
    @property
    def valid(self):
        return self.satisfied
    
    @property
    def satisfiable(self):
        U_d_user_ids = []
        
        U_d_user_ids.append(self.user_id)
        v_entries_monitor = self.validationentrymonitor_set.all().order_by('validation_entry__order')
        for vemonitor in v_entries_monitor:
            if vemonitor.terminated or vemonitor.active:
                for validator in vemonitor.validators:
                    U_d_user_ids.append(validator[0])
        
        v_policy = self.validation_policy
        v_entries = v_policy.validationentry_set.all().order_by('order')
        
        if len(v_entries) != len(v_entries_monitor):
            raise Exception("v_entries and v_entries_monitor are not of the same length. this should not have happened.")
        
        role_ids = []
        for ve_monitor in v_entries_monitor:
            if not ve_monitor.valid:
                role_id = ve_monitor.validation_entry.election_role.id 
                if role_id not in role_ids:
                    role_ids.append(role_id)
        
        officers_per_role = ElectionRole.get_officers_per_roles(role_ids)
        
        for role in officers_per_role:
            officer_ids = []
            for officer in officers_per_role[role]:
                if officer.user.user_id not in U_d_user_ids:
                    officer_ids.append(officer.id)
            officers_per_role[role] = officer_ids
        
        ve_user_mapping = {}
        for i, ve_monitor in enumerate(v_entries_monitor):
            still_needed_signatures = ve_monitor.validation_entry.needed_signatures - len(ve_monitor.approved_by)
            for j in range(still_needed_signatures):
                ve_role_id = ve_monitor.validation_entry.election_role.id
                if ve_role_id in officers_per_role:
                    ve_user_mapping['ve'+str((i+1)+((j+1)*.1))] = officers_per_role[ve_role_id]
        
        M, A, B = bi_matching(ve_user_mapping)            
        
        if len(M) == len(ve_user_mapping):
            return True
        else:
            return False
    
    def do_checks(self):
        if self.active_vm:
            if self.active_vm.satisfied:
                if not self.to_next_vm():
                    self.terminate()
            else:
                if not self.satisfiable:
                    self.active_vm.terminate()
                    self.terminate()
        else:
            self.terminate()
    #proceed to next validation entry to be processed
    def to_next_vm(self):
        
        if self.active_vm.satisfied:
            self.active_vm.terminate()
            
            vms = self.validationentrymonitor_set.filter(start_time__isnull=True, end_time__isnull=True).order_by('validation_entry__order')
        
            #if there are still vms
            if vms:
                vms[0].start()
                return True    
        #if all vms were satisfied already
        return None
    
    @classmethod
    def create(cls, user, election, req_data=None):
        if req_data == None:
            print "Erro1"
            return None
        #get election officer
        try:
            election_officer = ElectionOfficer.objects.get(election=election, user=user)
        except ObjectDoesNotExist:
            print "User: ", user, " is not authorized for this election = ", election
            return HttpResponse("Failure")
        
        request = cls(object_uuid=req_data['uuid'])    
        request.election_officer = election_officer
        request.election_uuid = election.uuid
        request.user_id = user.user_id
        request.object_uuid = req_data['uuid']
        request.modeltype = req_data['modeltype']
        request.action = req_data['action']
        #request.data = utils.to_json(req_data['data'])
        request.data = req_data['data']
        request.digest = "digest_value"
        request.validation_policy = req_data['vp']
        
        request.save()
        request.start()
        
        return request
        
    @classmethod
    def update_or_create(cls, user, election, req_data=None):
        
        
        if req_data == None:
            print "Erro1"
            return None
        
        #get election officer
        try:
            election_officer = ElectionOfficer.objects.get(election=election, user=user)
        except ObjectDoesNotExist:
            print "Error2"
            return HttpResponse("Failure")
        
        try:
            
            #get the request object
            request = cls.objects.get(election_uuid=election.uuid, object_uuid=req_data['uuid'], action=req_data['action'], committed_at__isnull=True, terminated_at__isnull=True)
            
            #update election officer
            request.election_officer = election_officer
            request.user_id = user.user_id
            
            #update requested_at
            request.requested_at = datetime.datetime.utcnow()
            
            #update data
            #request.data = utils.to_json(req_data['data'])
            request.data = req_data['data']
            
            #update hash
            request.digest = "digest_value"
            
            #update policy
            request.validation_policy = req_data['vp']
            request.save()
            
            request.reset()
            
            
        except ObjectDoesNotExist:
            
            request = cls(object_uuid=req_data['uuid'])    
            request.election_officer = election_officer
            request.election_uuid = election.uuid
            request.user_id = user.user_id
            request.object_uuid = req_data['uuid']
            request.modeltype = req_data['modeltype']
            request.action = req_data['action']
            #request.data = utils.to_json(req_data['data'])
            request.data = req_data['data']
            request.digest = "digest_value"
            request.validation_policy = req_data['vp']
            
            request.save()
            
            request.start()
        
        return request
    
    #gets ballot validation request by election
    @classmethod
    def get_ballot_req_by_election(cls, election):
        try:
            v_request = cls.objects.get(election_uuid = election.uuid, object_uuid='ballot_uuid', committed_at__isnull=True, terminated_at__isnull=True)
        except:
            v_request = None
        return v_request
    
    @classmethod
    def get_by_object_uuid_and_election(cls, object_uuid, election):
        return cls.objects.filter(object_uuid=object_uuid, election_uuid=election.uuid).order_by('committed_at')
    
    def set_user(self, user, request):
        if not hasattr(user, 'user_id'):
            self.user_can_decide = False
            return
        
        election = Election.get_by_uuid(self.election_uuid)
        
        #assume this is user public key
        user_id = user.user_id
        try:
            officer = ElectionOfficer.get_by_election_and_user(election, user)
        except:
            officer = None
            print "Hi"
            
        self.user_can_decide = False
        
        if officer:
            #check if there is still an active validatiom monitor, else request has terminated already
            if self.active_vm:
                active_role = self.active_vm.validation_entry.election_role
                if active_role in officer.roles:
                    if not officer.has_prior_participation(self, request=request):
                        self.user_can_decide = True
                    
        
    @property
    def user_can_participate(self):
        print self.user_can_decide
        return self.user_can_decide
    
    @staticmethod
    def get_active_requests_by_election(election):
        return ValidationRequest.objects.filter(election_uuid=election.uuid,  terminated_at__isnull=True)
    
    @staticmethod
    def get_active_voter_requests_by_election(election):
        return ValidationRequest.objects.filter(election_uuid=election.uuid,  terminated_at__isnull=True, modeltype=helios.VOTER)
    
    @staticmethod
    def get_active_other_requests_by_election(election):
        return ValidationRequest.objects.filter(election_uuid=election.uuid,  terminated_at__isnull=True, modeltype=helios.ELECTION).exclude(action=Election.DEFINE_BALLOT)
    
    @staticmethod
    def voter_v_request_exists_by_election(election, voter_name, voter_email):
        voter_requests = ValidationRequest.objects.filter(election_uuid=election.uuid, committed_at__isnull=True, terminated_at__isnull=True, action=Voter.ADD, modeltype=helios.VOTER)
        for voter_request in voter_requests:
            voter_data = voter_request.data['input']
            if voter_data['voter_email'] == voter_email and voter_data['voter_name'] == voter_name:
                return True
        return False
    
class ValidationEntryMonitor(models.Model):
    
    REJECTED = "rejected"
    APPROVED = "approved"
    ABSTAINED = "abstained"
    
    validation_entry = models.ForeignKey(ValidationEntry)
    validation_request = models.ForeignKey(ValidationRequest)
    start_time = models.DateTimeField(auto_now_add=False, default=None, null=True)
    end_time = models.DateTimeField(auto_now_add=False, default=None, null=True)
    validators = LDObjectField(type_hint='legacy/Data', null=True, default='[]')
    
    # start processing a validation entry
    def start(self):
        if not self.start_time:
            self.start_time = datetime.datetime.utcnow()
            self.end_time = None
            self.save()
        else:
            print "Error! Monitor already started!"
    
    #reset the processing of validation entry
    def reset(self):
        if self.start_time:
            self.start_time = None
            self.end_time = None
            self.validators = '[]'
            self.save()
        else:
            print "Error! Monitor has not yet started!"
    
    #end this validation monitor, assumingly it is done
    def terminate(self):
        if self.active:
            #defensive programming here, just checking you know!
            if self.satisfied:
                self.end_time = datetime.datetime.utcnow()
                self.save()
            else:
                if not self.validation_request.satisfiable:
                    self.end_time = datetime.datetime.utcnow()
                    self.save()
                else:
                    raise PermissionDenied("Validation Entry is not yet satisfied, you are not allowed to end it!")
        else:
            raise PermissionDenied("Validation Entry is not yet being processed, ending it does not make sense!")
    
    @property
    def inactive(self):
        return not (self.start_time and self.end_time)     
    @property
    def active(self):
        return self.start_time and not self.end_time
    
    @property
    def terminated(self):
        return self.start_time and self.end_time
    
    @property
    def satisfied(self):
        needed_signatures = self.validation_entry.needed_signatures
        approved = [validator for validator in self.validators if validator[2] == ValidationEntryMonitor.APPROVED]
        return len(approved) == needed_signatures
        
    @property
    def valid(self):
        return self.terminated and self.satisfied
    
    @property
    def status(self):
        if self.terminated:
            if self.valid:
                return u'Terminated-Valid'
            else:
                return u'Terminated-Invalid'
        else:
            if self.active:
                return u'Active-Invalid'
            else:
                return u'Inactive-Invalid'
        
    @property
    def validator_ids(self):
        user_ids = []
        for val in self.validators:
            user_ids.append(val[0])
        return user_ids
    
    @property
    def approved_by(self):
        names = []
        for val in self.validators:
            user_id = val[0]
            decision = val[2]
            if decision == ValidationEntryMonitor.APPROVED:
                user = User.objects.get(user_id=user_id)
                names.append(user.name)
        return names
    
    @property
    def rejected_by(self):
        names = []
        for val in self.validators:
            user_id = val[0]
            decision = val[2]
            if decision == ValidationEntryMonitor.REJECTED:
                user = User.objects.get(user_id=user_id)
                names.append(user.name)
        return names
    
    @property
    def abstention(self):
        names = []
        for val in self.validators:
            user_id = val[0]
            decision = val[2]
            if decision == ValidationEntryMonitor.ABSTAINED:
                user = User.objects.get(user_id=user_id)
                names.append(user.name)
        return names
    
#update an object using the data on a validation request            
def update_from_vrequest(v_request):
    pass



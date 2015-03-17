"""
Celery queued tasks for Helios

2010-08-01
ben@adida.net
"""

from celery.decorators import task

from models import *
from view_utils import render_template_raw
import signals

import copy

#added by John
from helios_auth.security import get_user
from helios.models import ValidationRequest

@task()
def cast_vote_verify_and_store(cast_vote_id, status_update_message=None, **kwargs):
    cast_vote = CastVote.objects.get(id = cast_vote_id)
    result = cast_vote.verify_and_store()

    voter = cast_vote.voter
    election = voter.election
    user = voter.user

    if result:
        # send the signal
        signals.vote_cast.send(sender=election, election=election, user=user, voter=voter, cast_vote=cast_vote)
        
        if status_update_message and user.can_update_status():
            from views import get_election_url

            user.update_status(status_update_message)
    else:
        logger = cast_vote_verify_and_store.get_logger(**kwargs)
        logger.error("Failed to verify and store %d" % cast_vote_id)
    
@task()
def voters_email(election_id, subject_template, body_template, extra_vars={},
                 voter_constraints_include=None, voter_constraints_exclude=None):
    """
    voter_constraints_include are conditions on including voters
    voter_constraints_exclude are conditions on excluding voters
    """
    election = Election.objects.get(id = election_id)

    # select the right list of voters
    voters = election.voter_set.all()
    if voter_constraints_include:
        voters = voters.filter(**voter_constraints_include)
    if voter_constraints_exclude:
        voters = voters.exclude(**voter_constraints_exclude)

    for voter in voters:
        single_voter_email.delay(voter.uuid, subject_template, body_template, extra_vars)

@task()
def voters_notify(election_id, notification_template, extra_vars={}):
    election = Election.objects.get(id = election_id)
    for voter in election.voter_set.all():
        single_voter_notify.delay(voter.uuid, notification_template, extra_vars)

@task()
def single_voter_email(voter_uuid, subject_template, body_template, extra_vars={}):
    voter = Voter.objects.get(uuid = voter_uuid)

    the_vars = copy.copy(extra_vars)
    the_vars.update({'voter' : voter})

    subject = render_template_raw(None, subject_template, the_vars)
    body = render_template_raw(None, body_template, the_vars)

    voter.user.send_message(subject, body)

@task()
def single_voter_notify(voter_uuid, notification_template, extra_vars={}):
    voter = Voter.objects.get(uuid = voter_uuid)

    the_vars = copy.copy(extra_vars)
    the_vars.update({'voter' : voter})

    notification = render_template_raw(None, notification_template, the_vars)

    voter.user.send_notification(notification)

@task()
def election_compute_tally(election_id):
    election = Election.objects.get(id = election_id)
    election.compute_tally()

    election_notify_all_officers.delay(election_id = election_id,
                                subject = "encrypted tally computed",
                                body = """
The encrypted tally for election %s has been computed.

--
Helios
""" % election.name)
                                
    if election.has_helios_trustee():
        tally_helios_decrypt.delay(election_id = election.id)

@task()
def tally_helios_decrypt(election_id):
    election = Election.objects.get(id = election_id)
    election.helios_trustee_decrypt()
    election_notify_all_officers.delay(election_id = election_id,
                                subject = 'Helios Decrypt',
                                body = """
Helios has decrypted its portion of the tally
for election %s.

--
Helios
""" % election.name)

@task()
def voter_file_process(request, voter_file_id, v_policy = None):
    
    voter_file = VoterFile.objects.get(id = voter_file_id)
    
    
    #start time of voter file processing
    voter_file.start_processing()
    print "Start processing!!"
    
    registrants = voter_file.registrants()
    
    election = voter_file.election
    user = get_user(request)
        
    if v_policy:
        for registrant in registrants:
            
            if not ValidationRequest.voter_v_request_exists_by_election(election, registrant.voter_name, registrant.voter_email):
                data = {'old_obj':{},
                        'input':registrant.toJSONDict(),
                        'output':registrant.toJSONDict()}
                
                #prepare data for the validation request creation
                req_data = { 'uuid' : registrant.uuid,
                        'data': data,
                        'action' : Voter.ADD,
                        'modeltype': helios.VOTER,
                        'vp' : v_policy
                      }
                #create the validation request for this registrant
                ValidationRequest.create(user, election, req_data=req_data)
    else:
        
        for registrant in registrants:
            if not ValidationRequest.voter_v_request_exists_by_election(election, registrant.voter_name, registrant.voter_email):
                #prepare data for the validation request creation
                data = {'old_obj':{},
                        'input':registrant.toJSONDict(),
                        'output':registrant.toJSONDict()}
                req_data = { 'uuid' : registrant.uuid,
                        'data': data,
                        'action' : Voter.ADD,
                        'modeltype': helios.VOTER,
                        'vp' : v_policy
                      }
                #create the validation request for this registrant
                v_request = ValidationRequest.create(user, election, req_data=req_data)
                registrant.save()
                v_request.commit()
        
        #voter_file.process()
        
    voter_file.end_processing()
    print "End processing!!"
    
    election_notify_admin.delay(user, election_id = voter_file.election.id, 
                                subject = 'voter file processed',
                                body = """
Your voter file upload for election %s
has been processed.

%s voters have been created.

--
Helios
""" % (voter_file.election.name, voter_file.num_voters))

@task()
def election_notify_admin(user, election_id, subject, body):
    #election = Election.objects.get(id = election_id)
    #election.admin.send_message(subject, body)
    user.send_message(subject, body)

@task()
def election_notify_all_officers(election_id, subject, body):
    officers = ElectionOfficer.get_by_election_id(election_id)
    
    for officer in officers:
        election_notify_an_officer.delay(officer, election_id, subject, body)
    
@task()
def election_notify_an_officer(officer, election_id, subject, body):
    officer.user.send_message(subject, body)
    

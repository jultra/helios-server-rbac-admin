"""
Helios URLs for Election related stuff

Ben Adida (ben@adida.net)
"""

from django.conf.urls.defaults import *

from helios.views import *

urlpatterns = patterns('',
    (r'^$', one_election),
    
    # edit election params
    (r'^/edit$', one_election_edit),
    (r'^/schedule$', one_election_schedule),
    (r'^/archive$', one_election_archive),

    # badge
    (r'^/badge$', election_badge),

    # adding trustees
    (r'^/trustees/$', list_trustees),
    (r'^/trustees/view$', list_trustees_view),
    (r'^/trustees/new$', new_trustee),
    (r'^/trustees/add-helios$', new_trustee_helios),
    (r'^/trustees/delete$', delete_trustee),
    
    # trustee pages
    (r'^/trustees/(?P<trustee_uuid>[^/]+)/home$', trustee_home),
    (r'^/trustees/(?P<trustee_uuid>[^/]+)/sendurl$', trustee_send_url),
    (r'^/trustees/(?P<trustee_uuid>[^/]+)/keygenerator$', trustee_keygenerator),
    (r'^/trustees/(?P<trustee_uuid>[^/]+)/check-sk$', trustee_check_sk),
    (r'^/trustees/(?P<trustee_uuid>[^/]+)/upoad-pk$', trustee_upload_pk),
    (r'^/trustees/(?P<trustee_uuid>[^/]+)/decrypt-and-prove$', trustee_decrypt_and_prove),
    (r'^/trustees/(?P<trustee_uuid>[^/]+)/upload-decryption$', trustee_upload_decryption),
    
    # election voting-process actions
    (r'^/view$', one_election_view),
    (r'^/result$', one_election_result),
    (r'^/result_proof$', one_election_result_proof),
    # (r'^/bboard$', one_election_bboard),
    (r'^/audited-ballots/$', one_election_audited_ballots),

    # get randomness
    (r'^/get-randomness$', get_randomness),

    # server-side encryption
    (r'^/encrypt-ballot$', encrypt_ballot),

    # construct election
    (r'^/questions$', one_election_questions),
    (r'^/set_reg$', one_election_set_reg),
    (r'^/set_featured$', one_election_set_featured),
    (r'^/save_questions$', one_election_save_questions),
    (r'^/register$', one_election_register),
    (r'^/freeze$', one_election_freeze), # includes freeze_2 as POST target
    
    # computing tally
    (r'^/compute_tally$', one_election_compute_tally),
    (r'^/combine_decryptions$', combine_decryptions),
    
    # casting a ballot before we know who the voter is
    (r'^/cast$', one_election_cast),
    (r'^/cast_confirm$', one_election_cast_confirm),
    (r'^/password_voter_login$', password_voter_login),
    (r'^/cast_done$', one_election_cast_done),
    
    # post audited ballot
    (r'^/post-audited-ballot', post_audited_ballot),
    
    # managing voters
    (r'^/voters/$', voter_list),
    (r'^/voters/upload$', voters_upload),
    (r'^/voters/upload-cancel$', voters_upload_cancel),
    (r'^/voters/list$', voters_list_pretty),
    (r'^/voters/eligibility$', voters_eligibility),
    (r'^/voters/email$', voters_email),
    (r'^/voters/(?P<voter_uuid>[^/]+)$', one_voter),
    (r'^/voters/(?P<voter_uuid>[^/]+)/delete$', voter_delete),
    
    # ballots
    (r'^/ballots/$', ballot_list),
    (r'^/ballots/(?P<voter_uuid>[^/]+)/all$', voter_votes),
    (r'^/ballots/(?P<voter_uuid>[^/]+)/last$', voter_last_vote),
    
    #added by John Ultra
    #admin
    (r'^/admin/view$', one_election_admin),
    (r'^/admin/officers/list$', one_election_officers_list),
    (r'^/admin/officer/new$', user_new),
    (r'^/admin/officer/(?P<officer_id>[^/]+)/edit$', user_edit),
    (r'^/admin/officer/(?P<officer_id>[^/]+)/delete$', user_delete),
    
    (r'^/admin/roles/list$', one_election_roles_list),
    (r'^/admin/role/new$', role_new),
    (r'^/admin/role/(?P<role_id>[^/]+)/edit$', role_edit),
    (r'^/admin/role/(?P<role_id>[^/]+)/delete$', role_delete),
    
    (r'^/admin/validation/list$', one_validations_list),
    (r'^/admin/validation/new/(?P<perm_id>[^/]+)/$', policy_new),
    (r'^/admin/validation/edit/(?P<val_id>[^/]+)$', policy_edit),
    (r'^/admin/validation/delete/(?P<val_id>[^/]+)$', policy_delete),
    (r'^/admin/validation/details/(?P<val_id>[^/]+)$', policy_details),
    (r'^/admin/validation/requests$', requests_list),
    (r'^/admin/validation/requests_ballot$', requests_ballot),
    (r'^/admin/validation/ballot_req_details/(?P<vr_id>[^/]+)$', ballot_req_details),
    (r'^/admin/validation/requests_voters$', requests_voters),
    (r'^/admin/validation/voter_req_details/(?P<vr_id>[^/]+)$', voter_req_details),
    (r'^/admin/validation/requests_trustee$', requests_trustees),
    (r'^/admin/validation/other_requests$', other_requests),
    (r'^/admin/validation/request_details/(?P<vr_id>[^/]+)$', request_details),
    (r'^/admin/validation/approve_request/(?P<vr_id>[^/]+)$', approve_request),
    (r'^/admin/validation/reject_request/(?P<vr_id>[^/]+)$', reject_request),
    (r'^/admin/validation/ignore_request/(?P<vr_id>[^/]+)$', ignore_request),
    
    (r'^/verify_object/(?P<uuid>[^/]+)$', verify_object_by_uuid),
    
    #saving ballot/questions
    #(r'^/save_questions/(?P<vr_id>[^/]+)$', one_election_save_questions),
    
    # any other case!
    (r'^/(?P<caller>[^/]+)/(?P<vr_id>[^/]+)$', one_election),
    
    #test urls
    (r'^/questions_s$', election_questions),
)

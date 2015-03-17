from helios.models import ValidationPolicy

def test_1():
    v_entries= [[{'election_role':4, 'needed_signatures':1},
              {'election_role':2, 'needed_signatures':2}, 
              {'election_role':3, 'needed_signatures':2}],
             [{'election_role':1, 'needed_signatures':1},
              {'election_role':2, 'needed_signatures':1}, 
              {'election_role':3, 'needed_signatures':1}],
             [{'election_role':1, 'needed_signatures':2},
              {'election_role':2, 'needed_signatures':2}, 
              {'election_role':3, 'needed_signatures':2}],
             [{'election_role':1, 'needed_signatures':1},
              {'election_role':2, 'needed_signatures':0}, 
              {'election_role':3, 'needed_signatures':2}],
             [{'election_role':2, 'needed_signatures':1},
              {'election_role':3, 'needed_signatures':2}]]
    
    test_results = [False, False, False, True, True]
    
    for i, e in enumerate(v_entries):
        print "Test Case ", i+1, " = ", ValidationPolicy.validate(e), " == ", test_results[i]
    
    
"""    
{"input": {"questions": [{"answer_urls": [null, null], "answers": ["Yes!!", "No!!!"], "choice_type": "approval", "max": 1, "min": 0, "question": "Are you human?", "result_type": "absolute", "short_name": "Are you human?", "tally_type": "homomorphic"}]}, 
 "old_obj": {"cast_url": "http://localhost:8000/helios/elections/500baa66-6568-11e2-af23-89c11804c825/cast", 
             "description": "", "frozen_at": null, "name": "Who Are You?", "openreg": false, "public_key": null, 
             "questions": [{"answer_urls": [null, null], "answers": ["Yes", "No"], "choice_type": "approval", "max": 1, "min": 0, "question": "Are you human?", "result_type": "absolute", "short_name": "Are you human?", "tally_type": "homomorphic"}], "short_name": "who-are-you-2013", "use_voter_aliases": false, "uuid": "500baa66-6568-11e2-af23-89c11804c825", "voters_hash": null, "voting_ends_at": null, "voting_starts_at": null}, 
 "output": {"cast_url": "http://localhost:8000/helios/elections/500baa66-6568-11e2-af23-89c11804c825/cast", 
            "description": "", "frozen_at": null, "name": "Who Are You?", "openreg": false, "public_key": null, 
            "questions": [{"answer_urls": [null, null], "answers": ["Yes!!", "No!!!"], "choice_type": "approval", "max": 1, "min": 0, "question": "Are you human?", "result_type": "absolute", "short_name": "Are you human?", "tally_type": "homomorphic"}], "short_name": "who-are-you-2013", "use_voter_aliases": false, "uuid": "500baa66-6568-11e2-af23-89c11804c825", "voters_hash": null, "voting_ends_at": null, "voting_starts_at": null}}
"""
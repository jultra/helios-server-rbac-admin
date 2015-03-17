
from django.conf import settings
from django.core.urlresolvers import reverse
from helios.views import election_shortcut

TEMPLATE_BASE = settings.HELIOS_TEMPLATE_BASE or "helios/templates/base.html"

# a setting to ensure that only admins can create an election
ADMIN_ONLY = settings.HELIOS_ADMIN_ONLY

# allow upload of voters via CSV?
VOTERS_UPLOAD = settings.HELIOS_VOTERS_UPLOAD

# allow emailing of voters?
VOTERS_EMAIL = settings.HELIOS_VOTERS_EMAIL

# default election administrator role
ELECTION_ADMIN_ROLE = settings.ELECTION_ADMIN_ROLE

# default admin roles

ELECTION_ADMIN_PERMS = settings.ELECTION_ADMIN_PERMS

#data models, hardcoding
ELECTION = "election"

VOTER = "voter"

TRUSTEE = "trustee"

TASKS = { ELECTION : {'define_ballot' : 'define_ballot' },
        VOTER : {'add': 'add_voter', 'delete': 'delete_voter'},
        TRUSTEE : {'add':'add_trustee', 'delete':'delete_trustee'}
        }
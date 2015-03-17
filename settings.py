
import os

# go through environment variables and override them
def get_from_env(var, default):
    if os.environ.has_key(var):
        return os.environ[var]
    else:
        return default

DEBUG = True
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    ('John Ultra', 'john.ultra@up.edu.ph'),
)

MANAGERS = ADMINS

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'heliosm',
        'USER': 'heliosmod',
        'PASSWORD': 'h3l10sm0d',
        'HOST': 'localhost'
    }
}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'Asia/Manila'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# Absolute path to the directory that holds media.
# Example: "/home/media/media.lawrence.com/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash if there is a path component (optional in other cases).
# Examples: "http://media.lawrence.com", "http://example.com/media/"
MEDIA_URL = ''

# URL prefix for admin media -- CSS, JavaScript and images. Make sure to use a
# trailing slash.
# Examples: "http://foo.com/media/", "/media/".
ADMIN_MEDIA_PREFIX = '/media/'

# Make this unique, and don't share it with anybody.
SECRET_KEY = get_from_env('SECRET_KEY', 'akij18s9shbaml102kjehes4a1krbqvi87301')

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.load_template_source',
    'django.template.loaders.app_directories.load_template_source',
#     'django.template.loaders.eggs.load_template_source',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'messages.middleware.MessageMiddleware',
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'messages.context_processors.messages',
)

ROOT_URLCONF = 'urls'

ROOT_PATH = os.path.dirname(__file__)
TEMPLATE_DIRS = (
    ROOT_PATH,
    os.path.join(ROOT_PATH, 'templates')
)

INSTALLED_APPS = (
#    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
#    'django.contrib.messages',
    ## needed for queues
    'djcelery',
    'djkombu',
    ## needed for schema migration
    'south',
    ## HELIOS stuff
    'helios_auth',
    'messages',
    'helios',
    'server_ui',
)

##
## HELIOS
##


MEDIA_ROOT = ROOT_PATH + "/media/"

# a relative path where voter upload files are stored
VOTER_UPLOAD_REL_PATH = "voters/%Y/%m/%d"


# Change your email settings
DEFAULT_FROM_EMAIL = get_from_env('DEFAULT_FROM_EMAIL', 'Hvoting Admin Officer')
DEFAULT_FROM_NAME = get_from_env('DEFAULT_FROM_NAME', 'Voting Administrator')
SERVER_EMAIL = '%s <%s>' % (DEFAULT_FROM_NAME, DEFAULT_FROM_EMAIL)

LOGOUT_ON_CONFIRMATION = True
LOGIN_URL = '/auth/'


# The two hosts are here so the main site can be over plain HTTP
# while the voting URLs are served over SSL.
URL_HOST = get_from_env("URL_HOST", "http://localhost:8000")

# IMPORTANT: you should not change this setting once you've created
# elections, as your elections' cast_url will then be incorrect.
SECURE_URL_HOST = "http://localhost:8000"
#SECURE_URL_HOST = get_from_env("SECURE_URL_HOST", "http://localhost:80")

# this additional host is used to iframe-isolate the social buttons,
# which usually involve hooking in remote JavaScript, which could be
# a security issue. Plus, if there's a loading issue, it blocks the whole
# page. Not cool.
SOCIALBUTTONS_URL_HOST= get_from_env("SOCIALBUTTONS_URL_HOST", "http://localhost:8000")

# election stuff
SITE_TITLE = get_from_env('SITE_TITLE', 'Helios Election Server')

# FOOTER links
FOOTER_LINKS = []
FOOTER_LOGO = False

WELCOME_MESSAGE = get_from_env('WELCOME_MESSAGE', "This is the default message")

HELP_EMAIL_ADDRESS = get_from_env('HELP_EMAIL_ADDRESS', 'johnultra@ymail.com')

AUTH_TEMPLATE_BASE = "server_ui/templates/base.html"
HELIOS_TEMPLATE_BASE = "server_ui/templates/base.html"
HELIOS_ADMIN_ONLY = True
HELIOS_VOTERS_UPLOAD = True
HELIOS_VOTERS_EMAIL = True

# set the name of the default Election Administrator role
ELECTION_ADMIN_ROLE = "Election Administrator"

#set the default set of permissions of the Election Administrator role
"""
Possible Permission Values
***************************
"upload_voterfile" - User Can Upload Voters from a voter file. By Helios design, only way to add voters to an election.
"delete_voter" - User can delete a voter, previously uploaded.
"add_trustee" - User can add election trustee. An election trustee is involced in the decryption of voters encrypted ballots.
"delete_trustee" - User can delete election trustee.
"add_electionofficer" - User can add an election officer to an election.
"change_electionofficer" - User can change election officer.
"delete_electionofficer" - User can remove an election officer from an election. 
"add_electionrole" - User can add an election role. 
"change_electionrole" - User can change an election role.
"delete_electionrole" - User can delete an election role. 
"define_ballot" - User can create and modify the ballot for an election.
"open_election" - User can start the election voting process.
"close_election" - User can stop the election voting process and commence the start of canvassing.
"change_election" - User can modify election information i.e. name, and other election attributes. 
"can_send_trustee_url" - User can send the trustee login information
"can_release_election_results" - User can release election results after it had been decrypted by the trustees.
"define_ballot" - User can create or define the election's official ballot. 
"add_policy" - User can create validation policy of a permission.
"delete_policy" - User can delete validation policy of a permission.
"change_policy" - User can edit validation policy of a permission.
"""
ELECTION_ADMIN_PERMS = ['add_electionofficer', 'change_electionofficer', 'delete_electionofficer',
                               'add_electionrole', 'change_electionrole', 'delete_electionrole',
                               'change_election', 'add_policy', 'delete_policy', 'change_policy',
                               'add_trustee', 'delete_trustee', 'can_send_trustee_url']




# are elections private by default?
HELIOS_PRIVATE_DEFAULT = True

# authentication systems enabled
#AUTH_ENABLED_AUTH_SYSTEMS = ['password','facebook','twitter', 'google', 'yahoo']
AUTH_ENABLED_AUTH_SYSTEMS = ['password','google']
AUTH_DEFAULT_AUTH_SYSTEM = 'password'

# facebook
FACEBOOK_APP_ID = ''
FACEBOOK_API_KEY = ''
FACEBOOK_API_SECRET = ''

# twitter
TWITTER_API_KEY = ''
TWITTER_API_SECRET = ''
TWITTER_USER_TO_FOLLOW = 'heliosvoting'
TWITTER_REASON_TO_FOLLOW = "we can direct-message you when the result has been computed in an election in which you participated"

# the token for Helios to do direct messaging
TWITTER_DM_TOKEN = {"oauth_token": "", "oauth_token_secret": "", "user_id": "", "screen_name": ""}

# LinkedIn
LINKEDIN_API_KEY = ''
LINKEDIN_API_SECRET = ''

# email server
EMAIL_HOST = get_from_env('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = 587
EMAIL_HOST_USER = get_from_env('EMAIL_HOST_USER', 'hvoting.adofficer@gmail.com')
EMAIL_HOST_PASSWORD = get_from_env('EMAIL_HOST_PASSWORD', 'hv0t1ng10')
EMAIL_USE_TLS = True

# set up logging
import logging
logging.basicConfig(
    level = logging.DEBUG,
    format = '%(asctime)s %(levelname)s %(message)s'
)

# set up django-celery
import djcelery
djcelery.setup_loader()
BROKER_BACKEND = "djkombu.transport.DatabaseTransport"
CELERY_RESULT_DBURI = DATABASES['default']

# for testing
CELERY_ALWAYS_EAGER = True

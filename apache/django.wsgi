import os
import sys

sys.path.append('/srv/voting')
sys.path.append('/srv/voting/helios-mod')
sys.path.append('/srv/voting/helios-mod/auth')
sys.path.append('/srv/voting/helios-mod/helios')
sys.path.append('/srv/voting/helios-mod/server_ui')

os.environ['DJANGO_SETTINGS_MODULE'] = 'helios-mod.settings'

import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()

import monitor
monitor.start(interval=1.0)

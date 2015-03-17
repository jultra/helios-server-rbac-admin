#!/bin/bash
dropdb helios
createdb helios
#python manage.py syncdb
#python manage.py migrate
python manage.py syncdb --all
echo "from helios_auth.models import User; User.objects.create(user_type='google',user_id='ben@adida.net', info={'name':'Ben Adida'}); User.objects.create(user_type='password',user_id='jultra', name='John Ultra', info={'email': 'johnultra@ymail.com', 'password':'jultrapass'}, admin_p=True);" | python manage.py shell

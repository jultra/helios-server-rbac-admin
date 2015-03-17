"""
Data Objects for user authentication

GAE

Ben Adida
(ben@adida.net)
"""

from django.db import models
from jsonfield import JSONField

#added by John Ultra
#from django.contrib.contenttypes.models import ContentType
from django.utils.translation import ugettext_lazy as _

import datetime, logging

from auth_systems import AUTH_SYSTEMS, can_check_constraint, can_list_categories

# an exception to catch when a user is no longer authenticated
class AuthenticationExpired(Exception):
  pass

# added  by John Ultra
# an exception to catch when an non-existent codename value of permission is supplied


class PermissionDoesNotExist(Exception):
  pass

class PermissionManager(models.Manager):
    def get_by_natural_key(self, codename, app_label, model):
        return self.get(
            codename=codename
        )

class Permission(models.Model):
    """code taken from django source
    """
    name = models.CharField(_('name'), max_length=50)
    model_type = models.CharField(max_length=50)
    codename = models.CharField(_('codename'), max_length=100)
    objects = PermissionManager()

    class Meta:
        verbose_name = _('permission')
        verbose_name_plural = _('permissions')
        unique_together = (('model_type', 'codename'),)
        #ordering = ('content_type__app_label', 'content_type__model', 'codename')
        ordering = ('name',)

    #def __unicode__(self):
    #    return u"%s | %s | %s" % (
    #        unicode(self.content_type.app_label),
    #        unicode(self.content_type),
    #        unicode(self.name))
        
    def __unicode__(self):
        return u"%s" % (unicode(self.name))

    def natural_key(self):
        return (self.codename,)
    natural_key.dependencies = ['contenttypes.contenttype']
    
    @classmethod
    def all_codenames(cls):
        codenames = []
        perms = cls.objects.all()
        for p in perms:
            codenames.append(str(p.codename))
        return set(codenames)
    
    @classmethod
    def get_unassigned_permissions_by_election(cls, election):
        if not election:
            return None
        all_perm = cls.objects.all()
        unassigned_perm = []
        for perm in all_perm:
            if not perm.electionrole_set.filter(election=election):
                unassigned_perm.append(perm)
        return unassigned_perm
            
class User(models.Model):
  user_type = models.CharField(max_length=50)
  user_id = models.CharField(max_length=100, unique=True)

  name = models.CharField(max_length=200, null=True)
  
  # other properties
  info = JSONField()
  
  # access token information
  token = JSONField(null = True)
  
  # administrator
  admin_p = models.BooleanField(default=False)

  class Meta:
    unique_together = (('user_type', 'user_id'),)
  
  @classmethod
  def _get_type_and_id(cls, user_type, user_id):
    return "%s:%s" % (user_type, user_id)    
    
  @property
  def type_and_id(self):
    return self._get_type_and_id(self.user_type, self.user_id)
    
  @classmethod
  def get_by_type_and_id(cls, user_type, user_id):
    return cls.objects.get(user_type = user_type, user_id = user_id)
  
  @classmethod
  def update_or_create(cls, user_type, user_id, name=None, info=None, token=None):
    obj, created_p = cls.objects.get_or_create(user_type = user_type, user_id = user_id, defaults = {'name': name, 'info':info, 'token':token})
    
    if not created_p:
      # special case the password: don't replace it if it exists
      if obj.info.has_key('password'):
        info['password'] = obj.info['password']

      obj.info = info
      obj.name = name
      obj.token = token
      obj.save()

    return obj
    
  def can_update_status(self):
    if not AUTH_SYSTEMS.has_key(self.user_type):
      return False

    return AUTH_SYSTEMS[self.user_type].STATUS_UPDATES

  def update_status_template(self):
    if not self.can_update_status():
      return None

    return AUTH_SYSTEMS[self.user_type].STATUS_UPDATE_WORDING_TEMPLATE

  def update_status(self, status):
    if AUTH_SYSTEMS.has_key(self.user_type):
      AUTH_SYSTEMS[self.user_type].update_status(self.user_id, self.info, self.token, status)
      
  def send_message(self, subject, body):
    if AUTH_SYSTEMS.has_key(self.user_type):
      subject = subject.split("\n")[0]
      AUTH_SYSTEMS[self.user_type].send_message(self.user_id, self.name, self.info, subject, body)

  def send_notification(self, message):
    if AUTH_SYSTEMS.has_key(self.user_type):
      if hasattr(AUTH_SYSTEMS[self.user_type], 'send_notification'):
        AUTH_SYSTEMS[self.user_type].send_notification(self.user_id, self.info, message)
  
  def is_eligible_for(self, eligibility_case):
    """
    Check if this user is eligible for this particular eligibility case, which looks like
    {'auth_system': 'cas', 'constraint': [{}, {}, {}]}
    and the constraints are OR'ed together
    """
    
    if eligibility_case['auth_system'] != self.user_type:
      return False
      
    # no constraint? Then eligible!
    if not eligibility_case.has_key('constraint'):
      return True
    
    # from here on we know we match the auth system, but do we match one of the constraints?  

    auth_system = AUTH_SYSTEMS[self.user_type]

    # does the auth system allow for checking a constraint?
    if not hasattr(auth_system, 'check_constraint'):
      return False
      
    for constraint in eligibility_case['constraint']:
      # do we match on this constraint?
      if auth_system.check_constraint(constraint=constraint, user = self):
        return True
  
    # no luck
    return False
    
  def __eq__(self, other):
    if other:
      return self.type_and_id == other.type_and_id
    else:
      return False
  

  @property
  def pretty_name(self):
    if self.name:
      return self.name

    if self.info.has_key('name'):
      return self.info['name']

    return self.user_id
  
  @property
  def public_url(self):
    if AUTH_SYSTEMS.has_key(self.user_type):
      if hasattr(AUTH_SYSTEMS[self.user_type], 'public_url'):
        return AUTH_SYSTEMS[self.user_type].public_url(self.user_id)

    return None
    
  def _display_html(self, size):
    public_url = self.public_url
    
    if public_url:
      name_display = '<a href="%s">%s</a>' % (public_url, self.pretty_name)
    else:
      name_display = self.pretty_name

    return """<img border="0" height="%s" src="/static/helios_auth/login-icons/%s.png" alt="%s" /> %s""" % (
      str(int(size)), self.user_type, self.user_type, name_display)

  @property
  def display_html_small(self):
    return self._display_html(15)

  @property
  def display_html_big(self):
    return self._display_html(25)


  def get_and_delete_messages(self):
    messages = []
    for m in self.message_set.all():
        messages.append(m.message)
        m.delete()
    return messages

class Message(models.Model):
  """
  The message system is a lightweight way to queue messages for given
  users. A message is associated with a User instance (so it is only
  applicable for registered users). There's no concept of expiration or
  timestamps. Messages are created by the Django admin after successful
  actions. For example, "The poll Foo was created successfully." is a
  message.
  """
  user = models.ForeignKey(User, related_name='_message_set')
  message = models.TextField(_('message'))

  def __unicode__(self):
    return self.message


"""
Forms for Helios
"""

from django import forms
from models import *
from widgets import *
from fields import *

#added by John Ultra
from helios_auth.models import Permission
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.forms.models import BaseModelFormSet
from helios.models import ValidationPolicy

class ElectionForm(forms.Form):
  short_name = forms.SlugField(max_length=25, help_text='no spaces, will be part of the URL for your election, e.g. my-club-2010')
  name = forms.CharField(max_length=100, widget=forms.TextInput(attrs={'size':60}), help_text='the pretty name for your election, e.g. My Club 2010 Election')
  description = forms.CharField(max_length=2000, widget=forms.Textarea(attrs={'cols': 70, 'wrap': 'soft'}), required=False)
  election_type = forms.ChoiceField(label="type", choices = Election.ELECTION_TYPES)
  use_voter_aliases = forms.BooleanField(required=False, initial=False, help_text='If selected, voter identities will be replaced with aliases, e.g. "V12", in the ballot tracking center')
  #use_advanced_audit_features = forms.BooleanField(required=False, initial=True, help_text='disable this only if you want a simple election with reduced security but a simpler user interface')
  #private_p = forms.BooleanField(required=False, initial=False, label="Private?", help_text='a private election is only visible to registered/eligible voters', widget=forms.HiddenInput)
  private_p = forms.BooleanField(required=False, initial=False, label="Private?", help_text='A private election is only visible to registered voters.')
  

class ElectionTimesForm(forms.Form):
  # times
  voting_starts_at = SplitDateTimeField(help_text = 'UTC date and time when voting begins',
                                   widget=SplitSelectDateTimeWidget)
  voting_ends_at = SplitDateTimeField(help_text = 'UTC date and time when voting ends',
                                   widget=SplitSelectDateTimeWidget)

  
class EmailVotersForm(forms.Form):
  subject = forms.CharField(max_length=80)
  body = forms.CharField(max_length=2000, widget=forms.Textarea)
  send_to = forms.ChoiceField(label="Send To", initial="all", choices= [('all', 'all voters'), ('voted', 'voters who have cast a ballot'), ('not-voted', 'voters who have not yet cast a ballot')])

class TallyNotificationEmailForm(forms.Form):
  subject = forms.CharField(max_length=80)
  body = forms.CharField(max_length=2000, widget=forms.Textarea, required=False)
  send_to = forms.ChoiceField(label="Send To", choices= [('all', 'all voters'), ('voted', 'only voters who cast a ballot'), ('none', 'no one -- are you sure about this?')])

class VoterPasswordForm(forms.Form):
  voter_id = forms.CharField(max_length=50, label="Voter ID")
  password = forms.CharField(widget=forms.PasswordInput(), max_length=100)


#added by John Ultra

from django.forms import ModelForm

class OfficerForm(ModelForm):
    
    user_id = forms.RegexField(label=_("username"), max_length=30, regex=r'^[\w.@+-]+$',
        help_text = _("Required. 30 characters or fewer. Letters, digits and @/./+/-/_ only. Also, please assign a unique username for each officer."),
        error_messages = {'invalid': _("This value may contain only letters, numbers and @/./+/-/_ characters.")})
    name = forms.CharField(max_length=50, label="name")
    super_p = forms.BooleanField(required=False, initial=False, label="election admin?", help_text="If selected, this officer will be assigned the role for election administrators i.e. " + settings.ELECTION_ADMIN_ROLE)
    email = forms.EmailField(label="e-mail address")
    
    
    #permissions = forms.ModelMultipleChoiceField(queryset=Permission.objects.all(),
    #                    widget=forms.SelectMultiple(attrs={'size':'20'},))
    electionrole = forms.ModelMultipleChoiceField(queryset=ElectionRole.objects.all(),
                    widget=forms.SelectMultiple(attrs={'size':'10'},), label="election roles",help_text=_("This user will get all permissions granted to each election role he/she is in."), required=False)
    
    def __init__(self, *args, **kwargs):
        self.election = kwargs.pop('election', None)
        super(OfficerForm, self).__init__(*args, **kwargs)

        if self.election:
            self.fields['electionrole'].queryset = ElectionRole.objects.filter(election=self.election).exclude(name=settings.ELECTION_ADMIN_ROLE)
    
    class Meta:
        model = ElectionOfficer
        exclude = ('user', 'election',)
        fields = ('user_id', 'name', 'super_p', 'email', 'electionrole')   

class OfficerEditForm(ModelForm):
    
    user_id = forms.RegexField(label=_("username"), max_length=30, regex=r'^[\w.@+-]+$',
        help_text = _("Required. 30 characters or fewer. Letters, digits and @/./+/-/_ only. Also, please assign a unique username for each officer."),
        error_messages = {'invalid': _("This value may contain only letters, numbers and @/./+/-/_ characters.")},
        widget=forms.TextInput(attrs={'readonly':'true'},))
    
    name = forms.CharField(max_length=50, label="name")
    super_p = forms.BooleanField(required=False, initial=False, label="election admin?", help_text="If selected, this officer will be assigned the role for election administrators i.e. " + settings.ELECTION_ADMIN_ROLE)
    email = forms.EmailField(label="e-mail address")
    
    
    #permissions = forms.ModelMultipleChoiceField(queryset=Permission.objects.all(),
    #                    widget=forms.SelectMultiple(attrs={'size':'20'},))
    electionrole = forms.ModelMultipleChoiceField(queryset=ElectionRole.objects.all(),
                    widget=forms.SelectMultiple(attrs={'size':'10'},), label="election roles",help_text=_("This user will get all permissions granted to each election role he/she is in."), required=False)
    
    def __init__(self, *args, **kwargs):
        self.election = kwargs.pop('election', None)
        super(OfficerEditForm, self).__init__(*args, **kwargs)

        if self.election:
            self.fields['electionrole'].queryset = ElectionRole.objects.filter(election=self.election).exclude(name=settings.ELECTION_ADMIN_ROLE)
    
    class Meta:
        model = ElectionOfficer
        exclude = ('user', 'election',)
        fields = ('user_id', 'name', 'super_p', 'email', 'electionrole')

    def clean(self):
        super(OfficerEditForm, self).clean()
        if any(self.errors):
            print self.errors
        
        election = self.election
        cleaned_data = self.cleaned_data        
        super_p = cleaned_data.get('super_p')
        user_id = cleaned_data.get('user_id')
        
        print super_p
        
        admins = None
        if not super_p:
            admins = ElectionOfficer.objects.filter(election=election,super_p=True).exclude(user__user_id=user_id)
            print admins
            if not admins:  
                raise forms.ValidationError("You need to have at least one (1) %s  for this election. " % (settings.ELECTION_ADMIN_ROLE))
        
        officer = ElectionOfficer.objects.filter(user__user_id=user_id,election=election)
        
        if not officer:
            return cleaned_data
        
        election_roles = list(cleaned_data.get('electionrole'))
        
        if super_p:
            election_roles.append(ElectionRole.objects.get(election=election, name=settings.ELECTION_ADMIN_ROLE))
            
        deleted_roles = []
        for role in officer[0].electionrole.all():
            if role not in election_roles:
                deleted_roles.append(role)
                
        if deleted_roles:
            v_policies = ValidationPolicy.get_by_election_and_officer(election, officer[0], delete_from_roles=deleted_roles, delete=True)
            if v_policies:
                print v_policies
                msg = []
                msg1 = "You are not allowed to remove officer %s from the roles " % (officer[0].user.name)
                print msg1
                for i, role in enumerate(deleted_roles):
                    msg1 = msg1 + " " + role.name
                    if i < (len(deleted_roles) - 1):
                        msg1 = msg1 + ", "
                msg1 = msg1 + "  because he is needed on deciding the following validation policies:"
                msg.append(msg1)
                print msg
                for policy in v_policies:
                    msg.append(policy.description)
                print msg
                raise forms.ValidationError(msg)    
        
        return cleaned_data
        
class RoleForm(ModelForm):
    class Meta:
        model = ElectionRole
        exclude = ('election',)
        widgets = {
            'permissions': forms.SelectMultiple(attrs={'size':'20'}),
        }
    #name = forms.CharField(max_length=50, label="name", help_text="Provide a descriptive name of an election role.")
    #permissions = forms.MultipleChoiceField(queryset=Permission.objects.all())
    def __init__(self, *args, **kwargs):
        #election = kwargs.pop('election', None)
        super(RoleForm, self).__init__(*args, **kwargs)

        #if election:
        self.fields['permissions'].queryset = Permission.objects.all().exclude(codename__in=settings.ELECTION_ADMIN_PERMS)
            
class PolicyForm(ModelForm):
    permission = forms.ModelChoiceField(queryset=Permission.objects.all(), empty_label=None)
    description = forms.CharField(widget=forms.TextInput(attrs={'size':'40'}), 
                                  help_text='e.g. Validation policy for defining election ballot')
    
    class Meta:
        model = ValidationPolicy
        fields = ('permission', 'description')
        
    def __init__(self, *args, **kwargs):
        perm_id = kwargs.pop('perm_id', None)
        super(PolicyForm, self).__init__(*args, **kwargs)
        
        if perm_id:
            perms = Permission.objects.filter(id=perm_id)
            self.fields['permission'].queryset= perms
            self.fields['description'].help_text = "e.g. Validation Policy for " + perms[0].name 
         
class PolicyEntryForm(ModelForm):
    description = forms.CharField(widget=forms.TextInput(attrs={'size':'40'}))
    needed_signatures = forms.IntegerField(min_value=1, label='needed_signatures',
                                widget=forms.TextInput(attrs={'size':'2'}))
    order = forms.IntegerField(min_value=1, 
                                widget=forms.TextInput(attrs={'size':'1'}))
    
    class Meta:
        model = ValidationEntry
        fields = ('description', 'election_role', 'needed_signatures', 'order')
    
    def __init__(self, *args, **kwargs):
        self.election = kwargs.pop('election', None)
        super(PolicyEntryForm, self).__init__(*args, **kwargs)
        
        if self.election:
           self.fields['election_role'].queryset= ElectionRole.objects.filter(election=self.election)
            
class BaseEntryFormSet(BaseModelFormSet):
    def __init__(self, *args, **kwargs):
        super(BaseEntryFormSet, self).__init__(*args, **kwargs)
        if args:
            # get the permission_id of the policy related to the Validation Entries, given through request.POST data
            self.policy_permission_id =  args[0]['permission']
            
        
    def clean(self):
        super(BaseEntryFormSet, self).clean()
        if any(self.errors):
            return
        
        msg = []
        all_instances = []
        election = self.forms[0].election
        for form in self.forms:
            instance = form.cleaned_data
            
            if instance:
                if not instance['DELETE']:
                    all_instances.append(instance)
        #print all_instances
        
        #validate its satisfiability, returns [Bool, errors], 
        #errors list the [needed_signatures, num_users] for each validation entry
        
        if not all_instances:
            msg.append("You must define at least one validation entry for this validation policy")
            
        results = ValidationPolicy.validate(all_instances, permission_id = self.policy_permission_id, election=election)
        if not results[0]:
            for i, er in enumerate(results[1]):
                if er[0] == 'perm':
                    msg.append("With this validation policy definition, no election officer would be able to execute this permission.")
                elif er[0] != er[1]:
                    msg.append(u""+all_instances[i]['description'] + " needed signatures should be less than " + str(er[0]))

        #validate the order
        ran = list(range(1, len(all_instances)+1))
        
        for e in all_instances:
            if not e['order'] in ran:
                msg.append("There is an error in the ordering of the validation entries")
                break
            else:
                ran.remove(e['order'])
                
        raise forms.ValidationError(msg)

    
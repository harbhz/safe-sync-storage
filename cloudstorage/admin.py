from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import UploadFile, Contact, Profile, ActivityLogs, FileTransfer, Chat, AnomalyEvent

@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'mobile', 'description', 'date_created')
    search_fields = ('name','email','mobile')
    list_filter = ('name','date_created')
    list_per_page = 50

@admin.register(UploadFile)
class UploadFileAdmin(admin.ModelAdmin):
    list_display = ('user', 'file_name', 'date_created')
    search_fields = ('file_name', 'date_created',)
    list_filter = ('date_created',)
    exclude = ('file_password', 'file_path')
    list_per_page = 20

    def has_delete_permission(self, request, obj=None):
        return False

class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'

class CustomUserAdmin(UserAdmin):
    inlines = (ProfileInline, )
    list_display = ('username', 'email', 'first_name', 'last_name', 'mobile','date_joined', 'is_staff')
    list_select_related = ('profile',)

    @admin.display(description='Mobile No.')
    def mobile(self, instance):
        return instance.profile.mobile

    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(CustomUserAdmin, self).get_inline_instances(request, obj)

admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

@admin.register(ActivityLogs)
class ActivityLogsAdmin(admin.ModelAdmin):
    list_display = ('user', 'activity_log', 'ip_address', 'user_agent', 'anomaly_severity', 'anomaly_score', 'date_created')
    search_fields = ('user__username', 'description', 'ip_address', 'user_agent')
    list_filter = ('activity_log', 'anomaly_severity', 'date_created')
    list_per_page = 50


@admin.register(AnomalyEvent)
class AnomalyEventAdmin(admin.ModelAdmin):
    list_display = ('user', 'actor_username', 'event_type', 'severity', 'anomaly_score', 'recommended_action', 'action_taken', 'date_created')
    search_fields = ('user__username', 'actor_username', 'source_ip', 'user_agent')
    list_filter = ('event_type', 'severity', 'date_created')
    list_per_page = 50

@admin.register(FileTransfer)
class FileTransferAdmin(admin.ModelAdmin):
    list_display = ('user', 'file_name', 'remarks', 'receiver_user', 'date_created')
    search_fields = ('user__username','receiver_user__username', 'remarks')
    list_filter = ('date_created', 'date_updated')
    list_per_page = 50

@admin.register(Chat)
class ChatAdmin(admin.ModelAdmin):
    list_display = ('sender_user', 'message', 'receiver_user', 'date_created')
    search_fields = ('sender_user__username', 'receiver_user__username', 'message')
    list_filter = ('date_created', )
    list_per_page = 50

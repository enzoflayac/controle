from django import template

register = template.Library()

@register.filter
def remove_user_path(value, user_id):
    return value.replace(f'user_{user_id}/', '')
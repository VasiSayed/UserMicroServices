# Generated by Django 5.2.3 on 2025-07-12 11:39

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0007_useraccess_categorylevel2_useraccess_categorylevel3_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='created_by',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_users', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='useraccessrole',
            name='role',
            field=models.CharField(choices=[('ADMIN', 'Admin'), ('Intializer', 'Intializer'), ('SUPERVISOR', 'Supervisor'), ('CHECKER', 'Checker'), ('MAKER', 'Maker')], max_length=50),
        ),
    ]

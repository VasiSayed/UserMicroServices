# Generated by Django 5.2.3 on 2025-07-03 10:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_rename_categorylevel2_useraccess_company_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_manager',
            field=models.BooleanField(default=False),
        ),
    ]

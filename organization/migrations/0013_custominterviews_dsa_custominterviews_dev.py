# Generated by Django 5.1.4 on 2025-02-15 19:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('organization', '0012_application_virtualresume_resumeconvo_resquestions'),
    ]

    operations = [
        migrations.AddField(
            model_name='custominterviews',
            name='DSA',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='custominterviews',
            name='Dev',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]

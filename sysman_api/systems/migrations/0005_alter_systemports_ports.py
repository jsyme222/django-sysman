# Generated by Django 3.2.4 on 2021-06-17 21:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('systems', '0004_auto_20210617_2049'),
    ]

    operations = [
        migrations.AlterField(
            model_name='systemports',
            name='ports',
            field=models.JSONField(default=list),
        ),
    ]

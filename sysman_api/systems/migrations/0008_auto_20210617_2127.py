# Generated by Django 3.2.4 on 2021-06-17 21:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('systems', '0007_alter_systemscan_sys_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='systemports',
            name='scan_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='systemports',
            name='sys_name',
            field=models.CharField(max_length=250),
        ),
    ]

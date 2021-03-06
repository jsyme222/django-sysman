# Generated by Django 3.2.4 on 2021-06-17 21:32

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('systems', '0009_alter_managedsystem_sys_location'),
    ]

    operations = [
        migrations.AlterField(
            model_name='managedsystem',
            name='sys_type',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='systems.managedsystemtype'),
        ),
        migrations.AlterField(
            model_name='systemports',
            name='scan_date',
            field=models.DateTimeField(blank=True, default=django.utils.timezone.now, null=True),
        ),
        migrations.AlterField(
            model_name='systemscan',
            name='ports',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='systems.systemports'),
        ),
    ]

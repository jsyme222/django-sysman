# Generated by Django 3.2.4 on 2021-06-18 02:02

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('systems', '0011_auto_20210617_2159'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='managedsystem',
            name='details',
        ),
        migrations.RemoveField(
            model_name='systemscan',
            name='ports',
        ),
        migrations.RemoveField(
            model_name='systemscan',
            name='sys_name',
        ),
        migrations.AddField(
            model_name='managedsystem',
            name='sys_scans',
            field=models.ManyToManyField(blank=True, to='systems.SystemScan'),
        ),
        migrations.AddField(
            model_name='systemscan',
            name='errors',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='systemscan',
            name='open_ports',
            field=models.JSONField(default=dict),
        ),
        migrations.AddField(
            model_name='systemscan',
            name='ports_to_scan',
            field=models.CharField(blank=True, default='22-80', max_length=20),
        ),
        migrations.AddField(
            model_name='systemscan',
            name='system',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='systems.managedsystem'),
        ),
        migrations.DeleteModel(
            name='SystemPorts',
        ),
    ]

from django.db import models
from django.db.models.signals import post_save
from django.utils import timezone
from django.dispatch import receiver
from .modules.subdom import buffover
import nmap
import ipwhois
import requests


class ManagedSystemType(models.Model):
    type_name = models.CharField(
        max_length=250,
        default="",
        blank=False,
    )
    details = models.JSONField(
        default=list
    )

    def __str__(self) -> str:
        return self.title


class SystemScan(models.Model):
    system = models.ForeignKey(
        "ManagedSystem",
        on_delete=models.CASCADE,
        null=True
    )
    scan_date = models.DateTimeField(
        blank=True,
        null=True
    )
    ports_scanned = models.CharField(
        max_length=20,
        default="22-80",
        blank=True,
    )
    open_ports = models.JSONField(default=dict)
    headers = models.JSONField(default=dict)
    whois = models.JSONField(default=dict)
    subdomains = models.JSONField(default=dict, null=True)

    errors = models.TextField(default="")

    def get_sys_ip(self):
        ip = None
        try:
            ip_block = self.open_ports["scan"]
            ip = [k for k in list(ip_block)[:1]][0]
            self.system.set_sys_ip(ip)
        except KeyError as e:
            print("NO SUCCESSFUL SCAN")
            self.errors = self.errors + '\n\n' + str(e)
        return ip

    def whois_lookup(self):
        print('\n[!] Whois Lookup : \n')

        try:
            lookup = ipwhois.IPWhois(self.get_sys_ip())
            results = lookup.lookup_whois()
            self.whois = results
        except Exception as e:
            self.errors = str(self.errors) + "\n" + str(e)
            print('[-] Error : ' + str(e))

    def get_headers(self):
        result = {}
        host = self.system.sys_location
        print('\n[!] Headers :\n')
        try:
            rqst = requests.get(host, verify=False)
            for k, v in rqst.headers.items():
                print('[+] {} : '.format(k) + v)
                result.update({k: v})
        except Exception as e:
            print('\n[-] Exception : ' + str(e) + '\n')
            self.errors = str(self.errors) + "\n" + str(e)
            result.update({'error': str(e)})

        self.headers = result

    def scan_ports(self, range: str = "22-80") -> None:
        payload = ["[!] See errors", ]
        host = self.system.sys_location
        if host.startswith("http"):
            host = host.split("/")[-1]
        try:
            nm = nmap.PortScanner()
            scan = nm.scan(host, (self.ports_scanned or range))
            payload = scan
        except Exception as e:
            self.errors = str(self.errors) + "\n" + str(e)
        self.open_ports = payload

    def get_subdomains(self):
        subs = buffover(self.system.sys_location)
        self.subdomains = subs

    def scan(self):
        self.scan_ports()
        self.get_headers()
        self.whois_lookup()
        self.get_subdomains()
        self.scan_date = timezone.now()
        self.save()

    def __str__(self) -> str:
        return f'{self.system.sys_name} -> {str(self.scan_date)[:-16]}'


class ManagedSystem(models.Model):
    sys_location = models.URLField(
        max_length=100,
        default="",
        blank=True,
        null=True,
    )
    sys_ip = models.CharField(
        max_length=100,
        default="",
        blank=True,
        null=True,
    )
    sys_type = models.ForeignKey(
        ManagedSystemType,
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )
    sys_name = models.CharField(
        max_length=250,
        blank=True,
        null=True,
        default=""
    )

    is_scanning = models.BooleanField(default=False)

    def sys_scans(self):
        scans = SystemScan.objects.filter(system=self)
        return scans

    def set_sys_ip(self, ip: str) -> None:
        print(ip)
        self.sys_ip = ip
        self.save()

    def scan_system(self) -> None:
        self.is_scanning = False
        system_scan = SystemScan.objects.create(system=self)
        system_scan.scan()

    def __str__(self) -> str:
        return self.sys_name or self.sys_location.split(".")[-2]

    def save(self, *args, **kwargs):
        if self.sys_location and not self.sys_name:
            self.sys_name = self.sys_location.split("/")[-1]
        return super(ManagedSystem, self).save(*args, *kwargs)


@receiver(post_save, sender=ManagedSystem)
def scan_system_save_receiver(sender, instance, **kwargs):
    if instance.is_scanning:
        instance.scan_system()

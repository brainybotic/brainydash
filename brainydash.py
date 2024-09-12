# Import libraries
import platform
import subprocess
import sys
import psutil
import os

import dns.resolver

from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich import box
from rich.console import Console
from rich.table import Table
from rich.columns import Columns
from rich.progress import track
from rich.spinner import Spinner
from rich.tree import Tree
from rich.console import Group

import yaml

import getchlib

import pythonping # from pythonping import ping

# Global variables
text = Text('')
last_key = ""
# Layout columns width
col1_width = 40
col2_width = 40
col3_width = 53
screen_width = col1_width + col2_width + col3_width + 2 * 2

yaml_filename = "devices_services.yaml"

from scapy.all import *
from datetime import datetime
conf.checkIPaddr = False

DHCP_DISCOVER = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff", type=0x800) \
                    / IP(src="0.0.0.0",dst="255.255.255.255") \
                    / UDP(sport=68,dport=67) \
                    / BOOTP(op=1, chaddr=RandMAC()) \
                    / DHCP(options=[("message-type","discover"),"end"])
                    # / IP(src="0.0.0.0",dst="10.0.2.1") \
                    # / IP(src="0.0.0.0",dst="255.255.255.255") \

old_value = 0

dhcp_answer = False
DHCP_Server1_service_list = []
DHCP_Server2_service_list = []
DHCP_Server3_service_list = []

#layout = Layout()

def read_config_file(yaml_filename: str):
    with open('./' + yaml_filename, 'r', encoding="utf-8") as file:
        config = yaml.safe_load(file)
    return config
config = read_config_file(yaml_filename)

def get_ch(): 
    global last_key
    
    # ch:str = getchlib.getkey(False, echo=False)
    key_code = getchlib.getkey(False, echo=False)
    last_key = key_code.strip("'") 
    
    # clear keyboard cache
    cache_key = getchlib.getkey(False, echo=False).strip("'") 
    while cache_key != '':
        cache_key = getchlib.getkey(False, echo=False).strip("'") 
        
    if key_code == '\x03' or last_key == 'q':
        sys.exit(0)

def ping(host):
    param = '-n' if platform.system().lower()=='windows' else '-c'
    command = ['ping', param, '1', host]

    result = subprocess.run(command, stdout=subprocess.PIPE)
    output = result.stdout.decode('utf8')
    if "Request timed out." in output or \
        "100% packet loss" in output or \
        "Destination host unreachable" in output or \
            "could not find host" in output:
        return "ERROR"
    return "CONNECTED"

def get_dhcp_answer_service_list(dhcp_answer):
    service_list = []
    try:
        service_list.append("IP:" + str(dhcp_answer[BOOTP].yiaddr))
        service_list.append("Router:" + str([item for item in dhcp_answer.getlayer(DHCP).fields["options"] if item[0] == 'router'][0][1]))  
        service_list.append("Mask:" + str([item for item in dhcp_answer.getlayer(DHCP).fields["options"] if item[0] == 'subnet_mask'][0][1]))  
        service_list.append("DNS:" + str([item for item in dhcp_answer.getlayer(DHCP).fields["options"] if item[0] == 'name_server'][0][1]))  
        service_list.append("Lease:" + str([item for item in dhcp_answer.getlayer(DHCP).fields["options"] if item[0] == 'lease_time'][0][1]))  
        service_list.append(dhcp_answer.getlayer(DHCP))
    except:
        pass
    return service_list

def get_service_tree(service, service_list):
    service_tree = Tree(":computer: " + service)
    for item in service_list:
        service_tree.add(":receipt: " + item)
    return service_tree

def get_dns_answer_service_list():
    service_tree = Tree(":computer: DNS - 10.0.4.1")
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['10.0.4.1'] # using google DNS
        result = resolver.resolve('rocky.brainybotic.local')
        for item in result:
            service_tree.add(":receipt: rocky.brainybotic.local - " + item.to_text())
                
        result = resolver.resolve('rockyrouter.brainybotic.local')
        for item in result:
            service_tree.add(":receipt: rockyrouter.brainybotic.local - " + item.to_text())
                
            #nameservers = [ns.to_text() for ns in result]     
    except:
        pass
    return service_tree

def convert_bytes(bytes):
    """
    Convert bytes to a human-readable format.
    """
    sizes = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while bytes >= 1024 and i < len(sizes)-1:
        bytes /= 1024
        i += 1
    return f"{bytes:.2f} {sizes[i]}"

def monitor_network_usage():
    """
    Monitor network usage in real-time.
    """
    global old_value
    
    old_value = psutil.net_io_counters().bytes_recv + psutil.net_io_counters().bytes_sent
    total_bytes = 0

    while True:
        new_value = psutil.net_io_counters().bytes_recv + psutil.net_io_counters().bytes_sent
        diff = new_value - old_value
        old_value = new_value
        total_bytes += diff

        
        return convert_bytes(diff)

def ProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█', printEnd = "\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    return (prefix + " |" + bar + "| " + percent + "%" + suffix)


def make_header_panel() -> Panel:

    global screen_width 
    global last_key
    current_datetime = datetime.now()
    formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")

    footer_text = f"[white]CET93 - Cinel                     {formatted_datetime}" 
    
    # spinner = Spinner("dots")
    spinner = Spinner("dots2", style="white")
    footer_text = footer_text.center(screen_width - 20, ' ')
    footer_columns = Columns(
        [
            spinner,
            footer_text,
            spinner,
        ],
        column_first=True,
        expand=True,
    )
       
    global keyboard_cache
    panel = Panel(
        footer_columns, \
        title="", \
        border_style="White", \
        title_align="left", \
        padding=(0, 0),
    )
    return panel

def make_services_panel1(dhcp_answer) -> Panel:
    blank_row = col2_width * " "
    
    server1 = "10.0.4.1"
    global DHCP_Server1_service_list
    if len(DHCP_Server1_service_list) == 0:
        if dhcp_answer:
            if dhcp_answer[IP].src == server1:
                DHCP_Server1_service_list = get_dhcp_answer_service_list(dhcp_answer)

    DHCP_Server1 = get_service_tree("DHCP - " + server1, DHCP_Server1_service_list)
    panel_1 = Panel.fit(
        DHCP_Server1, \
        border_style="none",
        box = box.MINIMAL,
    )

    server2 = "10.0.3.1"
    global DHCP_Server2_service_list
    if len(DHCP_Server2_service_list) == 0:
        if dhcp_answer:
            if dhcp_answer[IP].src == server2:
                DHCP_Server2_service_list = get_dhcp_answer_service_list(dhcp_answer)

    DHCP_Server2 = get_service_tree("DHCP - " + server2, DHCP_Server2_service_list)
    panel_2 = Panel.fit(
        DHCP_Server2, \
        border_style="none",
        box = box.MINIMAL,
    )
    
    panel_group = Group(
    panel_1,
    panel_2
    )

    services_panel1 = Panel(panel_group,
                        title="Services",
                        title_align="left", 
                        border_style="yellow", 
    )
    
    return services_panel1

def make_services_panel2(dhcp_answer) -> Panel:
    
    blank_row = col2_width * " "
    server3= "10.0.2.1"
    
    global DHCP_Server3_service_list
    if len(DHCP_Server3_service_list) == 0:
        if dhcp_answer:
            if dhcp_answer[IP].src == server3:
                DHCP_Server3_service_list = get_dhcp_answer_service_list(dhcp_answer)
            
    DHCP_Server3 = get_service_tree("DHCP - " + server3, DHCP_Server3_service_list)
    
    panel_1 = Panel.fit(
        DHCP_Server3, \
        border_style="none",
        box = box.MINIMAL,
    )
    
    panel_2 = Panel.fit(
        get_dns_answer_service_list(), 
        border_style="none",
        box = box.MINIMAL,
    )
    
        
        
    panel_group = Group(
    panel_1,
    panel_2,
    )
    services_panel2 = Panel(panel_group,
                        title="Services",
                        title_align="left", 
                        border_style="yellow", 
    )
    return services_panel2

def make_devices_panel(enable_ping) -> Panel:
    table = Table(box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Device")
    table.add_column("IP")
    table.add_column("STATUS")
    table.add_column("Latency")
    
    for devices in config['devices']:
        device = devices['name']
        ip = devices['ip']
        latency = 0
        result = "UNKNOWN"
        if enable_ping:
            # result = ping(ip)
            ping_result = ping_host(ip)
            if bool(ping_result):
                latency = ping_result['avg_latency'] if ping_result['packet_loss'] < 100 else 0
                result = "ERROR" if ping_result['packet_loss'] == 1 else "CONNECTED"
            #result = "ERROR" if ping_result.packets_lost == 0 else "CONNECTED"
            
            
        result = "[blink red]" + result if result != "CONNECTED" else "[green]" + result 
        table.add_row(device, ip, result, str(latency) + " ms")
    
    panel = Panel.fit(
        table, 
        title="Devices",
        border_style="blue",
        title_align="left",
        padding=(1, 1),
    )
    return panel

def make_processes_panel() -> Panel:
    bar_length = 14
    bar_cpu = ProgressBar(psutil.cpu_percent(1), 100, prefix = 'CPU:'.ljust(10), suffix = '', length = bar_length)
    bar_ram = ProgressBar(psutil.virtual_memory().percent, 100, prefix = 'Memory:'.ljust(10), suffix = '', length = bar_length)
    bar_swap = ProgressBar(psutil.swap_memory().percent, 100, prefix = 'Swap:'.ljust(10), suffix = '', length = bar_length)
    bar_disk = ProgressBar(psutil.disk_usage(os.getcwd()).percent, 100, prefix = 'Disk:'.ljust(10), suffix = '', length = bar_length)

    network = "Network:".ljust(10) + monitor_network_usage()
        
    panel = Panel.fit(
        bar_cpu + "\n" + \
        bar_ram + "\n" + \
        bar_disk + "\n" + \
        bar_swap + "\n" + \
        network \
        , \
        title="Processes", \
        border_style="Green", \
        title_align="left", \
        padding=(1, 2),
    )
    return panel

def make_footer_panel() -> Panel:
    global screen_width 
    global last_key
    footer_text = "[white]" + \
        "Last key:" + last_key + \
        "    " + \
        "Press 'q' to quit" 
    
    # spinner = Spinner("dots")
    spinner = Spinner("bouncingBall", style="red")
    

    footer_text = footer_text.center(screen_width - 20, ' ')
    
    footer_columns = Columns(
        [
            spinner,
            footer_text,
            spinner,
        ],
        column_first=True,
        expand=True,
    )
        
#         Align.center(footer_text), \
        
    global keyboard_cache
    panel = Panel(
        footer_columns, \
        title="", \
        border_style="White", \
        title_align="left", \
        padding=(0, 0),
    )
    return panel

def make_layout() -> Layout:
    global col1_width 
    global col2_width 
    global col3_width 
    
    layout = Layout()
    
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
        
    layout["body"].split_row(
        Layout(name='column1', size=col1_width),
        Layout(name='services', size=col2_width),
        Layout(name='devices', size=col3_width),
    )
    
    layout["column1"].split_column(
    Layout(name="processes"),
    Layout(name="services1")
    )
    layout["processes"].size = 10
    
    return layout

layout = make_layout()
layout['header'].update(make_header_panel())
layout['processes'].update(make_processes_panel())
layout['services1'].update(make_services_panel1(dhcp_answer))
layout['services'].update(make_services_panel2(dhcp_answer))
layout['devices'].update(make_devices_panel(False))
layout['footer'].update(make_footer_panel())

def ping_host(host):
    try:
        ping_result = pythonping.ping(target=host, count=1, timeout=2)
        return {
            'host': host,
            'avg_latency': ping_result.rtt_avg_ms,
            'min_latency': ping_result.rtt_min_ms,
            'max_latency': ping_result.rtt_max_ms,
            'packet_loss': ping_result.packet_loss
        }
    except:
        return {}

with Live(layout, refresh_per_second=2, transient=True, screen=True):
    while True:
        dhcp_answer = srp1(DHCP_DISCOVER, iface="Realtek USB GbE Family Controller", timeout=2, verbose=0)
        get_ch()
        layout['header'].update(make_header_panel())
        get_ch()
        layout['processes'].update(make_processes_panel())
        get_ch()
        layout['services1'].update(make_services_panel1(dhcp_answer))
        get_ch()
        layout['services'].update(make_services_panel2(dhcp_answer))
        get_ch()
        layout['devices'].update(make_devices_panel(True))
        get_ch()
        layout['footer'].update(make_footer_panel())
        get_ch()
       
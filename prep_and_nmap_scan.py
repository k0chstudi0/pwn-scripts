#!/usr/bin/python3

import logging
import os
import random
import re
import subprocess
import sys
import threading
import time
from xml.dom import minidom

IDENTIFIER_COMMAND = "command"
IDENTIFIER_COMMAND_NR = "command_nr"
IDENTIFIER_DIRECTORY = "directory"
IDENTIFIER_HOSTNAME = "hostname"
IDENTIFIER_IP = "ip"
IDENTIFIER_NMAP_OUTPUT_INITIAL_TCP_ALL = "nmap_initial_tcp_all"
IDENTIFIER_NMAP_OUTPUT_INITIAL_TCP_SERVICES = "nmap_initial_tcp_services"
IDENTIFIER_NMAP_OUTPUT_INITIAL_UDP_ALL = "nmap_initial_udp_all"

hosts_information = {}
logger = None
processes_information = {}

def get_path():
    base_path = input("Enter the base directory path (default: .): ") or os.getcwd()
    return base_path

def get_hosts():
    hosts = [] 
    host_count = int(input("Enter the number of hosts (default: 6): ") or 6)
    for i in range(host_count):
        ip = input(f"Enter the IP address for host {i}: ")
        ip_as_octet_list = re.split(r'(\.|/)', ip)
        hostname = input(f"Enter the hostname for host {i} (default: host_{ip_as_octet_list[6]}): ") or f"host_{ip_as_octet_list[6]}"
        hosts.append( (ip, hostname) )
    return hosts

def create_directory(base_path, dirname):
    global logger
    dir_path = os.path.join(base_path, dirname)
    if not os.path.exists(dir_path):
        logger.info(f"Creating directory {dir_path}")
        os.makedirs(dir_path)
    return dir_path

def run_nmap_scan(ip, options, output_file):
    global logger
    logger.debug(f"Got ip: {ip}, options: {options}, and output_file: {output_file}")
    nmap_command = []
    nmap_command.append("nmap")
    nmap_command.extend(options)
    nmap_command.append("-oA")
    nmap_command.append(output_file)
    nmap_command.append(ip)
    print_command = " ".join(nmap_command)
    logger.info(f"Running task for ip {ip}:\t\t{print_command}")
    return subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

def run_sleep(sec):
    sleep_command = ["sleep", str(sec)]
    return subprocess.Popen(sleep_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)

def run_nmap_initial_tcp_all(ip):
    global hosts_information
    global processes_information
    command = f"nmap -sS -Pn -p- -oA {hosts_information[ip][IDENTIFIER_DIRECTORY]}/{IDENTIFIER_NMAP_OUTPUT_INITIAL_TCP_ALL} {ip}"
    options = ["-sS", "-p-"]
    output_file = hosts_information[ip][IDENTIFIER_DIRECTORY] + "/" + IDENTIFIER_NMAP_OUTPUT_INITIAL_TCP_ALL
    process = run_nmap_scan(ip, options, output_file)
    processes_information[process] = {}
    processes_information[process][IDENTIFIER_COMMAND] = command
    processes_information[process][IDENTIFIER_COMMAND_NR] = 1
    processes_information[process][IDENTIFIER_IP] = ip

def run_nmap_initial_tcp_service(ip):
    global hosts_information
    global processes_information
    
    output_file = hosts_information[ip][IDENTIFIER_DIRECTORY] + "/" + IDENTIFIER_NMAP_OUTPUT_INITIAL_TCP_ALL + ".xml"
    open_ports = get_open_ports_from_nmap_xml(output_file)
    open_ports_string = ",".join(open_ports)
    open_ports_option = "-p" + open_ports_string
    command = f"nmap -sS {open_ports_option} -Pn -sC -sV -oA {hosts_information[ip][IDENTIFIER_DIRECTORY]}/{IDENTIFIER_NMAP_OUTPUT_INITIAL_TCP_SERVICES} {ip}"
    options = ["-sS", open_ports_option, "-sC", "-sV"]
    output_file = hosts_information[ip][IDENTIFIER_DIRECTORY] + "/" + IDENTIFIER_NMAP_OUTPUT_INITIAL_TCP_SERVICES
    process = run_nmap_scan(ip, options, output_file)
    processes_information[process] = {}
    processes_information[process][IDENTIFIER_COMMAND] = command
    processes_information[process][IDENTIFIER_COMMAND_NR] = 2
    processes_information[process][IDENTIFIER_IP] = ip

def run_nmap_initial_udp_all(ip):
    global hosts_information
    global processes_information
    command = f"nmap -sU -Pn -oA {hosts_information[ip][IDENTIFIER_DIRECTORY]}/{IDENTIFIER_NMAP_OUTPUT_INITIAL_UDP_ALL} {ip}"
    options = ["-sU"]
    output_file = hosts_information[ip][IDENTIFIER_DIRECTORY] + "/" + IDENTIFIER_NMAP_OUTPUT_INITIAL_UDP_ALL
    process = run_nmap_scan(ip, options, output_file)
    processes_information[process] = {}
    processes_information[process][IDENTIFIER_COMMAND] = command
    processes_information[process][IDENTIFIER_COMMAND_NR] = 3
    processes_information[process][IDENTIFIER_IP] = ip

def get_open_ports_from_nmap_xml(xml_file):
    ports = []
    dom = minidom.parse(xml_file)
    elements = dom.getElementsByTagName('port')
    for port_element in elements:
        state_elements = port_element.getElementsByTagName('state')
        if len(state_elements) == 1:
            if state_elements[0].attributes['state'].value == "open":
                ports.append(port_element.attributes['portid'].value)
            else:
                logger.error(f"The port {port_element.attributes['portid'].value} in the file {xml_file} does not have an 'open' state. This port will be omitted!")
        elif len(state_elements) == 0:
            logger.error(f"The port {port_element.attributes['portid'].value} in the file {xml_file} does not have a <state> element. This port will be omitted!")
        else:
            logger.error(f"The port {port_element.attributes['portid'].value} in the file {xml_file} does have multipe <state> elements. This port will be omitted!")
    return ports

def get_terminated_processes():
    result = []
    global logger
    global processes_information
    for process in processes_information.keys():
        if process.poll() is not None:
            logger.info(f"Task completed for ip {processes_information[process][IDENTIFIER_IP]}:\t{processes_information[process][IDENTIFIER_COMMAND]}")
            result.append(process)
    return result

def handle_terminated_process(process):
    global logger
    global processes_information
    previous_command_nr = processes_information[process][IDENTIFIER_COMMAND_NR]
    ip = processes_information[process][IDENTIFIER_IP]
    processes_information.pop(process)

    match previous_command_nr:
        case 1:
            run_nmap_initial_tcp_service(ip)
        case 2:
            run_nmap_initial_udp_all(ip)
        case 3:
            logger.info(f"Finished all tasks for ip {ip}!")
        case _:
            logger.error("Found unknown previous command number!")

class CustomFormatter(logging.Formatter):

    green = "\x1b[32;20m"
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    #format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d)"
    format = "%(levelname)s \t %(message)s"

    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: green + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

def main():
    global logger
    # create logger with 'spam_application'
    logger = logging.getLogger("prep_and_nmap_scan.py")
    logger.setLevel(logging.INFO)

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    
    # Get the base directory path as string
    base_path = get_path()
    logger.info(f"Got base path {base_path}")

    # Get all host information as list
    hosts = get_hosts()
    logger.info(f"Got hosts list {hosts}")
    global hosts_information

    for host in hosts:
        hosts_information[host[0]] = {}
        hosts_information[host[0]][IDENTIFIER_HOSTNAME] = host[1]
    logger.debug(f"Got current host information: {hosts_information}")

    # Create a subdirectory for each host
    for ip in hosts_information.keys():
        directory = create_directory(base_path, hosts_information[ip][IDENTIFIER_HOSTNAME])
        hosts_information[ip][IDENTIFIER_DIRECTORY] = directory
    logger.debug(f"Got current host information: {hosts_information}")

    for ip in hosts_information.keys():
        run_nmap_initial_tcp_all(ip)
    
    global processes_information
    while len(processes_information.keys()) > 0:
        terminated_processes = get_terminated_processes()
        for process in terminated_processes:
            handle_terminated_process(process)
        time.sleep(0.5)
    logger.info("No process running anymore... exiting")


if __name__ == "__main__":
    main()

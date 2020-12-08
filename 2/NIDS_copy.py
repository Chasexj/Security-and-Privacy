import csv
import matplotlib.pyplot as plt
from collections import defaultdict
from TestNIDS import *


def parse_netflow():
    """Use Python's built-in csv library to parse netflow.csv and return a list
       of dictionaries. The csv library documentation is here:
       https://docs.python.org/2/library/csv.html"""
    with open('netflow.csv', 'r') as netflow_file:
        netflow_reader = csv.DictReader(netflow_file)
        netflow_data = list(netflow_reader)
        return netflow_data


def is_internal_IP(ip):
    """Return True if the argument IP address is within campus network"""
    s = ip.split('.')
    if s[0] == "128" and s[1] == "112":
        return True
    return False


def plot_bro(num_blocked_hosts):
    """Plot the list of the number of Bro blocked hosts indexed by T"""
    fig = plt.figure(figsize=(16,8))
    plt.plot(range(len(num_blocked_hosts)), num_blocked_hosts, linewidth=3)
    plt.xlabel("Threshold", fontsize=16)
    plt.ylabel("Number of Blocked Hosts", fontsize=16)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    plt.title("Sensitivity of Bro Detection Algorithm", fontsize=16)
    plt.grid()
    plt.savefig("sensitivity_curve.png")


def detect_syn_scan(netflow_data):
    """Complete this function as described in readme.txt"""
    
    # Your code here
    syn_scan_count = 0
    total_tcp = 0
    for row in netflow_data:
        if row["Protocol"] == "TCP":
            total_tcp += 1
            if "S" in row["Flags"] and "A" not in row["Flags"]:
                syn_scan_count += 1

    percent_synonly = (syn_scan_count/total_tcp)*100
    # Do not change this print statement
    print("\nPercent SYN-only flows: {} -> {}\n".format(
        percent_synonly, test_percent_synonly(percent_synonly)))


def detect_portscan(netflow_data):
    """Complete this function as described in readme.txt"""

    # Your code here
    synonly_knownbad = []           # default value
    synonly_NOTknownbad = []        # default value
    other_knownbad = []             # default value      
    other_NOTknownbad = []          # default value

    percent_knownbad = 0            # default value
    percent_synonly_knownbad = 0    # default value
    percent_synonly_NOTknownbad = 0 # default value

    bad_ports = ["135", "139" ,"445", "1433"]
    total_tcp = 0
    total_knownbad = 0
    total_NOTknownbad = 0
    for row in netflow_data:
        if row["Protocol"] == "TCP":
            total_tcp += 1
            if row["Dst port"] in bad_ports:
                total_knownbad += 1
                if "S" in row["Flags"] and "A" not in row["Flags"]:
                    synonly_knownbad.append(row)
                else:
                    other_knownbad.append(row)
            else:
                total_NOTknownbad += 1
                if  "S" in row["Flags"] and "A" not in row["Flags"]:
                    synonly_NOTknownbad.append(row)
                else:
                    other_NOTknownbad.append(row)
    percent_knownbad = (total_knownbad/total_tcp)*100
    percent_synonly_knownbad = (len(synonly_knownbad)/total_knownbad)*100
    percent_synonly_NOTknownbad = (len(synonly_NOTknownbad)/total_NOTknownbad)*100

    # Do not change these statments
    print("Precent of TCP flows to known bad ports: {} -> {}".format(
        percent_knownbad, test_percent_knownbad(percent_knownbad)))
    print("Percent of SYN-only TCP flows to known bad ports: {} -> {}".format(
        percent_synonly_knownbad, test_percent_synonly_knownbad(percent_synonly_knownbad)))
    print("Percent of SYN-only TCP flows to other ports: {} -> {}\n".format(
        percent_synonly_NOTknownbad, test_percent_synonly_NOTknownbad(percent_synonly_NOTknownbad)))
    return synonly_knownbad, synonly_NOTknownbad, other_knownbad, other_NOTknownbad


def detect_malicious_hosts(netflow_data, synonly_knownbad, synonly_NOTknownbad, 
                           other_knownbad, other_NOTknownbad):
    """Complete this function as described in readme.txt"""

    # Your code here
    num_malicious_hosts = 0    # default value
    num_benign_hosts = 0       # default value
    num_questionable_hosts = 0 # default value

    synonly_knownbad_set = set()
    synonly_NOTknownbad_set = set()
    other_NOTknownbad_set = set()
    other_knownbad_set = set()
    
    # find the set of hosts with source IPs external to the campus network
    for row in synonly_knownbad:
        if not is_internal_IP(row['Src IP addr']):
            synonly_knownbad_set.add(row['Src IP addr'])

    for row in other_knownbad:
        if not is_internal_IP(row['Src IP addr']):
            other_knownbad_set.add(row['Src IP addr'])

    for row in synonly_NOTknownbad:
        if not is_internal_IP(row['Src IP addr']):
            synonly_NOTknownbad_set.add(row['Src IP addr'])

    for row in other_NOTknownbad:
        if not is_internal_IP(row['Src IP addr']):
            other_NOTknownbad_set.add(row['Src IP addr'])

    #intersection of malicious hosts with the benigh hosts:
    malicious_set = synonly_knownbad_set.union(synonly_NOTknownbad_set,other_knownbad_set)
    benign_set = other_NOTknownbad_set
    questionable_hosts = malicious_set.intersection(benign_set)
    
    malicious_set = malicious_set - questionable_hosts
    benign_set = benign_set - questionable_hosts

    num_malicious_hosts = len(malicious_set)
    num_benign_hosts = len(benign_set)
    num_questionable_hosts = len(questionable_hosts)
    
    # Do not change these print statments
    print("Number of malicious hosts: {} -> {}".format(
        num_malicious_hosts, test_num_malicious_hosts(num_malicious_hosts)))
    print("Number of benign hosts: {} -> {}".format(
        num_benign_hosts, test_num_benign_hosts(num_benign_hosts)))
    print("Number of questionable hosts: {} -> {}\n".format(
        num_questionable_hosts, test_num_questionable_hosts(num_questionable_hosts)))


class Bro:
    """TODO: complete the run() method below to implement the Bro algorithm"""
    
    def __init__(self, threshold):
        # self.T is the threshold number of unique destination addresses from
        #     successful and/or failed connection attempts (depending on port)
        #     before a host is marked as malicious
        self.T = threshold
        
        # self.good_services is the list of port numbers to which successful connections 
        #     (SYN and ACK) should not be counted against the sender
        self.good_services = [80, 22, 23, 25, 113, 20, 70]

    def successful_connection(self, row):
        return "S" in row["Flags"] and "A" in row["Flags"]

    def run(self, netflow_data):
        """TODO: Run the Bro algorithm on netflow_data, returning a 
                 set of blocked hosts. You may add additional helper methods 
                 or fields to the Bro class"""

        # Your code here
        blocked_hosts = set() # default value
        
        #dictionary for external hosts in A
        host_dict = {}
        #dictionary for external hosts in B

        for row in netflow_data:
            # check that host is external
            if row["Protocol"] == "TCP":
                if not is_internal_IP(row['Src IP addr']) and is_internal_IP(row["Dst IP addr"]):
                    if int(row["Dst port"]) in self.good_services:
                        if not self.successful_connection(row):
                            if row['Src IP addr'] not in host_dict:
                                host_dict[row['Src IP addr']] = set()
                                #host_dict[row['Src IP addr']].add(row["Dst IP addr"])
                            else:
                                host_dict[row['Src IP addr']].add(row["Dst IP addr"])
                    else:
                        if row['Src IP addr'] not in host_dict:
                            host_dict[row['Src IP addr']] = set()
                            #host_dict[row['Src IP addr']].add(row["Dst IP addr"])
                        else:
                            host_dict[row['Src IP addr']].add(row["Dst IP addr"])

        #find common key entries in dict a and dict b
        for external_host in host_dict.keys():
            if len(host_dict[external_host]) > self.T:
                blocked_hosts.add(external_host)

        print(self.T)
        print(len(blocked_hosts))
        print("--------------------------------")
        # Do not change this return statement
        return blocked_hosts


def main():
    """Run all functions"""
    netflow_data = parse_netflow()
    detect_syn_scan(netflow_data)
    portscan_flows = detect_portscan(netflow_data)
    detect_malicious_hosts(netflow_data, *portscan_flows)
    num_blocked_hosts = [len(Bro(T).run(netflow_data)) for T in range(121)]
    print("Your Bro implementation is {}".format(test_num_blocked_hosts(num_blocked_hosts)))
    plot_bro(num_blocked_hosts)


if __name__=="__main__":
    main()
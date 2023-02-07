import pyshark
import numpy as np
import os
from windowing import time_windowing
from sklearn import tree

#cap = pyshark.FileCapture('../captures/amazon/peppa_pig.pcapng')

def list_ips(cap):
    """returns a dict of all ips apearing in the capture featuring the number of time they appear"""
    list_dict = {}
    for c in cap:
        if 'src' in c[1].field_names:
            if c[1].src in list_dict.keys():
                list_dict[c[1].src] += 1
            else:
                list_dict[c[1].src] = 0
    return list_dict

def list_tcps(cap):
    list_dict = {}
    for c in cap:
        if 'TCP' in c:
            if c.tcp.port in list_dict.keys():
                list_dict[c.tcp.port] += 1
            else:
                list_dict[c.tcp.port] = 0
    return list_dict

def tcp_window_prob(cap):
    """calculates average and standard deviation of TCP window size"""
    res = {'mean': 0, 'sigma': 0}
    moment_1 = 0
    moment_2 = 0
    n = 0
    for c in cap:
        if 'TCP' in c:
            w = int(c.tcp.window_size)
            moment_1 += w
            moment_2 += w**2
            n += 1
    res['mean'] = moment_1/n
    res['sigma'] = np.sqrt(moment_2/(n**2) + res['mean']**2)
    return res

def ipt_prob(cap):
    """avg and sigma of inter-packet time"""
    res = {'mean': 0, 'sigma': 0}
    moment_1 = 0
    moment_2 = 0
    n = 0
    for c in cap:
        if n > 0:
            ipt = float(c.sniff_timestamp) - float(c_prec.sniff_timestamp)
            moment_1 += ipt
            moment_2 += ipt**2
        n += 1
        c_prec = c
    res['mean'] = moment_1/n
    res['sigma'] = np.sqrt(moment_2/(n**2) + res['mean']**2)
    return res

def packet_length_prob(cap):
    """calculates average and standard deviation of packet length"""
    res = {'mean': 0, 'sigma': 0}
    moment_1 = 0
    moment_2 = 0
    n = 0
    for c in cap:
        if 'ttl' in c[1].field_names:
            w = int(c[1].ttl)
            moment_1 += w
            moment_2 += w**2
            n += 1
    res['mean'] = moment_1/n
    res['sigma'] = np.sqrt(moment_2/(n**2) + res['mean']**2)
    return res

def ttl_prob(cap):
    """calculates average and standard deviation of ttl"""
    res = {'mean': 0, 'sigma': 0}
    moment_1 = 0
    moment_2 = 0
    n = 0
    for c in cap:
        w = int(c.length)
        moment_1 += w
        moment_2 += w**2
        n += 1
    res['mean'] = moment_1/n
    res['sigma'] = np.sqrt(moment_2/(n**2) + res['mean']**2)
    return res    

def list_udps(cap):
    list_dict = {}
    for c in cap:
        if 'UDP' in c:
            if c.udp.port in list_dict.keys():
                list_dict[c.udp.port] += 1
            else:
                list_dict[c.udp.port] = 0
    return list_dict

def temp_intensity_of_packets(cap):
    time_delta = cap[-1].sniff_timestamp - cap[0].sniff_timestamp
    total_number = total_number_of_packets(list_ips(cap))
    return total_number/time_delta

def total_number_of_packets(dict):
    total_number = 0
    for i in dict:
        total_number += dict[i]
    return total_number

def freq(dict):
    """from a dictionnary returns another dictionnary with frequencies instead of number of appearances"""
    res = {}
    total_number = total_number_of_packets(dict)
    for i in dict:
        res[i] = dict[i]/total_number
    return res

def beeg_matrix(capture):
    """a dumb matrix of litteraly every parameter to feed the AI"""

    l = time_windowing(capture, 15)
    res = []
    
    for cap in l:

        ips = list_ips(cap)
        tcps = list_tcps(cap)
        udps = list_udps(cap)
        ttls = ttl_prob(cap)
        ipts = ipt_prob(cap)
        tcpwins = tcp_window_prob(cap)
        pl = packet_length_prob(cap)
        res.append([
            total_number_of_packets(ips),
            total_number_of_packets(tcps),
            total_number_of_packets(udps),
            len(ips),
            len(tcps) + len(udps),
            ttls['mean'],
            ttls['sigma'],
            ipts['mean'],
            ipts['sigma'],
            tcpwins['mean'],
            tcpwins['sigma'],
            pl['mean'],
            pl['sigma'],
        ])

    return res

def ai_food(capture_folder_path_list):
    """final result to feed the ai"""
    res = [[], []]
    compteur = 0
    for path in capture_folder_path_list:
        dir_list = os.listdir(path)
        print(dir_list)
        for file in dir_list:
            cap = pyshark.FileCapture(path + "/" + file)
            b_m = beeg_matrix(cap)
            for i in b_m:
                res[0].append(i)
                res[1].append(compteur)
        compteur += 1
    return res


#clf = tree.DecisionTreeClassifier()
#clf.fit(ai_food(["../captures/google/not_present", "../captures/google/present"]))


#print(beeg_matrix(cap))
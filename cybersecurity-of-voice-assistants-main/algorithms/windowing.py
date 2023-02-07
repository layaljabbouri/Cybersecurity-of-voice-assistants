import pyshark
import numpy as np

#cap = pyshark.FileCapture('../captures/amazon/peppa_pig.pcapng')

def time_windowing(cap, delta_t):
    """converts a capture into a list of small delta_t captures"""
    res = []
    current_time = cap[0].sniff_timestamp
    l = []
    for c in cap:
        if float(c.sniff_timestamp) - float(current_time) > delta_t:
            res.append(l[:])
            l = []
            current_time = c.sniff_timestamp
        
        l.append(c)
    return res

#def packet_windowing(cap, n):
#print(time_windowing(cap, 15))
            

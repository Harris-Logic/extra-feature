# -*- coding: utf-8 -*-
"""
Created on Fri May 18 15:51:09 2018

@author: fuyixian
"""
#from math import log

import sys
sys.path.append('D:\\extra-feature')
#import numpy as np
#import pandas as pd
#from pprint import pprint
#from modules.processing .cuckooml import Instance
from cuckooml import Loader
from cuckooml import ML
read_from = "D:\\extra-feature\\Sample"
save_in = "D:\\extra-feature\\Sample2"


import json
import os
import sys
    #from lib.cuckoo.common.virustotal import VirusTotalAPI
    
if not os.path.exists(save_in):
    os.makedirs(save_in)
    #vt = VirusTotalAPI("", 0, 0)

for f in os.listdir(read_from):
    with open(read_from+"/"+f, "r") as malware_report:
        try:
            report = json.load(malware_report)
        except ValueError as error:
            print (sys.stderr, "Could not load file;", \
                    malware_report, "is not a valid JSON file.")
            print (sys.stderr, "Exception: %s" % str(error))
            print (sys.stderr, "Moving on to the next file...")
            continue
    
           
    with open(save_in+"/"+f, "w") as malware_report_updated:
        json.dump(report, malware_report_updated)
                    
                    

loader = Loader()
loader.load_binaries(save_in) #提取read_file里的所有文件

features_dict = loader.get_features()#获取特征

ml = ML(context="notebook")

ml.load_features(features_dict)#将特征数值化
#ml.features.to_csv(filename="D:\\sample_data\\features.csv", encoding='utf-8')
#ml.export_dataset(filename="D:\\sample_data\\features.csv")

features = ml.features#数值化后的特征赋值给features
features.to_csv("D:\\extra-feature\\features.csv", encoding='utf-8')

features_filtered = ml.filter_dataset(features)
features_filtered.to_csv("D:\\extra-feature\\features2.csv", encoding='utf-8')
#ml.export_dataset(filename="D:\\sample_data\\features2.csv")




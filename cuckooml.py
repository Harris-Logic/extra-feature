# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

#import collections
#import datetime
#import itertools
import json
import os
#import re
import sys
#from sklearn import svm
#import time

sys.path.append('D:\\extra-feature')
from common.config import Config
from common.constants import CUCKOO_ROOT
from math import log

try:
    import pandas as pd
    
except ImportError as e:
    print  (sys.stderr, "Some of the packages required by CuckooML are not \
        available.")
    print ( sys.stderr)

def init_cuckooml():
    """Initialise CuckooML analysis with default parameters."""
    cfg = Config("cuckooml")

    # Load reports for clustering
    loader = Loader()
    loader.load_binaries(CUCKOO_ROOT + "/" + cfg.cuckooml.data_directory)

    # Get features dictionaries
    
    features_dict = loader.get_features()
    
    # Transform them into proper features
    ml = ML()
    ml.load_features(features_dict)
 

class ML(object):
    """Feature formatting and machine learning for Cuckoo analysed binaries.
    All functions marked with asterisk (*) were inspired by code distributed
    with "Back to the Future: Malware Detection with Temporally Consistent
    Labels" by Brad Miller at al."""
    SIMPLE_CATEGORIES = {
        "properties":[
            "has_authenticode",
            "has_pdb",
            "pe_features",
            "packer_upx",
            "has_wmi"
        ],
        "behaviour":[
            "dumped_buffer2",
            "suspicious_process",
            "persistence_autorun",
            "raises_exception",
            "sniffer_winpcap",
            "injection_runpe",
            "dumped_buffer",
            "exec_crash",
            "creates_service",
            "allocates_rwx"
        ],
        "exploration":[
            "recon_fingerprint",
            "antidbg_windows",
            "locates_sniffer"
        ],
        "mutex":[
            "ardamax_mutexes",
            "rat_xtreme_mutexes",
            "bladabindi_mutexes"
        ],
        "networking":[
            "network_bind",
            "networkdyndns_checkip",
            "network_http",
            "network_icmp",
            "recon_checkip",
            "dns_freehosting_domain",
            "dns_tld_pw",
            "dns_tld_ru"
        ],
        "filesystem":[
            "modifies_files",
            "packer_polymorphic",
            "creates_exe",
            "creates_doc"
        ],
        "security":[
            "rat_xtreme",
            "disables_security",
            "trojan_redosru",
            "worm_renocide",
            "antivirus_virustotal"
        ],
        "virtualisation":[
            "antivm_vbox_files",
            "antivm_generic_bios",
            "antivm_vmware_keys",
            "antivm_generic_services",
            "antivm_vmware_files",
            "antivm_sandboxie",
            "antivm_vbox_keys",
            "antivm_generic_scsi",
            "antivm_vmware_in_instruction",
            "antivm_generic_disk",
            "antivm_virtualpc"
        ],
        "sanbox":[
            "antisandbox_unhook",
            "antisandbox_mouse_hook",
            "antisandbox_foregroundwindows",
            "antisandbox_productid",
            "antisandbox_idletime",
            "antisandbox_sleep"
        ],
        "infostealer":[
            "infostealer_browser",
            "infostealer_mail",
            "infostealer_keylogger",
            "infostealer_ftp",
        ],
        "ransomware":[
            "ransomware_files",
            "ransomware_bcdedit"
        ]
    }

    CATEGORIES = {
        "dynamic":{
            ":dimp:":[
                #"proc:",
                "mutex:"
            ],
            ":reg:":[
                "open:",
                "read:",
                "write:",
            ],
            ":win:":[
                ""
            ],  
        },
        "signature":{
                ":signature:":[
                ""
            ],  
                },
        "counts":{
            ":count:":{
                "proc":[""],
                "dimp":[""],
                "file:":[
                    "",
                    "read",
                    "written",
                    "deleted",
                    "created",
                    "moved",
                    "opened",
                ],
                "hosts":[""],        
                "tcp":[""],
                "udp":[""],
                "dns":[""],
                "http":[""],
                "reg:":[
                    #"",
                    "open",
                    "read",
                    "write"
                ],
                "wapi":[""],
                "extrasig":[""],
            }
        }
    }

    PATTERNS = [r"Armadillo", r"PECompact", r"ASPack", r"ASProtect",
        r"Upack", r"U(PX|px)", r"FSG", r"BobSoft Mini Delphi",
        r"InstallShield 2000", r"InstallShield Custom",
        r"Xtreme\-Protector", r"Crypto\-Lock", r"MoleBox", r"Dev\-C\+\+",
        r"StarForce", r"Wise Installer Stub", r"SVK Protector",
        r"eXPressor", r"EXECryptor", r"N(s|S)Pac(k|K)", r"KByS",
        r"themida", r"Packman", r"EXE Shield", r"WinRAR 32-bit SFX",
        r"WinZip 32-bit SFX", r"Install Stub 32-bit", r"P(E|e)tite",
        r"PKLITE32", r"y(o|0)da's (Protector|Crypter)", r"Ste@lth PE",
        r"PE\-Armor", r"KGB SFX", r"tElock", r"PEBundle", r"Crunch\/PE",
        r"Obsidium", r"nPack", r"PEX", r"PE Diminisher",
        r"North Star PE Shrinker", r"PC Guard for Win32", r"W32\.Jeefo",
        r"MEW [0-9]+", r"InstallAnywhere", r"Anskya Binder",
        r"BeRoEXEPacker", r"NeoLite", r"SVK\-Protector",
        r"Ding Boy's PE\-lock Phantasm", r"hying's PEArmor", r"E language",
        r"NSIS Installer", r"Video\-Lan\-Client", r"EncryptPE",
        r"HASP HL Protection", r"PESpin", r"CExe", r"UG2002 Cruncher",
        r"ACProtect", r"Thinstall", r"DBPE", r"XCR", r"PC Shrinker",
        r"AH(p|P)ack", r"ExeShield Protector",
        r"\* \[MSLRH\]", r"XJ \/ XPAL", r"Krypton", r"Stealth PE",
        r"Goats Mutilator", r"PE\-PACK", r"RCryptor", r"\* PseudoSigner",
        r"Shrinker", r"PC-Guard", r"PELOCKnt", r"WinZip \(32\-bit\)",
        r"EZIP", r"PeX", r"PE( |\-)Crypt", r"E(XE|xe)()?Stealth",
        r"ShellModify", r"Macromedia Windows Flash Projector\/Player",
        r"WARNING ->", r"PE Protector", r"Software Compress",
        r"PE( )?Ninja", r"Feokt", r"RLPack",
        r"Nullsoft( PIMP)? Install System", r"SDProtector Pro Edition",
        r"VProtector", r"WWPack32", r"CreateInstall Stub", r"ORiEN",
        r"dePACK", r"ENIGMA Protector", r"MicroJoiner", r"Virogen Crypt",
        r"SecureEXE", r"PCShrink", r"WinZip Self\-Extractor",
        r"PEiD\-Bundle", r"DxPack", r"Freshbind", r"kkrunchy"]  
        

    def __init__(self, context="standalone"):
        
        self.context = context
        self.features = None

    def __log_bin(self, value, base=3):
        """Return a logarithmic bin of given value. * """
        if value is None:
            return None
        # Add base -1 to count so that 0 is in its own bin
        return int(log(value + base - 1, base))

    def __n_grams(self, string, n=3, reorder=False):
        """Returns a *set* of n-grams. If the iterable is smaller than n, it is
        returned itself. * """
        if string is None:
            return None

        if len(string) <= n:
            if reorder:
                return set(["".join(sorted(string))])
            return set([string])

        ngrams = set()
        for i in range(0, len(string) - n + 1):
            if reorder:
                ngrams.add("".join(sorted(string[i:i+n])))
            else:
                ngrams.add(string[i:i+n])

        return ngrams
    
    def __handle_string(self, string):

        """Apply normalisation, simplification and n-gram extraction to a

        string. If the string is missing (None) return empty list."""
        handled = self.__n_grams(
                self.__simplify_string(
                        self.__normalise_string(string)
                        )
                )

        if handled is None:
            return []
        else:
            return handled


        # Add base -1 to count so that 0 is in its own bin
        #return int(log(value + base - 1, base))


    #def __normalise_string(self, string):
        #"""Get lower case string representation. * """
        #if string is None:
            #return None

        #return string.lower()

    def extract_features(self, features, include_API_calls=False, \
                      include_API_calls_count=False):
        """Extract features form an external object into pandas data frame."""
        my_features = {}
        for i in features:
            my_features[i] = {}

            # Categorise dynamic imports
            if features[i]["mutex"] is not None:
                my_features[i][":count:mutex"] = len(features[i]["mutex"])
        
            #for di in features[i]["dynamic_imports"]:
                #my_features[i][":dimp:" + di] = 1
            # Count dynamic imports
            #my_features[i][":count:dimp"] = \
                #len(features[i]["dynamic_imports"])
            import csv
            with open('dlls.csv', 'r') as f:
                reader = csv.reader(f)
                spamreader = list(reader)

            #FILE_OBJECT= open('order.log','r', encoding='UTF-8')
#            with open('dlls.csv','r',encoding='ANSI') as csvfile:#newline=''
#                spamreader = csv.reader(csvfile, delimiter=' ', quotechar='|')
                for e in spamreader:
                    a= ''.join(e)
#                    e.encode('utf-8').strip()
                    my_features[i][":dimp:" + a] = 1
                    #for j in self.__handle_string(features[i][e]):

                        #my_features[i][":dimp:" + j] = 1
                #my_features[i][":count:dimp"] = \
                        #len(features[i]["dynamic_imports"])   
           
            # TODO: better binning (linear not logarithmic)
            # File numbers
            operation_number = [("read", "files_read"),
                                ("written", "files_written"),
                                ("deleted", "files_deleted"),
                                ("created", "files_created"),
                                ("moved", "files_moved"),
                                ("opened", "files_opened")]
            for o in operation_number:
                my_features[i][":count:file:" + o[0]] = \
                    features[i][o[1]]

            # Networking
            # TODO: include subnets
            # TODO: tell apart type of connection: prefix features with "tcp",
            #       "udp", "dns"
            #for tcp in features[i]["tcp"]:
                #my_features[i][":net:" + tcp] = 1
            #for udp in features[i]["udp"]:
                #my_features[i][":net:" + udp] = 1
            #for dns in features[i]["dns"]:
                #my_features[i][":net:" + dns] = 1
                #for j in features[i]["dns"][dns]:
                    #my_features[i][":net:" + j] = 1
            #for http in features[i]["http"]:
                #my_features[i][":net:" + features[i]["http"][http]["host"]] \
                    #= 1
            #Count hosts 去重ip数
            my_features[i][":count:hosts"] = len(features[i]["hosts"])
            # Count tcp addresses
            my_features[i][":count:tcp"] = len(features[i]["tcp"])
            # Count udp addresses
            my_features[i][":count:udp"] = len(features[i]["udp"])
            # Count dns addresses
            my_features[i][":count:dns"] = len(features[i]["dns"])
            # Count http addresses
            my_features[i][":count:http"] = len(features[i]["http"])

            
            # Count register keys open
            my_features[i][":count:reg:open"] = \
                len(features[i]["regkey_opened"])
            
            # Count register keys read
            my_features[i][":count:reg:read"] = \
                len(features[i]["regkey_read"])
            
            # Count register keys write
            my_features[i][":count:reg:write"] = \
                len(features[i]["regkey_written"])

            # Windows API
            # TODO: better binning (linear not logarithmic)
            for wapi in features[i]["api_stats"]:
                my_features[i][":win:" + wapi] = \
                    self.__log_bin(features[i]["api_stats"][wapi])
                
            # Count Windows API calls
            my_features[i][":count:wapi"] = len(features[i]["api_stats"])
            
            # yara匹配规则signature
            # TODO: 查找每个文件的signature
            for signature in features[i]["signature"]:
                #print(features[i]["signature"])
                my_features[i][":signature:" + signature] = 1
                
            # Count signature
            my_features[i][":count:extrasig"] = len(features[i]["signature"])

        # Make Pandas DataFrame from the dictionary
        features_pd = pd.DataFrame(my_features).T
        # TODO: the operation below cannot tell apart missing vales and None
        features_pd.fillna(0, inplace=True)
        return features_pd

    def load_features(self, features, include_API_calls=False, \
                      include_API_calls_count=False):
        """Load features form an external object into pandas data frame."""
        self.features = self.extract_features(features, include_API_calls,
                                              include_API_calls_count)
        
        
    def filter_dataset(self, dataset=None, feature_coverage=0.1,
                       complement=False):
        """Prune features that are useless."""
        if dataset is None:
            dataset = self.features.copy()

        # Remove sparse features
        row_count = dataset.shape[0]
        remove_features = []
        for col in dataset:
            zero_count = 0.0
            for row in dataset[col]:
                if not row:
                    zero_count += 1
            # XOR
            if complement != (row_count-zero_count)/row_count<feature_coverage:
                remove_features.append(col)
        dataset.drop(remove_features, axis=1, inplace=True)

        return dataset


class Loader(object):
    """Loads instances for analysis and give possibility to extract properties
    of interest.(加载实例进行分析，并提供提取可能感兴趣的属性。)"""
    def __init__(self):
        self.binaries = {}
        self.binaries_location = ""
        self.binaries_updated = False


    def load_binaries(self, directory):
        """Load all binaries' reports from given directory.(从给定的目录加载所有二进制文件的报告。)"""
        self.binaries_location = directory + "/"
        for f in os.listdir(directory):
            self.binaries[f] = Instance()
            self.binaries[f].load_json(directory+"/"+f, f)
            self.binaries[f].extract_features()  #提取特征


    def update_binaries(self, elements, root, locations):
        """Append `elements` to the loaded JSONs at given `locations`.（在给定的“位置”上附加“元素”到加载的JSONs。）"""
        if isinstance(elements, pd.DataFrame) and isinstance(locations, dict):
            self.binaries_updated = True
            for i in elements.index:
                for j in elements.columns:
                    self.binaries[i].update(elements[j][i], root+[locations[j]])
        elif isinstance(locations, str):
            self.binaries_updated = True
            for i in self.binaries:
                self.binaries[i].update(elements, root+[locations])


    def save_binaries(self, alternative_location=""):
        """Save the binaries to given location if they have been updated.（如果它们已经被更新，将二进制文件保存到给定的位置。）"""
        if self.binaries_updated:
            save_location = self.binaries_location
            #print(save_location)
            if alternative_location:
                save_location = alternative_location
                if save_location[-1] != "/":
                    save_location += "/"

            # Create directory if it does not exist
            if not os.path.exists(save_location):
                os.makedirs(save_location)

            for f in self.binaries:
                self.binaries[f].save_json(save_location)
            self.binaries_updated = False
        else:
            print ("The binaries haven't been updated. No need to save them.")

    def get_features(self):
        """Return complex binary features as a labelled dictionary."""
        features = {}
        for i in self.binaries:
            features[i] = self.binaries[i].features
        return features


class Instance(object):
    """Machine Learning for Cuckoo."""

    def __init__(self):
        self.json_path = ""
        self.name = ""
        self.report = None
        self.total = None
        self.features = {}
        


    def load_json(self, json_file, name="unknown"):
        """Load JSON formatted malware report. It can handle both a path to
        JSON file and a dictionary object."""
        if isinstance(json_file, str):
            self.json_path = json_file
            with open(json_file, "r") as malware_report:
                try:
                    self.report = json.load(malware_report)
                except ValueError as error:
                    print ( sys.stderr, "Could not load file;", \
                        malware_report, "is not a valid JSON file.")
                    print ( sys.stderr, "Exception: %s" % str(error))
                    sys.exit(1)
        elif isinstance(json_file, dict):
            self.report = json_file
        else:
            # Unknown binary format
            print ( sys.stderr, "Could not load the data *", json, "* is of " \
                "unknown type: ", type(json), ".")

        self.name = name

    def update(self, element, location):
        """Insert `element` at given `location`."""
        element_to_update = self.report
        for l in location[:-1]:
            etu = element_to_update.get(l)
            if etu is None:
                element_to_update[l] = {}
                element_to_update = element_to_update.get(l)
            else:
                element_to_update = etu
        element_to_update[location[-1]] = element


    def save_json(self, root_dir):
        """Save JSON stored in th‘e class to a file."""
        with open(root_dir+self.name, "w") as j_file:
            json.dump(self.report, j_file)


    def extract_features(self):
        """Extract features of the loaded sample.(加载样例的特征提取)"""
        self.extract_features_dynamic()  #动态特征
        self.extract_features_signature()   #yara匹配规则

    def extract_features_dynamic(self):
        """Extract dynamic features of the loaded sample."""
        self.feature_dynamic_imports()
        self.feature_dynamic_filesystem()
        self.feature_dynamic_network()
        self.feature_dynamic_registry()
        self.feature_dynamic_windowsapi()
        
    def extract_features_signature(self):
        self.feature_signature()


    def feature_dynamic_imports(self):
        """Extract features from dynamic imports, mutexes, and processes.（从动态导入、互斥和过程中提取特性。）"""
        # Get mutexes
        self.features["mutex"] = \
            self.report.get("behavior", {}).get("summary", {}).get("mutex")

        # Get dynamically loaded library names
        #self.features["dynamic_imports"] = \
            #self.report.get("behavior", {}).get("summary", {})\
            #.get("dll_loaded", [])
        #print(self.features["dynamic_imports"])
#        et_tokens = ["ADVAPI.dll","comctl32.dll"]
#        for token in et_tokens:
#            self.features[token] = None
#        for attr in self.report.get("behavior", {}).get("summary", {})\
#            .get("dll_loaded", []):
#                if attr in et_tokens:
#                    self.features[attr] = attr
                    


    def feature_dynamic_filesystem(self):
        """Extract features from filesystem operations.（从文件系统操作中提取特性。）"""
        def flatten_list(structured):
            """Flatten nested list."""
            flat = []
            for i in structured:
                flat += i
            return flat

        # Get file operations and their number
        self.features["file_read"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_read",[])
#        print(self.features["file_read"])
        
        
        import re
        file_names = ["a.csv", "b.doc", "c.pptx", "d.doc", "e.csv", "f.csv"]
        file_name_suffixs = ["csv", "doc"]
        for file_name_suffix in file_name_suffixs:
            for file_name in file_names:
                pattern = ".+\." + file_name_suffix + "$"
                if re.match(pattern, file_name) is not None:
                    x = []          #一个新的盒子
                    x.append(file_name)
                    
        
        self.features["files_read"] = len(self.features["file_read"])
        #print(self.features["files_read"])
        self.features["file_written"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_written", [])
        self.features["files_written"] = len(self.features["file_written"])
        self.features["file_deleted"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_deleted", [])
        self.features["files_deleted"] = len(self.features["file_deleted"])
        self.features["file_created"] = flatten_list(\
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_created", [])
                                                   )
        self.features["files_created"] = len(\
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_created", [])
                                            )
        self.features["file_moved"] = flatten_list(\
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_moved", [])
                                                    )
        self.features["files_moved"] = len(self.features["file_moved"])

        # Get other file operations numbers
        self.features["file_opened"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_opened", [])
        self.features["files_opened"] = len(
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_opened", [])
        )
        """
        # Get total number of unique touched files
        file_operations = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_read", []) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_written", []) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_deleted", []) + \
            flatten_list(self.report.get("behavior", {}).get("summary", {})\
            .get("file_copied", [])) + \
            flatten_list(self.report.get("behavior", {}).get("summary", {})\
            .get("file_moved", [])) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_recreated", []) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_opened", []) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_exists", []) + \
            self.report.get("behavior", {}).get("summary", {})\
            .get("file_failed", [])
        # remove duplicates（删除重复记录）
        self.features["files_operations"] = len(list(set(file_operations)))
        """

    def feature_dynamic_network(self):
        """Extract features from network operations.（从网络操作中提取特性。）"""
        # Get host IP addresses
        self.features["hosts"] = []
        for c in self.report.get("network", {}).get("hosts", []):
            if c and c not in self.features["hosts"]:
                self.features["hosts"].append(c)
            
        # Get TCP IP addresses
        self.features["tcp"] = []
        for c in self.report.get("network", {}).get("tcp", []):
            c_dst = c.get("dst")
            if c_dst and c_dst not in self.features["tcp"]:
                self.features["tcp"].append(c_dst)
        

        # Get UDP IPs
        self.features["udp"] = []
        for c in self.report.get("network", {}).get("udp", []):
            c_dst = c.get("dst")
            if c_dst and c_dst not in self.features["udp"]:
                self.features["udp"].append(c_dst)

        # Get DNS queries and responses
        self.features["dns"] = {}
        for c in self.report.get("network", {}).get("dns", []):
            request = c.get("request")
            if request:
                self.features["dns"][request] = []
            else:
                continue

            answers = c.get("answers", [])
            for a in answers:
                a_type = a.get("type")
                a_data = a.get("data")
                if a_type == "A" and a_data:
                    self.features["dns"][request].append(a_data)
        

        # Get HTTP requests: method, host, port, path
        self.features["http"] = {}
        for c in self.report.get("network", {}).get("http", []):
            c_data = c.get("data")
            if c_data:
                self.features["http"][c_data] = {}
            else:
                continue

            c_method = c.get("method")
            if c_method:
                self.features["http"][c_data]["method"] = c_method
            c_host = c.get("host")
            if c_host:
                self.features["http"][c_data]["host"] = c_host
            c_port = c.get("port")
            if c_port:
                self.features["http"][c_data]["port"] = c_port
        


    def feature_dynamic_registry(self):
        """Extract features from registry operations.（从注册表操作中提取特性。）"""
        # Registry open
        self.features["regkey_opened"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("regkey_opened", [])
        #self.features["regkey_written-num"] = len(self.features["regkey_written"])
        # Registry read
        self.features["regkey_read"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("regkey_read", [])
        #self.features["regkey_deleted_num"] = len(self.features["regkey_deleted"])
        self.features["regkey_written"] = \
            self.report.get("behavior", {}).get("summary", {})\
            .get("regkey_written", [])


    def feature_dynamic_windowsapi(self):
        """Extract features from Windows API calls sequence."""
        self.features["api_stats"] = {}
        apistats = self.report.get("behavior", {}).get("apistats", {})
        for d in apistats:
            for e in apistats[d]:
                if e in self.features["api_stats"]:
                    self.features["api_stats"][e] += apistats[d][e]
                else:
                    self.features["api_stats"][e] = apistats[d][e]
#        print(self.features["api_stats"])


                
    def feature_signature(self):
        """Extract very basic set of features from *signatures* JSON field.
        These are extracted characteristics of the binary by cuckoo sandbox.（从签名JSON字段中提取非常基本的特性集。这些是由布谷鸟沙盒提取的二进制的特征。）"""
        self.features["signature"] = []
        for signature in self.report.get("signatures", []):
            sig_name = signature.get("name", "")
            if sig_name and sig_name not in self.features["signature"]:
                self.features["signature"].append(sig_name)
        #print(self.features["signature"])
            
           
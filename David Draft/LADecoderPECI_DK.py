#-------------------------------------------------------------------------------
# Name:        Entry program
# Purpose:
#
# Author:      ilinx
#
# Created:     2024/11/14
# Copyright:   (c) ilinx 2024
# Licence:     <your licence>
#-------------------------------------------------------------------------------
#!/usr/bin/env python
import sys
import os
import importlib
import argparse
import re
import csv
import glob
import threading

def get_module_path():
    mpath = __file__
    dpath = os.path.dirname(mpath)
    fpath = os.path.abspath(dpath)
    return fpath
    
def find_mmio_reg_def_file(reg_type='mmio'):
    target_fname = reg_type+'_reg_def.py'
    mpath = get_module_path()
    match_files = glob.glob(os.path.join(mpath, '**', f'*{target_fname}'),recursive=True)
    return match_files
    
def get_available_cpu_list():
    avil_cpu_dict={}
    mmio_list = find_mmio_reg_def_file(reg_type='mmio')
    for p in mmio_list:
        fn = p.split('\\')[-1]
        if '_mmio_reg_def.py' in fn:
            avil_cpu = fn.replace('_mmio_reg_def.py', '').upper()
            avil_cpu_dict[avil_cpu] = ['mmio']

    pcicfg_list = find_mmio_reg_def_file(reg_type='pcicfg')
    for p in pcicfg_list:
        fn = p.split('\\')[-1]
        if '_pcicfg_reg_def.py' in fn:
            avil_cpu = fn.replace('_pcicfg_reg_def.py', '').upper()
            if avil_cpu not in avil_cpu_dict:
                avil_cpu_dict[avil_cpu] = ['pcicfg']
            else:
                avil_cpu_dict[avil_cpu].append('pcicfg')
    return avil_cpu_dict


user_input = None
cpuname = None
die_id_map = {}
internal_dev_map = {}
mmio_reg_dict = {}
pcicfg_reg_dict = {}
avil_cpu_dict = {}


# Function to get user input with a timeout
def get_user_input():
    global user_input
    user_input = input()

def select_cpu_type(target_cpuname=None):
    global user_input
    global avil_cpu_dict
    global cpuname
    global die_id_map
    global internal_dev_map
    global mmio_reg_dict
    global pcicfg_reg_dict
    
    # Initialize variables
    user_input = None
    cpuname = None
    die_id_map ={}
    internal_dev_map ={}
    mmio_reg_dict ={}
    pcicfg_reg_dict ={}
   
    #Print Option Menu
    avil_cpu_dict = get_available_cpu_list()
    if avil_cpu_dict == {}:
        print("No any register definition files are available, script will not decode register name!")
    else:
        print("LADecoderPECI.py module support the register decoder for the following CPU family:")
        cpu_type_list = list(avil_cpu_dict.keys())
        avil_cnt =len(cpu_type_list)
        for i in range(avil_cnt):
            temp_type = cpu_type_list[i]
            print("    %2d : %s %s" %(i, temp_type, avil_cpu_dict[temp_type]))
        print("    %2d : No decoder" %(i+1))
        print()
        
        if target_cpuname in avil_cpu_dict:
            user_input = None
            cpuname = target_cpuname
            print("CPU Type = '%s' is selected!" %cpuname)
            print()
        else:
            print("Please select a platform (0-1):")
            # Create a thread to get user input
            input_thread = threading.Thread(target=get_user_input)
            
            # Start the input thread
            input_thread.start()
            
            # Wait for 10 seconds
            input_thread.join(timeout=3)
            
            #import pdb;pdb.set_trace()
            # Check if the user provided input
            if user_input is None:
                # If no input was provided within 10 seconds, force the option to 'No decoder'
                #print("i=%d" %i)
                user_input = int(i+1)
                print("\nNo input received within 10 seconds. Forcing to 'No decoder'.")
                print("CPU Type = None")
                print()
                print("Press any key to continue...")
            else:
                user_input = int(user_input)
                cpuname = cpu_type_list[user_input]
                # Print the selected option   
                print("CPU Type = '%s'" %cpuname)
                print()
            
        # Create mmio reg dict and pcicfg reg dict for the selected CPU Type
        if user_input != (i+1):
            target_fname = cpuname.lower()+'_dev_map.py'
            mpath = get_module_path()
            mmio_path = glob.glob(os.path.join(mpath, '**', f'{target_fname}'),recursive=True)[0]
            module_name = 'dev_map'
            spec = importlib.util.spec_from_file_location(module_name, mmio_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            die_id_map = module.die_id_map
            internal_dev_map = module.internal_dev_map
            
            target_fname = cpuname.lower()+'_mmio_reg_def.py'
            mpath = get_module_path()
            mmio_path = glob.glob(os.path.join(mpath, '**', f'{target_fname}'),recursive=True)[0]
            module_name = 'mmio_reg'
            spec = importlib.util.spec_from_file_location(module_name, mmio_path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            mmio_reg_dict = module.rdict
            
            target_fname = cpuname.lower()+'_pcicfg_reg_def.py'
            pcicfg_path = glob.glob(os.path.join(mpath, '**', f'{target_fname}'),recursive=True)[0]
            module_name = 'pcicfg_reg'
            spec = importlib.util.spec_from_file_location(module_name, pcicfg_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            pcicfg_reg_dict = module.rdict
    return


def gen_pci_bus_map_e2i(pci_bus_map_i2e):
    """
    Retrun a dictionary which key is exterbal PCI bus number and value is internal PCI bus number
    
    Input :
         pci_bus_map_i2e : a dictionary which key is internal PCI bus number and value is external bus number
         
    Note: The dictionary of 'pci_bus_map_i2e' for each can be got via CScripts/PythonSV command 'sv.socket0.target_info['pci_bus_map']' 
    """
    pci_bus_map_e2i = {}
    for bus_name in pci_bus_map_i2e:
        odict = pci_bus_map_i2e[bus_name]
        ndict  = {value: key for key, value in odict.items()}
        pci_bus_map_e2i[bus_name] = ndict
    return pci_bus_map_e2i


def gen_pci_bus_map_i2e_from_cscripts():
    pci_bus_map_i2e={}
    try:
        import namednodes as nn
        sv = nn.sv
        sv.refresh()
    except:
        print("ERROR: Fail to get CPU socket object!")
        print("       This Function support in CSCripts JTAG mode only!")
        return
    for skt in sv.sockets:
        temp_dict = skt.target_info['pci_bus_map']
        cpu_srt = 'cpu%d'%skt.target_info['socket_num']
        pci_bus_map_i2e[cpu_srt] = temp_dict
    return pci_bus_map_i2e


def gen_pci_bus_map_e2i_from_cscripts():
    pci_bus_map_i2e = gen_pci_bus_map_i2e_from_cscripts()
    pci_bus_map_e2i = gen_pci_bus_map_e2i(pci_bus_map_i2e)
    return pci_bus_map_e2i


bus_field_dict = { "I3C" :  [ 'Address (h)', 
                              'Command', 
                              'Data (h)', 
                              'Information'],
                    
                   "PECI" : [ 'Addr(h)',
                              'WrLen', 
                              'RdLen',
                              'Command(h)',
                              'Write Data(h)',
                              'FCS(Wr)(h)',
                              'Read Data(h)',
                              'FCS(Rd)(h)',
                              'Information'] }
                              
peci_cmd_code_map = { 'GetDIB(F7)'           : 0xf7,
                      'GetTemp(01)'          : 0x01,
                      'RdPkgConfig(A1)'      : 0xa1,
                      'WrPkgConfig(A5)'      : 0xa5,
                      'RdIAMSR(B1)'          : 0xb1,
                      'RdIAMSREx(D1)'        : 0xd1,
                      'WrIAMSR(B5)'          : 0xb5,
                      'RdPCIConfig(61)'      : 0x61,
                      'WrPCIConfig(65)'      : 0x65,
                      'RdPCIConfigLocal(E1)' : 0xe1,
                      'WrPCIConfigLocal(E5)' : 0xe5,
                      'RdEndPointConfig(C1)' : 0xc1,
                      'WrEndPointConfig(C5)' : 0xc5,
                      'CrashDump(71)'        : 0x71,
                      'Telemetry(81)'        : 0x81 }
                      

#extra_rdEp_field_list = ['addr', 
#                         'wlen', 
#                         'rlen', 
#                         'cmd',  
#                         'wdata',
#                         'wfcs', 
#                         'rdata',
#                         'rfcs', 
#                         'info', 
#                         'valid',
#                         'txn_type',
#                         'retry',
#                         'seg',
#                         'bus',
#                         'dev',
#                         'func',
#                         'offset'
#                         'data',
#                         'dev_name',
#                         'reg_name',
#                         'ibus',
#                         'decode_str' ]

pci_bus_map_i2e = {'cpu0' :{30: 126,
                            31: 127,
                             1: 58,
                             2: 20,
                             3: 41,
                             4: 75,
                             8: 0,
                             9: 1,
                             10: 3,
                             12: 5,
                             13: 6,
                             14: 8,
                             16: 10,
                             17: 11,
                             18: 13,
                             20: 15,
                             21: 16,
                             22: 18,
                             26: 109,
                             29: 92 },
                   'cpu1' :{30: 254,
                            31: 255,
                             1: 183,
                             2: 148,
                             3: 166,
                             4: 200,
                             8: 128,
                             9: 129,
                             10: 131,
                             12: 133,
                             13: 134,
                             14: 136,
                             16: 138,
                             17: 139,
                             18: 141,
                             20: 143,
                             21: 144,
                             22: 146,
                             26: 234,
                             29: 217} }
                             
pci_bus_map_i2e_2seg = {'cpu0': {30: 254, 31: 255, 1: 99, 2: 20, 3: 61, 4: 137, 8: 0, 9: 1, 10: 3, 12: 5, 13: 6, 14: 8, 16: 10, 17: 11, 18: 13, 20: 15, 21: 16, 22: 18, 26: 213, 29: 175}, 
                        'cpu1': {30: 254, 31: 255, 1: 99, 2: 20, 3: 61, 4: 137, 8: 0, 9: 1, 10: 3, 12: 5, 13: 6, 14: 8, 16: 10, 17: 11, 18: 13, 20: 15, 21: 16, 22: 18, 26: 213, 29: 175}}

pci_bus_map_i2e = pci_bus_map_i2e_2seg


pci_bus_map_e2i = gen_pci_bus_map_e2i(pci_bus_map_i2e)


bstr = '^:'
list_LA_RAW = []

def get_devname_by_bdf(cpunum, bus, dev, func, internal_bus=True, e2i_bus_map=None):
    global internal_dev_map
    #import pdb;pdb.set_trace()
    if internal_dev_map is None:
        return
    
    if internal_bus in [False, 0]:
        if e2i_bus_map in [ None, {} ]:
            return
        else:
            cpu_str = 'cpu%d'%cpunum
            e2i_bus_map_per_cpu = e2i_bus_map.get(cpu_str, {})
            ibus = e2i_bus_map_per_cpu.get(bus, None)
            if ibus is None:
                return
            else:
                dev_dict = internal_dev_map.get((ibus, dev, func), None)
                return dev_dict
    else:
        dev_dict = internal_dev_map.get((bus, dev, func), None)
        return dev_dict


def get_regname_vai_devtype_offset(devtype=None, regtype=None, offset=None):
    global mmio_reg_dict
    global pcicfg_reg_dict
    reg_type_dict = { 'mmio'   : mmio_reg_dict,
                      'pcicfg' : pcicfg_reg_dict
                     }
    reg_dict = reg_type_dict.get(regtype, {})
    reg_dict_per_dev = reg_dict.get(devtype, {})
    reg_name = reg_dict_per_dev.get(offset, '')
    return reg_name



def crc8(data):
    """
    Calculate the CRC8 checksum for a list of data bytes.
    
    :param data: List of data bytes (integers between 0 and 255)
    :return: CRC8 checksum (integer)
    """
    crc = 0x00  # Initial value
    polynomial = 0x07  # CRC-8 polynomial
    for byte in data:
        crc ^= byte  # XOR byte with current CRC value
        for _ in range(8):  # Process each bit
            if crc & 0x80:  # If the MSB is set
                crc = (crc << 1) ^ polynomial
            else:
                crc <<= 1
            crc &= 0xFF  # Ensure CRC remains 8-bit
    return crc

def cal_fcs(data_list=[]):
    return crc8(data_list)
    
def byte_str2int_list(byte_str):
    val_list = []
    if byte_str not in ['', ' ']:
        str_list = byte_str.split(' ')
        temp_val_str = ''
        for byte_str in str_list:
            val_list.append(int(byte_str, 16))
    return val_list


def byte_str2int(byte_str):
    if byte_str in ['', ' ']:
        return('')
    str_list = byte_str.split(' ')
    temp_val_str = ''
    for byte_str in str_list:
        temp_val_str = byte_str + temp_val_str
    return(int(temp_val_str, 16))

def byte2dw_list(byte_list=None):
    dw_list=[]
    bcnt = len(byte_list)
    dummy_cnt = (4 - bcnt%4)%4
    for d in range(dummy_cnt):
        byte_list.append(0x0)
    bcnt = len(byte_list)
    for i in range(0, bcnt, 4):
        dw = (byte_list[i+3] << 24) + (byte_list[i+2] << 16) +(byte_list[i+1] << 8) + byte_list[i]
        dw_list.append(dw)
    return dw_list
        
def data_list2str(byte_list=[]):
    tstr = ''
    for n in byte_list:
        tstr = '0x%08x '%n + tstr
    return tstr

def identify_bus_type(flist=None):
    #import pdb;pdb.set_trace()
    for bus in bus_field_dict:
        field_list = bus_field_dict[bus]
        bus_type = 'Unknown'
        mismatch = False
        for f in field_list:
            if f not in flist:
                mismatch = True
                break
        if mismatch is False:
            bus_type = 'BUS_'+bus
    return bus_type
    

def check_header_fields(field_list = None):
    valid_bus_name_dict = {}
    one_bus = False
    for h in field_list:
        if h != 'Timestamp':
            if bstr in h:
                tlist = h.split('^:')
                bus_name = tlist[0]
                field = tlist[1]
            else: #one bus only
                one_bus = True
                bus_name = 'Unknown'
                field = h
            if bus_name not in valid_bus_name_dict:
                valid_bus_name_dict[bus_name] = [field]
            else:
                valid_bus_name_dict[bus_name].append(field)
    if one_bus is True:
        clist = valid_bus_name_dict['Unknown']
        bus_name = identify_bus_type(clist)
        if bus_name is not None:
            valid_bus_name_dict={}
            valid_bus_name_dict[bus_name] = clist
    print("Find %d Bus(es) in the CSV file:" %len(valid_bus_name_dict))
    for bus in valid_bus_name_dict:
        print('             %s' %bus)
    print()
    return valid_bus_name_dict

def find_peci_bus(bus_dict):
    peci_bus_list = []
    for bus in bus_dict:
        if "BUS_PECI" in bus:
            peci_bus_list.append(bus)
    return peci_bus_list
    
    
def gen_new_field_list(peci_bus_list):
    new_field_list = []
    for b in peci_bus_list:
        new_field_list.append(b + '^:TnxDecode')
    return new_field_list
    
def clean_and_add_new_field(csv_data, new_field_list):
    new_csv_data_list = []
    #import pdb;pdb.set_trace()
    i = 0
    for raw_data in csv_data:
        for key in raw_data:
            tstr = raw_data[key]
            if '="' in tstr :
                mstr = tstr.split('"')[1]
                raw_data[key] = mstr
            if raw_data[key] in [' ']:
                raw_data[key] = ''
        for f in new_field_list:
            raw_data[f] = ''
        raw_data['row_num'] = i+2
        i = i+1
        new_csv_data_list.append(raw_data)
    return new_csv_data_list
    
def get_peci_cmd_field_list(ofield_list=None):
    vaild_peci_cmd_field_list = []
    bus_dict = check_header_fields(ofield_list)
    peci_bus_list = find_peci_bus(bus_dict)
    
    if len(peci_bus_list) == 1: # Single Bus
        for f in ofield_list:
            if 'Command(h)' in f:
                vaild_peci_cmd_field_list.append(f)
    else: # Multi Buses
        for f in ofield_list:
            if ('Command(h)' in f) and ('BUS_PECI' in f):
                vaild_peci_cmd_field_list.append(f)        
    return vaild_peci_cmd_field_list

def peci_raw_parser(csv_data_line):
    pass
 
def deocde_RdEndPointConfig(csv_data_line=None):
    pass 

#peci_cmd_decode_dict = { 'RdEndPointConfig(C1)' : PRdEndPointCfg}

class PECI_TXN():
    def __init__(self, csv_data_line, bus_name):
        self.valid_addr_list = list(range(0x30, 0x3f))
        
        self.var_field_map = { 'addr_raw'  : 'Addr(h)',
                               'wlen_raw'  : 'WrLen', 
                               'rlen_raw'  : 'RdLen',
                               'cmd_raw'   : 'Command(h)',
                               'wdata_raw'  : 'Write Data(h)',
                               'wfcs_raw'  : 'FCS(Wr)(h)',
                               'rdata_raw' : 'Read Data(h)',
                               'rfcs_raw'  : 'FCS(Rd)(h)',
                               'info_raw'  : 'Information'}
                          
        self.extra_field_list = ['addr', 
                                 'wlen', 
                                 'rlen', 
                                 'cmd',  
                                 'wdata',
                                 'wfcs', 
                                 'rdata',
                                 'rfcs', 
                                 'info', 
                                 'valid' ]

        self.bus_name = bus_name
        self.row_num = csv_data_line['row_num']
        for f in self.var_field_map:
            if bus_name != '':
                real_field_name = bus_name + '^:' + self.var_field_map[f]
            else:
                real_field_name = self.var_field_map[f]
            setattr(self, f, csv_data_line[real_field_name])
        self.raw_dict = csv_data_line
        self.addr = int(self.addr_raw, 16) 
        self.dest_dev_str = 'CPU%d' %(self.addr-0x30)
        self.wlen = int(self.wlen_raw, 10) 
        self.rlen = int(self.rlen_raw, 10)
        self.cmd = peci_cmd_code_map[self.cmd_raw]
        self.wdata = byte_str2int_list(self.wdata_raw)
        if ' (Error)' in self.wfcs_raw:
            temp_str = self.wfcs_raw.replace(' (Error)', '')
        else:
            temp_str = self.wfcs_raw
        self.wfcs = int(temp_str, 16)
        self.rdata = byte_str2int_list(self.rdata_raw)
        if ' (Error)' in self.rfcs_raw:
            temp_str = self.rfcs_raw.replace(' (Error)', '')
        else:
            temp_str = self.rfcs_raw
        self.rfcs = byte_str2int(temp_str)
        self.info = self.info_raw
        self.valid = 1
        self.err_msg = []
        self.is_txn_raw_valid()
        if (self.rlen == 0) and (seld.wlen==0):
            if self.wfcs == 0:
                self.txn_success = 0
            else:
                self.txn_success = 1
        else:
            #print('self.rdata = %s' %str(self.rdata))
            if self.rdata in ['', ' ', []]:
                self.txn_success = 0
                print('#%d : cc is empty, self.rdata = %s' %(self.row_num, str(self.rdata)))
            else:
                if self.rdata[0] == 0x40:
                    self.txn_success = 1
                else:
                    self.txn_success = 0
                    print('#%d : cc != 0x40, self.rdata = %s' %(self.row_num, str(self.rdata)))
        
    def check_wlen(self):
        if len(self.wdata) == (self.wlen-1):
            return True
        else:
            return False
            
    def check_rlen(self):
        if len(self.rdata) == self.rlen:
            return True
        else:
            return False
            
    def cal_wr_fcs(self):
        if self.wdata in ['', ' ']:
            return False
        fcs_wdata = [self.addr] + [self.wlen] + [self.rlen] + [self.cmd] + self.wdata
        #print(fcs_wdata)
        return crc8(fcs_wdata)
        
    def cal_rd_fcs(self):
        if self.wdata in ['', ' ']:
            return False
        return crc8(self.rdata)
    
    def is_txn_raw_valid(self):
        self.err_msg = []
        # Check if addr within 0x30-0x3f
        if self.addr not in self.valid_addr_list:
            if not isinstance(self.addr, int):
                self.err_msg.append("Error: 'Addr'= %s is not an integer type" %str(self.addr))
            else:
                self.err_msg.append("Error: 'Addr'=0x%0sx is not valid (should be within (0x3f, 0x30))" %self.addr)
        # Check Write Length
        if self.check_wlen() is False:
            if not isinstance(self.wlen, int):
                self.err_msg.append("Error: 'Write Length'= %s is not an integer type" %str(self.wlen))
            else:
                self.err_msg.append("Error: Write Length is mismatch (Expect: %d , Actual: %d)" %(self.wlen, len(self.wdata)+4))
        # Check WrFCS
        wr_fcs = self.cal_wr_fcs()
        if wr_fcs != self.wfcs:
            if not isinstance(self.wfcs, int):
                self.err_msg.append("Error: 'Write FCS'= %s is not an integer type" %str(self.wfcs))
            else:
                self.err_msg.append("Error: Write FCS is mismatch (Expect: 0x%02x , Actual: 0x%02x)" %(self.wfcs, wr_fcs))
        # Check Read Length
        if self.check_rlen() is False:
            if not isinstance(self.rlen, int):
                self.err_msg.append("Error: 'Write Length'= %s is not an integer type" %str(self.rlen))
            else:
                self.err_msg.append("Error: Read Length is mismatch (Expect: %d , Actual: %d)" %(self.rlen, len(self.rdata)))
        # Check WrFCS
        rd_fcs = self.cal_rd_fcs()
        if rd_fcs != self.rfcs:
            if not isinstance(self.rfcs, int):
                self.err_msg.append("Error: 'Read FCS'= %s is not an integer type" %str(self.rfcs))
            else:
                self.err_msg.append("Error: Read FCS is mismatch (Expect: 0x%02x , Actual: 0x%02x)" %(self.rfcs, rd_fcs))
        # Set self.valid 
        if len(self.err_msg) != 0:
            self.valid = 0

    def show_error(self):
        print("Detect %d Error(s) in this Transaction record# %d!" %(len(self.err_msg), self.row_num))
        for event in self.err_msg:
            print("    %s" %event)

    
class RdEndPointCfg():
                        
    def __init__(self, peci_txn_obj, cputype=cpuname):
        global pci_bus_map_e2i
        type_name = { 3 : 'Local PCI Cfg',
                      4 : 'PCI Cfg',
                      5 : 'MMIO' }
                      
        self.cputype = cputype
        self.raw_dict = peci_txn_obj.raw_dict
        self.row_num = peci_txn_obj.row_num
        self.cpu = peci_txn_obj.dest_dev_str
        self.cpu_num = peci_txn_obj.addr-0x30
        self.wlen = peci_txn_obj.wlen
        self.rlen = peci_txn_obj.rlen
        self.cmd  = peci_txn_obj.cmd
        self.cmd_str = peci_txn_obj.cmd_raw
        self.hid = (peci_txn_obj.wdata[0] >> 1) & 0x3f
        #die_id_map_per_cputype = die_id_map.get(self.cputype, {})
        self.die_str = die_id_map.get(self.hid, '')
        self.retry = peci_txn_obj.wdata[0] & 0x01
        self.msg_type = peci_txn_obj.wdata[1]
        self.decode_str = ''
        if self.msg_type in [0x3, 0x4]:
            self.type = type_name[self.msg_type]
            if self.type == 0x3:
                self.local = 1
            else:
                self.local = 0
            self.epid = peci_txn_obj.wdata[2]
            self.addr_type = peci_txn_obj.wdata[5]
            self.seg = peci_txn_obj.wdata[6]
            pci_addr = peci_txn_obj.wdata[7] + (peci_txn_obj.wdata[8] << 8 )+ (peci_txn_obj.wdata[9] << 16) + (peci_txn_obj.wdata[10] << 24)
            self.bus = (pci_addr >> 20) & 0xfff
            self.dev = (pci_addr >> 15) & 0x1f
            self.func = (pci_addr >> 12) & 0x7
            self.offset = pci_addr & 0xfff
            # map B:D:F to Device Name
            #import pdb;pdb.set_trace()
            dev_name_list = get_devname_by_bdf(self.cpu_num, self.bus, self.dev, self.func, self.local, pci_bus_map_e2i)
            if dev_name_list is None:
                self.dev_name = ''
                self.dev_type = ''
                self.reg_name = ''
            else:
                self.dev_name = dev_name_list[0]
                self.dev_type = dev_name_list[1]
                self.reg_name = get_regname_vai_devtype_offset(self.dev_type, 'pcicfg', self.offset)
                
            #reg_dict = pcicfg_reg_dict.get(self.dev_type, {})
            #reg_name = reg_dict.get(self.offset, '')
            
        elif self.msg_type in [0x5]:
            self.type = type_name[self.msg_type]
            self.local = 0
            self.epid = peci_txn_obj.wdata[2]
            self.bar = peci_txn_obj.wdata[4]
            self.addr_type = peci_txn_obj.wdata[5]
            self.seg = peci_txn_obj.wdata[6]
            self.bus = peci_txn_obj.wdata[8]
            self.dev = (peci_txn_obj.wdata[7] >> 3) & 0x1f
            self.func = peci_txn_obj.wdata[7] & 0x7
            offset_byte_list = peci_txn_obj.wdata[9:]
            self.offset = byte2dw_list(offset_byte_list)[0]
            #import pdb;pdb.set_trace()
            dev_name_list = get_devname_by_bdf(self.cpu_num, self.bus, self.dev, self.func, self.local, pci_bus_map_e2i)
            if dev_name_list is None:
                self.dev_name = ''
                self.dev_type = ''
                self.reg_name = ''
            else:
                self.dev_name = dev_name_list[0]
                self.dev_type = dev_name_list[1]
                self.reg_name = get_regname_vai_devtype_offset(self.dev_type, 'mmio', self.offset)
                
        self.rdata = byte2dw_list(peci_txn_obj.rdata[1:])
        self.decode_cmd()
        
    def decode_cmd(self):
        #      'CPU0 Compute Die0 Retry=0, RdEndPointConfig(C1), PCICfg Read S:B:D:F = 255: 30:30:2, offset = 0x1c0, Data = 0x12345678) 
        if self.msg_type in [0x3, 0x4]:
            self.decode_str = '%s, %s, Retry=%d, %s, %s Read, S:B:D:F = %02x:%02x:%02x:%x'  %(self.cpu, self.die_str, self.retry, self.cmd_str, self.type, self.seg, self.bus, self.dev, self.func)
            if self.dev_name not in ['', None]:
                self.decode_str = self.decode_str + ' (%s)' %self.dev_name
            self.decode_str = self.decode_str + ', Offset = 0x%03x' %(self.offset)
            if self.reg_name not in ['', None]:
                self.decode_str = self.decode_str + ' (%s)' %self.reg_name
            self.decode_str = self.decode_str + ', Data = %s' %(data_list2str(self.rdata))
        else:
            self.decode_str = '%s, %s, Retry=%d, %s, %s Read, S:B:D:F = %02x:%02x:%02x:%x ' %(self.cpu, self.die_str, self.retry, self.cmd_str, self.type, self.seg, self.bus, self.dev, self.func)
            if self.dev_name not in ['', None]:
                self.decode_str = self.decode_str + "(%s)" %self.dev_name
            self.decode_str = self.decode_str + ' BAR%d, Offset = 0x%03x' %(self.bar, self.offset)
            if self.reg_name not in ['', None]:
                self.decode_str = self.decode_str + " (%s)" %self.reg_name
            self.decode_str = self.decode_str + ", Data = %s" %( data_list2str(self.rdata))
    
    def show_decode(self):
        print("record# %d: %s" %(self.row_num, self.decode_str))
        
    def show_attrs(self):
        attr_list = dir(self)
        for a in attr_list:
            if '__' not in a:
                item = getattr(self, a)
                if isinstance(item, int):
                    temp_str = "0x%x" %item
                else:
                    temp_str = str(item)
                print("%s = %s" %(a, temp_str))
                


peci_cmd_decode_dict = { 'RdEndPointConfig(C1)' : RdEndPointCfg}

    
def main():

    #
    # Process paramter
    #
    strHelpString = \
                "===============================\r\n" +\
                "====  LA CSV Decoder (PECI) ===\r\n" +\
                "====       Ver 0.1     Ian  ===\r\n" +\
                "===============================\r\n" +\
                "Description:\r\n" +\
                "This tool can help PAE to easier decode PECI command from LA log \r\n" +\
                "\r\n"

    parser = argparse.ArgumentParser(prog="LA CSV Analyzer - PECI v0.1",
                                    usage="use -h to get more information", \
                                    description = strHelpString,\
                                    formatter_class=argparse.RawTextHelpFormatter,\
                                    )
    parser.add_argument("-f", dest="Format" , help="Input Format, currently support Acute MSO1162B only")
    parser.add_argument("-i", dest="InputFile", help="Input log file")
    parser.add_argument("-o", dest="OutputFile" , help="Output string csv file")
    args = parser.parse_args()


    if (len(sys.argv) == 1):
        print (strHelpString + "\r\nPlease -h to get more help")
        return

    if (args.InputFile == None):
        print ("Please enter input log file path as least!")
        return

    if (args.OutputFile == None):
        InputFilename = os.path.splitext(os.path.basename(args.InputFile))[0]
        args.OutputFile = InputFilename + "_OUT.csv"
        print ("Output file path didn't give me, I will put in the same folder\ - %s" % (args.OutputFile))

    parser_peci_csv(args.InputFile, args.OutputFile)


def parser_peci_csv(input_file=None, output_file=None, target_cpuname='GNR'):
    """
    Parse PECI Trace from a Acute MSO .csv file
    
    Input:
         input_file  : The MSO cvs file name (includes path)
         output_file : The output file name (includes path) for the decoded result file
    output:
         A csv file with PECI decoded result
    """
    select_cpu_type(target_cpuname)
    if (input_file == None):
        print ("Please enter input log file path as least!")
        return

    if (output_file == None):
        InputFilename = os.path.splitext(os.path.basename(input_file))[0]
        output_file = InputFilename + "_OUT.csv"
        print ("Output file/path is not given, will put output file in the same folder\ - %s" % (output_file))
    
    print ("[AcuteAnalyzer PECI] Loading file: %s" % (input_file))
    f=open(input_file, 'r')

    OutputFile = output_file
    if (os.path.exists(output_file)):
        print ("There's already file %s exist, will override it" % (output_file) )


    # parsing csv LA data
    out_data_list = []
    with open(input_file, mode='r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        original_field_names = csv_reader.fieldnames
        csv_data = list(csv_reader)
    
    #Get Bus count in CSV
    bus_dict = check_header_fields(original_field_names)
    #Get PECI Bus count in CSV
    peci_bus_list = find_peci_bus(bus_dict)
    #Create a list of new added 'TxnDecode' field for each PECI bus
    new_field_list = gen_new_field_list(peci_bus_list)
    #Remove '-"' from the field value in original Acute CSV file and add new key 'TxnDecode' for each PECI bus
    pcsv_data = clean_and_add_new_field(csv_data, new_field_list)
    #Create a list of the valid PECI command field name for all valid PECI bus 
    vaild_peci_cmd_field_list = get_peci_cmd_field_list(original_field_names)
    
    #Decode PECI Transaction per CSV Line
    dlen = len(pcsv_data)
    #import pdb;pdb.set_trace()
    for i in range(dlen):
        t = pcsv_data[i]
        print("#%d" %(i+2))
        print(t)
        #import pdb;pdb.set_trace()
        for fn in vaild_peci_cmd_field_list:
            if '^:' in fn:
                bus_name = fn.split('^:')[0]
            else:
                bus_name = ''
            print(t[fn])
            if t[fn] in peci_cmd_decode_dict:
                #if t[fn] == 'RdEndPointConfig(C1)':
                #    import pdb;pdb.set_trace()
                decode_fun = peci_cmd_decode_dict[t[fn]]
                p = PECI_TXN(t, bus_name)
                if p.valid != 1:
                    p.show_error()
                else:
                    cmd_obj = decode_fun(p)
                    cmd_obj.show_decode()
                    #try:
                    #    cmd_obj = decode_fun(p)
                    #    #cmd_obj.show_decode()
                    #except:
                    #    pass
                    
                
    return pcsv_data
    
    
    
        ## fill each raw by dictionary way
        #for dict_row_LA_RAW in csv_reader:
        #    #
        #    # initial feild
        #    #       inser new feild
        #    #       Node(CPU) / BDF / reg offset / PECI Completion code /
        #    new_field_names = ['PECI Rerty', 'CPU', 'Bus', 'Device', 'Function', 'Register/MMIO Offset', 'PECI Completion Code', ' '] + original_field_names
        #    #       fill data in new insered feild
        #    dict_row_LA_RAW['CPU'] = 'N/A'
        #    dict_row_LA_RAW['Bus'] = 'N/A'
        #    dict_row_LA_RAW['Device'] = 'N/A'
        #    dict_row_LA_RAW['Function'] = 'N/A'
        #    dict_row_LA_RAW['Register/MMIO Offset'] = 'N/A'
        #
        #    #
        #    # Process data from LA's log
        #    #
        #    LineIndex = 1
        #    strings = ''
        #      
        #    # Fetch CPU#
        #    CPU = "Unknown ({})".format(dict_row_LA_RAW['Addr(h)'])   # fill a default string
        #    PeciAddress = dict_row_LA_RAW['Addr(h)']
        #    if PeciAddress.isdigit():
        #        decimal_num = int(PeciAddress)
        #        if PeciAddress.startswith('3'):
        #            CPU = "CPU({})".format(decimal_num % 10)
        #    dict_row_LA_RAW['CPU'] = CPU
        #    
        #    #
        #    # Identify specific device commands 
        #    #     DOC#776485
        #    #           section 5.8 PECI Device Specific Commands 
        #    #           Implement   |    Commands
        #    #                              5.8.1 GetTemp()
        #    #                              5.8.2 RdPkgConfig()
        #    #                              5.8.3 WrPkgConfig()
        #    #                              5.8.4 RdIAMSR()
        #    #                              5.8.5 RdIAMSREx()
        #    #                              5.8.6 WrIAMSR()
        #    #                              5.8.7 RdPCIConfig()
        #    #                              5.8.8 WrPCIConfig()
        #    #                              5.8.9 RdPCIConfigLocal()
        #    #                              5.8.10 WrPCIConfigLocal()
        #    #              V               5.8.11 RdEndPointConfig()
        #    #              V               5.8.12 WrEndPointConfig()
        #    #                              5.8.13 CrashDump()
        #    #                              5.8.14 Telemetry()
        #    #
        #    
        #    #
        #    # RdEndPointConfig()
        #    #
        #    if (dict_row_LA_RAW['Command(h)'] == 'RdEndPointConfig(C1)'):
        #        #
        #        # 5.8.11.1 Command Format for RdEndPointConfig() Local PCI Cfg or PCI Cfg
        #        #
        #        # Figure 5-23 (data feild from byte 4)
        #        #   Byte 4(0):              HostID[7:1] / Retry [0]
        #        #   Byte 5(1):              Message Type (3-Local PCI Cfg, 4-PCI)
        #        #   Byte 6(2):              EndPointID
        #        #   Byte 7/8(3,4):          Reserved
        #        #   Byte 9(5):              Address Type (0x04)
        #        #   Byte 10(6):             PCIe Segment
        #        #   Byte 11-14(7,8,9,10):   PCIe Cfg Address 
        #        #                               Bit[31:20]: Bus
        #        #                               Bit[19:15]: Device
        #        #                               Bit[14:12]: Function
        #        #                               Bit[11:0]: Register Offset
        #        #                                   ex. "008181A0" -> Bus:8 / Dev:3 / Function:0 / Reg: 0x1A0
        #        #
        #        RawWriteData = dict_row_LA_RAW['Write Data(h)'].split()
        #        MessageType = int(RawWriteData[1], 16)
        #        if (MessageType == 0x03):               # Local PCI-Cfg
        #            hex_value = int(RawWriteData[0], 16)
        #            HostID = (hex_value >> 1) & 0x7F
        #            Retry = hex_value & 0x01
        #            # PCIe Cfg Address
        #            hex_value = 0
        #            selected_data = RawWriteData[7:11]
        #            if (selected_data):
        #                reversed_list = selected_data[::-1]
        #                hex_value_str = ''.join(reversed_list)
        #                hex_value = int(hex_value_str, 16)
        #
        #            Bus = (hex_value >> 20) & 0xFFF
        #            Device = (hex_value >> 15) & 0x1F
        #            Function = (hex_value >> 12) & 0x03
        #            RegOffset = (hex_value) & 0x0FFF
        #                            
        #            dict_row_LA_RAW['PECI Rerty'] = Retry
        #            dict_row_LA_RAW['Bus'] = Bus
        #            dict_row_LA_RAW['Device'] = Device
        #            dict_row_LA_RAW['Function'] = Function
        #            dict_row_LA_RAW['Register/MMIO Offset'] = hex(RegOffset)
        #            #dict_row_LA_RAW['PECI Completion Code']
        #            #print ("debug:")
        #            #print (dict_row_LA_RAW)
        #
        #        #
        #        # 5.8.11.2 Command Format for RdEndPointConfig() MMIO
        #        #
        #        # Figure 5-24 (data feild from byte 4)
        #        #   Byte 4(0):              HostID[7:1] / Retry [0]
        #        #   Byte 5(1):              Message Type (5)
        #        #   Byte 6(2):              EndPointID
        #        #   Byte 7(3):              Reserved
        #        #   Byte 8(4):              BAR(Memory type)
        #        #   Byte 9(5):              Address Type (0x05:32bit addressing, 0x06: 64bits addressing)
        #        #   Byte 10(6):             PCIe Segment
        #        #   Byte 11(7):             Device/Func
        #        #                               Bit[7:3]: Device
        #        #                               Bit[2:0]: Function
        #        #   Byte 12(8):             Bus
        #        #   Byte 13-16(9-12):       Address (32Bits addressing)
        #        #   or 
        #        #   Byte 13-20(9-16):       Address (64Bits addressing)
        #        #
        #        RawWriteData = dict_row_LA_RAW['Write Data(h)'].split()
        #        MessageType = int(RawWriteData[1], 16)
        #        if (MessageType == 0x05):                           # MMIO
        #            hex_value = int(RawWriteData[0], 16)
        #            HostID = (hex_value >> 1) & 0x7F
        #            Retry = hex_value & 0x01
        #            BAR = int(RawWriteData[4], 16)
        #            Bus = int(RawWriteData[8], 16)
        #            Device = (int(RawWriteData[7], 16) >> 3) & 0x01F
        #            Function = int(RawWriteData[7], 16) & 0x03
        #            hex_value = 0
        #            selected_data = RawWriteData[9:13]
        #            if (selected_data):
        #                reversed_list = selected_data[::-1]
        #                hex_value_str = ''.join(reversed_list)
        #                hex_value = int(hex_value_str, 16)
        #            RegOffsetString = "BAR:{} / Offset:{}".format(int(RawWriteData[4], 16), hex(hex_value))
        #            print ("debug: {}".format(RegOffset))
        #                            
        #            dict_row_LA_RAW['PECI Rerty'] = Retry
        #            dict_row_LA_RAW['Bus'] = Bus
        #            dict_row_LA_RAW['Device'] = Device
        #            dict_row_LA_RAW['Function'] = Function
        #            dict_row_LA_RAW['Register/MMIO Offset'] = RegOffsetString
        #            #dict_row_LA_RAW['PECI Completion Code']
        #    
        #    
        #    #Completion Code
        #    CompletionCode = 0
        #    dict_row_LA_RAW['PECI Completion Code'] = CompletionCode    
        #    
        #    out_data_list.append(dict_row_LA_RAW)
        #    #print (dict_row_LA_RAW)
        #    
        #
    # Write into csv
    with open(OutputFile, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write feilds
        writerDict = csv.DictWriter(csvfile, fieldnames=new_field_names)
        writerDict.writeheader()
        writerDict.writerows(out_data_list)
    pass

if __name__ == '__main__':
    main()

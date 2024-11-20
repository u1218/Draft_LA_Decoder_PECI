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
import argparse
import re
import csv

DebugFlag = False
list_LA_RAW = []

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

    #
    # Process paramter
    #
    print ("[eSPIAnalyzer] Loading file: %s" % (args.InputFile))
    f=open(args.InputFile, 'r')

    OutputFile = args.OutputFile
    if (os.path.exists(args.OutputFile)):
        print ("There's already file %s exist, will override it" % (args.OutputFile) )


    # parsing csv LA data
    out_data_list = []
    with open(args.InputFile, mode='r', encoding='utf-8') as file:
        csv_reader = csv.DictReader(file)
        original_field_names = csv_reader.fieldnames
        
        #
        # Make sure the csv file provide same feild name as we expected, if user modify it then notify user keep the default
        # What we expected feild names that we will use,
        #   Addr(h), Command(h),	Write Data(h),	Read Data(h), 
        #
        keys_to_check = ["Addr(h)", "Command(h)", "Write Data(h)", "Read Data(h)"]
        if set(keys_to_check).issubset(original_field_names):
            print("The list contains all the specified feild names, keep parsing the data...")
        else:
            print("[Error]: The list does not contain all the specified feild name we expected, please keep tool default when you export csv file.")
            print("[Error]: Necessary feild name: {}".format(keys_to_check))
            return

        # fill each raw by dictionary way
        for dict_row_LA_RAW in csv_reader:
            print ("parsing:{}".format(dict_row_LA_RAW))
        
            #
            # initial feild
            #       inser new feild
            #       Node(CPU) / BDF / reg offset / PECI Completion code /
            new_field_names = ['PECI Rerty', 'CPU', 'Bus', 'Device', 'Function', 'Register/MMIO Offset', 'R/W Data', 'PECI Completion Code', ' '] + original_field_names
            #       fill data in new insered feild
            dict_row_LA_RAW['CPU'] = 'N/A'
            dict_row_LA_RAW['Bus'] = 'N/A'
            dict_row_LA_RAW['Device'] = 'N/A'
            dict_row_LA_RAW['Function'] = 'N/A'
            dict_row_LA_RAW['Register/MMIO Offset'] = 'N/A'
            dict_row_LA_RAW['R/W Data'] = 'N/A' 
            dict_row_LA_RAW['PECI Completion Code'] = 'N/A'

            #
            # Process data from LA's log
            #
            LineIndex = 1
            strings = ''
              
            # Fetch CPU#
            CPU = "Unknown ({})".format(dict_row_LA_RAW['Addr(h)'])   # fill a default string
            PeciAddress = dict_row_LA_RAW['Addr(h)']
            if PeciAddress.isdigit():
                decimal_num = int(PeciAddress)
                if PeciAddress.startswith('3'):
                    CPU = "CPU({})".format(decimal_num % 10)
            dict_row_LA_RAW['CPU'] = CPU
            
            #
            # Identify specific device commands 
            #     DOC#776485
            #           section 5.8 PECI Device Specific Commands 
            #           Implement   |    Commands
            #                              5.8.1 GetTemp()
            #                              5.8.2 RdPkgConfig()
            #                              5.8.3 WrPkgConfig()
            #                              5.8.4 RdIAMSR()
            #                              5.8.5 RdIAMSREx()
            #                              5.8.6 WrIAMSR()
            #                              5.8.7 RdPCIConfig()
            #                              5.8.8 WrPCIConfig()
            #                              5.8.9 RdPCIConfigLocal()
            #                              5.8.10 WrPCIConfigLocal()
            #              V               5.8.11 RdEndPointConfig()
            #              V               5.8.12 WrEndPointConfig()
            #                              5.8.13 CrashDump()
            #                              5.8.14 Telemetry()
            #
            
            #
            # 5.8.11 RdEndPointConfig()
            #
            if (dict_row_LA_RAW['Command(h)'] == 'RdEndPointConfig(C1)'):
                # RdEndPointConfig() Local PCI Cfg or PCI Cfg - Message Type = 3,4
                DecodeRdEndPointConfig_PciCfg (dict_row_LA_RAW)
                # RdEndPointConfig() MMIO - Message Type = 5
                DecodeRdEndPointConfig_Mmio (dict_row_LA_RAW)
            if (dict_row_LA_RAW['Command(h)'] == 'WrEndPointConfig(C5)'):
                # WrEndPointConfig() Local PCI Cfg or PCI cfg - Message Type = 3,4
                DecodeWrEndPointConfig_PciCfg (dict_row_LA_RAW)
                # WrEndPointConfig() MMIO - Message Type = 5
                DecodeWrEndPointConfig_Mmio  (dict_row_LA_RAW)
            
            #Completion Code - Byte0 in 'Read Data' column
            data = dict_row_LA_RAW['Read Data(h)']
            if (data is not None and data.strip() != ''):
                RawReadData = dict_row_LA_RAW['Read Data(h)'].split()
                CompletionCode = int(RawReadData[0], 16)
                dict_row_LA_RAW['PECI Completion Code'] = hex(CompletionCode)
            
            # Append into output buffer for output csv file
            out_data_list.append(dict_row_LA_RAW)            

    # Write into csv
    with open(OutputFile, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write feilds
        writerDict = csv.DictWriter(csvfile, fieldnames=new_field_names)
        writerDict.writeheader()
        writerDict.writerows(out_data_list)
    pass

#
# 5.8.11.1 Command Format for RdEndPointConfig() Local PCI Cfg or PCI Cfg
#
# Figure 5-23 (data feild from byte 4)
#   Byte 4(0):              HostID[7:1] / Retry [0]
#   Byte 5(1):              Message Type (3-Local PCI Cfg, 4-PCI)
#   Byte 6(2):              EndPointID
#   Byte 7/8(3,4):          Reserved
#   Byte 9(5):              Address Type (0x04)
#   Byte 10(6):             PCIe Segment
#   Byte 11-14(7,8,9,10):   PCIe Cfg Address 
#                               Bit[31:20]: Bus
#                               Bit[19:15]: Device
#                               Bit[14:12]: Function
#                               Bit[11:0]: Register Offset
#                                   ex. "008181A0" -> Bus:8 / Dev:3 / Function:0 / Reg: 0x1A0
#
def DecodeRdEndPointConfig_PciCfg (row_LA_RAW):
    if (row_LA_RAW['Command(h)'] == 'RdEndPointConfig(C1)'):
        RawWriteData = row_LA_RAW['Write Data(h)'].split()
        MessageType = int(RawWriteData[1], 16)
        debug_print ('debug: RdEndPointConfig Message Type = {}'.format(MessageType))
        if (MessageType == 0x03 or MessageType == 0x04):                           # Message Type (3-Local PCI Cfg, 4-PCI)
            debug_print ('debug: RawWriteData = {}'.format(RawWriteData))
            hex_value = int(RawWriteData[0], 16)
            HostID = (hex_value >> 1) & 0x7F
            Retry = hex_value & 0x01
            # PCIe Cfg Address
            hex_value = 0
            selected_data = RawWriteData[7:11]
            if (selected_data):
                reversed_list = selected_data[::-1]
                hex_value_str = ''.join(reversed_list)
                hex_value = int(hex_value_str, 16)
            # Fetch BDF
            MessageType = int(RawWriteData[1], 16)
            if (MessageType == 0x03):               # Local PCI-Cfg
                Bus = '{} (Local PCI-Cfg)'.format((hex_value >> 20) & 0xFFF)
            elif (MessageType == 0x04):               # PCI-Cfg
                Bus = '{} (PCI-Cfg)'.format((hex_value >> 20) & 0xFFF)
            else:
                # Doc only define Message Type = 3, 4
                return
            Device = (hex_value >> 15) & 0x1F
            Function = (hex_value >> 12) & 0x03
            RegOffset = (hex_value) & 0x0FFF

            # Read Data
            if (row_LA_RAW['Read Data(h)'] is not None and row_LA_RAW['Read Data(h)'].strip() != ''):
                RawReadData = row_LA_RAW['Read Data(h)'].split()
                ReadData = 0
                hex_value = 0
                StringBytes = '(x Byte)'
                PeciRow_RdLen = row_LA_RAW['RdLen']   # use RdLen to identify recieved data length
                if (PeciRow_RdLen == '2'):     # 1 byte
                    selected_data = RawReadData[1]
                    hex_value_str = f"0x{selected_data:02X}"
                    StringBytes = '(1 Byte)'
                elif (PeciRow_RdLen == '3'):   # 2 bytes
                    selected_data = RawReadData[-2:]
                    reversed_list = selected_data[::-1]
                    hex_value = int(reversed_list, 16)
                    hex_value_str = f"0x{hex_value:04X}"
                    StringBytes = '(2 Bytes)'
                elif (PeciRow_RdLen == '5'):   # 4 bytes
                    selected_data = RawReadData[-4:]
                    reversed_list = selected_data[::-1]
                    hex_value = int((''.join(reversed_list)), 16)
                    hex_value_str = f"0x{hex_value:08X}"
                    StringBytes = '(4 Bytes)'

                row_LA_RAW['R/W Data'] = hex_value_str + StringBytes
                debug_print ('debug: store row_LA_RAW[RW Data] = {}'.format(row_LA_RAW['R/W Data']))
                            
            row_LA_RAW['PECI Rerty'] = Retry
            row_LA_RAW['Bus'] = Bus
            row_LA_RAW['Device'] = Device
            row_LA_RAW['Function'] = Function
            row_LA_RAW['Register/MMIO Offset'] = f"0x{RegOffset:04X}"
            debug_print ('debug: {}'.format(row_LA_RAW))

#
# 5.8.11.2 Command Format for RdEndPointConfig() MMIO
#
# Figure 5-24 (data feild from byte 4)
#   Byte 4(0):              HostID[7:1] / Retry [0]
#   Byte 5(1):              Message Type (5)
#   Byte 6(2):              EndPointID
#   Byte 7(3):              Reserved
#   Byte 8(4):              BAR(Memory type)
#   Byte 9(5):              Address Type (0x05:32bit addressing, 0x06: 64bits addressing)
#   Byte 10(6):             PCIe Segment
#   Byte 11(7):             Device/Func
#                               Bit[7:3]: Device
#                               Bit[2:0]: Function
#   Byte 12(8):             Bus
#   Byte 13-16(9-12):       Address (32Bits addressing)
#   or 
#   Byte 13-20(9-16):       Address (64Bits addressing)
#
def DecodeRdEndPointConfig_Mmio (row_LA_RAW):
    RawWriteData = row_LA_RAW['Write Data(h)'].split()
    MessageType = int(RawWriteData[1], 16)
    if (MessageType == 0x05):                           # MMIO
        hex_value = int(RawWriteData[0], 16)
        HostID = (hex_value >> 1) & 0x7F
        Retry = hex_value & 0x01
        BAR = int(RawWriteData[4], 16)
        Bus = int(RawWriteData[8], 16)
        Device = (int(RawWriteData[7], 16) >> 3) & 0x01F
        Function = int(RawWriteData[7], 16) & 0x03
        hex_value = 0
        # MMIO Offset (Address feild iin spec)
        AddressType = int(RawWriteData[5], 16)
        if (AddressType == 5): # 32bits Addressing
            selected_data = RawWriteData[9:13]
            if (selected_data):
                reversed_list = selected_data[::-1]
                hex_value_str = ''.join(reversed_list)
                hex_value = int(hex_value_str, 16)
            RegOffsetString = "BAR:{} / Offset(32bits):0x{:04X}".format(int(RawWriteData[4], 16), hex_value)
        elif (AddressType == 6): # 64bits Addressing
            selected_data = RawWriteData[9:17]
            if (selected_data):
                reversed_list = selected_data[::-1]
                hex_value_str = ''.join(reversed_list)
                hex_value = int(hex_value_str, 16)
            RegOffsetString = "BAR:{} / Offset(64bits):0x{:04X}".format(int(RawWriteData[4], 16), hex_value)
        else:
            RegOffsetString = 'Address Type Error'
        debug_print ("debug: {}".format(RegOffsetString))
        # Read Data
        if (row_LA_RAW['Read Data(h)'] is not None and row_LA_RAW['Read Data(h)'].strip() != ''):
            RawReadData = row_LA_RAW['Read Data(h)'].split()
            ReadData = 0
            hex_value = 0
            StringBytes = '(x Byte)'
            PeciRow_RdLen = row_LA_RAW['RdLen']   # use RdLen to identify recieved data length
            if (PeciRow_RdLen == '2'):     # 1 byte
                selected_data = RawReadData[1]
                hex_value_str = f"0x{selected_data:02X}"
                StringBytes = '(1 Byte)'
            elif (PeciRow_RdLen == '3'):   # 2 bytes
                selected_data = RawReadData[-2:]
                reversed_list = selected_data[::-1]
                hex_value = int(reversed_list, 16)
                hex_value_str = f"0x{hex_value:04X}"
                StringBytes = '(2 Bytes)'
            elif (PeciRow_RdLen == '5'):   # 4 bytes
                selected_data = RawReadData[-4:]
                reversed_list = selected_data[::-1]
                hex_value = int((''.join(reversed_list)), 16)
                hex_value_str = f"0x{hex_value:08X}"
                StringBytes = '(4 Bytes)'
            elif (PeciRow_RdLen == '9'):   # 8 bytes
                selected_data = RawReadData[-8:]
                reversed_list = selected_data[::-1]
                hex_value = int((''.join(reversed_list)), 16)
                hex_value_str = f"0x{hex_value:016X}"
                StringBytes = '(8 Bytes)'
                
            row_LA_RAW['R/W Data'] = hex_value_str + StringBytes
            debug_print ('debug: store row_LA_RAW[RW Data] = {}'.format(row_LA_RAW['R/W Data']))


        row_LA_RAW['PECI Rerty'] = Retry
        row_LA_RAW['Bus'] = '{} (MMIO)'.format(Bus)
        row_LA_RAW['Device'] = Device
        row_LA_RAW['Function'] = Function
        row_LA_RAW['Register/MMIO Offset'] = RegOffsetString

#
# 5.8.12.1 Command Format for WrEndPointConfig() Local PCI Cfg or PCI Cfg
#
# Figure 5-25 (data feild from byte 4)
#   Byte 4(0):                  HostID[7:1] / Retry [0]
#   Byte 5(1):                  Message Type (3-Local PCI Cfg, 4-PCI)
#   Byte 6(2):                  EndPointID
#   Byte 7/8(3,4):              Reserved
#   Byte 9(5):                  Address Type (0x04)
#   Byte 10(6):                 PCIe Segment
#   Byte 11-14(7,8,9,10):       PCIe Cfg Address 
#                                   Bit[31:20]: Bus
#                                   Bit[19:15]: Device
#                                   Bit[14:12]: Function
#                                   Bit[11:0]: Register Offset
#                                       ex. "008181A0" -> Bus:8 / Dev:3 / Function:0 / Reg: 0x1A0
#   Byte 15-18(11,12,13,14):    Data (1, 2, 4 bytess)
#                                   LSB -> MSB
#
def DecodeWrEndPointConfig_PciCfg (row_LA_RAW):
    if (row_LA_RAW['Command(h)'] == 'WrEndPointConfig(C5)'):
        RawWriteData = row_LA_RAW['Write Data(h)'].split()
        debug_print ("debug: original Write Data feild - {}".format(RawWriteData))
        MessageType = int(RawWriteData[1], 16)
        if (MessageType == 0x03 or MessageType == 0x04):                           # Message Type (3-Local PCI Cfg, 4-PCI)
            hex_value = int(RawWriteData[0], 16)
            HostID = (hex_value >> 1) & 0x7F
            Retry = hex_value & 0x01
            # PCIe Cfg Address
            hex_value = 0
            selected_data = RawWriteData[7:11]
            if (selected_data):
                reversed_list = selected_data[::-1]
                hex_value_str = ''.join(reversed_list)
                hex_value = int(hex_value_str, 16)
            # Fetch BDF
            MessageType = int(RawWriteData[1], 16)
            if (MessageType == 0x03):               # Local PCI-Cfg
                Bus = '{} (Local PCI-Cfg)'.format((hex_value >> 20) & 0xFFF)
            elif (MessageType == 0x04):               # PCI-Cfg
                Bus = '{} (PCI-Cfg)'.format((hex_value >> 20) & 0xFFF)
            Device = (hex_value >> 15) & 0x1F
            Function = (hex_value >> 12) & 0x03
            RegOffset = (hex_value) & 0x0FFF
            # Data be writen
            hex_value = 0
            StringBytes = '(x Byte)'
            PeciRow_WrLen = row_LA_RAW['WrLen'].split()   # use WRLen to identify wroten data length
            if (PeciRow_WrLen == '14'):     # 1 byte
                selected_data = RawWriteData[11]
                hex_value_str = f"0x{selected_data:02X}"
                StringBytes = '(1 Byte)'
            elif (PeciRow_WrLen == '15'):   # 2 bytes
                selected_data = RawWriteData[11:13]
                reversed_list = selected_data[::-1]
                hex_value = int(reversed_list, 16)
                hex_value_str = f"0x{hex_value:04X}"
                StringBytes = '(2 Bytes)'
            elif (PeciRow_WrLen == '17'):   # 4 bytes
                selected_data = RawWriteData[11:15]
                reversed_list = selected_data[::-1]
                hex_value = int((''.join(reversed_list)), 16)
                hex_value_str = f"0x{hex_value:08X}"
                StringBytes = '(4 Bytes)'

            if (selected_data):
                row_LA_RAW['R/W Data'] = hex_value_str + StringBytes
                debug_print ('debug: store row_LA_RAW[RW Data] = {}'.format(row_LA_RAW['R/W Data']))

            row_LA_RAW['PECI Rerty'] = Retry
            row_LA_RAW['Bus'] = Bus
            row_LA_RAW['Device'] = Device
            row_LA_RAW['Function'] = Function
            row_LA_RAW['Register/MMIO Offset'] = f"0x{RegOffset:04X}"
            debug_print ("debug:")
            debug_print (row_LA_RAW)

#
# 5.8.12.2 Command Format for WrEndPointConfig() MMIO
#
# Figure 5-26 (data feild from byte 4)
#   Byte 4(0):              HostID[7:1] / Retry [0]
#   Byte 5(1):              Message Type (5)
#   Byte 6(2):              EndPointID
#   Byte 7(3):              Reserved
#   Byte 8(4):              BAR(Memory type)
#   Byte 9(5):              Address Type (0x05:32bit addressing, 0x06: 64bits addressing)
#   Byte 10(6):             PCIe Segment
#   Byte 11(7):             Device/Func
#                               Bit[7:3]: Device
#                               Bit[2:0]: Function
#   Byte 12(8):             Bus
#   Byte 13-16(9-12):       Address (32Bits addressing)
#   or 
#   Byte 13-20(9-16):       Address (64Bits addressing)
#   
#   Byte 21-28(17-24):      Data (1, 2, 4, 8 bytess)
#
def DecodeWrEndPointConfig_Mmio (row_LA_RAW):
    if (row_LA_RAW['Command(h)'] == 'WrEndPointConfig(C5)'):
        RawWriteData = row_LA_RAW['Write Data(h)'].split()
        debug_print ("debug: DecodeWrEndPointConfig_Mmio() original Write Data feild - {}".format(RawWriteData))
        MessageType = int(RawWriteData[1], 16)
        if (MessageType == 0x05):                           # MMIO
            hex_value = int(RawWriteData[0], 16)
            HostID = (hex_value >> 1) & 0x7F
            Retry = hex_value & 0x01
            BAR = int(RawWriteData[4], 16)
            Bus = int(RawWriteData[8], 16)
            Device = (int(RawWriteData[7], 16) >> 3) & 0x01F
            Function = int(RawWriteData[7], 16) & 0x03
            hex_value = 0
            # MMIO Offset (Address feild iin spec)
            AddressType = int(RawWriteData[5], 16)
            debug_print ("debug: DecodeWrEndPointConfig_Mmio()  {}".format(RawWriteData))
            if (AddressType == 5): # 32bits Addressing
                selected_data = RawWriteData[9:13]
                if (selected_data):
                    reversed_list = selected_data[::-1]
                    hex_value_str = ''.join(reversed_list)
                    hex_value = int(hex_value_str, 16)
                RegOffsetString = "BAR:{} / Offset(32bits):0x{:04X}".format(int(RawWriteData[4], 16), hex_value)
            elif (AddressType == 6): # 64bits Addressing
                selected_data = RawWriteData[9:17]
                if (selected_data):
                    reversed_list = selected_data[::-1]
                    hex_value_str = ''.join(reversed_list)
                    hex_value = int(hex_value_str, 16)
                RegOffsetString = "BAR:{} / Offset(64bits):0x{:04X}".format(int(RawWriteData[4], 16), hex_value)
            else:
                RegOffsetString = 'Address Type Error'
            debug_print ("debug: {}".format(RegOffsetString))
            # Data be writen
            selected_data = 0
            hex_value = 0
            StringBytes = '(x Byte)'
            PeciRow_WrLen = row_LA_RAW['WrLen']   # use WRLen to identify wroten data length
            # WrLen = 16 (Byte), 17 (Word), 19 (DWord), 23 (QWord) for Address Type 0x05
            if (AddressType == 5):           
                if (PeciRow_WrLen == '16'):     # 1 byte
                    selected_data = RawWriteData[17]
                    hex_value_str = f"0x{selected_data:02X}"
                    StringBytes = '(1 Byte)'
                elif (PeciRow_WrLen == '17'):   # 2 bytes
                    selected_data = RawWriteData[17:19]
                    reversed_list = selected_data[::-1]
                    hex_value = int(reversed_list, 16)
                    hex_value_str = f"0x{hex_value:04X}"
                    StringBytes = '(2 Bytes)'
                elif (PeciRow_WrLen == '19'):   # 4 bytes
                    selected_data = RawWriteData[17:21]
                    reversed_list = selected_data[::-1]
                    debug_print (reversed_list)
                    
                    hex_value = int(''.join(reversed_list), 16)
                    hex_value_str = f"0x{hex_value:08X}"
                    StringBytes = '(4 Bytes)'
                elif (PeciRow_WrLen == '23'):   # 8 bytes
                    selected_data = RawWriteData[17:25]
                    reversed_list = selected_data[::-1]
                    hex_value = int(reversed_list, 16)
                    hex_value_str = f"0x{hex_value:016X}"
                    StringBytes = '(8 Bytes)'

            # WrLen = 20 (Byte), 21 (Word), 23 (DWord), 27 (QWord) for Address Type 0x06
            elif (AddressType == 6):           
                if (PeciRow_WrLen == '20'):     # 1 byte
                    selected_data = RawWriteData[17]
                    hex_value_str = f"0x{selected_data:02X}"
                    StringBytes = '(1 Byte)'
                elif (PeciRow_WrLen == '21'):   # 2 bytes
                    selected_data = RawWriteData[17:19]
                    reversed_list = selected_data[::-1]
                    hex_value = int(reversed_list, 16)
                    hex_value_str = f"0x{hex_value:04X}"
                    StringBytes = '(2 Bytes)'
                elif (PeciRow_WrLen == '23'):   # 4 bytes
                    selected_data = RawWriteData[17:21]
                    reversed_list = selected_data[::-1]
                    hex_value = int(reversed_list, 16)
                    hex_value_str = f"0x{hex_value:08X}"
                    StringBytes = '(4 Bytes)'
                elif (PeciRow_WrLen == '27'):   # 8 bytes
                    selected_data = RawWriteData[17:25]
                    reversed_list = selected_data[::-1]
                    hex_value = int(reversed_list, 16)
                    hex_value_str = f"0x{hex_value:016X}"
                    StringBytes = '(8 Bytes)'

            row_LA_RAW['R/W Data'] = hex_value_str + StringBytes
            debug_print ('debug: store row_LA_RAW[RW Data] = {}'.format(row_LA_RAW['R/W Data']))

            row_LA_RAW['PECI Rerty'] = Retry
            row_LA_RAW['Bus'] = '{} (MMIO)'.format(Bus)
            row_LA_RAW['Device'] = Device
            row_LA_RAW['Function'] = Function
            row_LA_RAW['Register/MMIO Offset'] = RegOffsetString

def debug_print(*args, sep=' ', end='\n'):
    global DebugFlag
    if DebugFlag:
        print(*args, sep=sep, end=end)

if __name__ == '__main__':
    main()

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

        # fill each raw by dictionary way
        for dict_row_LA_RAW in csv_reader:
            #
            # initial feild
            #       inser new feild
            #       Node(CPU) / BDF / reg offset / PECI Completion code /
            new_field_names = ['PECI Rerty', 'CPU', 'Bus', 'Device', 'Function', 'Register/MMIO Offset', 'PECI Completion Code', ' '] + original_field_names
            #       fill data in new insered feild
            dict_row_LA_RAW['CPU'] = 'N/A'
            dict_row_LA_RAW['Bus'] = 'N/A'
            dict_row_LA_RAW['Device'] = 'N/A'
            dict_row_LA_RAW['Function'] = 'N/A'
            dict_row_LA_RAW['Register/MMIO Offset'] = 'N/A'

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
            # RdEndPointConfig()
            #
            if (dict_row_LA_RAW['Command(h)'] == 'RdEndPointConfig(C1)'):
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
                RawWriteData = dict_row_LA_RAW['Write Data(h)'].split()
                MessageType = int(RawWriteData[1], 16)
                if (MessageType == 0x03):               # Local PCI-Cfg
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

                    Bus = (hex_value >> 20) & 0xFFF
                    Device = (hex_value >> 15) & 0x1F
                    Function = (hex_value >> 12) & 0x03
                    RegOffset = (hex_value) & 0x0FFF
                                    
                    dict_row_LA_RAW['PECI Rerty'] = Retry
                    dict_row_LA_RAW['Bus'] = Bus
                    dict_row_LA_RAW['Device'] = Device
                    dict_row_LA_RAW['Function'] = Function
                    dict_row_LA_RAW['Register/MMIO Offset'] = hex(RegOffset)
                    #dict_row_LA_RAW['PECI Completion Code']
                    #print ("debug:")
                    #print (dict_row_LA_RAW)

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
                RawWriteData = dict_row_LA_RAW['Write Data(h)'].split()
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
                    selected_data = RawWriteData[9:13]
                    if (selected_data):
                        reversed_list = selected_data[::-1]
                        hex_value_str = ''.join(reversed_list)
                        hex_value = int(hex_value_str, 16)
                    RegOffsetString = "BAR:{} / Offset:{}".format(int(RawWriteData[4], 16), hex(hex_value))
                    print ("debug: {}".format(RegOffset))
                                    
                    dict_row_LA_RAW['PECI Rerty'] = Retry
                    dict_row_LA_RAW['Bus'] = Bus
                    dict_row_LA_RAW['Device'] = Device
                    dict_row_LA_RAW['Function'] = Function
                    dict_row_LA_RAW['Register/MMIO Offset'] = RegOffsetString
                    #dict_row_LA_RAW['PECI Completion Code']
            
            
            #Completion Code
            CompletionCode = 0
            dict_row_LA_RAW['PECI Completion Code'] = CompletionCode    
            
            out_data_list.append(dict_row_LA_RAW)
            #print (dict_row_LA_RAW)
            

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

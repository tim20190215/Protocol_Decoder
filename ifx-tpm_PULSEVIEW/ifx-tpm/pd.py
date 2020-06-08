##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2011 Gareth McMullin <gareth@blacksphere.co.nz>
## Copyright (C) 2012-2014 Uwe Hermann <uwe@hermann-uwe.de>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import sigrokdecode as srd
from collections import namedtuple

Data = namedtuple('Data', ['ss', 'es', 'val'])

'''
OUTPUT_PYTHON format:

Packet:
[<ptype>, <data1>, <data2>]

<ptype>:
 - 'DATA': <data1> contains the MOSI data, <data2> contains the MISO data.
   The data is _usually_ 8 bits (but can also be fewer or more bits).
   Both data items are Python numbers (not strings), or None if the respective
   channel was not supplied.
 - 'BITS': <data1>/<data2> contain a list of bit values in this MOSI/MISO data
   item, and for each of those also their respective start-/endsample numbers.
 - 'CS-CHANGE': <data1> is the old CS# pin value, <data2> is the new value.
   Both data items are Python numbers (0/1), not strings. At the beginning of
   the decoding a packet is generated with <data1> = None and <data2> being the
   initial state of the CS# pin or None if the chip select pin is not supplied.
 - 'TRANSFER': <data1>/<data2> contain a list of Data() namedtuples for each
   byte transferred during this block of CS# asserted time. Each Data() has
   fields ss, es, and val.

Examples:
 ['CS-CHANGE', None, 1]
 ['CS-CHANGE', 1, 0]
 ['DATA', 0xff, 0x3a]
 ['BITS', [[1, 80, 82], [1, 83, 84], [1, 85, 86], [1, 87, 88],
           [1, 89, 90], [1, 91, 92], [1, 93, 94], [1, 95, 96]],
          [[0, 80, 82], [1, 83, 84], [0, 85, 86], [1, 87, 88],
           [1, 89, 90], [1, 91, 92], [0, 93, 94], [0, 95, 96]]]
 ['DATA', 0x65, 0x00]
 ['DATA', 0xa8, None]
 ['DATA', None, 0x55]
 ['CS-CHANGE', 0, 1]
 ['TRANSFER', [Data(ss=80, es=96, val=0xff), ...],
              [Data(ss=80, es=96, val=0x3a), ...]]
'''
# TCG Command
cmdcode = {
    0x0000011F: [28,'TPM_CC_NV_UNDEFINESPACESPECIAL'],
    0x00000120: [28,'TPM_CC_EVICTCONTROL'],
    0x00000121: [28,'TPM_CC_HIERARCHYCONTROL'],
    0x00000122: [28,'TPM_CC_NV_UNDEFINESPACE'],
    0x00000124: [28,'TPM_CC_CHANGEEPS'],
    0x00000125: [28,'TPM_CC_CHANGEPPS'],
    0x00000126: [28,'TPM_CC_CLEAR'],
    0x00000127: [28,'TPM_CC_CLEARCONTROL'],
    0x00000128: [28,'TPM_CC_CLOCKSET'],
    0x00000129: [28,'TPM_CC_HIERARCHYCHANGEAUTH'],
    0x0000012A: [28,'TPM_CC_NV_DEFINESPACE'],
    0x0000012B: [28,'TPM_CC_PCR_ALLOCATE'],
    0x0000012C: [28,'TPM_CC_PCR_SETAUTHPOLICY'],
    0x0000012D: [28,'TPM_CC_PP_COMMANDS'],
    0x0000012E: [28,'TPM_CC_SETPRIMARYPOLICY'],
    0x0000012F: [28,'TPM_CC_FIELDUPGRADESTART'],
    0x00000130: [28,'TPM_CC_CLOCKRATEADJUST'],
    0x00000131: [28,'TPM_CC_CREATEPRIMARY'],
    0x00000132: [28,'TPM_CC_NV_GLOBALWRITELOCK'],
    0x00000133: [28,'TPM_CC_GETCOMMANDAUDITDIGEST'],
    0x00000134: [28,'TPM_CC_NV_INCREMENT'],
    0x00000135: [28,'TPM_CC_NV_SETBITS'],
    0x00000136: [28,'TPM_CC_NV_EXTEND'],
    0x00000137: [28,'TPM_CC_NV_WRITE'],
    0x00000138: [28,'TPM_CC_NV_WRITELOCK'],
    0x00000139: [28,'TPM_CC_DICTIONARYATTACKLOCKRESET'],
    0x0000013A: [28,'TPM_CC_DICTIONARYATTACKPARAMETERS'],
    0x0000013B: [28,'TPM_CC_NV_CHANGEAUTH'],
    0x0000013C: [28,'TPM_CC_PCR_EVENT'],
    0x0000013D: [28,'TPM_CC_PCR_RESET'],
    0x0000013E: [28,'TPM_CC_SEQUENCECOMPLETE'],
    0x0000013F: [28,'TPM_CC_SETALGORITHMSET'],
    0x00000140: [28,'TPM_CC_SETCOMMANDCODEAUDITSTATUS'],
    0x00000141: [28,'TPM_CC_FIELDUPGRADEDATA'],
    0x00000142: [28,'TPM_CC_INCREMENTALSELFTEST'],
    0x00000143: [28,'TPM_CC_SELFTEST'],
    0x00000144: [28,'TPM_CC_STARTUP'],
    0x00000145: [28,'TPM_CC_SHUTDOWN'],
    0x00000146: [28,'TPM_CC_STIRRANDOM'],
    0x00000147: [28,'TPM_CC_ACTIVATECREDENTIAL'],
    0x00000148: [28,'TPM_CC_CERTIFY'],
    0x00000149: [28,'TPM_CC_POLICYNV'],
    0x0000014A: [28,'TPM_CC_CERTIFYCREATION'],
    0x0000014B: [28,'TPM_CC_DUPLICATE'],
    0x0000014C: [28,'TPM_CC_GETTIME'],
    0x0000014D: [28,'TPM_CC_GETSESSIONAUDITDIGEST'],
    0x0000014E: [28,'TPM_CC_NV_READ'],
    0x0000014F: [28,'TPM_CC_NV_READLOCK'],
    0x00000150: [28,'TPM_CC_OBJECTCHANGEAUTH'],
    0x00000151: [28,'TPM_CC_POLICYSECRET'],
    0x00000152: [28,'TPM_CC_REWRAP'],
    0x00000153: [28,'TPM_CC_CREATE'],
    0x00000154: [28,'TPM_CC_ECDH_ZGEN'],
    0x00000155: [28,'TPM_CC_HMAC'],
    0x00000156: [28,'TPM_CC_IMPORT'],
    0x00000157: [28,'TPM_CC_LOAD'],
    0x00000158: [28,'TPM_CC_QUOTE'],
    0x00000159: [28,'TPM_CC_RSA_DECRYPT'],
    0x0000015B: [28,'TPM_CC_HMAC_START'],
    0x0000015C: [28,'TPM_CC_SEQUENCEUPDATE'],
    0x0000015D: [28,'TPM_CC_SIGN'],
    0x0000015E: [28,'TPM_CC_UNSEAL'],
    0x00000160: [28,'TPM_CC_POLICYSIGNED'],
    0x00000161: [28,'TPM_CC_CONTEXTLOAD'],
    0x00000162: [28,'TPM_CC_CONTEXTSAVE'],
    0x00000163: [28,'TPM_CC_ECDH_KEYGEN'],
    0x00000164: [28,'TPM_CC_ENCRYPTDECRYPT'],
    0x00000165: [28,'TPM_CC_FLUSHCONTEXT'],
    0x00000167: [28,'TPM_CC_LOADEXTERNAL'],
    0x00000168: [28,'TPM_CC_MAKECREDENTIAL'],
    0x00000169: [28,'TPM_CC_NV_READPUBLIC'],
    0x0000016A: [28,'TPM_CC_POLICYAUTHORIZE'],
    0x0000016B: [28,'TPM_CC_POLICYAUTHVALUE'],
    0x0000016C: [28,'TPM_CC_POLICYCOMMANDCODE'],
    0x0000016D: [28,'TPM_CC_POLICYCOUNTERTIMER'],
    0x0000016E: [28,'TPM_CC_POLICYCPHASH'],
    0x0000016F: [28,'TPM_CC_POLICYLOCALITY'],
    0x00000170: [28,'TPM_CC_POLICYNAMEHASH'],
    0x00000171: [28,'TPM_CC_POLICYOR'],
    0x00000172: [28,'TPM_CC_POLICYTICKET'],
    0x00000173: [28,'TPM_CC_READPUBLIC'],
    0x00000174: [28,'TPM_CC_RSA_ENCRYPT'],
    0x00000176: [28,'TPM_CC_STARTAUTHSESSION'],
    0x00000177: [28,'TPM_CC_VERIFYSIGNATURE'],
    0x00000178: [28,'TPM_CC_ECC_PARAMETERS'],
    0x00000179: [28,'TPM_CC_FIRMWAREREAD'],
    0x0000017A: [28,'TPM_CC_GETCAPABILITY'],
    0x0000017B: [28,'TPM_CC_GETRANDOM'],
    0x0000017C: [28,'TPM_CC_GETTESTRESULT'],
    0x0000017D: [28,'TPM_CC_HASH'],
    0x0000017E: [28,'TPM_CC_PCR_READ'],
    0x0000017F: [28,'TPM_CC_POLICYPCR'],
    0x00000180: [28,'TPM_CC_POLICYRESTART'],
    0x00000181: [28,'TPM_CC_READCLOCK'],
    0x00000182: [28,'TPM_CC_PCR_EXTEND'],
    0x00000183: [28,'TPM_CC_PCR_SETAUTHVALUE'],
    0x00000184: [28,'TPM_CC_NV_CERTIFY'],
    0x00000185: [28,'TPM_CC_EVENTSEQUENCECOMPLETE'],
    0x00000186: [28,'TPM_CC_HASHSEQUENCESTART'],
    0x00000187: [28,'TPM_CC_POLICYPHYSICALPRESENCE'],
    0x00000188: [28,'TPM_CC_POLICYDUPLICATIONSELECT'],
    0x00000189: [28,'TPM_CC_POLICYGETDIGEST'],
    0x0000018A: [28,'TPM_CC_TESTPARMS'],
    0x0000018B: [28,'TPM_CC_COMMIT'],
    0x0000018C: [28,'TPM_CC_POLICYPASSWORD'],
    0x0000018D: [28,'TPM_CC_ZGEN_2PHASE'],
    0x0000018E: [28,'TPM_CC_EC_EPHEMERAL'],
    0x0000018F: [28,'TPM_CC_POLICYNVWRITTEN'],
    0x00000190: [28,'TPM_CC_POLICYTEMPLATE'],
    0x00000191: [28,'TPM_CC_CREATELOADED'],
    0x00000192: [28,'TPM_CC_POLICYAUTHORIZENV'],
    0x00000193: [28,'TPM_CC_ENCRYPTDECRYPT2'],
    0x00000194: [28,'TPM_CC_AC_GETCAPABILITY'],
    0x00000195: [28,'TPM_CC_AC_SEND'],
    0x00000196: [28,'TPM_CC_POLICY_AC_SENDSELECT'],
    0x00000197: [28,'TPM_CC_CERTIFYX509'],
    0x00000198: [28,'TPM_CC_ACT_SETTIMEOUT'],
}


# TCG TAG Main spec part 2
tag = {
    0x00C4: [26,'TPM_ST_RSP_COMMAND',           'RSP_CMD',           'RSP'],
    0x8000: [26,'TPM_ST_NULL',                  'NULL',               'NL'],
    0x8001: [26,'TPM_ST_NO_SESSIONS',           'NO_SESS',           'NSE'],
    0x8002: [26,'TPM_ST_SESSIONS',              'SESSION',           'SES'],
    0x8014: [26,'TPM_ST_ATTEST_NV',             'ATT_NV',            'ANV'],
    0x8015: [26,'TPM_ST_ATTEST_COMMAND_AUDIT',  'ATT_CMD',           'ACM'],
    0x8016: [26,'TPM_ST_ATTEST_SESSION_AUDIT',  'ATT_SES',           'ASE'],
    0x8017: [26,'TPM_ST_ATTEST_CERTIFY',        'ATT_CER',           'ACR'],
    0x8018: [26,'TPM_ST_ATTEST_QUOTE',          'ATT_QUO',           'AQU'],
    0x8019: [26,'TPM_ST_ATTEST_TIME',           'ATT_TIM',           'ATM'],
    0x801A: [26,'TPM_ST_ATTEST_CREATION',       'ATT_CRE',           'ACR'],
    0x801C: [26,'TPM_ST_ATTEST_NV_DIGEST',      'ATT_NVD',           'AND'],
    0x8021: [26,'TPM_ST_CREATION',              'CREATIN',           'CRE'],
    0x8022: [26,'TPM_ST_VERIFIED',              'VERIFED',           'VER'],
    0x8023: [26,'TPM_ST_AUTH_SECRET',           'AUTHSEC',           'ASC'],
    0x8024: [26,'TPM_ST_HASHCHECK',             'HASHCHK',           'HAC'],
    0x8025: [26,'TPM_ST_AUTH_SIGNED',           'AUTHSIG',           'ASG'],
    0x8029: [26,'TPM_ST_FU_MANIFEST',           'FU_MANI',           'FUM'],
}

# REG
reg = {
    0x0000: [17,'TPM_ACCESS_0',           'ACCESS_0',           'AC0'],
    0x0008: [17,'TPM_INT_ENABLE_0',       'INT_ENABLE_0',       'IE0'],
    0x000C: [17,'TPM_INT_VECTOR_0',       'INT_VECTOR_0',       'IV0'],
    0x0010: [17,'TPM_INT_STATUS_0',       'INT_STATUS_0',       'IS0'],
    0x0014: [17,'TPM_INTF_CAPABILITY_0',  'INTF_CAPABILITY_0',  'IC0'],
    0x0018: [17,'TPM_STS_0',              'STS_0',              'ST0'],
    0x0024: [17,'TPM_DATA_FIFO_0',        'DATA_FIFO_0',        'DF0'],
    0x0080: [17,'TPM_XDATA_FIFO_0',       'XDATA_FIFO_0',       'XD0'],
    0x0F00: [17,'TPM_DID_VID_0',          'DID_VID_0',          'DV0'],
    0x0F04: [17,'TPM_RID_0',              'RID_0',              'RI0'],
    0x0000: [17,'TPM_ACCESS_0',           'ACCESS_0',           'AC0'],

    0x1000: [9,'TPM_ACCESS_1',           'ACCESS_1',           'AC1'],
    0x1008: [9,'TPM_INT_ENABLE_1',       'INT_ENABLE_1',       'IE1'],
    0x100C: [9,'TPM_INT_VECTOR_1',       'INT_VECTOR_1',       'IV1'],
    0x1010: [9,'TPM_INT_STATUS_1',       'INT_STATUS_1',       'IS1'],
    0x1014: [9,'TPM_INTF_CAPABILITY_1',  'INTF_CAPABILITY_1',  'IC1'],
    0x1018: [9,'TPM_STS_1',              'STS_1',              'ST1'],
    0x1024: [9,'TPM_DATA_FIFO_1',        'DATA_FIFO_1',        'DF1'],
    0x1080: [9,'TPM_XDATA_FIFO_1',       'XDATA_FIFO_1',       'XD1'],
    0x1F00: [9,'TPM_DID_VID_1',          'DID_VID_1',          'DV1'],
    0x1F04: [9,'TPM_RID_1',              'RID_1',              'RI1'],

    0x2000: [11,'TPM_ACCESS_2',           'ACCESS_2',           'AC2'],
    0x2008: [11,'TPM_INT_ENABLE_2',       'INT_ENABLE_2',       'IE2'],
    0x200C: [11,'TPM_INT_VECTOR_2',       'INT_VECTOR_2',       'IV2'],
    0x2010: [11,'TPM_INT_STATUS_2',       'INT_STATUS_2',       'IS2'],
    0x2014: [11,'TPM_INTF_CAPABILITY_2',  'INTF_CAPABILITY_2',  'IC2'],
    0x2018: [11,'TPM_STS_2',              'STS_2',              'ST2'],
    0x2024: [11,'TPM_DATA_FIFO_2',        'DATA_FIFO_2',        'DF2'],
    0x2080: [11,'TPM_XDATA_FIFO_2',       'XDATA_FIFO_2',       'XD2'],
    0x2F00: [11,'TPM_DID_VID_2',          'DID_VID_2',          'DV2'],
    0x2F04: [11,'TPM_RID_2',              'RID_2',              'RI2'],

    0x3000: [13,'TPM_ACCESS_3',           'ACCESS_3',           'AC3'],
    0x3008: [13,'TPM_INT_ENABLE_3',       'INT_ENABLE_3',       'IE3'],
    0x300C: [13,'TPM_INT_VECTOR_3',       'INT_VECTOR_3',       'IV3'],
    0x3010: [13,'TPM_INT_STATUS_3',       'INT_STATUS_3',       'IS3'],
    0x3014: [13,'TPM_INTF_CAPABILITY_3',  'INTF_CAPABILITY_3',  'IC3'],
    0x3018: [13,'TPM_STS_3',              'STS_3',              'ST3'],
    0x3024: [13,'TPM_DATA_FIFO_3',        'DATA_FIFO_3',        'DF3'],
    0x3080: [13,'TPM_XDATA_FIFO_3',       'XDATA_FIFO_3',       'XD3'],
    0x3F00: [13,'TPM_DID_VID_3',          'DID_VID_3',          'DV3'],
    0x3F04: [13,'TPM_RID_3',              'RID_3',              'RI3'],

    0x4000: [15,'TPM_ACCESS_4',           'ACCESS_4',           'AC4'],
    0x4008: [15,'TPM_INT_ENABLE_4',       'INT_ENABLE_4',       'IE4'],
    0x400C: [15,'TPM_INT_VECTOR_4',       'INT_VECTOR_4',       'IV4'],
    0x4010: [15,'TPM_INT_STATUS_4',       'INT_STATUS_4',       'IS4'],
    0x4014: [15,'TPM_INTF_CAPABILITY_4',  'INTF_CAPABILITY_4',  'IC4'],
    0x4018: [15,'TPM_STS_4',              'STS_4',              'ST4'],
    0x4024: [15,'TPM_DATA_FIFO_4',        'DATA_FIFO_4',        'DF4'],
    0x4080: [15,'TPM_XDATA_FIFO_4',       'XDATA_FIFO_4',       'XD4'],
    0x4F00: [15,'TPM_DID_VID_4',          'DID_VID_4',          'DV4'],
    0x4F04: [15,'TPM_RID_4',              'RID_4',              'RI4'],
}

class ChannelError(Exception):
    pass

class Decoder(srd.Decoder):
    api_version = 3
    id = 'ifx-spi'
    name = '0-IFX-TPM'
    longname = 'TPM Serial Peripheral Interface'
    desc = 'TPM SPI protocol'
    license = 'gplv2+'
    inputs = ['logic']
    outputs = ['spi']
    tags = ['Embedded/industrial']
    channels = (
        {'id': 'clk', 'name': 'CLK', 'desc': 'Clock'},
        {'id': 'miso', 'name': 'MISO', 'desc': 'Master in, slave out'},
        {'id': 'mosi', 'name': 'MOSI', 'desc': 'Master out, slave in'},
        {'id': 'cs', 'name': 'CS#', 'desc': 'Chip-select'},
    )
    options = (
        {'id': 'cs_polarity', 'desc': 'CS# polarity', 'default': 'active-low',
            'values': ('active-low', 'active-high')},
    )
    annotations = (
        ('miso-data', 'MISO data'),                         #0
        ('mosi-data', 'MOSI data'),                         #1
        ('miso-bits', 'MISO bits'),                         #2
        ('mosi-bits', 'MOSI bits'),                         #3
        ('warnings', 'Human-readable warnings'),            #4
        ('miso-transfer', 'MISO transfer'),                 #5
        ('mosi-transfer', 'MOSI transfer'),                 #6

        ('reg-header-r', 'Register Header Read'),           #7
        ('reg-header-w', 'Register Header Write'),          #8
        ('locality1-reg-r', 'Locality 1 Register Read'),    #9
        ('locality1-reg-w', 'Locality 1 Register Write'),   #10
        ('locality2-reg-r', 'Locality 2 Register Read'),    #11
        ('locality2-reg-w', 'Locality 2 Register Write'),   #12
        ('locality3-reg-r', 'Locality 3 Register Read'),    #13
        ('locality3-reg-w', 'Locality 3 Register Write'),   #14
        ('locality4-reg-r', 'Locality 4 Register Read'),    #15
        ('locality4-reg-w', 'Locality 4 Register Write'),   #16

        ('reg-name', 'Register Name'),                      #17
        ('reg-sizeofxfer', 'Size of Transfer'),             #18
        ('reg-ack', 'Ack byte'),                            #19
        ('reg-nack', 'NAck byte'),                          #20
        ('reg-data-w', 'Reg Data Write'),                   #21
        ('reg-data-r', 'Reg Data Read'),                    #22

        ('state-1', 'State 1'),                             #23
        ('state-2', 'State 2'),                             #24
        ('state-3', 'State 3'),                             #25

        ('cmd-tag', 'Command Tag'),                         #26
        ('cmd-len', 'Command Length'),                      #27
        ('cmd-ord', 'Command Code'),                        #28
        ('cmd-data-w', 'Command Data Write'),               #29
        ('cmd-data-r', 'Command Data Read'),                #30

        ('frame-reg-sizeofxfer-w', 'Frame Sizeof Xfer-w'),  #31
        ('frame-reg-sizeofxfer-r', 'Frame Sizeof Xfer-r'),  #32
        ('frame-reg-name', 'Frame Register Name'),          #33
        ('frame-reg-ack', 'Frame Ack byte'),                #34
        ('frame-reg-nack', 'Frame NAck byte'),              #35
        ('frame-data-w', 'Frame Write'),                    #36
        ('frame-data-r', 'Frame Read'),                     #37

        ('frame-cmd-tag', 'Frame Command Tag'),             #38
        ('frame-cmd-len', 'Frame Command Length'),          #39
        ('frame-cmd-ord', 'Frame Command Code'),            #40
        ('frame-cmd-data-w', 'Frame Command Data Write'),   #41
        ('frame-cmd-data-r', 'Frame Command Data Read'),    #42

        ('frame-state-1', 'Frame state 1'),                 #43
        ('frame-state-2', 'Frame state 2'),                 #44
        ('frame-state-3', 'Frame state 3'),                 #45
        ('frame-state-4', 'Frame state 4'),                 #46
        ('frame-state-5', 'Frame state 5'),                 #47
        ('frame-state-6', 'Frame state 6'),                 #48

        ('cmd-err', 'Command Error'),                       #49
        ('state-err', 'State Error'),                       #50
        ('reg-err', 'Register Error'),                      #51
        ('frame-cmd-err', 'Frame Command Error'),           #52
        ('frame-state-err', 'Frame State Error'),           #53
        ('frame-reg-err', 'Frame Register Error'),          #54
    )
    annotation_rows = (
        ('miso-bits', 'MISO bits', (2,)),
        ('miso-data', 'MISO data', (0,)),
        ('miso-transfer', 'MISO transfer', (5,)),
        ('mosi-bits', 'MOSI bits', (3,)),
        ('mosi-data', 'MOSI data', (1,)),
        ('mosi-transfer', 'MOSI transfer', (6,)),
        ('other', 'Other', (4,)),

        ('cmd', 'Command', (26,27,28,29,30,49,)),
        ('state', 'State', (23,24,25,50,)),
        ('register','Register', (7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,51,)),

        ('frame-cmd','Frame-Command', (38,39,40,41,42,52,)),
        ('frame-state','Frame-State', (43,44,45,46,47,48,53,)),
        ('frame-reg','Frame-Register', (31,32,33,34,35,36,37,54,)),
    )
    binary = (
        ('miso', 'MISO'),
        ('mosi', 'MOSI'),
    )

    def __init__(self):
        self.reset()

    def reset(self):
        self.samplerate = None
        self.bitcount = 0
        self.misodata = self.mosidata = 0
        self.misobits = []
        self.mosibits = []
        self.misobytes = []
        self.mosibytes = []
        self.ss_block = -1
        self.ss_transfer = -1
        self.cs_was_deasserted = False
        self.have_cs = None

        self.bytecount = 0
        self.sizeofxfer = 0
        self.reg_sp = -1
        self.reg_ep = -1
        self.reg_wr = 0
        self.reg_addr = 0
        self.reg_locality = 0

        self.reg_data_avail = -1
        self.reg_expect = -1
        self.reg_selftest = 0
        self.reg_commandready = 0
        self.reg_valid = 0
        self_reg_responseretry = 0
        self.reg_tpmgo = 0

        self.reg_tpmestablishment = 0
        self.reg_requestuse = 0
        self.reg_pendingrequest = 0
        self.reg_seize = 0
        self.reg_beenseized = 0
        self.reg_activelocality = 0
        self.reg_tpmregvalidsts = 0
        self.reg_access_sts = ''
        self.reg_access_sts1 = ''

        self.cmd = 0
        self.cmd_count = 0
        self.cmd_tag = 0
        self.cmd_ord = 0
        self.cmd_rc = 0
        self.cmd_len = 0
        self.cmd_burst = 0
        self.cmd_expect = 0
        self.cmd_sp = -1
        self.cmd_ep = -1
        self.cmd_done = 0
        self.cmd_command = 0
        self.cmd_response = 0

        self.frame_sp = -1
        self.frame_ep = -1
        self.frame_cs = 0
        self.frame_cmd_sp = -1
        self.frame_cmd_ep = -1
        self.frame_cmd_wr = -1
        self.frame_bytes = []
        self.frame_reg_bytes = []
        self.frame_cmd_first = 0

    def start(self):
        self.out_python = self.register(srd.OUTPUT_PYTHON)
        self.out_ann = self.register(srd.OUTPUT_ANN)
        self.out_binary = self.register(srd.OUTPUT_BINARY)
        self.out_bitrate = self.register(srd.OUTPUT_META,
                meta=(int, 'Bitrate', 'Bitrate during transfers'))
        self.bw = (8 + 7) // 8

    def metadata(self, key, value):
       if key == srd.SRD_CONF_SAMPLERATE:
            self.samplerate = value

    def putw(self, data):
        self.put(self.ss_block, self.samplenum, self.out_ann, data)

    def putdata(self):
        # Pass MISO and MOSI bits and then data to the next PD up the stack.
        so = self.misodata
        si = self.mosidata
        so_bits = self.misobits
        si_bits = self.mosibits

        ss, es = self.misobits[-1][1], self.misobits[0][2]
        bdata = so.to_bytes(self.bw, byteorder='big')
        self.put(ss, es, self.out_binary, [0, bdata])

        ss, es = self.mosibits[-1][1], self.mosibits[0][2]
        bdata = si.to_bytes(self.bw, byteorder='big')
        self.put(ss, es, self.out_binary, [1, bdata])

        self.put(ss, es, self.out_python, ['BITS', si_bits, so_bits])
        self.put(ss, es, self.out_python, ['DATA', si, so])

        self.misobytes.append(Data(ss=ss, es=es, val=so))
        self.mosibytes.append(Data(ss=ss, es=es, val=si))

        # Bit annotations.
        for bit in self.misobits:
            self.put(bit[1], bit[2], self.out_ann, [2, ['%d' % bit[0]]])

        for bit in self.mosibits:
            self.put(bit[1], bit[2], self.out_ann, [3, ['%d' % bit[0]]])

        # Dataword annotations.
        self.put(ss, es, self.out_ann, [0, ['%02X' % self.misodata]])
        self.put(ss, es, self.out_ann, [1, ['%02X' % self.mosidata]])

        # Register annotations.
        if self.bytecount == 0:
            #first byte
            self.sizeofxfer = (self.mosidata & 0x7f) + 1
            if (self.mosidata & 0x80) == 0x00:
                #reg write
                self.reg_wr = 1
                self.put(ss, es, self.out_ann, [8, ['WRITE:%d' % self.sizeofxfer, 'WR:%d' % self.sizeofxfer, 'W:%d' % self.sizeofxfer]])
            else:
                #reg read
                self.reg_wr = 0
                self.put(ss, es, self.out_ann, [7, ['READ:%d' % self.sizeofxfer, 'RD:%d' % self.sizeofxfer, 'R:%d' % self.sizeofxfer],])
        elif self.bytecount == 1:
            # skip D4
            self.reg_sp = ss
        elif self.bytecount == 2:
            # upper reg address
            self.reg_addr = (self.mosidata << 8)
        elif self.bytecount == 3:
            # lower reg address
            self.reg_ep = es
            self.reg_addr += self.mosidata
            self.reg_locality = (self.reg_addr & 0xf000) >> 12
            if ((self.reg_addr & 0x0fff) == 0x0024) or ((self.reg_addr & 0x0fff) == 0x0080):
                # TPM Command / Response byte stream
                self.cmd = 1
            try:
                self.put(self.reg_sp,self.reg_ep,self.out_ann,[reg[self.reg_addr][0],['%s' % reg[self.reg_addr][1],
                                                        '%s' % reg[self.reg_addr][2],'%s' % reg[self.reg_addr][3]]])
            except:
                self.put(self.reg_sp,self.reg_ep,self.out_ann,[51, ['PROTOCOL ERROR','ERROR','ERR','E']])

            if self.misodata == 1:
                self.put(ss,es,self.out_ann,[19,['ACK','AK','A']])
            else:
                self.put(ss,es,self.out_ann,[20,['NACK','NK','N']])
        else:
            if self.reg_wr == 1:
                self.put(ss,es,self.out_ann,[21,['WRITE:0x%02X' % self.mosidata,'WR:0x%02X' % self.mosidata,
                                                    'W:%02X' % self.mosidata,'%02X' % self.mosidata]])
                # Reg Header / Status
                if ((self.reg_addr & 0x0fff) == 0x0000):
                    # TPM_ACCESS
                    if self.mosidata == 0x20:
                        self.reg_access_sts = 'RELINUISH'
                    elif self.mosidata == 0x10:
                        self.reg_access_sts = 'CLEAR SEIZED'
                    elif self.mosidata == 0x08:
                        self.reg_access_sts = 'SEIZE'
                    elif self.mosidata == 0x02:
                        self.reg_access_sts = 'REQUEST'
                    else:
                        self.reg_access_sts = 'ERROR'

                    self.put(self.mosibits[7][1],self.mosibits[7][2],self.out_ann,[23,['VALIDSTS:%d'%self.mosibits[7][0]]])
                    self.put(self.mosibits[6][1],self.mosibits[6][2],self.out_ann,[24,['RESERVED:%d'%self.mosibits[6][0]]])
                    self.put(self.mosibits[5][1],self.mosibits[5][2],self.out_ann,[23,['ACTIVELOCALITY:%d'%self.mosibits[5][0]]])
                    self.put(self.mosibits[4][1],self.mosibits[4][2],self.out_ann,[24,['BEENSEIZED:%d'%self.mosibits[4][0]]])
                    self.put(self.mosibits[3][1],self.mosibits[3][2],self.out_ann,[23,['SEIZE:%d'%self.mosibits[3][0]]])
                    self.put(self.mosibits[2][1],self.mosibits[2][2],self.out_ann,[24,['PENDING:%d'%self.mosibits[2][0]]])
                    self.put(self.mosibits[1][1],self.mosibits[1][2],self.out_ann,[23,['REQUESTUSE:%d'%self.mosibits[1][0]]])
                    self.put(self.mosibits[0][1],self.mosibits[0][2],self.out_ann,[24,['ESTABLISHMENT:%d'%self.mosibits[0][0]]])

                    #self.put(ss, es,self.out_ann,[23,['%s' % (self.reg_access_sts)]])

                if ((self.reg_addr & 0x0fff) == 0x0018):
                    # TPM_STATUS
                    self.reg_tpmgo = self.mosibits[5][0]
                    self.reg_commandready = self.mosibits[6][0]
                    self.reg_responseretry = self.mosibits[2][0]

                    if ((self.reg_tpmgo == 1) or (self.reg_commandready == 1)):
                        self.cmd_response = 0
                        self.cmd_command = 0

                    self.put(self.mosibits[7][1],self.mosibits[7][2],self.out_ann,[23,['VALIDSTS:%d'%self.mosibits[7][0]]])
                    self.put(self.mosibits[6][1],self.mosibits[6][2],self.out_ann,[24,['READY:%d'%self.mosibits[6][0]]])
                    self.put(self.mosibits[5][1],self.mosibits[5][2],self.out_ann,[23,['TPMGO:%d'%self.mosibits[5][0]]])
                    self.put(self.mosibits[4][1],self.mosibits[4][2],self.out_ann,[24,['DATAAVAIL:%d'%self.mosibits[4][0]]])
                    self.put(self.mosibits[3][1],self.mosibits[3][2],self.out_ann,[23,['EXPECT:%d'%self.mosibits[3][0]]])
                    self.put(self.mosibits[2][1],self.mosibits[2][2],self.out_ann,[24,['SELFTESTDONE:%d'%self.mosibits[2][0]]])
                    self.put(self.mosibits[1][1],self.mosibits[1][2],self.out_ann,[23,['RESPRETRY:%d'%self.mosibits[1][0]]])
                    self.put(self.mosibits[0][1],self.mosibits[0][2],self.out_ann,[24,['RESERVED:%d'%self.mosibits[0][0]]])

                    #self.put(ss,es,self.out_ann,[23,['TPMGO:%d, CMDREADY:%d, RESPONSERETRY:%d' % (self.reg_tpmgo,self.reg_commandready,self.reg_responseretry)]])
            else:
                self.put(ss,es,self.out_ann,[22,['READ:0x%02X' % self.misodata,'RD:0x%02X' % self.misodata,
                                                    'R:%02X' % self.misodata,'%02X' % self.misodata]])
                # Reg Header / Status
                if ((self.reg_addr & 0x0fff) == 0x0000):
                    # TPM_ACCESS
                    reg_byte = es - ss
                    reg_bit = int(reg_byte / 8)

                    self.reg_tpmestablishment = self.misobits[0][0]
                    self.reg_requestuse = self.misobits[1][0]
                    self.reg_pendingrequest = self.misobits[2][0]
                    self.reg_beenseized = self.misobits[4][0]
                    self.reg_activelocality = self.misobits[5][0]
                    self.reg_tpmregvalidsts = self.misobits[7][0]

                    if self.reg_tpmregvalidsts == 1:
                        self.reg_access_sts = 'NOT ACTIVE'
                        if self.reg_activelocality == 1:
                            self.reg_access_sts = 'ACTIVE'
                        if self.reg_beenseized == 1:
                            self.reg_access_sts = 'SEIZED'
                        if self.reg_requestuse == 1:
                            self.reg_access_sts = 'REQUEST'

                        if self.reg_pendingrequest == 1:
                            self.reg_access_sts1 = 'PENDING'

                        self.put(self.misobits[7][1],self.misobits[7][2],self.out_ann,[23,['VALIDSTS:%d'%self.misobits[7][0]]])
                        self.put(self.misobits[6][1],self.misobits[6][2],self.out_ann,[24,['RESERVED:%d'%self.misobits[6][0]]])
                        self.put(self.misobits[5][1],self.misobits[5][2],self.out_ann,[23,['ACTIVELOCALITY:%d'%self.misobits[5][0]]])
                        self.put(self.misobits[4][1],self.misobits[4][2],self.out_ann,[24,['BEENSEIZED:%d'%self.misobits[4][0]]])
                        self.put(self.misobits[3][1],self.misobits[3][2],self.out_ann,[23,['SEIZE:%d'%self.misobits[3][0]]])
                        self.put(self.misobits[2][1],self.misobits[2][2],self.out_ann,[24,['PENDING:%d'%self.misobits[2][0]]])
                        self.put(self.misobits[1][1],self.misobits[1][2],self.out_ann,[23,['REQUESTUSE:%d'%self.misobits[1][0]]])
                        self.put(self.misobits[0][1],self.misobits[0][2],self.out_ann,[24,['ESTABLISHMENT:%d'%self.misobits[0][0]]])
                    else:
                        self.put(self.misobits[7][1],self.misobits[7][2],self.out_ann,[25,['VALIDSTS:%d'%self.misobits[7][0]]])
                        self.put(self.misobits[6][1],self.misobits[6][2],self.out_ann,[24,['RESERVED:%d'%self.misobits[6][0]]])
                        self.put(self.misobits[5][1],self.misobits[5][2],self.out_ann,[23,['ACTIVELOCALITY:%d'%self.misobits[5][0]]])
                        self.put(self.misobits[4][1],self.misobits[4][2],self.out_ann,[24,['BEENSEIZED:%d'%self.misobits[4][0]]])
                        self.put(self.misobits[3][1],self.misobits[3][2],self.out_ann,[23,['SEIZE:%d'%self.misobits[3][0]]])
                        self.put(self.misobits[2][1],self.misobits[2][2],self.out_ann,[24,['PENDING:%d'%self.misobits[2][0]]])
                        self.put(self.misobits[1][1],self.misobits[1][2],self.out_ann,[23,['REQUESTUSE:%d'%self.misobits[1][0]]])
                        self.put(self.misobits[0][1],self.misobits[0][2],self.out_ann,[24,['ESTABLISHMENT:%d'%self.misobits[0][0]]])

                if ((self.reg_addr & 0x0fff) == 0x0018):
                    # TPM_STATUS
                    if (self.bytecount == 4):
                        self.reg_selftest = self.misobits[2][0]
                        self.reg_commandready = self.misobits[6][0]
                        self.reg_valid = self.misobits[7][0]
                        if (self.reg_valid != 0x00):
                            self.reg_data_avail = self.misobits[4][0]
                            self.reg_expect = self.misobits[3][0]

                            self.put(self.misobits[7][1],self.misobits[7][2],self.out_ann,[23,['VALIDSTS:%d'%self.misobits[7][0]]])
                            self.put(self.misobits[6][1],self.misobits[6][2],self.out_ann,[24,['READY:%d'%self.misobits[6][0]]])
                            self.put(self.misobits[5][1],self.misobits[5][2],self.out_ann,[23,['TPMGO:%d'%self.misobits[5][0]]])
                            self.put(self.misobits[4][1],self.misobits[4][2],self.out_ann,[24,['DATAAVAIL:%d'%self.misobits[4][0]]])
                            self.put(self.misobits[3][1],self.misobits[3][2],self.out_ann,[23,['EXPECT:%d'%self.misobits[3][0]]])
                            self.put(self.misobits[2][1],self.misobits[2][2],self.out_ann,[24,['SELFTESTDONE:%d'%self.misobits[2][0]]])
                            self.put(self.misobits[1][1],self.misobits[1][2],self.out_ann,[23,['RESPRETRY:%d'%self.misobits[1][0]]])
                            self.put(self.misobits[0][1],self.misobits[0][2],self.out_ann,[24,['RESERVED:%d'%self.misobits[0][0]]])
                        else:
                            self.reg_data_avail = -1
                            self.reg_expect = -1

                            self.put(self.misobits[7][1],self.misobits[7][2],self.out_ann,[25,['VALIDSTS:%d'%self.misobits[7][0]]])
                            self.put(self.misobits[6][1],self.misobits[6][2],self.out_ann,[24,['READY:%d'%self.misobits[6][0]]])
                            self.put(self.misobits[5][1],self.misobits[5][2],self.out_ann,[23,['TPMGO:%d'%self.misobits[5][0]]])
                            self.put(self.misobits[4][1],self.misobits[4][2],self.out_ann,[25,['DATAAVAIL:%d'%self.misobits[4][0]]])
                            self.put(self.misobits[3][1],self.misobits[3][2],self.out_ann,[25,['EXPECT:%d'%self.misobits[3][0]]])
                            self.put(self.misobits[2][1],self.misobits[2][2],self.out_ann,[24,['SELFTESTDONE:%d'%self.misobits[2][0]]])
                            self.put(self.misobits[1][1],self.misobits[1][2],self.out_ann,[23,['RESPRETRY:%d'%self.misobits[1][0]]])
                            self.put(self.misobits[0][1],self.misobits[0][2],self.out_ann,[24,['RESERVED:%d'%self.misobits[0][0]]])

                    elif (self.bytecount == 5):
                        self.reg_sp = ss
                        self.reg_burstcnt = self.misodata
                    elif (self.bytecount == 6):
                        self.reg_ep = es
                        self.reg_burstcnt += (self.misodata << 8)
                        if self.reg_data_avail == 1:
                            self.cmd_burst = self.reg_burstcnt
                        self.put(self.reg_sp,self.reg_ep,self.out_ann,[23,['BURSTCOUNT:%d' % self.reg_burstcnt,
                                                    'BC:%d' % self.reg_burstcnt,'%d' % self.reg_burstcnt]])

            # Command annotation
            if self.cmd == 1:
                if (self.cmd_command == 0) and (self.cmd_response == 0):
                    # tag
                    if self.cmd_count == 0:
                        self.cmd_sp = ss
                        if self.reg_wr == 1:
                            self.frame_cmd_wr = 1
                            self.cmd_tag = (self.mosidata << 8)
                        else:
                            self.frame_cmd_wr = 0
                            self.cmd_tag = (self.misodata << 8)
                    elif self.cmd_count == 1:
                        self.cmd_ep = es
                        if self.reg_wr == 1:
                            self.cmd_tag += (self.mosidata)
                        else:
                            self.cmd_tag += (self.misodata)
                        try:
                            self.put(self.cmd_sp,self.cmd_ep,self.out_ann,[tag[self.cmd_tag][0],['%s' % tag[self.cmd_tag][1],
                                                '%s' % tag[self.cmd_tag][2],'%s' % tag[self.cmd_tag][3]]])
                        except:
                            self.put(self.cmd_sp,self.cmd_ep,self.out_ann,[49, ['PROTOCOL ERROR','ERROR','ERR','E']])
                    # length
                    elif self.cmd_count == 2:
                        self.cmd_sp = ss
                        if self.reg_wr == 1:
                            self.cmd_len = (self.mosidata << 24)
                        else:
                            self.cmd_len = (self.misodata << 24)
                    elif self.cmd_count == 3:
                        if self.reg_wr == 1:
                            self.cmd_len += (self.mosidata << 16)
                        else:
                            self.cmd_len += (self.misodata << 16)
                    elif self.cmd_count == 4:
                        if self.reg_wr == 1:
                            self.cmd_len += (self.mosidata << 8)
                        else:
                            self.cmd_len += (self.misodata << 8)
                    elif self.cmd_count == 5:
                        self.cmd_ep = es
                        if self.reg_wr == 1:
                            self.cmd_len += (self.mosidata)
                        else:
                            self.cmd_len += (self.misodata)
                        self.put(self.cmd_sp,self.cmd_ep,self.out_ann,[27,['LENGTH:%d' % self.cmd_len,
                                            'LEN:%d' % self.cmd_len,'%d' % self.cmd_len]])
                    # Command Code
                    elif self.cmd_count == 6:
                        self.cmd_sp = ss
                        if self.reg_wr == 1:
                            self.cmd_ord = (self.mosidata << 24)
                        else:
                            self.cmd_rc = (self.misodata << 24)
                    elif self.cmd_count == 7:
                        if self.reg_wr == 1:
                            self.cmd_ord += (self.mosidata << 16)
                        else:
                            self.cmd_rc += (self.misodata << 16)
                    elif self.cmd_count == 8:
                        if self.reg_wr == 1:
                            self.cmd_ord += (self.mosidata << 8)
                        else:
                            self.cmd_rc += (self.misodata << 8)
                    elif self.cmd_count == 9:
                        self.cmd_ep = es
                        if self.reg_wr == 1:
                            self.cmd_command = 1
                            self.cmd_response = 0

                            self.cmd_ord += (self.mosidata)
                            if (self.cmd_ord & 0x2000) == 0:
                                # TCG Command
                                try:
                                    self.put(self.cmd_sp,self.cmd_ep,self.out_ann,[cmdcode[self.cmd_ord][0],['%s' % cmdcode[self.cmd_ord][1]]])
                                except:
                                    self.put(self.cmd_sp,self.cmd_ep,self.out_ann,[49, ['PROTOCOL ERROR','ERROR','ERR','E']])
                            else:
                                # Vendor Specific Command
                                self.put(self.cmd_sp,self.cmd_ep,self.out_ann,[28,['VENDOR SPECIFIC CMD : 0x%08X' % self.cmd_ord,
                                                    'VENDOR:0x%08X' % self.cmd_ord,'V:%08X' % self.cmd_ord,'%08X' % self.cmd_ord]])
                        else:
                            self.cmd_response = 1
                            self.cmd_command = 0
                            self.cmd_rc += (self.misodata)
                            self.reg_tpmgo = 0
                            self.put(self.cmd_sp,self.cmd_ep,self.out_ann,[30,['RC : 0x%08X' % self.cmd_rc]])

                        self.cmd_expect = self.cmd_len - 10
                        # flag if there is not more expected bytes
                        if self.cmd_expect == 0:
                            self.cmd_done = 1
                        else:
                            self.cmd_done = 0

                        self.put(self.cmd_sp,self.cmd_ep,self.out_ann,[25,['remaining : %d' % self.cmd_expect]])

                else:
                    if self.cmd_command == 1:
                        self.put(ss,es,self.out_ann,[29,['WRITE:0x%02X' % self.mosidata,'WR:0x%02X' % self.mosidata,
                                                    'W:%02X' % self.mosidata,'%02X' % self.mosidata]])
                    else:
                        self.put(ss,es,self.out_ann,[30,['READ:0x%02X' % self.misodata,'RD:0x%02X' % self.misodata,
                                                    'R:%02X' % self.misodata,'%02X' % self.misodata]])
                    self.cmd_expect -= 1
                    if self.cmd_expect == 0:
                        self.cmd_response = 0
                        self.cmd_command = 0
                        self.cmd_done = 0
                self.cmd_count += 1
        self.bytecount += 1

    def reset_decoder_state(self):
        self.misodata = 0
        self.mosidata = 0
        self.misobits = []
        self.mosibits = []
        self.bitcount = 0

    def cs_asserted(self, cs):
        active_low = (self.options['cs_polarity'] == 'active-low')
        return (cs == 0) if active_low else (cs == 1)

    def handle_bit(self, miso, mosi, clk, cs):
        # If this is the first bit of a dataword, save its sample number.
        if self.bitcount == 0:
            self.ss_block = self.samplenum
            self.cs_was_deasserted = \
                not self.cs_asserted(cs) if self.have_cs else False

        ws = 8

        # Receive MISO bit into our shift register.
        self.misodata |= miso << (ws - 1 - self.bitcount)

        # Receive MOSI bit into our shift register.
        self.mosidata |= mosi << (ws - 1 - self.bitcount)

        # Guesstimate the endsample for this bit (can be overridden below).
        es = self.samplenum
        if self.bitcount > 0:
            es += self.samplenum - self.misobits[0][1]
            es += self.samplenum - self.mosibits[0][1]

        self.misobits.insert(0, [miso, self.samplenum, es])
        self.mosibits.insert(0, [mosi, self.samplenum, es])

        if self.bitcount > 0:
            self.misobits[1][2] = self.samplenum
        if self.bitcount > 0:
            self.mosibits[1][2] = self.samplenum

        self.bitcount += 1

        # Continue to receive if not enough bits were received, yet.
        if self.bitcount != ws:
            return

        self.putdata()

        # Meta bitrate.
        if self.samplerate:
            elapsed = 1 / float(self.samplerate)
            elapsed *= (self.samplenum - self.ss_block + 1)
            bitrate = int(1 / elapsed * ws)
            self.put(self.ss_block, self.samplenum, self.out_bitrate, bitrate)

        if self.have_cs and self.cs_was_deasserted:
            self.putw([4, ['CS# was deasserted during this data word!']])

        self.reset_decoder_state()

    def find_clk_edge(self, miso, mosi, clk, cs, first):
        if self.have_cs and (first or self.matched[self.have_cs]):
            # Send all CS# pin value changes.
            oldcs = None if first else 1 - cs
            self.put(self.samplenum, self.samplenum, self.out_python,
                     ['CS-CHANGE', oldcs, cs])

            if self.cs_asserted(cs):
                self.ss_transfer = self.samplenum
                self.misobytes = []
                self.mosibytes = []
            elif self.ss_transfer != -1:
                self.put(self.ss_transfer, self.samplenum, self.out_ann,
                    [5, [' '.join(format(x.val, '02X') for x in self.misobytes)]])
                self.put(self.ss_transfer, self.samplenum, self.out_ann,
                    [6, [' '.join(format(x.val, '02X') for x in self.mosibytes)]])
                self.put(self.ss_transfer, self.samplenum, self.out_python,
                    ['TRANSFER', self.mosibytes, self.misobytes])

                # Frame Register
                self.frame_sp = self.ss_transfer
                self.frame_ep = self.samplenum

                frame_total_sample = self.frame_ep - self.frame_sp
                frame_byte = int(frame_total_sample / (self.sizeofxfer + 4))

                # First Byte
                ss, es = self.frame_sp, self.frame_sp + (frame_byte * 1)
                if self.reg_wr == 1:
                    self.put(ss, es,self.out_ann,[31,['WRITE:%d' % self.sizeofxfer,
                                'WR:%d' % self.sizeofxfer, 'W:%d' % self.sizeofxfer]])
                else:
                    self.put(ss, es,self.out_ann,[32,['READ:%d' % self.sizeofxfer,
                                'RD:%d' % self.sizeofxfer, 'R:%d' % self.sizeofxfer]])
                # Register Name
                ss, es = es, self.frame_sp + (frame_byte * 3)
                try:
                    self.put(ss,es,self.out_ann,[33,['%s' % reg[self.reg_addr][1],
                                                            '%s' % reg[self.reg_addr][2],'%s' % reg[self.reg_addr][3]]])
                except:
                    self.put(ss,es,self.out_ann,[54, ['PROTOCOL ERROR','ERROR','ERR','E']])
                # Ack
                ss, es = es, self.frame_sp + (frame_byte * 4)
                if self.misobytes[3][2] == 1:
                    self.put(ss,es,self.out_ann,[34,['ACK','AK','A']])
                else:
                    self.put(ss,es,self.out_ann,[35,['NACK','NK','N']])

                # Data
                ss, es = es, self.frame_ep
                frame_reg_total_sample = es - ss
                if self.reg_wr == 1:
                    self.frame_reg_bytes = self.mosibytes[4:]
                    frame_reg_byte = int(frame_reg_total_sample / len(self.frame_reg_bytes))
                    self.put(ss, es, self.out_ann,[36, [' '.join(format(x.val, '02X') for x in self.frame_reg_bytes)]])
                else:
                    self.frame_reg_bytes = self.misobytes[4:]
                    frame_reg_byte = int(frame_reg_total_sample / len(self.frame_reg_bytes))
                    self.put(ss, es, self.out_ann,[37, [' '.join(format(x.val, '02X') for x in self.frame_reg_bytes)]])


                # Frame Reg Header / Status
                if ((self.reg_addr & 0x0fff) == 0x0000):
                    # TPM_ACCESS Reg
                    reg_byte = self.frame_ep - self.frame_sp
                    reg_bit = int(reg_byte / 8)
                    if self.reg_wr == 1:
                        if ((self.reg_access_sts == 'RELINUISH') or (self.reg_access_sts == 'CLEAR SEIZED') or
                                (self.reg_access_sts == 'SEIZE') or (self.reg_access_sts == 'REQUEST')):
                            self.put(self.frame_sp, self.frame_ep,self.out_ann,[48,['%s' % (self.reg_access_sts)]])
                        else:
                            self.put(self.frame_sp, self.frame_ep,self.out_ann,[45,['%s' % (self.reg_access_sts)]])
                    else:
                        if self.reg_tpmregvalidsts == 1:
                            if ((self.reg_access_sts == 'NOT ACTIVE') or (self.reg_access_sts == 'SEIZED') or
                                    (self.reg_access_sts == 'REQUEST') or (self.reg_access_sts1 == 'PENDING')):
                                self.put(self.frame_sp, self.frame_sp + (reg_bit*7),self.out_ann,[45,['%s %s' % (self.reg_access_sts,self.reg_access_sts1)]])
                            else:
                                self.put(self.frame_sp, self.frame_sp + (reg_bit*7),self.out_ann,[43,['%s %s' % (self.reg_access_sts,self.reg_access_sts1)]])
                            self.put(self.frame_sp + (reg_bit*7), self.frame_ep,self.out_ann,[44,['ESTABLISHMENT:%d' % (self.reg_tpmestablishment),
                                                    'EST:%d' % (self.reg_tpmestablishment),'%d' % (self.reg_tpmestablishment)]])
                        else:
                            self.put(self.frame_sp, self.frame_ep,self.out_ann,[45,['INVALID FLAG']])

                ss, es = self.frame_sp, self.frame_sp + (frame_reg_byte * 1)
                if ((self.reg_addr & 0x0fff) == 0x0018):
                    # TPM_STATUS Reg
                    if self.reg_wr == 1:
                        if (self.reg_tpmgo + self.reg_commandready + self.reg_responseretry) == 1:
                            if self.reg_tpmgo == 1:
                                self.put(ss,self.frame_ep,self.out_ann,[46,['TPMGO','GO']])
                            elif self.reg_commandready == 1:
                                self.put(ss,self.frame_ep,self.out_ann,[47,['COMMAND ABORT','ABORT','AB']])
                            else:
                                self.put(ss,self.frame_ep,self.out_ann,[47,['RESPONSE RETRY','RETRY','RT']])
                        else:
                            self.put(ss,self.frame_ep,self.out_ann,[45,['ERROR : %d%d%d' % (self.reg_tpmgo,self.reg_commandready,self.reg_responseretry)]])
                    else:
                        es = (ss + (frame_reg_byte * 2))
                        if (self.reg_valid != 0x00):
                            if self.reg_data_avail == 1:
                                self.put(ss,es,self.out_ann,[43,['DATA AVAILABLE','DATA','DA']])
                            elif self.reg_expect == 1:
                                self.put(ss,es,self.out_ann,[43,['EXPECT COMMAND','EXPECT','EP']])
                            else:
                                self.put(ss,es,self.out_ann,[43,['NONE','NN']])
                        else:
                            self.put(ss,es,self.out_ann,[45,['INVALID DATA_AVAIL/EXPECT FLAG','IVD AVA/EXP']])

                        ss = es
                        es = (ss + (frame_reg_byte * 1))
                        self.put(ss,es,self.out_ann,[43,['SELFTESTDONE:%d'%self.reg_selftest,'STEST:%d'%self.reg_selftest,
                                                            'ST:%d'%self.reg_selftest]])
                        ss = es
                        es = (ss + (frame_reg_byte * 2))
                        if self.reg_commandready == 1:
                            self.put(ss,es,self.out_ann,[43,['COMMAND READY','READY','RY']])
                        else:
                            self.put(ss,es,self.out_ann,[45,['COMMAND BUSY','BUSY','BZ']])

                        if len(self.frame_reg_bytes) > 1:
                            ss = es
                            es = self.frame_ep
                            self.put(ss,es,self.out_ann,[43,['BURSTCOUNT:%d' % self.reg_burstcnt,
                                                        'BC:%d' % self.reg_burstcnt,'%d' % self.reg_burstcnt]])

                # Frame Command
                if self.cmd == 1:
                    if self.cmd_done == 0:
                        if (self.cmd_expect == 0):
                            self.frame_cmd_ep = self.samplenum
                            self.cmd_done = 2
                            if self.frame_cmd_wr == 1:
                                self.frame_bytes.extend(self.mosibytes[4:])
                            else:
                                self.frame_bytes.extend(self.misobytes[4:])
                            self.frame_cmd_first = 0
                        elif self.frame_cmd_first == 1:
                            if self.frame_cmd_wr == 1:
                                self.frame_bytes.extend(self.mosibytes[4:])
                            else:
                                self.frame_bytes.extend(self.misobytes[4:])
                        else:
                            self.frame_cmd_sp = self.ss_transfer
                            if self.frame_cmd_wr == 1:
                                self.frame_bytes = self.mosibytes[4:]
                            else:
                                self.frame_bytes = self.misobytes[4:]
                            self.frame_cmd_first = 1
                    elif self.cmd_done == 1:
                            self.frame_cmd_sp = self.ss_transfer
                            self.frame_cmd_ep = self.samplenum
                            self.cmd_done = 2
                            if self.frame_cmd_wr == 1:
                                self.frame_bytes = self.mosibytes[4:]
                            else:
                                self.frame_bytes = self.misobytes[4:]

                    if self.cmd_done == 2:
                        frame_total_sample = self.frame_cmd_ep - self.frame_cmd_sp
                        frame_byte = int(frame_total_sample / len(self.frame_bytes))

                        # Frame Tag
                        ss, es = self.frame_cmd_sp, self.frame_cmd_sp + (frame_byte * 2)
                        try:
                            self.put(ss, es, self.out_ann,[38, ['%s' % tag[self.cmd_tag][1],
                                       '%s' % tag[self.cmd_tag][2],'%s' % tag[self.cmd_tag][3]]])
                        except:
                            self.put(ss,es,self.out_ann,[52, ['PROTOCOL ERROR','ERROR','ERR','E']])
                        # Frame Length
                        ss, es = es, self.frame_cmd_sp + (frame_byte * 6)
                        self.put(ss, es, self.out_ann,[39, ['LENGTH:%d' % self.cmd_len,
                                    'LEN:%d' % self.cmd_len,'%d' % self.cmd_len]])
                        # Frame Command/Response
                        ss, es = es, self.frame_cmd_sp + (frame_byte * 10)
                        if self.frame_cmd_wr == 1:
                            if (self.cmd_ord & 0x2000) == 0:
                                # TCG Command
                                try:
                                    self.put(ss,es,self.out_ann,[40,['%s' % cmdcode[self.cmd_ord][1]]])
                                except:
                                    self.put(ss,es,self.out_ann,[52, ['PROTOCOL ERROR','ERROR','ERR','E']])
                            else:
                                # Vendor Specific Command
                                self.put(ss,es,self.out_ann,[40,['VENDOR SPECIFIC CMD : 0x%08X' % self.cmd_ord,
                                                    'VENDOR:0x%08X' % self.cmd_ord,'V:%08X' % self.cmd_ord,'%08X' % self.cmd_ord]])
                        else:
                            self.put(ss,es,self.out_ann,[42,['RC : 0x%08X' % self.cmd_rc]])
                        # Frame rest of data
                        if es != self.frame_cmd_ep:
                            ss, es = es, self.frame_cmd_ep
                            if self.frame_cmd_wr == 1:
                                self.put(ss, es, self.out_ann,[41, [' '.join(format(x.val, '02X') for x in self.frame_bytes[10:])]])
                            else:
                                self.put(ss, es, self.out_ann,[42, [' '.join(format(x.val, '02X') for x in self.frame_bytes[10:])]])


            # Reset decoder state when CS# changes (and the CS# pin is used).
            self.reset_decoder_state()

        # We only care about samples if CS# is asserted.
        if self.have_cs and not self.cs_asserted(cs):
            # Reset when not CS#
            self.bytecount = 0
            self.reg_locality = 0
            self.reg_addr = 0
            self.cmd = 0
            self.cmd_count = 0
            return

        # Ignore sample if the clock pin hasn't changed.
        if first or not self.matched[0]:
            return

        # Found the correct clock edge, now get the SPI bit(s).
        self.handle_bit(miso, mosi, clk, cs)

    def decode(self):
        # The CLK input is mandatory. Other signals are (individually)
        # optional. Yet either MISO or MOSI (or both) must be provided.
        # Tell stacked decoders when we don't have a CS# signal.
        self.have_cs = self.has_channel(3)
        if not self.have_cs:
            self.put(0, 0, self.out_python, ['CS-CHANGE', None, None])

        # We want all CLK changes. We want all CS changes if CS is used.
        # Map 'have_cs' from boolean to an integer index. This simplifies
        # evaluation in other locations.
        wait_cond = [{0: 'r'}]
        if self.have_cs:
            self.have_cs = len(wait_cond)
            wait_cond.append({3: 'e'})

        # "Pixel compatibility" with the v2 implementation. Grab and
        # process the very first sample before checking for edges. The
        # previous implementation did this by seeding old values with
        # None, which led to an immediate "change" in comparison.
        (clk, miso, mosi, cs) = self.wait({})
        self.find_clk_edge(miso, mosi, clk, cs, True)

        while True:
            (clk, miso, mosi, cs) = self.wait(wait_cond)
            self.find_clk_edge(miso, mosi, clk, cs, False)

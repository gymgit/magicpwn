import os
import ConfigParser
os.environ['TERM'] = 'xterm-256color'
from pwn import *
import string
import thread
from random import choice
from time import sleep

class ShitStorm(Exception):
    pass

def dump_static_seccomp(path, graph=False):
    # TODO add support for graph+ fix arch flag+path
    if graph:
        raise ShitStorm("Once this is going to be implemented")
    cmd = "cat %s | %s -a x86_64"%(path, "/home/gym/ctf/tools/libseccomp/tools/scmp_bpf_disasm")
    p = process(cmd, shell=True)
    if p.poll(True) != 0:
        # TODO log this
        sleep(1)
    output = p.recvall()
    return output


def compile_shell(path, constants, debug=False, vma=None):
    """
    path: path of the c source file
    constants: map of defined constant names and their values
    """
    # TODO add options to X compile
    define = ""
    for k, v in constants.iteritems():
        define += " -D%s=%s" % (k, str(v))
    flags = "-s -nostdlib -ffreestanding -fno-stack-protector -fpic -fPIE"
    #elf = tempfile.gettempdir()
    elf = "/tmp/%s" % "".join(choice(string.ascii_letters) for x in range(8))
    cmd = "gcc %s %s %s -o %s" % (define, flags, path, elf)
    ret = os.system(cmd)
    # TODO check return value
    binary = "/tmp/%s" % "".join(choice(string.ascii_letters) for x in range(8))
    cmd = "objcopy -O binary --only-section=.text %s %s"  % (elf, binary)
    ret = os.system(cmd)
    # TODO check return value
    # TODO add debug possibility maybe
    with open(binary, 'r') as sh:
        shell = sh.read()
        if debug:
            # TODO debug why this is not working
            gdb.debug_shellcode(shell, vma=vma)
        return shell


class Magic(object):
    def __init__(self, target, debug, env={}, **kwargs):
        self.c = None
        self.e = None
        self.l = None
        self.log = kwargs.get("logger", log)

        self.__load_cfg(**kwargs)
        self.target = target
        self.debug = debug

        # get the appropriate libc path
        self.__get_libc_path()

        # get the target path
        self.__get_exec_path()

        # Get the arguments
        self.args = kwargs.get("args", [])

        # Setup the pwntools context
        if self.config['word_size'] != 0:
            context(arch=self.config['arch'],
                    os=self.config['os'],
                    endian=self.config['endian'],
                    terminal=self.config['terminal'],
                    aslr=self.config['aslr'],
                    word_size=self.config['word_size'])
        else:
            context(arch=self.config['arch'],
                    os=self.config['os'],
                    endian=self.config['endian'],
                    terminal=self.config['terminal'],
                    aslr=self.config['aslr'])

        # Get the ENV
        if target == "vm":
            self.ssh = ssh(
                    host=self.config['ssh_ip'],
                    port=self.config['ssh_port'],
                    user=self.config['ssh_user'],
                    password=self.config['ssh_pass'])
            envdump = self.ssh.run_to_end("printenv")
            if envdump[1] != 0:
                raise ShitStorm("Could not retrieve VM env")
            self.env = { x.split('=')[0]: x.split('=')[1] for x in envdump[0].rstrip('\n').split('\n') }
        else:
            self.env = os.environ.copy()
            self.ssh = None

        # Setup ENV
        self.env.update(kwargs.get('env', {}))

        # preload libc's
        if self.config['libc'] == "remote":
            if self.target == "vm":
                self.env['LD_PRELOAD'] = self.guest_libc
            else:
                self.env['LD_PRELOAD'] = self.libc_path

        # Add LD_PRELOADS
        for lib in kwargs.get('preloads', []):
            if "LD_PRELOAD" in self.env:
                self.env['LD_PRELOAD'] += ";"+lib
            else:
                self.env['LD_PRELOAD'] = lib
        self.log.debug("ENV: ")
        self.log.debug(self.env)

    def __del__(self):
        if self.debug == "villoc" or self.debug == "gdbv":
            self.finish_viz()

    def start(self, bp = [], disp = [], cmds = [], ida=True, sysroot=True, ccmd=None):
        # TODO fix monkey patched custom CMD
        # SOCK:
        #   native: start service, remote localhost
        #       gdb: start service gdb, remote localhsot source villoc if needed
        #       villoc: start service with ltrace, remote localhost
        #   vm: start service ssh?, remote vm
        #       gdb: start service ssh, remote vm
        #       villoc: start service ssh with ltrace, remote vm
        #   remote: remote
        # IO:
        #   native: start process #process
        #       gdb: debug process
        #       villoc: start with cmd line
        #   vm: start ssh process #self.s.process
        #       gdb: debug with ssh
        #       villoc: ssh process with ltrace
        if self.target == 'remote':
            self.c = remote(self.config['remote_ip'], self.config['remote_port'])
            return self.c

        if self.debug == 'villoc':
            # TODO handle custom command
            cmd = []
            if not self.config['aslr']:
                cmd.append('setarch')
                if self.config['arch'] == 'amd64':
                    cmd.append('x86_64')
                else:
                    cmd.append(self.config['arch'])
                cmd.append('-R')

            if self.target == 'vm':
                cmd.extend(['ltrace', '-o', '/ctf/trace.tmp', self.exec_path] + self.args)
            else:
                cmd.extend(['ltrace', '-o', 'trace.tmp', self.exec_path] + self.args)
        else:
            # FIXME
            if ccmd != None:
                cmd = ccmd
            else:
                cmd = [self.exec_path] + self.args
        self.log.debug("Command Line: %s"%" ".join(cmd))
        if 'gdb' in self.debug:
            script = self.__prepare_gdb_script(bp, disp, cmds, ida, sysroot)
            # TODO debug log script
            self.pipe = gdb.debug(cmd, env=self.env, gdbscript=script, ssh=self.ssh)

            #self.pipe = gdb.debug(cmd, gdbscript=script, ssh=self.ssh)
        elif self.target == 'vm':
            self.pipe = self.ssh.process(cmd, env=self.env)
        else:
            self.pipe = process(cmd, env=self.env)

        if self.config['type'] == 'SOCK':
            if self.target == 'native':
                self.c = remote('localhost', self.config['remote_port'])
            else:
                self.c = remote(self.config['ssh_ip'], self.config['remote_port'])
        else:
            self.c = self.pipe

        return self.c

    def finish_viz(self):
        # Generate villoc viz from trace
        trace = "./trace.tmp"

        # Get trace from the vm
        if self.target == "vm":
            trace = os.path.join(self.config['vm_path'], 'share', "trace.tmp")

        self.log.info("Creating Heap Viz from: " + str(trace))
        # Call villoc
        p = process(['python3', self.config['villoc_path'], trace, 'viz.html'])
        if p.poll(True) != 0:
            self.log.warn(p.recvall())
        self.log.info("Done.")
        # Open the output in browser
        cmd = self.config['browser_cmd'].replace('$path', os.path.join(os.getcwd(), 'viz.html'))
        p = os.system(cmd)

    def load_libc(self):
        # pwntools ELF on libc
        self.l = ELF(self.libc_path)
        return self.l

    def load_elf(self):
        # pwntools ELF on binary
        self.e = ELF(self.config['binary'])
        return self.e

    def find_libc(self, addr):
        # use libc_db to identify libc version (from leaks)
        command = [os.path.join(self.config['libc_db'], "find")]
        command.extend(addr)
        return subprocess.check_output(command, cwd=self.config['libc_db'])

    def start_brute(self, main, thread_count=10, args=None):
        lock = thread.allocate_lock()
        self.log.info("Staring %d threads"%thread_count)
        for i in range(thread_count):
            if args != None:
                arg = args[i]
            else:
                arg = None
            thread.start_new_thread(main, (self, lock, arg, ))
        while True:
            sleep(2)


    def __prepare_gdb_script(self, bp, disp, cmds, ida, sysroot):
        script = []
        # Preload libraries
        if 'LD_PRELOAD' in self.env:
            # Might need additional list (:) with other preloaded libraries
            script.append("set solib-search-path " + os.path.dirname(self.libc_path))
            # TODO set env LD_PRELOAD
        if self.target == "vm" and sysroot:
            # Set the sysroot so libraries won't be downloaded
            script.append("set sysroot " + os.path.join(self.config['vm_path'], self.config['vm_name'], "sysroot"))
            # Same with dbg libraries
            #script.append("set debug-file-directory " + os.path.join(self.config['vm_path'], self.config['vm_name'], "sysroot/usr/lib/debug"))
        if ida:
            # enable the pwndbg ida integration
            script.append("set ida-rpc-host " + self.config['ida_ip'])

        if self.debug == "gdbv":
            # TODO source the gdb villoc thing and start it later
            pass
        for br in bp:
            try:
                script.append("br *"+hex(br))
            except (ValueError, TypeError):
                script.append("br "+br)

            # if isinstance(br (int, long)):
            #     script.append("br *"+hex(br))
            # else:
            #     script.append("br "+br)

        # Display addresses
        script.extend(['display/gx ' + hex(ad) for ad in disp])
        script.extend(cmds)
        script = flat(map(lambda x: x + '\n', script))
        self.log.debug("GDB Script:\n%s"%script)
        return script

    def __get_libc_path(self):
        if self.config['libc'] == "remote":
            self.libc_path = self.config['rlibc']
            if self.target == "vm":
                #self.guest_libc = os.path.join(self.config['vm_path'], "share", os.path.basename(self.config['rlibc']))
                self.guest_libc = os.path.join("/ctf", os.path.basename(self.config['rlibc']))

        elif self.target == "vm":
            self.libc_path = os.path.join(self.config['vm_path'], self.config['vm_name'], "libcs", "libc-"+self.config['arch']+".so")
        else:
            # TODO remote target, vm libc?
            # local libc (this is arch specific)
            self.libc_path = "/usr/lib/libc.so.6"

    def __get_exec_path(self):
        if self.target == 'vm':
            self.exec_path = os.path.join("/ctf", os.path.basename(self.config['binary']))
        else:
            self.exec_path = self.config['binary']

    def __set_default_cfg(self):
        # Load the default configuration
        self.config = {}
        self.config['terminal'] = ""
        self.config['base_path'] = "~/ctf/challs"
        self.config['arch'] = "amd64"
        self.config['binary'] = None
        self.config['libc'] = "vm"
        self.config['aslr'] = False
        self.config['rlibc'] = None
        self.config['remote_ip'] = None
        self.config['remote_port'] = "1337"
        self.config['type'] = "IO"
        self.config['os'] = "linux"
        self.config['endian'] = "little"
        self.config['word_size'] = "0"
        self.config['villoc_path'] = "~/ctf/tools/villoc/villoc.py"
        self.config['vm_path'] = "~/ctf/vagrant"
        self.config['vm_name'] = "xenial64"
        self.config['ssh_ip'] = "192.168.101.10"
        self.config['ssh_port'] = "22"
        self.config['ssh_user'] = "ubuntu"
        self.config['ssh_pass'] = None
        self.config['ida_ip'] = '192.168.101.15'
        self.config['libc_db'] = "~/ctf/tools/libc-database"
        self.config['libseccomp'] = "~/ctf/tools/libseccomp/tools/scmp_bpf_disasm"
        self.config['browser_cmd'] = "chromium $path"


    def __load_cfg(self, **kwargs):
        self.__set_default_cfg()

        # Create config parser
        parser = ConfigParser.RawConfigParser()
        parser.add_section("options")
        # Load the config file if exists
        config_path = os.path.abspath(kwargs.get("config", "./CONFIG"))
        if os.path.isfile(config_path):
            parser.read(config_path)

        # Parse the config args (overwrites config file options)
        for key, value in kwargs.iteritems():
            if key in self.config:
                parser.set("options", key, value)

        # Overwrite default values from parser options
        for item in parser.items("options"):
            self.config[item[0]] = item[1]

        # Fix up paths
        self.config['base_path'] = os.path.expanduser(self.config['base_path'])
        self.config['villoc_path'] = os.path.expanduser(self.config['villoc_path'])
        self.config['vm_path'] = os.path.expanduser(self.config['vm_path'])
        self.config['libc_db'] = os.path.expanduser(self.config['libc_db'])
        self.config['libseccomp'] = os.path.expanduser(self.config['libseccomp'])
        if self.config['binary']:
            self.config['binary'] = os.path.join(self.config['base_path'], self.config['binary'])
        if self.config['rlibc']:
            self.config['rlibc'] = os.path.join(self.config['base_path'], self.config['rlibc'])

        self.config['remote_port'] = int(self.config['remote_port'])
        self.config['word_size'] = int(self.config['word_size'])
        self.config['ssh_port'] = int(self.config['ssh_port'])
        self.config['terminal'] = self.config['terminal'].strip('"\'').split()

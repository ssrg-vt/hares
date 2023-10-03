import argparse
import shutil
import sys
import traceback
import re
import string
import os
import json

from abc import ABC, abstractmethod

from enum import Enum
from typing import List, Optional, Dict

from elftools import __version__
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection, DynamicSegment
from elftools.elf.gnuversions import (
    GNUVerSymSection, GNUVerDefSection,
    GNUVerNeedSection,
    )
from elftools.elf.sections import (
    NoteSection, SymbolTableSection, SymbolTableIndexSection
)
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_rh_flags, describe_sh_type, describe_sh_flags,
    describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
    describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
    describe_dt_flags, describe_dt_flags_1, describe_ver_flags, describe_note,
    describe_attr_tag_arm, describe_symbol_other
    )

from elftools.elf.constants import E_FLAGS
from elftools.elf.constants import E_FLAGS_MASKS
from elftools.elf.constants import SH_FLAGS
from elftools.elf.constants import SHN_INDICES


SCRIPT_DESCRIPTION = 'Modify the contents of ELF format files for popsgx enclave offloading'

# Matcher for all control characters, for transforming them into "^X" form when
# formatting symbol names for display.
_CONTROL_CHAR_RE = re.compile(r'[\x01-\x1f]')

def _format_symbol_name(s):
    return _CONTROL_CHAR_RE.sub(lambda match: '^' + chr(0x40 + ord(match[0])), s)

class Symbol:
    def __init__(self, symbol_name, symbol):
        self.metadata = symbol
        self.name = symbol_name

class ReadElf():
    class Verbosity(Enum):
        DEBUG = 0
        INFO = 1
        ERROR = 2

    def __init__(self, file, output, verbosity=Verbosity.ERROR) -> None:
        """ file:
                stream object with the ELF file to read

            output:
                output stream to write to
        """
        self.elffile = ELFFile(file)
        self.output = output
        self.verbosity = verbosity
        self._versioninfo = None

    def _init_versioninfo(self):
        """ Search and initialize informations about version related sections
            and the kind of versioning used (GNU or Solaris).
        """
        if self._versioninfo is not None:
            return

        self._versioninfo = {'versym': None, 'verdef': None,
                             'verneed': None, 'type': None}

        for section in self.elffile.iter_sections():
            if isinstance(section, GNUVerSymSection):
                self._versioninfo['versym'] = section
            elif isinstance(section, GNUVerDefSection):
                self._versioninfo['verdef'] = section
            elif isinstance(section, GNUVerNeedSection):
                self._versioninfo['verneed'] = section
            elif isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag['d_tag'] == 'DT_VERSYM':
                        self._versioninfo['type'] = 'GNU'
                        break

        if not self._versioninfo['type'] and (
                self._versioninfo['verneed'] or self._versioninfo['verdef']):
            self._versioninfo['type'] = 'Solaris'

    def _get_symbol_shndx(self, symbol, symbol_index, symtab_index):
        """ Get the index into the section header table for the "symbol"
            at "symbol_index" located in the symbol table with section index
            "symtab_index".
        """
        symbol_shndx = symbol['st_shndx']
        if symbol_shndx != SHN_INDICES.SHN_XINDEX:
            return symbol_shndx

        # Check for or lazily construct index section mapping (symbol table
        # index -> corresponding symbol table index section object)
        if self._shndx_sections is None:
            self._shndx_sections = {sec.symboltable: sec for sec in self.elffile.iter_sections()
                                    if isinstance(sec, SymbolTableIndexSection)}
        return self._shndx_sections[symtab_index].get_section_index(symbol_index)


    def _format_hex(self, addr, fieldsize=None, fullhex=False, lead0x=True,
                    alternate=False):
        """ Format an address into a hexadecimal string.

            fieldsize:
                Size of the hexadecimal field (with leading zeros to fit the
                address into. For example with fieldsize=8, the format will
                be %08x
                If None, the minimal required field size will be used.

            fullhex:
                If True, override fieldsize to set it to the maximal size
                needed for the elfclass

            lead0x:
                If True, leading 0x is added

            alternate:
                If True, override lead0x to emulate the alternate
                hexadecimal form specified in format string with the #
                character: only non-zero values are prefixed with 0x.
                This form is used by readelf.
        """
        if alternate:
            if addr == 0:
                lead0x = False
            else:
                lead0x = True
                if fieldsize is not None:
                    fieldsize -= 2

        s = '0x' if lead0x else ''
        if fullhex:
            fieldsize = 8 if self.elffile.elfclass == 32 else 16
        if fieldsize is None:
            field = '%x'
        else:
            field = '%' + '0%sx' % fieldsize
        return s + field % addr

    def _symbol_version(self, nsym):
        """ Return a dict containing information on the
            or None if no version information is available
        """
        self._init_versioninfo()

        symbol_version = dict.fromkeys(('index', 'name', 'filename', 'hidden'))

        if (not self._versioninfo['versym'] or
                nsym >= self._versioninfo['versym'].num_symbols()):
            return None

        symbol = self._versioninfo['versym'].get_symbol(nsym)
        index = symbol.entry['ndx']
        if not index in ('VER_NDX_LOCAL', 'VER_NDX_GLOBAL'):
            index = int(index)

            if self._versioninfo['type'] == 'GNU':
                # In GNU versioning mode, the highest bit is used to
                # store whether the symbol is hidden or not
                if index & 0x8000:
                    index &= ~0x8000
                    symbol_version['hidden'] = True

            if (self._versioninfo['verdef'] and
                    index <= self._versioninfo['verdef'].num_versions()):
                _, verdaux_iter = \
                        self._versioninfo['verdef'].get_version(index)
                symbol_version['name'] = next(verdaux_iter).name
            else:
                verneed, vernaux = \
                        self._versioninfo['verneed'].get_version(index)
                symbol_version['name'] = vernaux.name
                symbol_version['filename'] = verneed.name

        symbol_version['index'] = index
        return symbol_version

    def _emit(self, s=''):
        """ Emit an object to output
        """
        if self.verbosity.value <= ReadElf.Verbosity.INFO.value:
            self.output.write(str(s))

    def _emitline(self, s=''):
        """ Emit an object to output, followed by a newline
        """
        if self.verbosity.value <= ReadElf.Verbosity.INFO.value:
            self.output.write(str(s).rstrip() + '\n')

    def iter_through_symbol_tables(self, filter_func=None) -> List[Dict]:
        """ Display the symbol tables contained in the file
        """
        self._init_versioninfo()

        filtered_symbols = []

        symbol_tables = [(idx, s) for idx, s in enumerate(self.elffile.iter_sections())
                         if isinstance(s, SymbolTableSection)]

        if not symbol_tables and self.elffile.num_sections() == 0:
            self._emitline('')
            self._emitline('Dynamic symbol information is not available for'
                           ' displaying symbols.')

        for section_index, section in symbol_tables:
            if not isinstance(section, SymbolTableSection):
                continue

            if section['sh_entsize'] == 0:
                self._emitline("\nSymbol table '%s' has a sh_entsize of zero!" % (
                    section.name))
                continue

            self._emitline("\nSymbol table '%s' contains %d %s:" % (
                section.name,
                section.num_symbols(),
                'entry' if section.num_symbols() == 1 else 'entries'))

            if self.elffile.elfclass == 32:
                self._emitline('   Num:    Value  Size Type    Bind   Vis      Ndx Name')
            else: # 64
                self._emitline('   Num:    Value          Size Type    Bind   Vis      Ndx Name')

            for nsym, symbol in enumerate(section.iter_symbols()):
                version_info = ''
                # readelf doesn't display version info for Solaris versioning
                if (section['sh_type'] == 'SHT_DYNSYM' and
                        self._versioninfo['type'] == 'GNU'):
                    continue

                symbol_name = symbol.name
                # Print section names for STT_SECTION symbols as readelf does
                if (symbol['st_info']['type'] == 'STT_SECTION'
                    and symbol['st_shndx'] < self.elffile.num_sections()
                    and symbol['st_name'] == 0):
                    symbol_name = self.elffile.get_section(symbol['st_shndx']).name

                # symbol names are truncated to 25 chars, similarly to readelf
                self._emitline('%6d: %s %s %-7s %-6s %-7s %4s %.25s%s' % (
                    nsym,
                    self._format_hex(
                        symbol['st_value'], fullhex=True, lead0x=False),
                    "%5d" % symbol['st_size'] if symbol['st_size'] < 100000 else hex(symbol['st_size']),
                    describe_symbol_type(symbol['st_info']['type']),
                    describe_symbol_bind(symbol['st_info']['bind']),
                    describe_symbol_other(symbol['st_other']),
                    describe_symbol_shndx(self._get_symbol_shndx(symbol,
                                                                 nsym,
                                                                 section_index)),
                    _format_symbol_name(symbol_name),
                    version_info))
                
                
                ##filtering the symbols along with adding the symbol name to the symbol
                msymbol = Symbol(symbol_name, symbol)
                if filter_func is None or filter_func(msymbol):
                    filtered_symbols.append(msymbol)
    
        return filtered_symbols

class ConfigReader:
    def __init__(self, config_file):
        self.config_file = config_file
        self.config = None
        try:
            with open(self.config_file, 'r') as file:
                self.config = json.load(file)
        except FileNotFoundError:
            print(f"Config file '{self.config_file}' not found.")
        except json.JSONDecodeError:
            print(f"Error decoding JSON in config file '{self.config_file}'.")

    def get_breakpoints(self):
        if self.config:
            return self.config.get("breakpoints", [])
        else:
            return []

class PopsgxFilters():
    @staticmethod
    def get_oe_func_symbols(symbol):
        return "oe" in symbol.name and describe_symbol_type(symbol.metadata['st_info']['type']) == 'FUNC'
    
    @staticmethod 
    def get_non_oe_func_symbols(symbol):
        return "oe" not in symbol.name and describe_symbol_type(symbol.metadata['st_info']['type']) == 'FUNC'
    
    @staticmethod
    def get_code_offset_start_symbol(symbol):
        return symbol.name == '_start'

class Clean(ABC):
    x86_NOP_CODE = b'\x90'

    def __init__(self, bin_pyelf, dir_path, config_reader = None):
        self.bin_pyelf = bin_pyelf
        self.dir_path = dir_path
        self.config_reader = config_reader

        offset = -1
        for nsec, section in enumerate(self.bin_pyelf.elffile.iter_sections()):
            if section.name == '.text':
                offset = section['sh_addr'] - section['sh_offset']
                break

        if offset == -1:
            raise Exception(f"Failed due to .text section not found")
        
        self.code_offset = offset

    @abstractmethod
    def find_symbols_to_clean(self):
        pass

    @abstractmethod
    def remove_symbols(self, fd, symbols):
        pass

class SGXClean(Clean):
    def find_symbols_to_clean(self):
        print("SGXClean finding symbols to clean")
        return self.bin_pyelf.iter_through_symbol_tables(PopsgxFilters.get_oe_func_symbols)
    
    def remove_symbols(self, fd, symbols):
        print("SGXClean removing symbols")
        for symbol in symbols:
            if symbol.metadata['st_size'] > 0:
                fd.seek(symbol.metadata['st_value'] - self.code_offset)
                nop_instructions = self.x86_NOP_CODE * symbol.metadata['st_size']
                fd.write(nop_instructions)

class NSGXClean(Clean):
    def __find_non_oe_symbols_within_user_files(self, filename, func_names = None):
        non_oe_symbols_in_object = []
        
        with open(filename, 'rb') as file:
            try:
                pyelf = ReadElf(file, sys.stdout)
                non_oe_symbols_in_object = pyelf.iter_through_symbol_tables(PopsgxFilters.get_non_oe_func_symbols)
                if func_names is not None:
                    non_oe_symbols_in_object = [symbol for symbol in non_oe_symbols_in_object 
                                                if any(func_name in symbol.name for func_name in func_names)]
                return non_oe_symbols_in_object
            except ELFError as ex:
                sys.stdout.flush()
                sys.stderr.write('ELF error: %s\n' % ex)

        return None
    
    def __find_functions_within_user_files(self, filename):
        function_names = []

        with open(filename, 'r') as file:
            source_code = file.read()
            FUNCTION_PATTERN =  r'\b(\w+)\s+(\w+)\s*\([^)]*\)\s*{'

            # Find all function declarations using the regular expression pattern
            function_matches = re.finditer(FUNCTION_PATTERN, source_code)
        
            # Extract and store the function names
            for match in function_matches:
                return_type, function_name = match.groups()
                # Exclude functions with "if" in their names and functions with return types
                if "if" not in function_name and return_type != "if":
                    function_names.append(function_name)
        
        return function_names
            
    def __find_user_files_within_dir(self, dir):
        user_files_source = []
        user_files_objects = []

        for filename in os.listdir(dir):
            # Check if the filename does not contain an underscore (_) and does end with ".o"
            if "_" not in filename and filename.endswith(".c"):
                #print("Found a matching file:", os.path.join(dir, filename))
                user_files_source.append(os.path.join(dir, filename))
            if "_" not in filename and filename.endswith(".o"):
                #print("Found a matching file:", os.path.join(dir, filename))
                user_files_objects.append(os.path.join(dir, filename))
        
        return (user_files_source, user_files_objects)

    def find_symbols_to_clean(self):
        print("NSGXClean finding symbols to clean")
        non_oe_symbols_in_object = []
        non_oe_symbols_in_bin = []
        HOST_DIR = 'App/'
        function_names = []

        user_files_source, user_files_objects = self.__find_user_files_within_dir(self.dir_path + HOST_DIR)

        for filename in user_files_source:
            function_names = self.__find_functions_within_user_files(filename)
            print(function_names)
        
        
        for filename in user_files_objects:
            non_oe_symbols_in_object.extend(self.__find_non_oe_symbols_within_user_files(filename, function_names))
        
        print("Symbols to be deleted are as follows")
        for object in non_oe_symbols_in_object:
            print(object.name)

        non_oe_symbols_in_bin = self.bin_pyelf.iter_through_symbol_tables(PopsgxFilters.get_non_oe_func_symbols)

        ##We need the metadata from the final elf of bin and not from the object files
        return [obj1 for obj1 in non_oe_symbols_in_bin for obj2 in non_oe_symbols_in_object if obj1.name == obj2.name]

    def __store_bytes_from_breakpoints(self, fd):
        data_from_breakpoints = {}
        BREAKPOINT_BYES = 5  # Number of bytes to read

        for breakpoint in self.config_reader.get_breakpoints():
            breakpoint_off = (int(breakpoint, 16) - self.code_offset)
            fd.seek(breakpoint_off)
            data_from_breakpoints[breakpoint_off] = fd.read(BREAKPOINT_BYES)

        return data_from_breakpoints
    
    def remove_symbols(self, fd, symbols):
        print("NSGXClean removing symbols") 
        data_from_breakpoints = self.__store_bytes_from_breakpoints(fd)
        
        for symbol in symbols:
            if symbol.metadata['st_value'] - self.code_offset > 0:
                print(symbol.name)
                fd.seek(symbol.metadata['st_value'] - self.code_offset)
                nop_instructions = self.x86_NOP_CODE * symbol.metadata['st_size']
                fd.write(nop_instructions)

        for offset, value in data_from_breakpoints.items():
            fd.seek(offset)
            fd.write(value)

class PopSGXCleaner(ABC):
    BIN_NAME_TO_APPEND = ""

    @abstractmethod
    def create_cleaner(self, elf):
        pass

    def __init__(self, dir_path, bin_path, config_json = None):
        self.bin = bin_path 
        self.modified_bin = bin_path + self.BIN_NAME_TO_APPEND
        self.config_json_reader = ConfigReader(config_json) if config_json is not None else None

        # Copy the contents of the bin file to the modified file
        if not self.__copy_bin(self.bin, self.modified_bin):
            raise Exception(f"Failed due to file copy error {self.bin} to {self.modified_bin}")

        self.modified_bin_fd = open(self.modified_bin, 'rb+')

        try:
            self.bin_pyelf = ReadElf(self.modified_bin_fd, sys.stdout)
        except ELFError as ex:
            sys.stdout.flush()
            sys.stderr.write('ELF error: %s\n' % ex)
        
        self.cleaner = self.create_cleaner(self.bin_pyelf, dir_path, self.config_json_reader)

    def __copy_bin(self, bin, modified_bin):
        try:
            shutil.copy(bin, modified_bin)
            print(f"File '{bin}' copied to '{modified_bin}' successfully.")
            return True
        except FileNotFoundError:
            print(f"Error: Source file '{bin}' not found.")
        except Exception as e:
            print(f"An error occurred: {e}")
        return False

    def clean_symbols(self):
        symbols_to_clean = self.cleaner.find_symbols_to_clean()
        self.cleaner.remove_symbols(self.modified_bin_fd, symbols_to_clean)

    def __del__(self):
        self.modified_bin_fd.close()
    

class NSGXCleaner(PopSGXCleaner):
    BIN_NAME_TO_APPEND = "_sgx"

    def create_cleaner(self, elf, dir_path, config_reader):
        return NSGXClean(elf, dir_path, config_reader)

class SGXCleaner(PopSGXCleaner):
    BIN_NAME_TO_APPEND = "_nsgx"

    def create_cleaner(self, elf, dir_path, config_reader):
        return SGXClean(elf, dir_path)

def main(stream=None):
    argparser = argparse.ArgumentParser(
            usage='usage: %(prog)s [options] <elf-file>',
            description=SCRIPT_DESCRIPTION,
            add_help=False, # -h is a real option of readelf
            prog='popsgx_cleaner.py')

    argparser.add_argument('--dir', 
            type=str, help='Path to the directory of the application source')
    argparser.add_argument('--file', 
            type=str, help='Binary of the application source to modify')
    argparser.add_argument('--config_json', 
            type=str, help='config json of the popsgx application')
    argparser.add_argument('-H', '--help',
            action='store_true', dest='help',
            help='Display this information')
   
    args = argparser.parse_args()
   
    if args.help or not args.dir or not args.file or not args.config_json:
        argparser.print_help()
        sys.exit(0)

    sgx_cleaner = SGXCleaner(args.dir, args.file)
    nsgx_cleaner = NSGXCleaner(args.dir, args.file, args.config_json)
    
    for cleaner in [sgx_cleaner, nsgx_cleaner]:
        cleaner.clean_symbols()

if __name__ == '__main__':
    main()

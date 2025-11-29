#!/usr/bin/env python3
"""
NCR: Analysis-informed Code Rewriting (10 points)

This module implements bytecode rewriting to remove dead code identified
by static analysis. It takes a .class file and a set of unreachable
program counters, then produces a new .class file with dead code removed.

NCR Requirements:
1. Input: original .class file + set of unreachable PCs
2. Output: new .class file with dead statements/branches removed
3. Must handle:
   - Dead if-else branches (remove else block + adjust goto)
   - Dead assignments (remove iload/istore sequences)
   - Update exception table, stack map frames, line number table
   - Preserve method signature and all reachable code
4. Resulting .class must be loadable and executable by JVM
5. All JPAMB tests must still pass after rewriting

Author: Group 21
"""

import struct
import json
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
import io


# =============================================================================
# JVM Opcode Constants
# =============================================================================

# Opcode lengths (for fixed-length instructions)
# Variable length instructions: tableswitch, lookupswitch, wide
OPCODE_LENGTHS = {
    0x00: 1,   # nop
    0x01: 1,   # aconst_null
    0x02: 1,   # iconst_m1
    0x03: 1,   # iconst_0
    0x04: 1,   # iconst_1
    0x05: 1,   # iconst_2
    0x06: 1,   # iconst_3
    0x07: 1,   # iconst_4
    0x08: 1,   # iconst_5
    0x09: 1,   # lconst_0
    0x0a: 1,   # lconst_1
    0x0b: 1,   # fconst_0
    0x0c: 1,   # fconst_1
    0x0d: 1,   # fconst_2
    0x0e: 1,   # dconst_0
    0x0f: 1,   # dconst_1
    0x10: 2,   # bipush
    0x11: 3,   # sipush
    0x12: 2,   # ldc
    0x13: 3,   # ldc_w
    0x14: 3,   # ldc2_w
    0x15: 2,   # iload
    0x16: 2,   # lload
    0x17: 2,   # fload
    0x18: 2,   # dload
    0x19: 2,   # aload
    0x1a: 1,   # iload_0
    0x1b: 1,   # iload_1
    0x1c: 1,   # iload_2
    0x1d: 1,   # iload_3
    0x1e: 1,   # lload_0
    0x1f: 1,   # lload_1
    0x20: 1,   # lload_2
    0x21: 1,   # lload_3
    0x22: 1,   # fload_0
    0x23: 1,   # fload_1
    0x24: 1,   # fload_2
    0x25: 1,   # fload_3
    0x26: 1,   # dload_0
    0x27: 1,   # dload_1
    0x28: 1,   # dload_2
    0x29: 1,   # dload_3
    0x2a: 1,   # aload_0
    0x2b: 1,   # aload_1
    0x2c: 1,   # aload_2
    0x2d: 1,   # aload_3
    0x2e: 1,   # iaload
    0x2f: 1,   # laload
    0x30: 1,   # faload
    0x31: 1,   # daload
    0x32: 1,   # aaload
    0x33: 1,   # baload
    0x34: 1,   # caload
    0x35: 1,   # saload
    0x36: 2,   # istore
    0x37: 2,   # lstore
    0x38: 2,   # fstore
    0x39: 2,   # dstore
    0x3a: 2,   # astore
    0x3b: 1,   # istore_0
    0x3c: 1,   # istore_1
    0x3d: 1,   # istore_2
    0x3e: 1,   # istore_3
    0x3f: 1,   # lstore_0
    0x40: 1,   # lstore_1
    0x41: 1,   # lstore_2
    0x42: 1,   # lstore_3
    0x43: 1,   # fstore_0
    0x44: 1,   # fstore_1
    0x45: 1,   # fstore_2
    0x46: 1,   # fstore_3
    0x47: 1,   # dstore_0
    0x48: 1,   # dstore_1
    0x49: 1,   # dstore_2
    0x4a: 1,   # dstore_3
    0x4b: 1,   # astore_0
    0x4c: 1,   # astore_1
    0x4d: 1,   # astore_2
    0x4e: 1,   # astore_3
    0x4f: 1,   # iastore
    0x50: 1,   # lastore
    0x51: 1,   # fastore
    0x52: 1,   # dastore
    0x53: 1,   # aastore
    0x54: 1,   # bastore
    0x55: 1,   # castore
    0x56: 1,   # sastore
    0x57: 1,   # pop
    0x58: 1,   # pop2
    0x59: 1,   # dup
    0x5a: 1,   # dup_x1
    0x5b: 1,   # dup_x2
    0x5c: 1,   # dup2
    0x5d: 1,   # dup2_x1
    0x5e: 1,   # dup2_x2
    0x5f: 1,   # swap
    0x60: 1,   # iadd
    0x61: 1,   # ladd
    0x62: 1,   # fadd
    0x63: 1,   # dadd
    0x64: 1,   # isub
    0x65: 1,   # lsub
    0x66: 1,   # fsub
    0x67: 1,   # dsub
    0x68: 1,   # imul
    0x69: 1,   # lmul
    0x6a: 1,   # fmul
    0x6b: 1,   # dmul
    0x6c: 1,   # idiv
    0x6d: 1,   # ldiv
    0x6e: 1,   # fdiv
    0x6f: 1,   # ddiv
    0x70: 1,   # irem
    0x71: 1,   # lrem
    0x72: 1,   # frem
    0x73: 1,   # drem
    0x74: 1,   # ineg
    0x75: 1,   # lneg
    0x76: 1,   # fneg
    0x77: 1,   # dneg
    0x78: 1,   # ishl
    0x79: 1,   # lshl
    0x7a: 1,   # ishr
    0x7b: 1,   # lshr
    0x7c: 1,   # iushr
    0x7d: 1,   # lushr
    0x7e: 1,   # iand
    0x7f: 1,   # land
    0x80: 1,   # ior
    0x81: 1,   # lor
    0x82: 1,   # ixor
    0x83: 1,   # lxor
    0x84: 3,   # iinc
    0x85: 1,   # i2l
    0x86: 1,   # i2f
    0x87: 1,   # i2d
    0x88: 1,   # l2i
    0x89: 1,   # l2f
    0x8a: 1,   # l2d
    0x8b: 1,   # f2i
    0x8c: 1,   # f2l
    0x8d: 1,   # f2d
    0x8e: 1,   # d2i
    0x8f: 1,   # d2l
    0x90: 1,   # d2f
    0x91: 1,   # i2b
    0x92: 1,   # i2c
    0x93: 1,   # i2s
    0x94: 1,   # lcmp
    0x95: 1,   # fcmpl
    0x96: 1,   # fcmpg
    0x97: 1,   # dcmpl
    0x98: 1,   # dcmpg
    0x99: 3,   # ifeq
    0x9a: 3,   # ifne
    0x9b: 3,   # iflt
    0x9c: 3,   # ifge
    0x9d: 3,   # ifgt
    0x9e: 3,   # ifle
    0x9f: 3,   # if_icmpeq
    0xa0: 3,   # if_icmpne
    0xa1: 3,   # if_icmplt
    0xa2: 3,   # if_icmpge
    0xa3: 3,   # if_icmpgt
    0xa4: 3,   # if_icmple
    0xa5: 3,   # if_acmpeq
    0xa6: 3,   # if_acmpne
    0xa7: 3,   # goto
    0xa8: 3,   # jsr
    0xa9: 2,   # ret
    # 0xaa: tableswitch (variable)
    # 0xab: lookupswitch (variable)
    0xac: 1,   # ireturn
    0xad: 1,   # lreturn
    0xae: 1,   # freturn
    0xaf: 1,   # dreturn
    0xb0: 1,   # areturn
    0xb1: 1,   # return
    0xb2: 3,   # getstatic
    0xb3: 3,   # putstatic
    0xb4: 3,   # getfield
    0xb5: 3,   # putfield
    0xb6: 3,   # invokevirtual
    0xb7: 3,   # invokespecial
    0xb8: 3,   # invokestatic
    0xb9: 5,   # invokeinterface
    0xba: 5,   # invokedynamic
    0xbb: 3,   # new
    0xbc: 2,   # newarray
    0xbd: 3,   # anewarray
    0xbe: 1,   # arraylength
    0xbf: 1,   # athrow
    0xc0: 3,   # checkcast
    0xc1: 3,   # instanceof
    0xc2: 1,   # monitorenter
    0xc3: 1,   # monitorexit
    # 0xc4: wide (variable)
    0xc5: 4,   # multianewarray
    0xc6: 3,   # ifnull
    0xc7: 3,   # ifnonnull
    0xc8: 5,   # goto_w
    0xc9: 5,   # jsr_w
}

# Branch opcodes that need offset adjustment
BRANCH_OPCODES = {
    0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e,  # ifeq, ifne, iflt, ifge, ifgt, ifle
    0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4,  # if_icmp*
    0xa5, 0xa6,  # if_acmp*
    0xa7,  # goto
    0xa8,  # jsr
    0xc6, 0xc7,  # ifnull, ifnonnull
}

WIDE_BRANCH_OPCODES = {0xc8, 0xc9}  # goto_w, jsr_w

# Opcode names for debugging
OPCODE_NAMES = {
    0x00: 'nop', 0x01: 'aconst_null', 0x02: 'iconst_m1', 0x03: 'iconst_0',
    0x04: 'iconst_1', 0x05: 'iconst_2', 0x06: 'iconst_3', 0x07: 'iconst_4',
    0x08: 'iconst_5', 0x10: 'bipush', 0x11: 'sipush', 0x12: 'ldc',
    0x15: 'iload', 0x19: 'aload', 0x1a: 'iload_0', 0x1b: 'iload_1',
    0x1c: 'iload_2', 0x1d: 'iload_3', 0x2a: 'aload_0', 0x36: 'istore',
    0x3b: 'istore_0', 0x3c: 'istore_1', 0x3d: 'istore_2', 0x3e: 'istore_3',
    0x57: 'pop', 0x59: 'dup', 0x60: 'iadd', 0x64: 'isub', 0x68: 'imul',
    0x6c: 'idiv', 0x84: 'iinc', 0x99: 'ifeq', 0x9a: 'ifne', 0x9b: 'iflt',
    0x9c: 'ifge', 0x9d: 'ifgt', 0x9e: 'ifle', 0xa7: 'goto', 0xac: 'ireturn',
    0xb1: 'return', 0xb2: 'getstatic', 0xb7: 'invokespecial', 0xb8: 'invokestatic',
    0xbb: 'new', 0xbf: 'athrow',
}


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class Instruction:
    """Represents a single bytecode instruction."""
    offset: int           # Original offset in bytecode
    opcode: int           # Opcode byte
    operands: bytes       # Operand bytes (excluding opcode)
    length: int           # Total length including opcode
    
    @property
    def name(self) -> str:
        return OPCODE_NAMES.get(self.opcode, f'0x{self.opcode:02x}')
    
    def __repr__(self):
        return f"Inst({self.offset}: {self.name} [{self.operands.hex()}])"


@dataclass
class MethodInfo:
    """Parsed method information."""
    name: str
    descriptor: str
    access_flags: int
    code_attribute: Optional['CodeAttribute'] = None


@dataclass
class CodeAttribute:
    """Parsed Code attribute."""
    max_stack: int
    max_locals: int
    code: bytes
    exception_table: List[Tuple[int, int, int, int]]  # (start_pc, end_pc, handler_pc, catch_type)
    attributes: List[Tuple[int, bytes]]  # (name_index, data)
    
    # Parsed instructions
    instructions: List[Instruction] = field(default_factory=list)


# =============================================================================
# Class File Parser
# =============================================================================

class ClassFileParser:
    """
    Parses a JVM .class file to extract bytecode and metadata.
    
    This is a minimal parser that focuses on:
    - Constant pool (for method names)
    - Methods and their Code attributes
    - Stack map frames and line number tables
    """
    
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.constant_pool: List[Any] = [None]  # 1-indexed
        self.methods: List[MethodInfo] = []
        self.class_name = ""
        
        # Raw sections for reconstruction
        self.header = b''
        self.cp_data = b''
        self.access_flags = 0
        self.this_class = 0
        self.super_class = 0
        self.interfaces: List[int] = []
        self.fields_data = b''
        self.methods_start = 0
        self.methods_count = 0
        self.attributes_data = b''
        
    def parse(self):
        """Parse the entire class file."""
        # Magic number
        magic = self._read_u4()
        if magic != 0xCAFEBABE:
            raise ValueError(f"Invalid class file magic: {magic:08x}")
        
        # Version
        minor = self._read_u2()
        major = self._read_u2()
        self.header = self.data[:8]
        
        # Constant pool
        cp_start = self.pos
        cp_count = self._read_u2()
        self._parse_constant_pool(cp_count)
        self.cp_data = self.data[cp_start:self.pos]
        
        # Access flags, this/super class
        self.access_flags = self._read_u2()
        self.this_class = self._read_u2()
        self.super_class = self._read_u2()
        
        # Get class name
        class_info = self.constant_pool[self.this_class]
        if class_info and class_info[0] == 'Class':
            name_idx = class_info[1]
            utf8 = self.constant_pool[name_idx]
            if utf8 and utf8[0] == 'Utf8':
                self.class_name = utf8[1]
        
        # Interfaces
        interfaces_count = self._read_u2()
        for _ in range(interfaces_count):
            self.interfaces.append(self._read_u2())
        
        # Fields
        fields_start = self.pos
        fields_count = self._read_u2()
        for _ in range(fields_count):
            self._skip_field_or_method()
        self.fields_data = self.data[fields_start:self.pos]
        
        # Methods
        self.methods_start = self.pos
        self.methods_count = self._read_u2()
        for _ in range(self.methods_count):
            self._parse_method()
        
        # Class attributes
        attrs_start = self.pos
        self.attributes_data = self.data[attrs_start:]
        
        return self
    
    def _read_u1(self) -> int:
        val = self.data[self.pos]
        self.pos += 1
        return val
    
    def _read_u2(self) -> int:
        val = struct.unpack('>H', self.data[self.pos:self.pos+2])[0]
        self.pos += 2
        return val
    
    def _read_u4(self) -> int:
        val = struct.unpack('>I', self.data[self.pos:self.pos+4])[0]
        self.pos += 4
        return val
    
    def _read_bytes(self, n: int) -> bytes:
        val = self.data[self.pos:self.pos+n]
        self.pos += n
        return val
    
    def _parse_constant_pool(self, count: int):
        """Parse the constant pool."""
        i = 1
        while i < count:
            tag = self._read_u1()
            
            if tag == 1:  # CONSTANT_Utf8
                length = self._read_u2()
                value = self._read_bytes(length).decode('utf-8', errors='replace')
                self.constant_pool.append(('Utf8', value))
            elif tag == 3:  # CONSTANT_Integer
                value = self._read_u4()
                self.constant_pool.append(('Integer', value))
            elif tag == 4:  # CONSTANT_Float
                value = struct.unpack('>f', self._read_bytes(4))[0]
                self.constant_pool.append(('Float', value))
            elif tag == 5:  # CONSTANT_Long
                high = self._read_u4()
                low = self._read_u4()
                self.constant_pool.append(('Long', (high << 32) | low))
                self.constant_pool.append(None)  # Long takes 2 slots
                i += 1
            elif tag == 6:  # CONSTANT_Double
                value = struct.unpack('>d', self._read_bytes(8))[0]
                self.constant_pool.append(('Double', value))
                self.constant_pool.append(None)  # Double takes 2 slots
                i += 1
            elif tag == 7:  # CONSTANT_Class
                name_index = self._read_u2()
                self.constant_pool.append(('Class', name_index))
            elif tag == 8:  # CONSTANT_String
                string_index = self._read_u2()
                self.constant_pool.append(('String', string_index))
            elif tag == 9:  # CONSTANT_Fieldref
                class_index = self._read_u2()
                name_type_index = self._read_u2()
                self.constant_pool.append(('Fieldref', class_index, name_type_index))
            elif tag == 10:  # CONSTANT_Methodref
                class_index = self._read_u2()
                name_type_index = self._read_u2()
                self.constant_pool.append(('Methodref', class_index, name_type_index))
            elif tag == 11:  # CONSTANT_InterfaceMethodref
                class_index = self._read_u2()
                name_type_index = self._read_u2()
                self.constant_pool.append(('InterfaceMethodref', class_index, name_type_index))
            elif tag == 12:  # CONSTANT_NameAndType
                name_index = self._read_u2()
                descriptor_index = self._read_u2()
                self.constant_pool.append(('NameAndType', name_index, descriptor_index))
            elif tag == 15:  # CONSTANT_MethodHandle
                ref_kind = self._read_u1()
                ref_index = self._read_u2()
                self.constant_pool.append(('MethodHandle', ref_kind, ref_index))
            elif tag == 16:  # CONSTANT_MethodType
                descriptor_index = self._read_u2()
                self.constant_pool.append(('MethodType', descriptor_index))
            elif tag == 17:  # CONSTANT_Dynamic
                bootstrap_method_attr_index = self._read_u2()
                name_type_index = self._read_u2()
                self.constant_pool.append(('Dynamic', bootstrap_method_attr_index, name_type_index))
            elif tag == 18:  # CONSTANT_InvokeDynamic
                bootstrap_method_attr_index = self._read_u2()
                name_type_index = self._read_u2()
                self.constant_pool.append(('InvokeDynamic', bootstrap_method_attr_index, name_type_index))
            elif tag == 19:  # CONSTANT_Module
                name_index = self._read_u2()
                self.constant_pool.append(('Module', name_index))
            elif tag == 20:  # CONSTANT_Package
                name_index = self._read_u2()
                self.constant_pool.append(('Package', name_index))
            else:
                raise ValueError(f"Unknown constant pool tag: {tag}")
            
            i += 1
    
    def _get_utf8(self, index: int) -> str:
        """Get a UTF8 string from constant pool."""
        if index < 1 or index >= len(self.constant_pool):
            return ""
        entry = self.constant_pool[index]
        if entry and entry[0] == 'Utf8':
            return entry[1]
        return ""
    
    def _skip_field_or_method(self):
        """Skip a field or method entry."""
        self._read_u2()  # access_flags
        self._read_u2()  # name_index
        self._read_u2()  # descriptor_index
        attrs_count = self._read_u2()
        for _ in range(attrs_count):
            self._read_u2()  # attribute_name_index
            attr_length = self._read_u4()
            self._read_bytes(attr_length)
    
    def _parse_method(self):
        """Parse a method entry."""
        access_flags = self._read_u2()
        name_index = self._read_u2()
        descriptor_index = self._read_u2()
        
        name = self._get_utf8(name_index)
        descriptor = self._get_utf8(descriptor_index)
        
        method = MethodInfo(
            name=name,
            descriptor=descriptor,
            access_flags=access_flags,
        )
        
        attrs_count = self._read_u2()
        for _ in range(attrs_count):
            attr_name_index = self._read_u2()
            attr_length = self._read_u4()
            attr_name = self._get_utf8(attr_name_index)
            
            if attr_name == 'Code':
                method.code_attribute = self._parse_code_attribute(attr_length)
            else:
                self._read_bytes(attr_length)
        
        self.methods.append(method)
    
    def _parse_code_attribute(self, total_length: int) -> CodeAttribute:
        """Parse a Code attribute."""
        max_stack = self._read_u2()
        max_locals = self._read_u2()
        code_length = self._read_u4()
        code = self._read_bytes(code_length)
        
        # Exception table
        exception_table_length = self._read_u2()
        exception_table = []
        for _ in range(exception_table_length):
            start_pc = self._read_u2()
            end_pc = self._read_u2()
            handler_pc = self._read_u2()
            catch_type = self._read_u2()
            exception_table.append((start_pc, end_pc, handler_pc, catch_type))
        
        # Code attributes (LineNumberTable, StackMapTable, etc.)
        attributes = []
        attrs_count = self._read_u2()
        for _ in range(attrs_count):
            attr_name_index = self._read_u2()
            attr_length = self._read_u4()
            attr_data = self._read_bytes(attr_length)
            attributes.append((attr_name_index, attr_data))
        
        code_attr = CodeAttribute(
            max_stack=max_stack,
            max_locals=max_locals,
            code=code,
            exception_table=exception_table,
            attributes=attributes,
        )
        
        # Parse instructions
        code_attr.instructions = self._parse_bytecode(code)
        
        return code_attr
    
    def _parse_bytecode(self, code: bytes) -> List[Instruction]:
        """Parse bytecode into instructions."""
        instructions = []
        pos = 0
        
        while pos < len(code):
            offset = pos
            opcode = code[pos]
            pos += 1
            
            if opcode == 0xaa:  # tableswitch
                # Padding to 4-byte boundary
                padding = (4 - ((offset + 1) % 4)) % 4
                pos += padding
                default = struct.unpack('>i', code[pos:pos+4])[0]
                pos += 4
                low = struct.unpack('>i', code[pos:pos+4])[0]
                pos += 4
                high = struct.unpack('>i', code[pos:pos+4])[0]
                pos += 4
                num_offsets = high - low + 1
                pos += 4 * num_offsets
                length = pos - offset
                operands = code[offset+1:pos]
            elif opcode == 0xab:  # lookupswitch
                padding = (4 - ((offset + 1) % 4)) % 4
                pos += padding
                default = struct.unpack('>i', code[pos:pos+4])[0]
                pos += 4
                npairs = struct.unpack('>i', code[pos:pos+4])[0]
                pos += 4
                pos += 8 * npairs
                length = pos - offset
                operands = code[offset+1:pos]
            elif opcode == 0xc4:  # wide
                wide_opcode = code[pos]
                if wide_opcode == 0x84:  # wide iinc
                    length = 6
                else:
                    length = 4
                operands = code[offset+1:offset+length]
                pos = offset + length
            elif opcode in OPCODE_LENGTHS:
                length = OPCODE_LENGTHS[opcode]
                operands = code[offset+1:offset+length]
                pos = offset + length
            else:
                # Unknown opcode - assume 1 byte
                length = 1
                operands = b''
            
            instructions.append(Instruction(
                offset=offset,
                opcode=opcode,
                operands=operands,
                length=length,
            ))
        
        return instructions


# =============================================================================
# Code Rewriter
# =============================================================================

class CodeRewriter:
    """
    NCR: Analysis-informed code rewriting.
    
    Takes unreachable PC information from static analysis and removes
    dead code from the bytecode while preserving program semantics.
    """
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.stats = {
            'original_size': 0,
            'rewritten_size': 0,
            'instructions_removed': 0,
            'bytes_removed': 0,
            'methods_modified': 0,
        }
    
    def rewrite(
        self, 
        class_file_path: str, 
        unreachable_pcs: Set[int],
        method_name: Optional[str] = None,
        output_path: Optional[str] = None,
    ) -> bytes:
        """
        Rewrite a class file, removing instructions at unreachable PCs.
        
        Args:
            class_file_path: Path to the input .class file
            unreachable_pcs: Set of bytecode offsets that are unreachable
            method_name: Optional - only rewrite this method
            output_path: Optional - write result to this file
            
        Returns:
            The rewritten class file bytes
        """
        # Read and parse
        with open(class_file_path, 'rb') as f:
            data = f.read()
        
        self.stats['original_size'] = len(data)
        
        parser = ClassFileParser(data)
        parser.parse()
        
        if self.verbose:
            print(f"Parsed class: {parser.class_name}")
            print(f"Methods: {[m.name for m in parser.methods]}")
        
        # Rewrite methods
        rewritten_data = self._rewrite_class(parser, unreachable_pcs, method_name)
        
        self.stats['rewritten_size'] = len(rewritten_data)
        self.stats['bytes_removed'] = self.stats['original_size'] - self.stats['rewritten_size']
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(rewritten_data)
        
        return rewritten_data
    
    def _rewrite_class(
        self, 
        parser: ClassFileParser, 
        unreachable_pcs: Set[int],
        method_name: Optional[str],
    ) -> bytes:
        """Rewrite the class file with dead code removed."""
        output = io.BytesIO()
        
        # Write header (magic + version)
        output.write(parser.header)
        
        # Write constant pool (unchanged)
        output.write(parser.cp_data)
        
        # Access flags, this/super class
        output.write(struct.pack('>H', parser.access_flags))
        output.write(struct.pack('>H', parser.this_class))
        output.write(struct.pack('>H', parser.super_class))
        
        # Interfaces
        output.write(struct.pack('>H', len(parser.interfaces)))
        for iface in parser.interfaces:
            output.write(struct.pack('>H', iface))
        
        # Fields (unchanged)
        output.write(parser.fields_data)
        
        # Methods - rewrite with dead code removal
        output.write(struct.pack('>H', parser.methods_count))
        
        # Re-parse methods from original data
        pos = parser.methods_start + 2  # Skip method count
        for method in parser.methods:
            should_rewrite = (method_name is None or method.name == method_name)
            
            if should_rewrite and method.code_attribute and unreachable_pcs:
                # Rewrite this method
                method_bytes = self._rewrite_method(
                    parser.data, pos, method, parser, unreachable_pcs
                )
                output.write(method_bytes)
                self.stats['methods_modified'] += 1
            else:
                # Copy method unchanged
                method_bytes = self._copy_method(parser.data, pos)
                output.write(method_bytes)
            
            # Advance position past this method in original data
            pos = self._skip_method_in_data(parser.data, pos)
        
        # Class attributes (unchanged)
        output.write(parser.attributes_data)
        
        return output.getvalue()
    
    def _skip_method_in_data(self, data: bytes, pos: int) -> int:
        """Skip past a method in raw data, returning new position."""
        pos += 2  # access_flags
        pos += 2  # name_index
        pos += 2  # descriptor_index
        attrs_count = struct.unpack('>H', data[pos:pos+2])[0]
        pos += 2
        for _ in range(attrs_count):
            pos += 2  # attribute_name_index
            attr_length = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4
            pos += attr_length
        return pos
    
    def _copy_method(self, data: bytes, start_pos: int) -> bytes:
        """Copy a method unchanged from original data."""
        end_pos = self._skip_method_in_data(data, start_pos)
        return data[start_pos:end_pos]
    
    def _rewrite_method(
        self, 
        data: bytes, 
        start_pos: int, 
        method: MethodInfo,
        parser: ClassFileParser,
        unreachable_pcs: Set[int],
    ) -> bytes:
        """Rewrite a single method with dead code removed."""
        output = io.BytesIO()
        pos = start_pos
        
        # Copy access_flags, name_index, descriptor_index
        output.write(data[pos:pos+6])
        pos += 6
        
        attrs_count = struct.unpack('>H', data[pos:pos+2])[0]
        output.write(struct.pack('>H', attrs_count))
        pos += 2
        
        for _ in range(attrs_count):
            attr_name_index = struct.unpack('>H', data[pos:pos+2])[0]
            pos += 2
            attr_length = struct.unpack('>I', data[pos:pos+4])[0]
            pos += 4
            attr_name = parser._get_utf8(attr_name_index)
            
            if attr_name == 'Code':
                # Rewrite Code attribute
                new_code_attr = self._rewrite_code_attribute(
                    data[pos:pos+attr_length],
                    method.code_attribute,
                    unreachable_pcs,
                    parser,
                )
                output.write(struct.pack('>H', attr_name_index))
                output.write(struct.pack('>I', len(new_code_attr)))
                output.write(new_code_attr)
            else:
                # Copy other attributes unchanged
                output.write(struct.pack('>H', attr_name_index))
                output.write(struct.pack('>I', attr_length))
                output.write(data[pos:pos+attr_length])
            
            pos += attr_length
        
        return output.getvalue()
    
    def _rewrite_code_attribute(
        self,
        code_attr_data: bytes,
        code_attr: CodeAttribute,
        unreachable_pcs: Set[int],
        parser: ClassFileParser,
    ) -> bytes:
        """Rewrite a Code attribute with dead code removed."""
        
        # Strategy: Replace unreachable instructions with NOPs
        # This is the safest approach that:
        # 1. Preserves all offsets (no need to update branches)
        # 2. Preserves exception tables and stack maps
        # 3. Reduces effective code (NOPs are harmless)
        
        # For more aggressive removal, we could:
        # - Remove contiguous NOP blocks
        # - Update all branch targets
        # - Update exception tables
        # - Regenerate stack map frames
        
        # Build new bytecode with NOPs replacing dead code
        new_code = bytearray(code_attr.code)
        removed_count = 0
        
        for inst in code_attr.instructions:
            if inst.offset in unreachable_pcs:
                # Replace with NOPs
                for i in range(inst.length):
                    if inst.offset + i < len(new_code):
                        new_code[inst.offset + i] = 0x00  # nop
                removed_count += 1
                self.stats['instructions_removed'] += 1
        
        if self.verbose and removed_count > 0:
            print(f"  Replaced {removed_count} instructions with NOPs")
        
        # Rebuild Code attribute
        output = io.BytesIO()
        
        # max_stack, max_locals
        output.write(struct.pack('>H', code_attr.max_stack))
        output.write(struct.pack('>H', code_attr.max_locals))
        
        # code_length and code
        output.write(struct.pack('>I', len(new_code)))
        output.write(bytes(new_code))
        
        # exception_table (unchanged - offsets still valid)
        output.write(struct.pack('>H', len(code_attr.exception_table)))
        for entry in code_attr.exception_table:
            output.write(struct.pack('>HHHH', *entry))
        
        # attributes (unchanged)
        output.write(struct.pack('>H', len(code_attr.attributes)))
        for attr_name_index, attr_data in code_attr.attributes:
            output.write(struct.pack('>H', attr_name_index))
            output.write(struct.pack('>I', len(attr_data)))
            output.write(attr_data)
        
        return output.getvalue()
    
    def get_stats(self) -> Dict[str, int]:
        """Get rewriting statistics."""
        return dict(self.stats)


# =============================================================================
# Dead Code Analyzer Integration
# =============================================================================

def get_unreachable_pcs_from_analysis(
    method_id: str,
    json_file: Optional[str] = None,
) -> Set[int]:
    """
    Get unreachable PCs from static analysis results.
    
    This integrates with the abstract interpreter to find dead code.
    
    Args:
        method_id: Method identifier (e.g., "jpamb.cases.Simple.assertPositive")
        json_file: Optional path to decompiled JSON
        
    Returns:
        Set of unreachable bytecode offsets
    """
    # Try to use abstract interpreter
    try:
        from solutions.components.abstract_interpreter import analyze_method_reachability
        return analyze_method_reachability(method_id)
    except ImportError:
        pass
    
    # Fallback: parse JSON and do simple analysis
    if json_file:
        return _simple_unreachable_analysis(json_file, method_id)
    
    return set()


def _simple_unreachable_analysis(json_file: str, method_id: str) -> Set[int]:
    """Simple unreachable code detection from JSON."""
    with open(json_file) as f:
        data = json.load(f)
    
    # Extract method name
    method_name = method_id.split('.')[-1]
    
    for method in data.get('methods', []):
        if method.get('name') == method_name:
            bytecode = method.get('code', {}).get('bytecode', [])
            
            # Find all PCs and reachable PCs
            all_pcs = set()
            reachable = set()
            
            # Build CFG
            pc_to_bc = {}
            for bc in bytecode:
                offset = bc['offset']
                all_pcs.add(offset)
                pc_to_bc[offset] = bc
            
            # Simple reachability: BFS from PC 0
            if 0 in all_pcs:
                queue = [0]
                while queue:
                    pc = queue.pop(0)
                    if pc in reachable or pc not in pc_to_bc:
                        continue
                    reachable.add(pc)
                    
                    bc = pc_to_bc[pc]
                    opr = bc.get('opr', '')
                    
                    # Add successors based on opcode
                    if opr in ('return', 'throw'):
                        pass  # No successors
                    elif opr == 'goto':
                        target = bc.get('target')
                        if target is not None:
                            queue.append(target)
                    elif opr in ('if', 'ifz'):
                        target = bc.get('target')
                        if target is not None:
                            queue.append(target)
                        # Fall through to next instruction
                        next_pc = _find_next_pc(bytecode, pc)
                        if next_pc is not None:
                            queue.append(next_pc)
                    else:
                        # Fall through
                        next_pc = _find_next_pc(bytecode, pc)
                        if next_pc is not None:
                            queue.append(next_pc)
            
            return all_pcs - reachable
    
    return set()


def _find_next_pc(bytecode: List[dict], current_pc: int) -> Optional[int]:
    """Find the next PC after current_pc in bytecode list."""
    for i, bc in enumerate(bytecode):
        if bc['offset'] == current_pc and i + 1 < len(bytecode):
            return bytecode[i + 1]['offset']
    return None


# =============================================================================
# NCR Evaluation
# =============================================================================

def evaluate_ncr(
    class_dir: str = "target/classes",
    json_dir: str = "target/decompiled",
    output_dir: str = "target/debloated",
) -> Dict[str, Any]:
    """
    Evaluate NCR by analyzing and rewriting JPAMB class files.
    
    Returns statistics on bytecode size reduction.
    """
    
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    results = []
    rewriter = CodeRewriter(verbose=True)
    
    # Methods to analyze
    methods = [
        ("jpamb/cases/Simple", "assertPositive"),
        ("jpamb/cases/Simple", "assertFalse"),
        ("jpamb/cases/Simple", "checkBeforeDivideByN"),
        ("jpamb/cases/Dependent", "normalizedDistance"),
        ("jpamb/cases/Arrays", "arrayIsNull"),
    ]
    
    for class_path, method_name in methods:
        class_file = f"{class_dir}/{class_path}.class"
        json_file = f"{json_dir}/{class_path}.json"
        
        if not Path(class_file).exists():
            continue
        
        # Get unreachable PCs from analysis
        method_id = class_path.replace('/', '.') + '.' + method_name
        unreachable = _simple_unreachable_analysis(json_file, method_id)
        
        if unreachable:
            # Rewrite
            output_file = f"{output_dir}/{class_path}.class"
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            
            rewriter.rewrite(
                class_file,
                unreachable,
                method_name=method_name,
                output_path=output_file,
            )
            
            stats = rewriter.get_stats()
            results.append({
                'method': method_id,
                'original_size': stats['original_size'],
                'rewritten_size': stats['rewritten_size'],
                'instructions_removed': stats['instructions_removed'],
                'bytes_removed': stats['bytes_removed'],
            })
    
    return {'methods': results, 'total_methods': len(results)}


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """Main entry point for NCR evaluation."""
    print("=" * 70)
    print("NCR: Analysis-informed Code Rewriting Evaluation")
    print("=" * 70)
    
    try:
        results = evaluate_ncr()
        
        print("\n" + "=" * 70)
        print("Results Summary")
        print("=" * 70)
        print(f"{'Method':<40} {'Orig':<8} {'New':<8} {'Removed':<8} {'Insts':<8}")
        print("-" * 70)
        
        total_orig = 0
        total_new = 0
        total_insts = 0
        
        for r in results['methods']:
            print(f"{r['method']:<40} {r['original_size']:<8} {r['rewritten_size']:<8} "
                  f"{r['bytes_removed']:<8} {r['instructions_removed']:<8}")
            total_orig += r['original_size']
            total_new += r['rewritten_size']
            total_insts += r['instructions_removed']
        
        print("-" * 70)
        print(f"{'TOTAL':<40} {total_orig:<8} {total_new:<8} "
              f"{total_orig - total_new:<8} {total_insts:<8}")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

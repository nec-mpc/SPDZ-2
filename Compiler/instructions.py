# Confidential:
# (C) 2017 University of Bristol. See License.txt

""" This module is for classes of actual assembly instructions.

All base classes, utility functions etc. should go in
instructions_base.py instead. This is for two reasons:
1) Easier generation of documentation
2) Ensures that 'from instructions import *' will only import assembly
instructions and nothing else.

Note: every instruction should have a suitable docstring for auto-generation of
documentation
"""

import itertools
import tools
from random import randint
from Compiler.config import *
from Compiler.exceptions import *
import Compiler.instructions_base as base
import math



# avoid naming collision with input instruction
_python_input = input

###
### Load and store instructions
###

@base.gf2n
@base.vectorize
class ldi(base.Instruction):
    r""" Assigns register $c_i$ the value $n$. """
    __slots__ = []
    code = base.opcodes['LDI']
    arg_format = ['cw','i']
    
    def execute(self):
        self.args[0].value = self.args[1]

@base.gf2n
@base.vectorize
class ldsi(base.Instruction):
    r""" Assigns register $s_i$ a share of the value $n$. """
    __slots__ = []
    code = base.opcodes['LDSI']
    arg_format = ['sw','i']
    
    def execute(self):
        self.args[0].value = self.args[1]

@base.gf2n
@base.vectorize
class ldmc(base.DirectMemoryInstruction, base.ReadMemoryInstruction):
    r""" Assigns register $c_i$ the value in memory \verb+C[n]+. """
    __slots__ = ["code"]
    code = base.opcodes['LDMC']
    arg_format = ['cw','int']

    def execute(self):
        self.args[0].value = program.mem_c[self.args[1]]

@base.gf2n
@base.vectorize
class ldms(base.DirectMemoryInstruction, base.ReadMemoryInstruction):
    r""" Assigns register $s_i$ the value in memory \verb+S[n]+. """
    __slots__ = ["code"]
    code = base.opcodes['LDMS']
    arg_format = ['sw','int']

    def execute(self):
        self.args[0].value = program.mem_s[self.args[1]]

@base.gf2n
@base.vectorize
class stmc(base.DirectMemoryWriteInstruction):
    r""" Sets \verb+C[n]+ to be the value $c_i$. """
    __slots__ = ["code"]
    code = base.opcodes['STMC']
    arg_format = ['c','int']

    def execute(self):
        program.mem_c[self.args[1]] = self.args[0].value

@base.gf2n
@base.vectorize
class stms(base.DirectMemoryWriteInstruction):
    r""" Sets \verb+S[n]+ to be the value $s_i$. """
    __slots__ = ["code"]
    code = base.opcodes['STMS']
    arg_format = ['s','int']

    def execute(self):
        program.mem_s[self.args[1]] = self.args[0].value

@base.vectorize
class ldmint(base.DirectMemoryInstruction, base.ReadMemoryInstruction):
    r""" Assigns register $ci_i$ the value in memory \verb+Ci[n]+. """
    __slots__ = ["code"]
    code = base.opcodes['LDMINT']
    arg_format = ['ciw','int']

    def execute(self):
        self.args[0].value = program.mem_i[self.args[1]]

@base.vectorize
class stmint(base.DirectMemoryWriteInstruction):
    r""" Sets \verb+Ci[n]+ to be the value $ci_i$. """
    __slots__ = ["code"]
    code = base.opcodes['STMINT']
    arg_format = ['ci','int']

    def execute(self):
        program.mem_i[self.args[1]] = self.args[0].value

# must have seperate instructions because address is always modp
@base.vectorize
class ldmci(base.ReadMemoryInstruction):
    r""" Assigns register $c_i$ the value in memory \verb+C[cj]+. """
    code = base.opcodes['LDMCI']
    arg_format = ['cw','ci']
    
    def execute(self):
        self.args[0].value = program.mem_c[self.args[1].value]

@base.vectorize
class ldmsi(base.ReadMemoryInstruction):
    r""" Assigns register $s_i$ the value in memory \verb+S[cj]+. """
    code = base.opcodes['LDMSI']
    arg_format = ['sw','ci']

    def execute(self):
        self.args[0].value = program.mem_s[self.args[1].value]

@base.vectorize
class stmci(base.WriteMemoryInstruction):
    r""" Sets \verb+C[cj]+ to be the value $c_i$. """
    code = base.opcodes['STMCI']
    arg_format = ['c','ci']

    def execute(self):
        program.mem_c[self.args[1].value] = self.args[0].value

@base.vectorize
class stmsi(base.WriteMemoryInstruction):
    r""" Sets \verb+S[cj]+ to be the value $s_i$. """
    code = base.opcodes['STMSI']
    arg_format = ['s','ci']

    def execute(self):
        program.mem_s[self.args[1].value] = self.args[0].value

@base.vectorize
class ldminti(base.ReadMemoryInstruction):
    r""" Assigns register $ci_i$ the value in memory \verb+Ci[cj]+. """
    code = base.opcodes['LDMINTI']
    arg_format = ['ciw','ci']

    def execute(self):
        self.args[0].value = program.mem_i[self.args[1].value]

@base.vectorize
class stminti(base.WriteMemoryInstruction):
    r""" Sets \verb+Ci[cj]+ to be the value $ci_i$. """
    code = base.opcodes['STMINTI']
    arg_format = ['ci','ci']

    def execute(self):
        program.mem_i[self.args[1].value] = self.args[0].value

@base.vectorize
class gldmci(base.ReadMemoryInstruction):
    r""" Assigns register $c_i$ the value in memory \verb+C[cj]+. """
    code = base.opcodes['LDMCI'] + 0x100
    arg_format = ['cgw','ci']
    
    def execute(self):
        self.args[0].value = program.mem_c[self.args[1].value]

@base.vectorize
class gldmsi(base.ReadMemoryInstruction):
    r""" Assigns register $s_i$ the value in memory \verb+S[cj]+. """
    code = base.opcodes['LDMSI'] + 0x100
    arg_format = ['sgw','ci']

    def execute(self):
        self.args[0].value = program.mem_s[self.args[1].value]

@base.vectorize
class gstmci(base.WriteMemoryInstruction):
    r""" Sets \verb+C[cj]+ to be the value $c_i$. """
    code = base.opcodes['STMCI'] + 0x100
    arg_format = ['cg','ci']

    def execute(self):
        program.mem_c[self.args[1].value] = self.args[0].value

@base.vectorize
class gstmsi(base.WriteMemoryInstruction):
    r""" Sets \verb+S[cj]+ to be the value $s_i$. """
    code = base.opcodes['STMSI'] + 0x100
    arg_format = ['sg','ci']

    def execute(self):
        program.mem_s[self.args[1].value] = self.args[0].value

@base.gf2n
@base.vectorize
class protectmems(base.Instruction):
    r""" Protects secret memory range $[ci_i,ci_j)$. """
    code = base.opcodes['PROTECTMEMS']
    arg_format = ['ci','ci']

@base.gf2n
@base.vectorize
class protectmemc(base.Instruction):
    r""" Protects clear memory range $[ci_i,ci_j)$. """
    code = base.opcodes['PROTECTMEMC']
    arg_format = ['ci','ci']

@base.gf2n
@base.vectorize
class protectmemint(base.Instruction):
    r""" Protects integer memory range $[ci_i,ci_j)$. """
    code = base.opcodes['PROTECTMEMINT']
    arg_format = ['ci','ci']

@base.gf2n
@base.vectorize
class movc(base.Instruction):
    r""" Assigns register $c_i$ the value in the register $c_j$. """
    __slots__ = ["code"]
    code = base.opcodes['MOVC']
    arg_format = ['cw','c']

    def execute(self):
        self.args[0].value = self.args[1].value

@base.gf2n
@base.vectorize
class movs(base.Instruction):
    r""" Assigns register $s_i$ the value in the register $s_j$. """
    __slots__ = ["code"]
    code = base.opcodes['MOVS']
    arg_format = ['sw','s']

    def execute(self):
        self.args[0].value = self.args[1].value

@base.vectorize
class movint(base.Instruction):
    r""" Assigns register $ci_i$ the value in the register $ci_j$. """
    __slots__ = ["code"]
    code = base.opcodes['MOVINT']
    arg_format = ['ciw','ci']

@base.vectorize
class pushint(base.StackInstruction):
    r""" Pushes register $ci_i$ to the thread-local stack. """
    code = base.opcodes['PUSHINT']
    arg_format = ['ci']

@base.vectorize
class popint(base.StackInstruction):
    r""" Pops from the thread-local stack to register $ci_i$. """
    code = base.opcodes['POPINT']
    arg_format = ['ciw']


###
### Machine
###

@base.vectorize
class ldtn(base.Instruction):
    r""" Assigns register $c_i$ the number of the current thread. """
    code = base.opcodes['LDTN']
    arg_format = ['ciw']

@base.vectorize
class ldarg(base.Instruction):
    r""" Assigns register $c_i$ the argument passed to the current thread. """
    code = base.opcodes['LDARG']
    arg_format = ['ciw']

@base.vectorize
class starg(base.Instruction):
    r""" Assigns register $c_i$ to the argument. """
    code = base.opcodes['STARG']
    arg_format = ['ci']

@base.gf2n
class reqbl(base.Instruction):
    r""" Require bit length $n". """
    code = base.opcodes['REQBL']
    arg_format = ['int']

class time(base.Instruction):
    r""" Output epoch time. """
    code = base.opcodes['TIME']
    arg_format = []

class start(base.Instruction):
    r""" Start timer. """
    code = base.opcodes['START']
    arg_format = ['i']

class stop(base.Instruction):
    r""" Stop timer. """
    code = base.opcodes['STOP']
    arg_format = ['i']

class use(base.Instruction):
    r""" Offline data usage. """
    code = base.opcodes['USE']
    arg_format = ['int','int','int']

class use_inp(base.Instruction):
    r""" Input usage. """
    code = base.opcodes['USE_INP']
    arg_format = ['int','int','int']

class run_tape(base.Instruction):
    r""" Start tape $n$ in thread $c_i$ with argument $c_j$. """
    code = base.opcodes['RUN_TAPE']
    arg_format = ['int','int','int']

class join_tape(base.Instruction):
    r""" Join thread $c_i$. """
    code = base.opcodes['JOIN_TAPE']
    arg_format = ['int']

class crash(base.IOInstruction):
    r""" Crash runtime. """
    code = base.opcodes['CRASH']
    arg_format = []

@base.gf2n
class use_prep(base.Instruction):
    r""" Input usage. """
    code = base.opcodes['USE_PREP']
    arg_format = ['str','int']

###
### Basic arithmetic
###

@base.gf2n
@base.vectorize
class addc(base.AddBase):
    r""" Clear addition $c_i=c_j+c_k$. """
    __slots__ = []
    code = base.opcodes['ADDC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class adds(base.AddBase):
    r""" Secret addition $s_i=s_j+s_k$. """
    __slots__ = []
    code = base.opcodes['ADDS']
    arg_format = ['sw','s','s']


#@base.gf2n
#@base.vectorize
#class eadds(base.AddBase):
    r""" Secret addition $s_i=s_j+s_k$. """
#    __slots__ = []
#    code = base.opcodes['EADDS']
#    arg_format = ['sw','s','s']


@base.gf2n
@base.vectorize
class addm(base.AddBase):
    r""" Mixed addition $s_i=s_j+c_k$. """
    __slots__ = []
    code = base.opcodes['ADDM']
    arg_format = ['sw','s','c']


#@base.gf2n
#@base.vectorize
#class eaddm(base.AddBase):
    r""" Mixed addition $s_i=s_j+c_k$. """
#    __slots__ = []
#    code = base.opcodes['EADDM']
#    arg_format = ['sw','s','c']


@base.gf2n
@base.vectorize
class subc(base.SubBase):
    r""" Clear subtraction $c_i=c_j-c_k$. """
    __slots__ = []
    code = base.opcodes['SUBC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class subs(base.SubBase):
    r""" Secret subtraction $s_i=s_j-s_k$. """
    __slots__ = []
    code = base.opcodes['SUBS']
    arg_format = ['sw','s','s']


#@base.gf2n
#@base.vectorize
#class esubs(base.SubBase):
    r""" Secret subtraction $s_i=s_j-s_k$. """
#    __slots__ = []
#    code = base.opcodes['ESUBS']
#    arg_format = ['sw','s','s']


@base.gf2n
@base.vectorize
class subml(base.SubBase):
    r""" Mixed subtraction $s_i=s_j-c_k$. """
    __slots__ = []
    code = base.opcodes['SUBML']
    arg_format = ['sw','s','c']

@base.gf2n
@base.vectorize
class submr(base.SubBase):
    r""" Mixed subtraction $s_i=c_j-s_k$. """
    __slots__ = []
    code = base.opcodes['SUBMR']
    arg_format = ['sw','c','s']

@base.gf2n
@base.vectorize
class mulc(base.MulBase):
    r""" Clear multiplication $c_i=c_j \cdot c_k$. """
    __slots__ = []
    code = base.opcodes['MULC']
    arg_format = ['cw','c','c']

@base.gf2n
@base.vectorize
class mulm(base.MulBase):
    r""" Mixed multiplication $s_i=c_j \cdot s_k$. """
    __slots__ = []
    code = base.opcodes['MULM']
    arg_format = ['sw','s','c']


#@base.gf2n
#@base.vectorize
#class emulm(base.MulBase):
    r""" Mixed multiplication $s_i=c_j \cdot s_k$. """
#    __slots__ = []
#    code = base.opcodes['EMULM']
#    arg_format = ['sw','s','c']


@base.gf2n
@base.vectorize
class divc(base.Instruction):
    r""" Clear division $c_i=c_j/c_k$. """
    __slots__ = []
    code = base.opcodes['DIVC']
    arg_format = ['cw','c','c']
    
    def execute(self):
        self.args[0].value = self.args[1].value * pow(self.args[2].value, program.P-2, program.P) % program.P

@base.gf2n
@base.vectorize
class modc(base.Instruction):
    r""" Clear modular reduction $c_i=c_j/c_k$. """
    __slots__ = []
    code = base.opcodes['MODC']
    arg_format = ['cw','c','c']

    def execute(self):
        self.args[0].value = self.args[1].value % self.args[2].value

@base.vectorize
class legendrec(base.Instruction):
    r""" Clear Legendre symbol computation, $c_i = (c_j / p)$. """
    __slots__ = []
    code = base.opcodes['LEGENDREC']
    arg_format = ['cw','c']

@base.vectorize
class digestc(base.Instruction):
    r""" Clear truncated hash computation, $c_i = H(c_j)[bytes]$. """
    __slots__ = []
    code = base.opcodes['DIGESTC']
    arg_format = ['cw','c','int']

###
### Bitwise operations
###

@base.gf2n
@base.vectorize
class andc(base.Instruction):
    r""" Clear logical AND $c_i = c_j \land c_k$ """
    __slots__ = []
    code = base.opcodes['ANDC']
    arg_format = ['cw','c','c']
    
    def execute(self):
        self.args[0].value = (self.args[1].value & self.args[2].value) % program.P

@base.gf2n
@base.vectorize
class orc(base.Instruction):
    r""" Clear logical OR $c_i = c_j \lor c_k$ """
    __slots__ = []
    code = base.opcodes['ORC']
    arg_format = ['cw','c','c']
    
    def execute(self):
        self.args[0].value = (self.args[1].value | self.args[2].value) % program.P

@base.gf2n
@base.vectorize
class xorc(base.Instruction):
    r""" Clear logical XOR $c_i = c_j \oplus c_k$ """
    __slots__ = []
    code = base.opcodes['XORC']
    arg_format = ['cw','c','c']
    
    def execute(self):
        self.args[0].value = (self.args[1].value ^ self.args[2].value) % program.P

@base.vectorize
class notc(base.Instruction):
    r""" Clear logical NOT $c_i = \lnot c_j$ """
    __slots__ = []
    code = base.opcodes['NOTC']
    arg_format = ['cw','c', 'int']
    
    def execute(self):
        self.args[0].value = (~self.args[1].value + 2 ** self.args[2]) % program.P

@base.vectorize
class gnotc(base.Instruction):
    r""" Clear logical NOT $cg_i = \lnot cg_j$ """
    __slots__ = []
    code = (1 << 8) + base.opcodes['NOTC']
    arg_format = ['cgw','cg']

    def is_gf2n(self):
        return True

    def execute(self):
        self.args[0].value = ~self.args[1].value

@base.vectorize
class gbitdec(base.Instruction):
    r""" Store every $n$-th bit of $cg_i$ in $cg_j, \dots$. """
    __slots__ = []
    code = base.opcodes['GBITDEC']
    arg_format = tools.chain(['cg', 'int'], itertools.repeat('cgw'))

    def is_g2fn(self):
        return True

    def has_var_args(self):
        return True

# ADDED

#@base.vectorize
#class e_skew_dec(base.Instruction):
    #r""" Pre-computation for bit-decomposition """
    #__slots__ = []
    #code = base.opcodes['E_SKEW_DEC']
    #arg_format = tools.chain(['s', 'int'], itertools.repeat('sgw'))

@base.vectorize
class e_skew_bit_dec(base.Instruction):
    r""" Pre-computation for bit-decomposition """
    __slots__ = []
    code = base.opcodes['E_SKEW_BIT_DEC']
    arg_format = tools.chain(['s', 'int'], itertools.repeat('sgw'))

class e_skew_bit_rec(base.Instruction):
    r""" Pre-computation for ring-composition """
    __slots__ = []
    code = base.opcodes['E_SKEW_BIT_REC']
    arg_format = ['sg', 'sgw', 'sgw', 'sgw']

@base.vectorize
class e_skew_bit_inj(base.Instruction):
    r""" Pre-computation for bit-injection """
    __slots__ = []
    code = base.opcodes['E_SKEW_BIT_INJ']
    arg_format = ['sg', 'sw', 'sw', 'sw']

#class e_post_rec(base.Instruction):
    #r""" Post-computation for ring-composition """
    #__slots__ = []
    #code = base.opcodes['E_POST_REC']
    #arg_format = tools.chain(['sw', 'int'], itertools.repeat('sg'))

class e_skew_ring_rec(base.Instruction):
    r""" Post-computation for ring-composition """
    __slots__ = []
    code = base.opcodes['E_SKEW_RING_REC']
    arg_format = tools.chain(['sw', 'int'], itertools.repeat('sg'))

# END ADDED

@base.vectorize
class gbitcom(base.Instruction):
    r""" Store the bits $cg_j, \dots$ as every $n$-th bit of $cg_i$. """
    __slots__ = []
    code = base.opcodes['GBITCOM']
    arg_format = tools.chain(['cgw', 'int'], itertools.repeat('cg'))

    def is_g2fn(self):
        return True

    def has_var_args(self):
        return True


###
### Special GF(2) arithmetic instructions
###

@base.vectorize
class gmulbitc(base.MulBase):
    r""" Clear GF(2^n) by clear GF(2) multiplication """
    __slots__ = []
    code = base.opcodes['GMULBITC']
    arg_format = ['cgw','cg','cg']

    def is_gf2n(self):
        return True

@base.vectorize
class gmulbitm(base.MulBase):
    r""" Secret GF(2^n) by clear GF(2) multiplication """
    __slots__ = []
    code = base.opcodes['GMULBITM']
    arg_format = ['sgw','sg','cg']

    def is_gf2n(self):
        return True

###
### Arithmetic with immediate values
###

@base.gf2n
@base.vectorize
class addci(base.ClearImmediate):
    """ Clear addition of immediate value $c_i=c_j+n$. """
    __slots__ = []
    code = base.opcodes['ADDCI']
    op = '__add__'

@base.gf2n
@base.vectorize
class addsi(base.SharedImmediate):
    """ Secret addition of immediate value $s_i=s_j+n$. """
    __slots__ = []
    code = base.opcodes['ADDSI']
    op = '__add__'

@base.gf2n
@base.vectorize
class subci(base.ClearImmediate):
    r""" Clear subtraction of immediate value $c_i=c_j-n$. """
    __slots__ = []
    code = base.opcodes['SUBCI']
    op = '__sub__'

@base.gf2n
@base.vectorize
class subsi(base.SharedImmediate):
    r""" Secret subtraction of immediate value $s_i=s_j-n$. """
    __slots__ = []
    code = base.opcodes['SUBSI']
    op = '__sub__'

@base.gf2n
@base.vectorize
class subcfi(base.ClearImmediate):
    r""" Clear subtraction from immediate value $c_i=n-c_j$. """
    __slots__ = []
    code = base.opcodes['SUBCFI']
    op = '__rsub__'

@base.gf2n
@base.vectorize
class subsfi(base.SharedImmediate):
    r""" Secret subtraction from immediate value $s_i=n-s_j$. """
    __slots__ = []
    code = base.opcodes['SUBSFI']
    op = '__rsub__'

@base.gf2n
@base.vectorize
class mulci(base.ClearImmediate):
    r""" Clear multiplication by immediate value $c_i=c_j \cdot n$. """
    __slots__ = []
    code = base.opcodes['MULCI']
    op = '__mul__'

@base.gf2n
@base.vectorize
class mulsi(base.SharedImmediate):
    r""" Secret multiplication by immediate value $s_i=s_j \cdot n$. """
    __slots__ = []
    code = base.opcodes['MULSI']
    op = '__mul__'

@base.gf2n
@base.vectorize
class divci(base.ClearImmediate):
    r""" Clear division by immediate value $c_i=c_j/n$. """
    __slots__ = []
    code = base.opcodes['DIVCI']
    def execute(self):
        self.args[0].value = self.args[1].value * pow(self.args[2], program.P-2, program.P) % program.P

@base.gf2n
@base.vectorize
class modci(base.ClearImmediate):
    r""" Clear modular reduction by immediate value $c_i=c_j \mod{n}$. """
    __slots__ = []
    code = base.opcodes['MODCI']
    op = '__mod__'

@base.gf2n
@base.vectorize
class andci(base.ClearImmediate):
    r""" Clear logical AND with immediate value $c_i = c_j \land c_k$ """
    __slots__ = []
    code = base.opcodes['ANDCI']
    op = '__and__'

@base.gf2n
@base.vectorize
class xorci(base.ClearImmediate):
    r""" Clear logical XOR with immediate value $c_i = c_j \oplus c_k$ """
    __slots__ = []
    code = base.opcodes['XORCI']
    op = '__xor__'

@base.gf2n
@base.vectorize
class orci(base.ClearImmediate):
    r""" Clear logical OR with immediate value $c_i = c_j \vee c_k$ """
    __slots__ = []
    code = base.opcodes['ORCI']
    op = '__or__'


###
### Shift instructions
###

@base.gf2n
@base.vectorize
class shlc(base.Instruction):
    r""" Clear bitwise shift left $c_i = c_j << c_k$ """
    __slots__ = []
    code = base.opcodes['SHLC']
    arg_format = ['cw','c','c']
    
    def execute(self):
        self.args[0].value = (self.args[1].value << self.args[2].value) % program.P

@base.gf2n
@base.vectorize
class shrc(base.Instruction):
    r""" Clear bitwise shift right $c_i = c_j >> c_k$ """
    __slots__ = []
    code = base.opcodes['SHRC']
    arg_format = ['cw','c','c']
    
    def execute(self):
        self.args[0].value = (self.args[1].value >> self.args[2].value) % program.P

@base.gf2n
@base.vectorize
class shlci(base.ClearShiftInstruction):
    r""" Clear bitwise shift left by immediate value $c_i = c_j << n$ """
    __slots__ = []
    code = base.opcodes['SHLCI']
    op = '__lshift__'

@base.gf2n
@base.vectorize
class shrci(base.ClearShiftInstruction):
    r""" Clear bitwise shift right by immediate value $c_i = c_j >> n$ """
    __slots__ = []
    code = base.opcodes['SHRCI']
    op = '__rshift__'


###
### Data access instructions
###

@base.gf2n
@base.vectorize
class triple(base.DataInstruction):
    r""" Load secret variables $s_i$, $s_j$ and $s_k$
    with the next multiplication triple. """
    __slots__ = ['data_type']
    code = base.opcodes['TRIPLE']
    arg_format = ['sw','sw','sw']
    data_type = 'triple'
    
    def execute(self):
        self.args[0].value = randint(0,program.P)
        self.args[1].value = randint(0,program.P)
        self.args[2].value = (self.args[0].value * self.args[1].value) % program.P

@base.vectorize
class gbittriple(base.DataInstruction):
    r""" Load secret variables $s_i$, $s_j$ and $s_k$
    with the next GF(2) multiplication triple. """
    __slots__ = ['data_type']
    code = base.opcodes['GBITTRIPLE']
    arg_format = ['sgw','sgw','sgw']
    data_type = 'bittriple'
    field_type = 'gf2n'

    def is_gf2n(self):
        return True

@base.vectorize
class gbitgf2ntriple(base.DataInstruction):
    r""" Load secret variables $s_i$, $s_j$ and $s_k$
    with the next GF(2) and GF(2^n) multiplication triple. """
    code = base.opcodes['GBITGF2NTRIPLE']
    arg_format = ['sgw','sgw','sgw']
    data_type = 'bitgf2ntriple'
    field_type = 'gf2n'

    def is_gf2n(self):
        return True

@base.gf2n
@base.vectorize
class bit(base.DataInstruction):
    r""" Load secret variable $s_i$
    with the next secret bit. """
    __slots__ = []
    code = base.opcodes['BIT']
    arg_format = ['sw']
    data_type = 'bit'
    
    def execute(self):
        self.args[0].value = randint(0,1)

@base.gf2n
@base.vectorize
class square(base.DataInstruction):
    r""" Load secret variables $s_i$ and $s_j$
    with the next squaring tuple. """
    __slots__ = []
    code = base.opcodes['SQUARE']
    arg_format = ['sw','sw']
    data_type = 'square'
    
    def execute(self):
        self.args[0].value = randint(0,program.P)
        self.args[1].value = (self.args[0].value * self.args[0].value) % program.P

@base.gf2n
@base.vectorize
class inverse(base.DataInstruction):
    r""" Load secret variables $s_i$, $s_j$ and $s_k$
    with the next inverse triple. """
    __slots__ = []
    code = base.opcodes['INV']
    arg_format = ['sw','sw']
    data_type = 'inverse'
    
    def execute(self):
        self.args[0].value = randint(0,program.P)
        import gmpy
        self.args[1].value = int(gmpy.invert(self.args[0].value, program.P))

@base.gf2n
@base.vectorize
class inputmask(base.Instruction):
    r""" Load secret $s_i$ with the next input mask for player $p$ and
    write the mask on player $p$'s private output. """ 
    __slots__ = []
    code = base.opcodes['INPUTMASK']
    arg_format = ['sw', 'p']
    field_type = 'modp'

    def add_usage(self, req_node):
        req_node.increment((self.field_type, 'input', self.args[1]), \
                               self.get_size())

@base.gf2n
@base.vectorize
class prep(base.Instruction):
    r""" Custom preprocessed data """
    __slots__ = []
    code = base.opcodes['PREP']
    arg_format = tools.chain(['str'], itertools.repeat('sw'))
    gf2n_arg_format = tools.chain(['str'], itertools.repeat('sgw'))
    field_type = 'modp'

    def add_usage(self, req_node):
        req_node.increment((self.field_type, self.args[0]), 1)

    def has_var_args(self):
        return True

###
### I/O
###

@base.gf2n
@base.vectorize
class asm_input(base.IOInstruction):
    r""" Receive input from player $p$ and put in register $s_i$. """
    __slots__ = []
    code = base.opcodes['INPUT']
    arg_format = ['sw', 'p']
    field_type = 'modp'

    def add_usage(self, req_node):
        req_node.increment((self.field_type, 'input', self.args[1]), \
                               self.get_size())
    def execute(self):
        self.args[0].value = _python_input("Enter player %d's input:" % self.args[1]) % program.P

@base.gf2n
class startinput(base.RawInputInstruction):
    r""" Receive inputs from player $p$. """
    __slots__ = []
    code = base.opcodes['STARTINPUT']
    arg_format = ['p', 'int']
    field_type = 'modp'

    def add_usage(self, req_node):
        req_node.increment((self.field_type, 'input', self.args[0]), \
                               self.args[1])

class stopinput(base.RawInputInstruction):
    r""" Receive inputs from player $p$ and put in registers. """
    __slots__ = []
    code = base.opcodes['STOPINPUT']
    arg_format = tools.chain(['p'], itertools.repeat('sw'))

    def has_var_args(self):
        return True

class gstopinput(base.RawInputInstruction):
    r""" Receive inputs from player $p$ and put in registers. """
    __slots__ = []
    code = 0x100 + base.opcodes['STOPINPUT']
    arg_format = tools.chain(['p'], itertools.repeat('sgw'))

    def has_var_args(self):
        return True

@base.gf2n
@base.vectorize
class print_mem(base.IOInstruction):
    r""" Print value in clear memory \verb|C[ci]| to stdout. """
    __slots__ = []
    code = base.opcodes['PRINTMEM']
    arg_format = ['c']
    
    def execute(self):
        pass

@base.gf2n
@base.vectorize
class print_reg(base.IOInstruction):
    r""" Print value of register \verb|ci| to stdout and optional 4-char comment. """
    __slots__ = []
    code = base.opcodes['PRINTREG']
    arg_format = ['c','i']
    
    def __init__(self, reg, comment=''):
        super(print_reg_class, self).__init__(reg, self.str_to_int(comment))

    def execute(self):
        pass

@base.gf2n
@base.vectorize
class print_reg_plain(base.IOInstruction):
    r""" Print only the value of register \verb|ci| to stdout. """
    __slots__ = []
    code = base.opcodes['PRINTREGPLAIN']
    arg_format = ['c']

#@base.gf2n
@base.vectorize
class e_print_fixed_plain(base.IOInstruction):
    r""" Print only the fixed value of register \verb|ci| to stdout. """
    __slots__ = []
    code = base.opcodes['E_PRINTFIXEDPLAIN']
    arg_format = ['c', 'int']


@base.vectorize
class print_float_plain(base.IOInstruction):
    __slots__ = []
    code = base.opcodes['PRINTFLOATPLAIN']
    arg_format = ['c', 'c', 'c', 'c']

class print_int(base.IOInstruction):
    r""" Print only the value of register \verb|ci| to stdout. """
    __slots__ = []
    code = base.opcodes['PRINTINT']
    arg_format = ['ci']

class print_char(base.IOInstruction):
    r""" Print a single character to stdout. """
    code = base.opcodes['PRINTCHR']
    arg_format = ['int']

    def __init__(self, ch):
        super(print_char, self).__init__(ord(ch))

class print_char4(base.IOInstruction):
    r""" Print a 4 character string. """
    code = base.opcodes['PRINTSTR']
    arg_format = ['int']

    def __init__(self, val):
        super(print_char4, self).__init__(self.str_to_int(val))

@base.vectorize
class print_char_regint(base.IOInstruction):
    r""" Print register $ci_i$ as a single character to stdout. """
    code = base.opcodes['PRINTCHRINT']
    arg_format = ['ci']

@base.vectorize
class print_char4_regint(base.IOInstruction):
    r""" Print register $ci_i$ as a four character string to stdout. """
    code = base.opcodes['PRINTSTRINT']
    arg_format = ['ci']

@base.vectorize
class pubinput(base.PublicFileIOInstruction):
    __slots__ = []
    code = base.opcodes['PUBINPUT']
    arg_format = ['ciw']

@base.vectorize
class readsocketc(base.IOInstruction):
    """Read a variable number of clear GF(p) values from socket for a specified client id and store in registers"""
    __slots__ = []
    code = base.opcodes['READSOCKETC']
    arg_format = tools.chain(['ci'], itertools.repeat('cw'))

    def has_var_args(self):
        return True

@base.vectorize
class readsockets(base.IOInstruction):
    """Read a variable number of secret shares + MACs from socket for a client id and store in registers"""
    __slots__ = []
    code = base.opcodes['READSOCKETS']
    arg_format = tools.chain(['ci'], itertools.repeat('sw'))

    def has_var_args(self):
        return True

@base.vectorize
class readsocketint(base.IOInstruction):
    """Read variable number of 32-bit int from socket for a client id and store in registers"""
    __slots__ = []
    code = base.opcodes['READSOCKETINT']
    arg_format = tools.chain(['ci'], itertools.repeat('ciw'))

    def has_var_args(self):
        return True

@base.vectorize
class writesocketc(base.IOInstruction):
    """
    Write a variable number of clear GF(p) values from registers into socket 
    for a specified client id, message_type
    """
    __slots__ = []
    code = base.opcodes['WRITESOCKETC']
    arg_format = tools.chain(['ci', 'int'], itertools.repeat('c'))

    def has_var_args(self):
        return True

@base.vectorize
class writesockets(base.IOInstruction):
    """
    Write a variable number of secret shares + MACs from registers into a socket
    for a specified client id, message_type
    """
    __slots__ = []
    code = base.opcodes['WRITESOCKETS']
    arg_format = tools.chain(['ci', 'int'], itertools.repeat('s'))

    def has_var_args(self):
        return True

@base.vectorize
class writesocketshare(base.IOInstruction):
    """
    Write a variable number of secret shares (without MACs) from registers into socket 
    for a specified client id, message_type
    """
    __slots__ = []
    code = base.opcodes['WRITESOCKETSHARE']
    arg_format = tools.chain(['ci', 'int'], itertools.repeat('s'))

    def has_var_args(self):
        return True

@base.vectorize
class writesocketint(base.IOInstruction):
    """
    Write a variable number of 32-bit ints from registers into socket
    for a specified client id, message_type
    """
    __slots__ = []
    code = base.opcodes['WRITESOCKETINT']
    arg_format = tools.chain(['ci', 'int'], itertools.repeat('ci'))

    def has_var_args(self):
        return True

class listen(base.IOInstruction):
    """Open a server socket on a party specific port number and listen for client connections (non-blocking)"""
    __slots__ = []
    code = base.opcodes['LISTEN']
    arg_format = ['int']

class acceptclientconnection(base.IOInstruction):
    """Wait for a connection at the given port and write socket handle to register """
    __slots__ = []
    code = base.opcodes['ACCEPTCLIENTCONNECTION']
    arg_format = ['ciw', 'int']

class connectipv4(base.IOInstruction):
    """Connect to server at IPv4 address in register \verb|cj| at given port. Write socket handle to register \verb|ci|"""
    __slots__ = []
    code = base.opcodes['CONNECTIPV4']
    arg_format = ['ciw', 'ci', 'int']

class readclientpublickey(base.IOInstruction):
    """Read a client public key as 8 32-bit ints for a specified client id"""
    __slots__ = []
    code = base.opcodes['READCLIENTPUBLICKEY']
    arg_format = tools.chain(['ci'], itertools.repeat('ci'))

    def has_var_args(self):
        return True

class initsecuresocket(base.IOInstruction):
    """Read a client public key as 8 32-bit ints for a specified client id,
    negotiate a shared key via STS and use it for replay resistant comms"""
    __slots__ = []
    code = base.opcodes['INITSECURESOCKET']
    arg_format = tools.chain(['ci'], itertools.repeat('ci'))

    def has_var_args(self):
        return True

class respsecuresocket(base.IOInstruction):
    """Read a client public key as 8 32-bit ints for a specified client id,
    negotiate a shared key via STS and use it for replay resistant comms"""
    __slots__ = []
    code = base.opcodes['RESPSECURESOCKET']
    arg_format = tools.chain(['ci'], itertools.repeat('ci'))

    def has_var_args(self):
        return True

class writesharestofile(base.IOInstruction):
    """Write shares to a file"""
    __slots__ = []
    code = base.opcodes['WRITEFILESHARE']
    arg_format = itertools.repeat('s')

    def has_var_args(self):
        return True

class readsharesfromfile(base.IOInstruction):
    """
    Read shares from a file. Pass in start posn, return finish posn, shares.
    Finish posn will return:
      -2 file not found
      -1 eof reached
      position in file after read finished
    """
    __slots__ = []
    code = base.opcodes['READFILESHARE']
    arg_format = tools.chain(['ci', 'ciw'], itertools.repeat('sw'))

    def has_var_args(self):
        return True

@base.gf2n
@base.vectorize
class raw_output(base.PublicFileIOInstruction):
    r""" Raw output of register \verb|ci| to file. """
    __slots__ = []
    code = base.opcodes['RAWOUTPUT']
    arg_format = ['c']

@base.gf2n
@base.vectorize
class startprivateoutput(base.Instruction):
    r""" Initiate private output to $n$ of $s_j$ via $s_i$. """
    __slots__ = []
    code = base.opcodes['STARTPRIVATEOUTPUT']
    arg_format = ['sw','s','p']

@base.gf2n
@base.vectorize
class stopprivateoutput(base.Instruction):
    r""" Previously iniated private output to $n$ via $c_i$. """
    __slots__ = []
    code = base.opcodes['STOPPRIVATEOUTPUT']
    arg_format = ['c','p']

@base.vectorize
class rand(base.Instruction):
    __slots__ = []
    code = base.opcodes['RAND']
    arg_format = ['ciw','ci']

###
### Integer operations
### 

@base.vectorize
class ldint(base.Instruction):
    __slots__ = []
    code = base.opcodes['LDINT']
    arg_format = ['ciw', 'i']

@base.vectorize
class addint(base.IntegerInstruction):
    __slots__ = []
    code = base.opcodes['ADDINT']

@base.vectorize
class subint(base.IntegerInstruction):
    __slots__ = []
    code = base.opcodes['SUBINT']

@base.vectorize
class mulint(base.IntegerInstruction):
    __slots__ = []
    code = base.opcodes['MULINT']

@base.vectorize
class divint(base.IntegerInstruction):
    __slots__ = []
    code = base.opcodes['DIVINT']

###
### Clear comparison instructions
###

@base.vectorize
class eqzc(base.UnaryComparisonInstruction):
    r""" Clear comparison $c_i = (c_j \stackrel{?}{==} 0)$. """
    __slots__ = []
    code = base.opcodes['EQZC']
    
    def execute(self):
        if self.args[1].value == 0:
            self.args[0].value = 1
        else:
            self.args[0].value = 0

@base.vectorize
class ltzc(base.UnaryComparisonInstruction):
    r""" Clear comparison $c_i = (c_j \stackrel{?}{<} 0)$. """
    __slots__ = []
    code = base.opcodes['LTZC']

@base.vectorize
class ltc(base.IntegerInstruction):
    r""" Clear comparison $c_i = (c_j \stackrel{?}{<} c_k)$. """
    __slots__ = []
    code = base.opcodes['LTC']

@base.vectorize
class gtc(base.IntegerInstruction):
    r""" Clear comparison $c_i = (c_j \stackrel{?}{>} c_k)$. """
    __slots__ = []
    code = base.opcodes['GTC']

@base.vectorize
class eqc(base.IntegerInstruction):
    r""" Clear comparison $c_i = (c_j \stackrel{?}{==} c_k)$. """
    __slots__ = []
    code = base.opcodes['EQC']


###
### Jumps etc
###

class jmp(base.JumpInstruction):
    """ Unconditional relative jump of $n+1$ instructions. """
    __slots__ = []
    code = base.opcodes['JMP']
    arg_format = ['int']
    jump_arg = 0

    def execute(self):
        pass

class jmpi(base.JumpInstruction):
    """ Unconditional relative jump of $c_i+1$ instructions. """
    __slots__ = []
    code = base.opcodes['JMPI']
    arg_format = ['ci']
    jump_arg = 0

class jmpnz(base.JumpInstruction):
    r""" Jump $n+1$ instructions if $c_i \neq 0$.

    e.g.
    jmpnz(c, n) : advance n+1 instructions if c is non-zero 
    jmpnz(c, 0) : do nothing
    jmpnz(c, -1): infinite loop if c is non-zero
    """
    __slots__ = []
    code = base.opcodes['JMPNZ']
    arg_format = ['ci', 'int']
    jump_arg = 1
    
    def execute(self):
        pass

class jmpeqz(base.JumpInstruction):
    r""" Jump $n+1$ instructions if $c_i == 0$. """
    __slots__ = []
    code = base.opcodes['JMPEQZ']
    arg_format = ['ci', 'int']
    jump_arg = 1
    
    def execute(self):
        pass

###
### Conversions
###

@base.gf2n
@base.vectorize
class convint(base.Instruction):
    """ Convert from integer register $ci_j$ to clear modp register $c_i$. """
    __slots__ =  []
    code = base.opcodes['CONVINT']
    arg_format = ['cw', 'ci']

@base.vectorize
class convmodp(base.Instruction):
    """ Convert from clear modp register $c_j$ to integer register $ci_i$. """
    __slots__ =  []
    code = base.opcodes['CONVMODP']
    arg_format = ['ciw', 'c', 'int']
    def __init__(self, *args, **kwargs):
        bitlength = kwargs.get('bitlength', program.bit_length)
        super(convmodp_class, self).__init__(*(args + (bitlength,)))

@base.vectorize
class gconvgf2n(base.Instruction):
    """ Convert from clear modp register $c_j$ to integer register $ci_i$. """
    __slots__ =  []
    code = base.opcodes['GCONVGF2N']
    arg_format = ['ciw', 'cg']

###
### Other instructions
###

@base.gf2n
@base.vectorize
class startopen(base.VarArgsInstruction):
    """ Start opening secret register $s_i$. """
    __slots__ = []
    code = base.opcodes['STARTOPEN']
    arg_format = itertools.repeat('s')
    
    def execute(self):
        for arg in self.args[::-1]:
            program.curr_block.open_queue.append(arg.value)

@base.gf2n
@base.vectorize
class e_startopen(startopen_class):
    """ Start opening secret register $s_i$. """
    __slots__ = []
    code = base.opcodes['E_STARTOPEN']
    arg_format = itertools.repeat('s')

    def execute(self):
        for arg in self.args[::-1]:
            program.curr_block.open_queue.append(arg.value)

    def has_var_args(self):
        return True

@base.gf2n
@base.vectorize
class stopopen(base.VarArgsInstruction):
    """ Store previous opened value in $c_i$. """
    __slots__ = []
    code = base.opcodes['STOPOPEN']
    arg_format = itertools.repeat('cw')
    
    def execute(self):
        for arg in self.args:
            arg.value = program.curr_block.open_queue.pop()

@base.gf2n
@base.vectorize
class e_stopopen(stopopen_class):
    """ Store previous opened value in $c_i$. """

    __slots__ = []
    code = base.opcodes['E_STOPOPEN']
    arg_format = itertools.repeat('cw')

    def execute(self):
        for arg in self.args:
            arg.value = program.curr_block.open_queue.pop()

    def has_var_args(self):
        return True

###
### CISC-style instructions
###

# rename 'open' to avoid conflict with built-in open function
@base.gf2n
@base.vectorize
class asm_open(base.CISC):
    """ Open the value in $s_j$ and assign it to $c_i$. """
    __slots__ = []
    arg_format = ['cw','s']

    def expand(self):

        startopen(self.args[1])
        stopopen(self.args[0])


        """ Extended (NEC) open the value in $s_j$ and assign it to $c_i$. """
        #estartopen(self.args[1])
        #estopopen(self.args[0])

@base.gf2n
@base.vectorize
class e_asm_open(base.CISC):
    """ Open the value in $s_j$ and assign it to $c_i$. """
    __slots__ = []
    arg_format = ['cw','s']

    def expand(self):
        """
        startopen(self.args[1])
        stopopen(self.args[0])
        """

        """ Extended (NEC) open the value in $s_j$ and assign it to $c_i$. """
        e_startopen(self.args[1])
        e_stopopen(self.args[0])


@base.gf2n
@base.vectorize
class e_lessthan(base.CISC):
    """ less than function . """
    __slots__ = []
    arg_format = ['s','s','int','sgw']

    def expand(self):
        step = self.args[2]
        tmp = program.curr_block.new_reg('s')
        bit_array_sub = [program.curr_block.new_reg('sg') for _ in range(step)]

        # signed ver. (start)
        prod_left = program.curr_block.new_reg('sg')
        prod_right = program.curr_block.new_reg('sg')
        prod = program.curr_block.new_reg('sg')
        ans = program.curr_block.new_reg('sg')
        bit_array_self = [program.curr_block.new_reg('sg') for _ in range(step)]
        bit_array_other = [program.curr_block.new_reg('sg') for _ in range(step)]
        # signed ver. (end)

        subs(tmp, self.args[0], self.args[1])
        e_bitdec(tmp, step, *bit_array_sub)

        # signed ver. (start)
        e_bitdec(self.args[0], step, *bit_array_self)
        e_bitdec(self.args[1], step, *bit_array_other)
        gadds(prod_left, bit_array_self[step - 1], bit_array_other[step - 1])
        gadds(prod_right, bit_array_sub[step - 1], bit_array_self[step - 1])
        ge_startmult(prod_left, prod_right)
        ge_stopmult(prod)
        gadds(self.args[3], prod, bit_array_sub[step - 1])
        # signed ver. (end)

        # DEBUG (start)
        """
        c_bit_array = [cgf2n() for _ in range(step)]
        for i in range(step):
            print_char4("i=")
            print_char4(str(i))
            print_char('\n')
            gstartopen(bit_array[i])
            gstopopen(c_bit_array[i])
            gprint_reg_plain(c_bit_array[i])
            print_char('\n')
        """
        # DEBUG (end)
        # result = bit_array_sub[step - 1].e_bit_inject()



@base.gf2n
@base.vectorize
class e_trunc(base.CISC):
    """ Truncate . """
    __slots__ = []
    arg_format = ['s','int','sw']

    def expand(self):
        a = [program.curr_block.new_reg('sg') for _ in range(64)]
        b = [program.curr_block.new_reg('sg') for _ in range(64)]

        e_bitdec(self.args[0], 64, *a)
        for i in range(64):
            if i + self.args[1] >= 64 :
                gldsi(b[i],0)
            else :
                b[i] = a[i + self.args[1]]

        e_bitrec(self.args[2], 64, *b)
       # return a


@base.gf2n
@base.vectorize
class e_pow2(base.CISC):
    """calculate 2^{a} by squaring (not optimized)"""
    __slots__ = []
    arg_format = ['s', 'int', 'sw']

    def expand(self):
        m = int(math.ceil(math.log(self.args[1],2)))
        ai = [program.curr_block.new_reg('sg') for _ in range(m)]
        a = [program.curr_block.new_reg('s') for _ in range(m)]
        pow2k = [program.curr_block.new_reg('c') for _ in range(m)]
        tmp_x = [program.curr_block.new_reg('s') for _ in range(m)]
        tmp2_x = [program.curr_block.new_reg('s') for _ in range(m)]
        tmp3_x = [program.curr_block.new_reg('s') for _ in range(m)]
        x = [program.curr_block.new_reg('s') for _ in range(m)]

        e_bitdec(self.args[0], m ,*ai)
        for i in range(m):
            e_bitinj(ai[i], a[i])


        ldi(pow2k[0], 2)

        for i in range(0,m-1):
            mulc(pow2k[i+1], pow2k[i], pow2k[i])

        mulm(tmp_x[0], a[0], pow2k[0])
        addsi(tmp2_x[0], tmp_x[0], 1)
        subs(tmp3_x[0], tmp2_x[0], a[0])


        for i in range(1,m):
            mulm(tmp_x[i], a[i], pow2k[i])
            addsi(tmp2_x[i], tmp_x[i], 1)
            subs(tmp3_x[i], tmp2_x[i], a[i])

        x[0] = tmp3_x[0]

        for i in range(0,m-1):
            muls(x[i+1], tmp3_x[i+1], x[i])

        addsi(self.args[2], x[m-1], 0)
        #addm(self.args[2],tmp, pow2k[3])


#@base.gf2n
@base.vectorize
class e_prefixor(base.CISC):
    """n-rounds prefixOR operation including bit decomposition"""
    __slots__ = []
    arg_format = tools.chain(['s', 'int'], itertools.repeat('sw'))

    def expand(self):
        array1 = [program.curr_block.new_reg('sg') for _ in range(self.args[1])]
        array2 = [program.curr_block.new_reg('s') for _ in range(self.args[1])]
        garray = [program.curr_block.new_reg('sg') for _ in range(self.args[1])]
        tmp1 = [program.curr_block.new_reg('sg') for _ in range(self.args[1])]
        tmp2 = [program.curr_block.new_reg('sg') for _ in range(self.args[1])]
        tmp3 = [program.curr_block.new_reg('sg') for _ in range(self.args[1])]
        tmp4 = [program.curr_block.new_reg('sg') for _ in range(self.args[1])]
        n = self.args[1]

        e_bitdec(self.args[0], n, *array1)
        garray[0] = array1[n -1]
        e_bitinj(array1[n-1], self.args[2])

        for i in range(1, n):
            gaddsi(tmp1[i], array1[n - (i + 1)], 1)
            gaddsi(tmp2[i], garray[i - 1], 1)
            gmuls(tmp3[i], tmp1[i], tmp2[i])
            gaddsi(garray[i], tmp3[i], 1)
            e_bitinj(garray[i], self.args[2 + i])

        #OR(a,b)=((1+a)*(1+b))+1


#@base.gf2n
@base.vectorize
class e_bitdec(base.CISC):
    r""" Convert a share mod 2^n to n-array of shares mod 2. """
    __slots__ = []
    code = base.opcodes['E_BITDEC']
    arg_format = tools.chain(['s', 'int'], itertools.repeat('sgw'))

    def expand(self):

        #decomposition : square_root(n) round ver. (start)
        # skew_res = [program.curr_block.new_reg('sg') for i in range(3 * 64)]
        # x1_xor_x2 = [program.curr_block.new_reg('sg') for i in range(64)]
        # z = [program.curr_block.new_reg('sg') for i in range(64)]
        # in_c_left = [program.curr_block.new_reg('sg') for i in range(64)]
        # x1_xor_x3 = [program.curr_block.new_reg('sg') for i in range(64)]
        # in_c_prod = [program.curr_block.new_reg('sg') for i in range(64)]
        # c = [program.curr_block.new_reg('sg') for i in range(64 + 1)]
        #
        # c_xor_d = [[program.curr_block.new_reg('sg') for i in range(64)] for j in range(2)]
        # in_d_left = [[program.curr_block.new_reg('sg') for i in range(64)] for j in range(2)]
        # in_d_prod = [[program.curr_block.new_reg('sg') for i in range(64)] for j in range(2)]
        # c_xor_z = [program.curr_block.new_reg('sg') for i in range(64)]
        #
        # first_4bit_d = [program.curr_block.new_reg('sg') for i in range(5)]
        # d_4bit_block = [[program.curr_block.new_reg('sg') for i in range(5)] for j in range(2)]
        # d_5bit_block = [[program.curr_block.new_reg('sg') for i in range(6)] for j in range(2)]
        # d_6bit_block = [[program.curr_block.new_reg('sg') for i in range(7)] for j in range(2)]
        # d_7bit_block = [[program.curr_block.new_reg('sg') for i in range(8)] for j in range(2)]
        # d_8bit_block = [[program.curr_block.new_reg('sg') for i in range(9)] for j in range(2)]
        # d_9bit_block = [[program.curr_block.new_reg('sg') for i in range(10)] for j in range(2)]
        # d_10bit_block = [[program.curr_block.new_reg('sg') for i in range(11)] for j in range(2)]
        # d_11bit_block = [[program.curr_block.new_reg('sg') for i in range(12)] for j in range(2)]
        #
        # in_mux_right_4 = [program.curr_block.new_reg('sg') for i in range(5)]
        # in_mux_prod_4 = [program.curr_block.new_reg('sg') for i in range(5)]
        # in_mux_right_5 = [program.curr_block.new_reg('sg') for i in range(6)]
        # in_mux_prod_5 = [program.curr_block.new_reg('sg') for i in range(6)]
        # in_mux_right_6 = [program.curr_block.new_reg('sg') for i in range(7)]
        # in_mux_prod_6 = [program.curr_block.new_reg('sg') for i in range(7)]
        # in_mux_right_7 = [program.curr_block.new_reg('sg') for i in range(8)]
        # in_mux_prod_7 = [program.curr_block.new_reg('sg') for i in range(8)]
        # in_mux_right_8 = [program.curr_block.new_reg('sg') for i in range(9)]
        # in_mux_prod_8 = [program.curr_block.new_reg('sg') for i in range(9)]
        # in_mux_right_9 = [program.curr_block.new_reg('sg') for i in range(10)]
        # in_mux_prod_9 = [program.curr_block.new_reg('sg') for i in range(10)]
        # in_mux_right_10 = [program.curr_block.new_reg('sg') for i in range(11)]
        # in_mux_prod_10 = [program.curr_block.new_reg('sg') for i in range(11)]
        # in_mux_right_11 = [program.curr_block.new_reg('sg') for i in range(12)]
        # in_mux_prod_11 = [program.curr_block.new_reg('sg') for i in range(12)]
        #
        # e_skew_bit_dec(self.args[0], 64, *skew_res)
        #
        # gldsi(c[0], 0)
        # gldsi(first_4bit_d[0], 0)
        #
        # gldsi(d_4bit_block[0][0], 0)
        # gldsi(d_4bit_block[1][0], 1)
        #
        # gldsi(d_5bit_block[0][0], 0)
        # gldsi(d_5bit_block[1][0], 1)
        #
        # gldsi(d_6bit_block[0][0], 0)
        # gldsi(d_6bit_block[1][0], 1)
        #
        # gldsi(d_7bit_block[0][0], 0)
        # gldsi(d_7bit_block[1][0], 1)
        #
        # gldsi(d_8bit_block[0][0], 0)
        # gldsi(d_8bit_block[1][0], 1)
        #
        # gldsi(d_9bit_block[0][0], 0)
        # gldsi(d_9bit_block[1][0], 1)
        #
        # gldsi(d_10bit_block[0][0], 0)
        # gldsi(d_10bit_block[1][0], 1)
        #
        # gldsi(d_11bit_block[0][0], 0)
        # gldsi(d_11bit_block[1][0], 1)
        #
        # # compute all [z] and [c]
        # for j in range(64):
        #     # compute [z]
        #     gadds(x1_xor_x2[j], skew_res[3 * j], skew_res[3 * j + 1])
        #     gadds(z[j], skew_res[3 * j + 2], x1_xor_x2[j])
        #     # compute [c]
        #     gaddsi(in_c_left[j], x1_xor_x2[j], 1)
        #     gadds(x1_xor_x3[j], skew_res[3 * j], skew_res[3 * j + 2])
        #     ge_startmult(in_c_left[j], x1_xor_x3[j])
        #     ge_stopmult(in_c_prod[j])
        #     gadds(c[j + 1], in_c_prod[j], skew_res[3 * j + 2])
        #     # compute c_xor_z
        #     gadds(c_xor_z[j], c[j], z[j])
        #
        # # compute for first 4 bit and next 4bit
        # for j in range(4):
        #     # for frist_4_bit_d
        #     gadds(c_xor_d[0][j], c[j], first_4bit_d[j])
        #     gaddsi(in_d_left[0][j], c_xor_d[0][j], 1)
        #     ge_startmult(in_d_left[0][j], c_xor_z[j])
        #     ge_stopmult(in_d_prod[0][j])
        #     gadds(first_4bit_d[j + 1], in_d_prod[0][j], z[j])
        #     # compute [x|j]
        #     gadds(self.args[2 + j], c_xor_z[j], first_4bit_d[j])
        #
        #     for i in range(2):
        #         # for other block
        #         # first bit of 4bit_block = 4th bit
        #         gadds(c_xor_d[i][4+j], c[4+j], d_4bit_block[i][j])
        #         gaddsi(in_d_left[i][4+j], c_xor_d[i][4+j], 1)
        #         ge_startmult(in_d_left[i][4+j], c_xor_z[4+j])
        #         ge_stopmult(in_d_prod[i][4+j])
        #         gadds(d_4bit_block[i][j+1], in_d_prod[i][4+j], z[4+j])
        #
        # # compute for next 5bit
        # for j in range(5):
        #     for i in range(2):
        #         # first bit of 5bit_block = 8th bit
        #         gadds(c_xor_d[i][8+j], c[8+j], d_5bit_block[i][j])
        #         gaddsi(in_d_left[i][8+j], c_xor_d[i][8+j], 1)
        #         ge_startmult(in_d_left[i][8+j], c_xor_z[8+j])
        #         ge_stopmult(in_d_prod[i][8+j])
        #         gadds(d_5bit_block[i][j+1], in_d_prod[i][8+j], z[8+j])
        #
        # # compute for next 6bit
        # for j in range(6):
        #     for i in range(2):
        #         # first bit of 6bit_block = 13th bit
        #         gadds(c_xor_d[i][13+j], c[13+j], d_6bit_block[i][j])
        #         gaddsi(in_d_left[i][13+j], c_xor_d[i][13+j], 1)
        #         ge_startmult(in_d_left[i][13+j], c_xor_z[13+j])
        #         ge_stopmult(in_d_prod[i][13+j])
        #         gadds(d_6bit_block[i][j+1], in_d_prod[i][13+j], z[13+j])
        #
        # # compute for next 7bit
        # for j in range(7):
        #     for i in range(2):
        #         # first bit of 7bit_block = 19th bit
        #         gadds(c_xor_d[i][19+j], c[19+j], d_7bit_block[i][j])
        #         gaddsi(in_d_left[i][19+j], c_xor_d[i][19+j], 1)
        #         ge_startmult(in_d_left[i][19+j], c_xor_z[19+j])
        #         ge_stopmult(in_d_prod[i][19+j])
        #         gadds(d_7bit_block[i][j+1], in_d_prod[i][19+j], z[19+j])
        #
        # # compute for next 8bit
        # for j in range(8):
        #     for i in range(2):
        #         # first bit of 8bit_block = 26th bit
        #         gadds(c_xor_d[i][26 + j], c[26 + j], d_8bit_block[i][j])
        #         gaddsi(in_d_left[i][26 + j], c_xor_d[i][26 + j], 1)
        #         ge_startmult(in_d_left[i][26 + j], c_xor_z[26 + j])
        #         ge_stopmult(in_d_prod[i][26 + j])
        #         gadds(d_8bit_block[i][j + 1], in_d_prod[i][26 + j], z[26 + j])
        #
        # # compute for next 9bit
        # for j in range(9):
        #     for i in range(2):
        #         # first bit of 9bit_block = 34th bit
        #         gadds(c_xor_d[i][34 + j], c[34 + j], d_9bit_block[i][j])
        #         gaddsi(in_d_left[i][34 + j], c_xor_d[i][34 + j], 1)
        #         ge_startmult(in_d_left[i][34 + j], c_xor_z[34 + j])
        #         ge_stopmult(in_d_prod[i][34 + j])
        #         gadds(d_9bit_block[i][j + 1], in_d_prod[i][34 + j], z[34 + j])
        #
        # # compute for next 10bit
        # for j in range(10):
        #     for i in range(2):
        #         # first bit of 10bit_block = 43th bit
        #         gadds(c_xor_d[i][43 + j], c[43 + j], d_10bit_block[i][j])
        #         gaddsi(in_d_left[i][43 + j], c_xor_d[i][43 + j], 1)
        #         ge_startmult(in_d_left[i][43 + j], c_xor_z[43 + j])
        #         ge_stopmult(in_d_prod[i][43 + j])
        #         gadds(d_10bit_block[i][j + 1], in_d_prod[i][43 + j], z[43 + j])
        #
        # # compute for next 11bit
        # for j in range(11):
        #     for i in range(2):
        #         # first bit of 11bit_block = 53th bit
        #         gadds(c_xor_d[i][53 + j], c[53 + j], d_11bit_block[i][j])
        #         gaddsi(in_d_left[i][53 + j], c_xor_d[i][53 + j], 1)
        #         ge_startmult(in_d_left[i][53 + j], c_xor_z[53 + j])
        #         ge_stopmult(in_d_prod[i][53 + j])
        #         gadds(d_11bit_block[i][j + 1], in_d_prod[i][53 + j], z[53 + j])
        #
        # # connect first 4bit and next 4bit block
        # selected_d_4bit_block = [program.curr_block.new_reg('sg') for i in range(5)]
        # for j in range(5):
        #     # compute MUX
        #     gadds(in_mux_right_4[j], d_4bit_block[0][j], d_4bit_block[1][j])
        #     ge_startmult(in_mux_right_4[j], first_4bit_d[4])
        #     ge_stopmult(in_mux_prod_4[j])
        #     gadds(selected_d_4bit_block[j], in_mux_prod_4[j], d_4bit_block[0][j])
        #     if j < 4:
        #         # compute [x|j]
        #         gadds(self.args[2 + (4 + j)], c_xor_z[4 + j], selected_d_4bit_block[j])
        #
        # # connect 4bit block and next 5bit block
        # selected_d_5bit_block = [program.curr_block.new_reg('sg') for i in range(6)]
        # for j in range(6):
        #     # compute MUX
        #     gadds(in_mux_right_5[j], d_5bit_block[0][j], d_5bit_block[1][j])
        #     ge_startmult(in_mux_right_5[j], selected_d_4bit_block[4])
        #     ge_stopmult(in_mux_prod_5[j])
        #     gadds(selected_d_5bit_block[j], in_mux_prod_5[j], d_5bit_block[0][j])
        #     if j < 5:
        #         # compute [x|j]
        #         gadds(self.args[2 + (8 + j)], c_xor_z[8 + j], selected_d_5bit_block[j])
        #
        # # connect 5bit block and next 6bit block
        # selected_d_6bit_block = [program.curr_block.new_reg('sg') for i in range(7)]
        # for j in range(7):
        #     # compute MUX
        #     gadds(in_mux_right_6[j], d_6bit_block[0][j], d_6bit_block[1][j])
        #     ge_startmult(in_mux_right_6[j], selected_d_5bit_block[5])
        #     ge_stopmult(in_mux_prod_6[j])
        #     gadds(selected_d_6bit_block[j], in_mux_prod_6[j], d_6bit_block[0][j])
        #     if j < 6:
        #         # compute [x|j]
        #         gadds(self.args[2 + (13 + j)], c_xor_z[13 + j], selected_d_6bit_block[j])
        #
        # # connect 6bit block and next 7bit block
        # selected_d_7bit_block = [program.curr_block.new_reg('sg') for i in range(8)]
        # for j in range(8):
        #     # compute MUX
        #     gadds(in_mux_right_7[j], d_7bit_block[0][j], d_7bit_block[1][j])
        #     ge_startmult(in_mux_right_7[j], selected_d_6bit_block[6])
        #     ge_stopmult(in_mux_prod_7[j])
        #     gadds(selected_d_7bit_block[j], in_mux_prod_7[j], d_7bit_block[0][j])
        #     if j < 7:
        #         # compute [x|j]
        #         gadds(self.args[2 + (19 + j)], c_xor_z[19 + j], selected_d_7bit_block[j])
        #
        # # connect 7bit block and next 8bit block
        # selected_d_8bit_block = [program.curr_block.new_reg('sg') for i in range(9)]
        # for j in range(9):
        #     # compute MUX
        #     gadds(in_mux_right_8[j], d_8bit_block[0][j], d_8bit_block[1][j])
        #     ge_startmult(in_mux_right_8[j], selected_d_7bit_block[7])
        #     ge_stopmult(in_mux_prod_8[j])
        #     gadds(selected_d_8bit_block[j], in_mux_prod_8[j], d_8bit_block[0][j])
        #     if j < 8:
        #         # compute [x|j]
        #         gadds(self.args[2 + (26 + j)], c_xor_z[26 + j], selected_d_8bit_block[j])
        #
        # # connect 8bit block and next 9bit block
        # selected_d_9bit_block = [program.curr_block.new_reg('sg') for i in range(10)]
        # for j in range(10):
        #     # compute MUX
        #     gadds(in_mux_right_9[j], d_9bit_block[0][j], d_9bit_block[1][j])
        #     ge_startmult(in_mux_right_9[j], selected_d_8bit_block[8])
        #     ge_stopmult(in_mux_prod_9[j])
        #     gadds(selected_d_9bit_block[j], in_mux_prod_9[j], d_9bit_block[0][j])
        #     if j < 9:
        #         # compute [x|j]
        #         gadds(self.args[2 + (34 + j)], c_xor_z[34 + j], selected_d_9bit_block[j])
        #
        # # connect 9bit block and next 10bit block
        # selected_d_10bit_block = [program.curr_block.new_reg('sg') for i in range(11)]
        # for j in range(11):
        #     # compute MUX
        #     gadds(in_mux_right_10[j], d_10bit_block[0][j], d_10bit_block[1][j])
        #     ge_startmult(in_mux_right_10[j], selected_d_9bit_block[9])
        #     ge_stopmult(in_mux_prod_10[j])
        #     gadds(selected_d_10bit_block[j], in_mux_prod_10[j], d_10bit_block[0][j])
        #     if j < 10:
        #         # compute [x|j]
        #         gadds(self.args[2 + (43 + j)], c_xor_z[43 + j], selected_d_10bit_block[j])
        #
        # # connect 10bit block and next 11bit block
        # selected_d_11bit_block = [program.curr_block.new_reg('sg') for i in range(12)]
        # for j in range(11):
        #     # compute MUX
        #     gadds(in_mux_right_11[j], d_11bit_block[0][j], d_11bit_block[1][j])
        #     ge_startmult(in_mux_right_11[j], selected_d_10bit_block[10])
        #     ge_stopmult(in_mux_prod_11[j])
        #     gadds(selected_d_11bit_block[j], in_mux_prod_11[j], d_11bit_block[0][j])
        #     # compute [x|j]
        #     gadds(self.args[2 + (53 + j)], c_xor_z[53 + j], selected_d_11bit_block[j])
        #decomposition : square_root(n) round ver. (end)

        #decomposition : log(n) round ver. (start)
        # log_val = int(math.ceil(math.log(self.args[1], 2)))
        #
        # skew_res = [program.curr_block.new_reg('sg') for i in range(3 * self.args[1])]
        # x1_xor_x2 = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        # z = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        # in_c_left = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        # x1_xor_x3 = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        # in_c_prod = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        # c = [program.curr_block.new_reg('sg') for i in range(self.args[1] + 1)]
        # c_xor_z = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        #
        # c_xor_d = [[[program.curr_block.new_reg('sg') for i in range(self.args[1])] for j in range(2)] for k in range(log_val)]
        # in_d_left = [[[program.curr_block.new_reg('sg') for i in range(self.args[1])] for j in range(2)] for k in range(log_val)]
        # in_d_prod = [[[program.curr_block.new_reg('sg') for i in range(self.args[1])] for j in range(2)] for k in range(log_val)]
        # d = [[[program.curr_block.new_reg('sg') for i in range(self.args[1] + 1)] for j in range(2)] for k in range(log_val)]
        #
        # in_mux_right = [[[program.curr_block.new_reg('sg') for i in range(self.args[1] + 1)] for j in range(2)] for k in range(log_val)]
        # in_mux_prod = [[[program.curr_block.new_reg('sg') for i in range(self.args[1] + 1)] for j in range(2)] for k in range(log_val)]
        #
        # gldsi(c[0],0)
        # gldsi(d[log_val - 1][0][0], 0)
        #
        # e_skew_bit_dec(self.args[0], self.args[1], *skew_res)
        #
        # # compute all [z] and [c]
        # for j in range(self.args[1]):
        #     # compute [z]
        #     gadds(x1_xor_x2[j], skew_res[3 * j], skew_res[3 * j + 1])
        #     gadds(z[j], skew_res[3 * j + 2], x1_xor_x2[j])
        #     # compute [c]
        #     gaddsi(in_c_left[j], x1_xor_x2[j], 1)
        #     gadds(x1_xor_x3[j], skew_res[3 * j], skew_res[3 * j + 2])
        #     ge_startmult(in_c_left[j], x1_xor_x3[j])
        #     ge_stopmult(in_c_prod[j])
        #     gadds(c[j + 1], in_c_prod[j], skew_res[3 * j + 2])
        #     # compute c_xor_z
        #     gadds(c_xor_z[j], c[j], z[j])
        #
        # # compute all [d] -- assume that self.args[1] >= 8
        # for k in range(log_val - 1):
        #     valid_carry_idx = 2 ** (k + 1)
        #     # print("valid_carry_idx = {0}".format(valid_carry_idx))
        #     if k == 0:
        #         # compute candidate of [d]
        #         for j in range(2):
        #             for i in range(self.args[1]):
        #                 if (j == 0) and (i == 0):
        #                     gadds(c_xor_d[k][0][i], c[i], d[log_val - 1][0][i])
        #                     gaddsi(in_d_left[k][0][i], c_xor_d[k][0][i], 1)
        #                     ge_startmult(in_d_left[k][0][i], c_xor_z[i])
        #                     ge_stopmult(in_d_prod[k][0][i])
        #                     gadds(d[log_val - 1][0][i+1], in_d_prod[k][0][i], z[i])
        #                 elif (j == 0) and (i == 1):
        #                     gadds(c_xor_d[k][0][i], c[i], d[log_val - 1][0][i])
        #                     gaddsi(in_d_left[k][0][i], c_xor_d[k][0][i], 1)
        #                     ge_startmult(in_d_left[k][0][i], c_xor_z[i])
        #                     ge_stopmult(in_d_prod[k][0][i])
        #                     gadds(d[log_val - 1][0][i+1], in_d_prod[k][0][i], z[i])
        #                 elif (i >= 2) and (i % 2 == 0):
        #                     gaddsi(c_xor_d[k][j][i], c[i], j)
        #                     gaddsi(in_d_left[k][j][i], c_xor_d[k][j][i], 1)
        #                     ge_startmult(in_d_left[k][j][i], c_xor_z[i])
        #                     ge_stopmult(in_d_prod[k][j][i])
        #                     gadds(d[k][j][i+1], in_d_prod[k][j][i], z[i])
        #
        #                 elif (i >= 2) and (i % 2 == 1):
        #                     gadds(c_xor_d[k][j][i], c[i], d[k][j][i])
        #                     gaddsi(in_d_left[k][j][i], c_xor_d[k][j][i], 1)
        #                     ge_startmult(in_d_left[k][j][i], c_xor_z[i])
        #                     ge_stopmult(in_d_prod[k][j][i])
        #                     gadds(d[k][j][i+1], in_d_prod[k][j][i], z[i])
        #
        #         # select and connect blocks of [d]
        #         for j in range(2):
        #             for i in range(1, self.args[1]):
        #                 if (j == 0) and (i == valid_carry_idx):
        #                     for connect_idx in range(valid_carry_idx, 2 * valid_carry_idx):
        #                         # compute MUX
        #                         gadds(in_mux_right[k][j][connect_idx + 1], d[k][0][connect_idx + 1], d[k][1][connect_idx + 1])
        #                         ge_startmult(in_mux_right[k][j][connect_idx + 1], d[log_val - 1][0][i])
        #                         ge_stopmult(in_mux_prod[k][j][connect_idx + 1])
        #                         gadds(d[log_val - 1][0][connect_idx + 1], in_mux_prod[k][j][connect_idx + 1], d[k][0][connect_idx + 1])
        #                 elif (i >= 2 * valid_carry_idx) and (i % (2 * valid_carry_idx) == valid_carry_idx -1):
        #                     d[k + 1][j][i] = d[k][j][i]
        #                 elif (i >= 2 * valid_carry_idx) and (i % (2 * valid_carry_idx) == valid_carry_idx):
        #                     for connect_idx in range(i, i + valid_carry_idx):
        #                         # compute MUX
        #                         gadds(in_mux_right[k][j][connect_idx + 1], d[k][0][connect_idx + 1], d[k][1][connect_idx + 1])
        #                         ge_startmult(in_mux_right[k][j][connect_idx + 1], d[k][j][i])
        #                         ge_stopmult(in_mux_prod[k][j][connect_idx + 1])
        #                         gadds(d[k + 1][j][connect_idx + 1], in_mux_prod[k][j][connect_idx + 1], d[k][0][connect_idx + 1])
        #                         if connect_idx == i:
        #                             d[k+1][j][i] = d[k][j][i]
        #     else:
        #         # select and connect blocks of [d]
        #         for j in range(2):
        #             count = 1
        #             for i in range(1, self.args[1]):
        #                 finished_block = 2 * count
        #                 if (j == 0) and (i == valid_carry_idx):
        #                     for connect_idx in range(valid_carry_idx, 2 * valid_carry_idx):
        #                         # compute MUX
        #                         gadds(in_mux_right[k][j][connect_idx + 1], d[k][0][connect_idx + 1], d[k][1][connect_idx + 1])
        #                         ge_startmult(in_mux_right[k][j][connect_idx + 1], d[log_val - 1][0][i])
        #                         ge_stopmult(in_mux_prod[k][j][connect_idx + 1])
        #                         gadds(d[log_val - 1][0][connect_idx + 1], in_mux_prod[k][j][connect_idx + 1], d[k][0][connect_idx + 1])
        #                 elif (i >= finished_block * valid_carry_idx) and (i % (2 * valid_carry_idx) > 0) and (i % (2 * valid_carry_idx) <= valid_carry_idx - 1) and (k <= (log_val - 2)):
        #                     d[k + 1][j][i] = d[k][j][i]
        #                 elif (i >= finished_block * valid_carry_idx) and (i % (2 * valid_carry_idx) >= valid_carry_idx) and (k <= (log_val - 2)):
        #                     for connect_idx in range(i, i + valid_carry_idx):
        #                         # compute MUX
        #                         gadds(in_mux_right[k][j][connect_idx + 1], d[k][0][connect_idx + 1], d[k][1][connect_idx + 1])
        #                         ge_startmult(in_mux_right[k][j][connect_idx + 1], d[k][j][i])
        #                         ge_stopmult(in_mux_prod[k][j][connect_idx + 1])
        #                         gadds(d[k + 1][j][connect_idx + 1], in_mux_prod[k][j][connect_idx + 1], d[k][0][connect_idx + 1])
        #                         if connect_idx == i:
        #                             d[k + 1][j][i] = d[k][j][i]
        #                         if connect_idx == i + valid_carry_idx - 1:
        #                             count += 1
        # # compute [x|j]
        # for i in range(self.args[1]):
        #     gadds(self.args[2 + i], c_xor_z[i], d[log_val - 1][0][i])
        # decomposition : log(n) round ver. (end)

        # decomposition : n-1 round ver. (start)
        skew_res = [program.curr_block.new_reg('sg') for i in range(3 * self.args[1])]
        x1_xor_x2 = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        z = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        in_c_left = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        x1_xor_x3 = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        in_c_prod = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        c = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        c_xor_d = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        in_d_left = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        in_d_prod = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        c_xor_z = [program.curr_block.new_reg('sg') for i in range(self.args[1])]
        d = [program.curr_block.new_reg('sg') for i in range(self.args[1])]


        e_skew_bit_dec(self.args[0], self.args[1], *skew_res)
        gldsi(c[0], 0)
        gldsi(d[0], 0)

        for j in range(self.args[1]):
            if self.args[1] == 1:
                gadds(x1_xor_x2[j], skew_res[3 * j], skew_res[3 * j + 1])
                gadds(self.args[2 + j], skew_res[3 * j + 2], x1_xor_x2[j])
            else:
                if j == self.args[1] - 1:
                    # compute [z]
                    gadds(x1_xor_x2[j], skew_res[3 * j], skew_res[3 * j + 1])
                    gadds(z[j], skew_res[3 * j + 2], x1_xor_x2[j])
                    # compute c_xor_d[j]
                    gadds(c_xor_d[j], c[j], d[j])
                    # compute [x|j]
                    gadds(self.args[2 + j], z[j], c_xor_d[j])
                else:
                    # compute [z]
                    gadds(x1_xor_x2[j], skew_res[3 * j], skew_res[3 * j + 1])
                    gadds(z[j], skew_res[3 * j + 2], x1_xor_x2[j])
                    # compute [c]
                    gaddsi(in_c_left[j], x1_xor_x2[j], 1)
                    gadds(x1_xor_x3[j], skew_res[3 * j], skew_res[3 * j + 2])
                    ge_startmult(in_c_left[j], x1_xor_x3[j])
                    ge_stopmult(in_c_prod[j])
                    gadds(c[j+1], in_c_prod[j], skew_res[3 * j + 2])
                    # compute [d]
                    gadds(c_xor_d[j], c[j], d[j])
                    gaddsi(in_d_left[j], c_xor_d[j], 1)
                    gadds(c_xor_z[j], c[j], z[j])
                    ge_startmult(in_d_left[j], c_xor_z[j])
                    ge_stopmult(in_d_prod[j])
                    gadds(d[j + 1], in_d_prod[j], z[j])
                    # compute [x|j]
                    gadds(self.args[2 + j], z[j], c_xor_d[j])
        # decomposition : n-1 round ver. (end)


#@base.gf2n
@base.vectorize
class e_bitinj(base.CISC):
    r""" Convert a share mod 2 to the share mod 2^n """
    __slots__ = []
    code = base.opcodes['E_BITINJ']
    arg_format = ['sg', 'sw']
    def expand(self):

        x1 = program.curr_block.new_reg('s')
        x2 = program.curr_block.new_reg('s')
        x3 = program.curr_block.new_reg('s')

        sum12 = program.curr_block.new_reg('s')
        sum123 = program.curr_block.new_reg('s')

        prod12 = program.curr_block.new_reg('s')

        twice_prod12 = program.curr_block.new_reg('s')
        twice_x3 = program.curr_block.new_reg('s')

        round2_right = program.curr_block.new_reg('s')
        round2_prod = program.curr_block.new_reg('s')

        res_left = program.curr_block.new_reg('s')

        #e_skew_inj(self.args[0], x1, x2, x3)
        e_skew_bit_inj(self.args[0], x1, x2, x3)

        # compute [x1] + [x2] +[x3]
        adds(sum12, x1, x2)
        adds(sum123, x3, sum12)

        # compute [x1] * [x2]
        e_startmult(x1, x2)
        e_stopmult(prod12)

        # * 2
        mulsi(twice_prod12, prod12, 2)
        mulsi(twice_x3, x3, 2)

        # compute ([x1] + [x2] - 2 * [x1] * [x2])
        subs(round2_right, sum12, twice_prod12)

        e_startmult(twice_x3, round2_right)
        e_stopmult(round2_prod)

        # compute result
        subs(res_left, sum123, twice_prod12)
        subs(self.args[1], res_left, round2_prod)

        """
        
        # DEBUG MODE
        x1 = program.curr_block.new_reg('s')
        x2 = program.curr_block.new_reg('s')
        x3 = program.curr_block.new_reg('s')

        c1 = program.curr_block.new_reg('c')
        c2 = program.curr_block.new_reg('c')
        c3 = program.curr_block.new_reg('c')
        c_sum123 = program.curr_block.new_reg('c')
        c_prod12 = program.curr_block.new_reg('c')
        c_twice_prod12 = program.curr_block.new_reg('c')
        c_twice_x3 = program.curr_block.new_reg('c')
        c_round2_right = program.curr_block.new_reg('c')
        c_round2_prod = program.curr_block.new_reg('c')

        sum12 = program.curr_block.new_reg('s')
        sum123 = program.curr_block.new_reg('s')

        prod12 = program.curr_block.new_reg('s')

        twice_prod12 = program.curr_block.new_reg('s')
        twice_x3 = program.curr_block.new_reg('s')

        round2_right = program.curr_block.new_reg('s')
        round2_prod = program.curr_block.new_reg('s')

        res_left = program.curr_block.new_reg('s')

        e_skew_inj(self.args[0], x1, x2, x3)

        # DEBUG (START)
        startopen(x1, x2, x3)
        stopopen(c1, c2, c3)
        print_reg_plain(c1)
        print_char('\n')
        print_reg_plain(c2)
        print_char('\n')
        print_reg_plain(c3)
        print_char('\n')
        # DEBUG (END)

        # compute [x1] + [x2] +[x3]
        adds(sum12, x1, x2)
        adds(sum123, x3, sum12)

        # DEBUG (START)
        startopen(sum123)
        stopopen(c_sum123)
        print_reg_plain(c_sum123)
        print_char('\n')
        # DEBUG (END)

        # compute [x1] * [x2]
        e_startmult(x1, x2)
        e_stopmult(prod12)

        # DEBUG (START)
        startopen(prod12)
        stopopen(c_prod12)
        print_reg_plain(c_prod12)
        print_char('\n')
        # DEBUG (END)

        # * 2
        mulsi(twice_prod12, prod12, 2)
        mulsi(twice_x3, x3, 2)

        # DEBUG (START)
        startopen(twice_prod12, twice_x3)
        stopopen(c_twice_prod12, c_twice_x3)
        print_reg_plain(c_twice_prod12)
        print_char('\n')
        print_reg_plain(c_twice_x3)
        print_char('\n')
        # DEBUG (END)

        # compute ([x1] + [x2] - 2 * [x1] * [x2])
        subs(round2_right, sum12, twice_prod12)

        # DEBUG (START)
        startopen(round2_right)
        stopopen(c_round2_right)
        print_reg_plain(c_round2_right)
        print_char('\n')
        # DEBUG (END)

        e_startmult(twice_x3, round2_right)
        e_stopmult(round2_prod)

        # DEBUG (START)
        startopen(round2_prod)
        stopopen(c_round2_prod)
        print_reg_plain(c_round2_prod)
        print_char('\n')
        # DEBUG (END)

        # compute result
        subs(res_left, sum123, twice_prod12)
        subs(self.args[1], res_left, round2_prod)
        """


@base.vectorize
class e_bitrec(base.CISC):
    r""" Convert an n-array of shares mod 2 to a share mod 2^n. """
    __slots__ = []
    code = base.opcodes['E_BITREC']
    arg_format = tools.chain(['sw', 'int'], itertools.repeat('sg'))

    def expand(self):
        # self.args[1] is the number of array's elements
        # assume that 0 < self.args[1] <= ring_size

        # re-composition using bit-injection (start)
        # injected_a = [program.curr_block.new_reg('s') for i in range(self.args[1])]
        # two_power_a = [program.curr_block.new_reg('s') for i in range(self.args[1])]
        # res = [program.curr_block.new_reg('s') for i in range(self.args[1])]
        #
        # if self.args[1] > 1:
        #     for i in range(self.args[1]):
        #         e_bitinj(self.args[2+i], injected_a[i])
        #         if i == 0:
        #             two_power_a[i] = injected_a[i]
        #         elif i == 1:
        #             mulsi(two_power_a[i], injected_a[i], 2)
        #         else:
        #             tmp_two_power_a = [program.curr_block.new_reg('s') for z in range(i+1)]
        #             for j in range(i+1):
        #                 if j == 0:
        #                     tmp_two_power_a[j] = injected_a[i]
        #                 elif j == i:
        #                     mulsi(two_power_a[i], tmp_two_power_a[j - 1], 2)
        #                 else:
        #                     mulsi(tmp_two_power_a[j], tmp_two_power_a[j - 1], 2)
        #
        #     res[0] = two_power_a[0]
        #     for i in range(1, self.args[1]):
        #         if i == self.args[1] - 1:
        #             adds(self.args[0], two_power_a[i], res[i - 1])
        #         elif i == 1:
        #             adds(res[i], two_power_a[i], two_power_a[i - 1])
        #         else:
        #             adds(res[i], two_power_a[i], res[i - 1])
        # else:
        #     e_bitinj(self.args[2], self.args[0])
        # re-composition using bit-injection (end)

        # re-composition: n-1 round ver. (end)
        ring_size = 64

        bit_s = [program.curr_block.new_reg('sg') for i in range(ring_size)]
        c_xor_d = [program.curr_block.new_reg('sg') for i in range(ring_size)]

        x1 = [program.curr_block.new_reg('sg') for i in range(ring_size)]
        x2 = [program.curr_block.new_reg('sg') for i in range(ring_size)]
        x3 = [program.curr_block.new_reg('sg') for i in range(ring_size)]

        x12 = [program.curr_block.new_reg('sg') for i in range(ring_size)]
        x13 = [program.curr_block.new_reg('sg') for i in range(ring_size)]

        in1_left = [program.curr_block.new_reg('sg') for i in range(ring_size)]
        c = [program.curr_block.new_reg('sg') for i in range(ring_size + 1)]
        c_left = [program.curr_block.new_reg('sg') for i in range(ring_size)]

        in2_left = [program.curr_block.new_reg('sg') for i in range(ring_size)]
        in2_right = [program.curr_block.new_reg('sg') for i in range(ring_size)]
        d = [program.curr_block.new_reg('sg') for i in range(ring_size + 1)]
        d_left = [program.curr_block.new_reg('sg') for i in range(ring_size)]

        zero_shares = [program.curr_block.new_reg('sg') for i in range(ring_size - self.args[1])]

        gldsi(c[0], 0)
        gldsi(d[0], 0)

        for j in range(ring_size - self.args[1]):
            gldsi(zero_shares[j], 0)

        for j in range(ring_size):
            if j == 0:
                gadds(c_xor_d[j], c[j], d[j])
                gadds(bit_s[j], c_xor_d[j], self.args[2 + j])

                e_skew_bit_rec(bit_s[j], x1[j], x2[j], x3[j])

                # compute 1bit carry "c"
                gadds(x12[j], x1[j], x2[j])

                gaddsi(in1_left[j], x12[j], 1)

                gadds(x13[j], x1[j], x3[j])

                ge_startmult(in1_left[j], x13[j])
                ge_stopmult(c_left[j])

                gadds(c[j + 1], c_left[j], x3[j])

                # compute 2bit carry "d"
                gaddsi(in2_left[j], c_xor_d[j], 1)

                gadds(in2_right[j], c[j], bit_s[j])

                ge_startmult(in2_left[j], in2_right[j])
                ge_stopmult(d_left[j])

                gadds(d[j + 1], d_left[j], bit_s[j])

            elif j == ring_size - 1:
                if j < self.args[1]:
                    gadds(c_xor_d[j], c[j], d[j])

                    gadds(bit_s[j], c_xor_d[j], self.args[2 + j])

                else:
                    gadds(c_xor_d[j], c[j], d[j])

                    gadds(bit_s[j], c_xor_d[j], zero_shares[j - self.args[1]])

                # compute 1bit carry "c" - skip
                # compute 2bit carry "d" - skip
            else:
                if j < self.args[1]:
                    gadds(c_xor_d[j], c[j], d[j])
                    gadds(bit_s[j], c_xor_d[j], self.args[2 + j])
                else:
                    gadds(c_xor_d[j], c[j], d[j])
                    gadds(bit_s[j], c_xor_d[j], zero_shares[j - self.args[1]])

                e_skew_bit_rec(bit_s[j], x1[j], x2[j], x3[j])

                # compute 1bit carry "c"
                gadds(x12[j], x1[j], x2[j])
                gaddsi(in1_left[j], x12[j], 1)
                gadds(x13[j], x1[j], x3[j])

                ge_startmult(in1_left[j], x13[j])
                ge_stopmult(c_left[j])
                gadds(c[j + 1], c_left[j], x3[j])
                # compute 2bit carry "d"
                gaddsi(in2_left[j], c_xor_d[j], 1)
                gadds(in2_right[j], c[j], bit_s[j])
                ge_startmult(in2_left[j], in2_right[j])
                ge_stopmult(d_left[j])

                gadds(d[j + 1], d_left[j], bit_s[j])

        e_skew_ring_rec(self.args[0], ring_size, *bit_s)
        # re-composition: n-1 round ver. (end)



#@base.gf2n
@base.vectorize
class e_read_from_file(base.CISC):
    r""" Convert a share mod 2^n to n-array of shares mod 2. """
    __slots__ = []
    code = base.opcodes['E_READ_FROM_FILE']
    arg_format = tools.chain(['s', 'int', 'int'], itertools.repeat('sw'))

    def expand(self):
        res = [program.curr_block.new_reg('s') for i in range(self.args[2])]
        for j in range(self.args[2]):
            res[j] = self.args[3+j]
        e_input_share_int(self.args[1], self.args[2], *res)

@base.vectorize
class ge_read_from_file(base.CISC):
    r""" Convert a share mod 2^n to n-array of shares mod 2. """
    __slots__ = []
    code = base.opcodes['GE_READ_FROM_FILE']
    arg_format = tools.chain(['sg', 'int', 'int'], itertools.repeat('sgw'))

    def expand(self):
        res = [program.curr_block.new_reg('sg') for i in range(self.args[2])]
        for j in range(self.args[2]):
            res[j] = self.args[3+j]
        ge_input_share_int(self.args[1], self.args[2], *res)


#@base.vectorize
#class e_ringcmp(base.Instruction):
    #r""" Convert an n-array of shares mod 2 to a share mod 2^n. """
    #__slots__ = []
    #code = base.opcodes['E_RING_CMP']
    #arg_format = tools.chain(['sw', 'int'], itertools.repeat('sg'))

@base.vectorize
class e_input_share_int(base.Instruction):
    r""" Read input from file as token. """
    __slots__ = []
    code = base.opcodes['E_INPUT_SHARE_INT']
    arg_format = tools.chain(['int', 'int'], itertools.repeat('sw'))

@base.vectorize
class ge_input_share_int(base.Instruction):
    r""" Read input from file as token. """
    __slots__ = []
    code = base.opcodes['GE_INPUT_SHARE_INT']
    arg_format = tools.chain(['int', 'int'], itertools.repeat('sgw'))


@base.vectorize
class e_multi_startmult(startopen_class):
    """ Start opening secret register $s_i$. """
    __slots__ = []
    code = base.opcodes['E_MULTI_STARTMULT']
    arg_format = itertools.repeat('s')

@base.vectorize
class e_multi_stopmult(stopopen_class):
    """ Store previous opened value in $c_i$. """
    __slots__ = []
    code = base.opcodes['E_MULTI_STOPMULT']
    arg_format = itertools.repeat('sw')

@base.gf2n
@base.vectorize
class e_startmult(startopen_class):
    """ Start opening secret register $s_i$. """
    __slots__ = []
    code = base.opcodes['E_STARTMULT']
    arg_format = itertools.repeat('s')

@base.gf2n
@base.vectorize
class e_stopmult(stopopen_class):
    """ Store previous opened value in $c_i$. """
    __slots__ = []
    code = base.opcodes['E_STOPMULT']
    arg_format = itertools.repeat('sw')

@base.gf2n
@base.vectorize
class muls(base.CISC):
    """ Secret multiplication $s_i = s_j \cdot s_k$. """
    __slots__ = []
    arg_format = ['sw','s','s']

    def expand(self):
        e_startmult(self.args[1],self.args[2])
        e_stopmult(self.args[0])

        """
        s = [program.curr_block.new_reg('s') for i in range(9)]
        c = [program.curr_block.new_reg('c') for i in range(3)]
        triple(s[0], s[1], s[2])
        subs(s[3], self.args[1], s[0])
        subs(s[4], self.args[2], s[1])
        startopen(s[3], s[4])
        stopopen(c[0], c[1])
        mulm(s[5], s[1], c[0])
        mulm(s[6], s[0], c[1])
        mulc(c[2], c[0], c[1])
        adds(s[7], s[2], s[5])
        adds(s[8], s[7], s[6])
        addm(self.args[0], s[8], c[2])
        """

        """ Extended (NEC) secret multiplication $s_i = s_j \cdot s_k$. """
        #emuls(self.args[0],self.args[1],self.args[2])
        """
        s = [program.curr_block.new_reg('s') for i in range(9)]
        c = [program.curr_block.new_reg('c') for i in range(3)]
        triple(s[0], s[1], s[2])
        esubs(s[3], self.args[1], s[0])
        esubs(s[4], self.args[2], s[1])
        estartopen(s[3], s[4])
        estopopen(c[0], c[1])
        emulm(s[5], s[1], c[0])
        emulm(s[6], s[0], c[1])
        mulc(c[2], c[0], c[1])
        eadds(s[7], s[2], s[5])
        eadds(s[8], s[7], s[6])
        eaddm(self.args[0], s[8], c[2])
        """

#@base.gf2n
#@base.vectorize
#class emuls(base.AddBase):
    """ Secret multiplication $s_i = s_j \cdot s_k$. """
#    code = base.opcodes['EMULS']
#    __slots__ = []
#    arg_format = ['sw','s','s']

@base.gf2n
@base.vectorize
class sqrs(base.CISC):
    """ Secret squaring $s_i = s_j \cdot s_j$. """
    __slots__ = []
    arg_format = ['sw', 's']
    
    def expand(self):
        s = [program.curr_block.new_reg('s') for i in range(6)]
        c = [program.curr_block.new_reg('c') for i in range(2)]
        square(s[0], s[1])
        subs(s[2], self.args[1], s[0])
        asm_open(c[0], s[2])
        mulc(c[1], c[0], c[0])
        mulm(s[3], self.args[1], c[0])
        adds(s[4], s[3], s[3])
        adds(s[5], s[1], s[4])
        subml(self.args[0], s[5], c[1])


@base.gf2n
@base.vectorize
class lts(base.CISC):
    """ Secret comparison $s_i = (s_j < s_k)$. """
    __slots__ = []
    arg_format = ['sw', 's', 's', 'int', 'int']

    def expand(self):
        a = program.curr_block.new_reg('s')
        subs(a, self.args[1], self.args[2])
        comparison.LTZ(self.args[0], a, self.args[3], self.args[4])

@base.vectorize
class g2muls(base.CISC):
    r""" Secret GF(2) multiplication """
    __slots__ = []
    arg_format = ['sgw','sg','sg']

    def expand(self):
        s = [program.curr_block.new_reg('sg') for i in range(9)]
        c = [program.curr_block.new_reg('cg') for i in range(3)]
        gbittriple(s[0], s[1], s[2])
        gsubs(s[3], self.args[1], s[0])
        gsubs(s[4], self.args[2], s[1])
        gstartopen(s[3], s[4])
        gstopopen(c[0], c[1])
        gmulbitm(s[5], s[1], c[0])
        gmulbitm(s[6], s[0], c[1])
        gmulbitc(c[2], c[0], c[1])
        gadds(s[7], s[2], s[5])
        gadds(s[8], s[7], s[6])
        gaddm(self.args[0], s[8], c[2])

#@base.vectorize
#class gmulbits(base.CISC):
#    r""" Secret $GF(2^n) \times GF(2)$ multiplication """
#    __slots__ = []
#    arg_format = ['sgw','sg','sg']
#
#    def expand(self):
#        s = [program.curr_block.new_reg('s') for i in range(9)]
#        c = [program.curr_block.new_reg('c') for i in range(3)]
#        g2ntriple(s[0], s[1], s[2])
#        subs(s[3], self.args[1], s[0])
#        subs(s[4], self.args[2], s[1])
#        startopen(s[3], s[4])
#        stopopen(c[0], c[1])
#        mulm(s[5], s[1], c[0])
#        mulm(s[6], s[0], c[1])
#        mulc(c[2], c[0], c[1])
#        adds(s[7], s[2], s[5])
#        adds(s[8], s[7], s[6])
#        addm(self.args[0], s[8], c[2])

# hack for circular dependency
from Compiler import comparison

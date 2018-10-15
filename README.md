# SPDZ-2-With Extensions for Ring

A fork of the University Of Bristol SPDZ-2 Repository, with changes to support extending the SPDZ-2 Framework to run additional protocols. Changes performed by Bar Ilan Cryptography Research Group and NEC Security Research Labs. This code is used in the publication "Generalizing the SPDZ Compiler For Other Protocols" accepted for ACM-CCS 2018. A link to the eprint is https://eprint.iacr.org/2018/762 
This code is for Ring based protocol.

We would like to thank to the team behind the SPDZ-2 framework, which is an extensive effort and an excellent contribution to the MPC community. Special thanks to Marcel Keller for his numerous insights and explanations making this work possible.

(C) 2017 University of Bristol. See License.txt Software for the SPDZ and MASCOT secure multi-party computation protocols. See Programs/Source/ for some example MPC programs.

## SPDZ-2 With Extensions - rationale

The SPDZ-2 extensions is a mechanism that enables substitution of the original implementation of various operations with an alternate external implementation. This is done by dynamically loading a configured library and prescribed API function pointers. In runtime, the SPDZ-2 processor will call the loaded API functions instead of the original implementation and provide it with the required parameters. In this repository, we set library for ring based protocol as configured library.

### MPC programs source code
The [Programs/Source](https://github.com/nec-mpc/SPDZ-2/tree/master/Programs/Source) folder of this fork contains MPC programs added as part of our work to evaluate different protocols under the framework. For example, the following program evaluates a decision tree.  
```
import util
#------------------------------------------------------------------------------
#definitions

c_FeaturesSetSize = 17
c_TreeDepth = 30
c_NodeSetSize = 1255

#user 0 the evaluator
#user 1 is the evaluee
#------------------------------------------------------------------------------
# Code for oblivious selection of an array member by a secure index
def oblivious_selection(sec_array, array_size, sec_index):
    bitcnt = util.log2(array_size)
    sec_index_bits = sec_index.e_bit_decompose(bitcnt)
    return obliviously_select(sec_array, array_size, 0, sec_index_bits, len(sec_index_bits) - 1)

def obliviously_select(array, size, offset, bits, bits_index):
    #print('size={}; offset={}; bi={};'.format(size, offset, bits_index))
    if offset >= size:
        return 0
    elif bits_index < 0:
        return array[offset]
    else:
        half_size = 2**(bits_index)
        msb = bits[bits_index]
        return msb.if_else(
            obliviously_select(array, size, offset + half_size, bits, bits_index-1) ,
            obliviously_select(array, size, offset, bits, bits_index-1) )
#------------------------------------------------------------------------------
# Reading feature set from user 1 (the evaluee)
#print_ln('user 1: please enter input offset:')
User1InputOffset = sint.get_input_from(1)
#print_ln('user 1: please enter feature set (%s feature values):', c_FeaturesSetSize)
FeaturesSet = [sint() for i in range(c_FeaturesSetSize)]

for i in range(c_FeaturesSetSize):
    FeaturesSet[i] = sint.get_input_from(1) - User1InputOffset
    #debug-print
    #print_ln('FeaturesSet[%s] = %s', i, FeaturesSet[i].reveal())
#------------------------------------------------------------------------------
def test(FeatureIdx, Operator, Threshold):
    feature_value = oblivious_selection(FeaturesSet, c_FeaturesSetSize, FeatureIdx)
    return Operator.if_else(feature_value > Threshold, feature_value == Threshold)
#------------------------------------------------------------------------------
#print_ln('user 0: please enter input offset:')
User0InputOffset = sint.get_input_from(0)
def read_node(i):
    #print_ln('user 0: please enter node %s feature index:', i)
    FeatureIdx = sint.get_input_from(0) - User0InputOffset
    #debug-print
    #print_ln('FeatureIdx[%s] = %s', i, FeatureIdx.reveal())
    #print_ln('user 0: please enter node %s operator:', i)
    Operator = sint.get_input_from(0) - User0InputOffset
    #debug-print
    #print_ln('Operator[%s] = %s', i, Operator.reveal())

    #print_ln('user 0: please enter node %s Threshold:', i)
    Threshold = sint.get_input_from(0) - User0InputOffset
    #debug-print
    #print_ln('Threshold[%s] = %s', i, Threshold.reveal())

    #print_ln('user 0: please enter node %s GT/EQ:', i)
    GT_or_EQ = sint.get_input_from(0) - User0InputOffset
    #debug-print
    #print_ln('GT_or_EQ[%s] = %s', i, GT_or_EQ.reveal())

    #print_ln('user 0: please enter node %s LTE/NEQ:', i)
    LTE_or_NEQ = sint.get_input_from(0) - User0InputOffset
    #debug-print
    #print_ln('LTE_or_NEQ[%s] = %s', i, LTE_or_NEQ.reveal())

    NodePass = test(FeatureIdx, Operator, Threshold)
    #debug-print
    #print_ln('Node[%s] passage = %s', i, NodePass.reveal())

    return NodePass*GT_or_EQ + (1 - NodePass)*LTE_or_NEQ
#------------------------------------------------------------------------------
# Reading node set from user 0 (the evaluator)
NodeSet = [sint() for i in range(c_NodeSetSize)]
for i in range(c_NodeSetSize):
    NodeSet[i] = read_node(i)
#------------------------------------------------------------------------------
#evaluation
NodePtr = MemValue(sint(0))
for i in range(c_TreeDepth):
    NextNodePtr = oblivious_selection(NodeSet, c_NodeSetSize, NodePtr)
    CycleBack = (NextNodePtr < 0) * (i < (c_TreeDepth-1))
    NodePtr.write(CycleBack.if_else(NodePtr, NextNodePtr))
    #debug-print
    #print_ln('CurrentLayer = %s; NodePtr = %s; NextNodePtr = %s', i, NodePtr.reveal(), NextNodePtr.reveal())

NodePtr = (NodePtr + 1) * (-1)
print_ln('evaluation result = %s', NodePtr.reveal())
```
### SPDZ-2 extension library
See https://github.com/nec-mpc/SPDZ-2-Extension-Ring for our implemented extension library.

## SPDZ-2
### Requirements:

- GCC (tested with 4.8.5) or ICC (18.0.3)
- MPIR library, compiled with C++ support (use flag --enable-cxx when running configure)
- libsodium library, tested against 1.0.11
- CPU supporting AES-NI
- Python 2.x (tested with 2.7.5)

### To compile:
1) Download files of this repository to above environment.

2) Change directories to download one.

3) Run `make clean all`

### To generate the bytecode:
1) Set the program source file of MPC on [Programs/Source](https://github.com/nec-mpc/SPDZ-2/tree/master/Programs/Source). 
 - File extension is ".mpc"
 
2) Change directories to download one.

3) Run `python compile.py [PROGRAM NAME]`

### To run the protocol:
1) Set environment variables for extension library. 
 - See the URL and README.md

2) Change directories to download one.

3) Run each entity as follows.
* [Proxy]
	`./Server.x 3 [port number]`
	
* [Each MPC server(0/1/2)] 
	`.Player-Online.x -pn [port number] -lgp 64 [server ID] [PROGRAM NAME]`

- iEx.jvariance_modified_10input (This program computes variance from 10 inputs)
   * [Proxy]
     `./Server.x 3 60000`
   * [MPC server0]
     `.Player-Online.x -pn 60000 -lgp 64 0 variance_modified_10input`
   * [MPC server1]
      ` .Player-Online.x -pn 60000 -lgp 64 1 variance_modified_10input`
   * [MPC server2]
      `.Player-Online.x -pn 60000 -lgp 64 2 variance_modified_10input`
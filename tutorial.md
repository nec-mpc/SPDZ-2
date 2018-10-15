(C) 2018 University of Bristol. See License.txt

Suppose we want to add 3 integers mod 2^64 in clear over 3 parties inputs: P0, P1 and P2.

First create a file named "addition.mpc" in Programs/Source/ folder containing the following:


Addition on Clear Data
==================

```
a = cint(2)
b = cint(10)
c = cint(5)

d = a + b + c
print_ln('Result is %s', c)
```

If you want to run it, please see the README.md to know how to generate the bytecodes and run the protocol.

The output is the result of the computation.

````
	Result is 17

````


Addition on Secret Shared data
=================================

```
a = sint(2)
b = sint(10)
c = sint(5)

d = a + b + c
print_ln('Result is %s', d.reveal())
```
This means that a = a_0 + a_1 + a_2, b = b_0 + b_1 + b_2 and c = c_0 + c_1 + c_2 where a_i, b_i and c_i belong to party P_i. 

If there are multiple calls to reveal() then the rounds of communication are merged automatically by the compiler.

Remember that a, b and c are hard-coded constants so the data is shared by one
party having the actualy inputs (a_0=2, b_0=10, c_0=5) where the others has (a_1 = a_2 = 
0, b_1 = b_2 =  0, c_1 = c_2 = 0). Usually it's easier to debug when things are written in this way.

If we want to run a real MPC computation - P0 shares a, P1 shares b  and P2 shares c- and
reveal the sum of the values then we can write the following.

```
a = sint.get_input_from(0)
b = sint.get_input_from(1)
c = sint.get_input_from(2)

d = a + b + c
print_ln('Result is %s', d.reveal())

```

For another example, if we want to run another MPC computation - P0 would like to share a = 2 and h = 1, P1 would like to share b = 10 and i = 1, and  P2 would like to share c = 5 and j = 1 - and reveal the sums of the values, i.e., d = a + b + c and k = h + i + j  then we can write the following.

```
a = sint.get_input_from(0)
b = sint.get_input_from(1)
c = sint.get_input_from(2)

h = sint.get_input_from(0)
i  = sint.get_input_from(1)
j  = sint.get_input_from(2)

d = a + b + c
k = h + i + j

print_ln('Result of d is %s', d.reveal())
print_ln('Result of k is %s', k.reveal())
```
### To make inputs:
In above case, for example, P0 needs to write his/her inputs to integers_input_0.txt as follows:

```
2
1
```

That is, each party (who has a party id "pid") needs to write his/her inputs to integers_input_pid.txt in vertical.


Multiplication on Secret Shared data
=================================
SPDZ supports not only addition (+) but also multiplication (*) mod 2^64.

Second create a file named "multiplication.mpc" in Programs/Source/ folder containing the following:


```
a = sint(2)
b = sint(10)
c = sint(5)

ab = a * b
abc = ab * c
print_ln('Result is %s', abc.reveal())
```

The output is the result of the computation.

````
	Result is 100

````

If there are multiple calls to multiplication(*) then the rounds of communication are merged automatically by the compiler.

XOR on Clear data
=================================
In SPDZ, we can compute the binary circuit. 

Suppose we want to xor 3 bits in clear over 3 parties inputs: P0, P1 and P2.

Third create a file named "xor.mpc" in Programs/Source/ folder containing the following:


```
a = cgf2n(0)
b = cgf2n(1)
c = cgf2n(0)

d = a + b + c
print_ln('Result is %s', d)
```

The output is the result of the computation.

````
	Result is 0x1

````

XOR on Secret Shared data
=================================

```
a = sgf2n(0)
b = sgf2n(1)
c = sgf2n(0)

d = a + b + c
print_ln('Result is %s', d.reveal())
```

The output is the result of the computation.

````
	Result is 0x1

````

AND on Secret Shared data
=================================
SPDZ supports not only xor (+) but also and (*) mod 2.

Fourth create a file named "and.mpc" in Programs/Source/ folder containing the following:


```
a = sgf2n(1)
b = sgf2n(0)
c = sgf2n(1)

ab = a * b
abc = ab * c
print_ln('Result is %s', abc.reveal())
```

The output is the result of the computation.

````
	Result is 0x0

````

To change the variants of conversion instructions
===========================================
We can change the variants of conversion instructions. 

If we change the types of bit decomposition instruction from communication-efficient one to round-efficient one (variable-length/conditional sum adder), comment out from line 2044 to 2093 in Compiler/instructions.py and uncomment from line 1918/1649 to 2040/1915 in Compiler/instructions.py.

If we change the types of bit recomposition instruction from communication-efficient one to round-efficient one, comment out from line 2298 to 2395 in Compiler/instructions.py and uncomment from line 2264 to 2294 in Compiler/instructions.py.

After the above change, we run `python compile.py [PROGRAM NAME]` then the other bytecode is generated.


To run some experiments of [A+18 paper](https://eprint.iacr.org/2018/762)
==============================================================
We prepare program codes of some experiments in Program/Source as follows:
* List of test programs
  - mean_modified_10input.mpc
  - variance_modified_10input.mpc
  - sql_query_3_modified_10input.mpc
  - Non_Balanced_Generic_Decision_Tree_modified.mpc

* Caution
 - File name shows the compuation and the number of input.
 - If the number of input is less than it, programs go core-dump. 
 - Programs whose name includes "modified" is  carefully written in such a way as to be optimized well. The compilation time is long but the processing time is fast.

## To run the programs
### mean_modified_10input

1) Make inputs.
```
cat ./single_input/mean_10input/Input/parallel_1_mean_10input.txt > ./integers_input_2.txt
```

2) Generate the bytecode.
```
python compile.py mean_modified_10input 
```

3) Run the protocol. (See "To run the protocol:" in README.md.)

### variance_modified_10input

1) Make inputs.
```
cat ./single_input/variance_10input/Input/parallel_1_variance_10input.txt > ./integers_input_2.txt
```

2) Generate the bytecode.
```
python compile.py variance_modified_10input 
```

3) Run the protocol. (See "To run the protocol:" in README.md.)

### sql_query_3_modified_10input

1) Make inputs.
```
cat ./single_input/sql_program_10input/Input/parallel_1_sql_int_10input_0.txt > ./integers_input_0.txt
cat ./single_input/sql_program_10input/Input/parallel_1_sql_int_10input_1.txt > ./integers_input_1.txt
cat ./single_input/sql_program_10input/Input/parallel_1_sql_int_10input_2.txt > ./integers_input_2.txt
```

2) Generate the bytecode.
```
python compile.py sql_query_3_modified_10input
```

3) Run the protocol. (See "To run the protocol:" in README.md.)

### Non_Balanced_Generic_Decision_Tree_modified

1) Make inputs.
```
cat ./single_input/decision_tree/Input/parallel_1_0.txt > ./integers_input_0.txt
cat ./single_input/decision_tree/Input/parallel_1_dc_input_4spdz2.txt > ./integers_input_1.txt
```
We also prepare another example file, parallel_1_1.txt. It provides the another result. 

2) Generate the bytecode.
```
python compile.py Non_Balanced_Generic_Decision_Tree_modified
```

3) Run the protocol. (See "To run the protocol:" in README.md.)


### To check the result
We prepare the expected result files in ./single_input/[type of experiment]/Result/. 


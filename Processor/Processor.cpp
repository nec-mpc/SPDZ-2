// (C) 2018 University of Bristol. See License.txt


#include "Processor/Processor.h"
#include "Networking/STS.h"
#include "Auth/MAC_Check.h"

#include "Auth/fake-stuff.h"
#include <sodium.h>
#include <string>

#include <sys/stat.h>
#include <dlfcn.h>

spdz_ext_ifc the_ext_lib_z2n, the_ext_lib_z2;

Processor::Processor(int thread_num,Data_Files& DataF,Player& P,
        MAC_Check<gf2n>& MC2,MAC_Check<gfp>& MCp,Machine& machine,
        const Program& program)
: thread_num(thread_num),DataF(DataF),P(P),MC2(MC2),MCp(MCp),machine(machine),
  private_input_filename(get_filename(PREP_DIR "Private-Input-",true)),
  input2(*this,MC2),inputp(*this,MCp),privateOutput2(*this),privateOutputp(*this),sent(0),rounds(0),
  external_clients(ExternalClients(P.my_num(), DataF.prep_data_dir)),binary_file_io(Binary_File_IO()),
  mult_allocated(0), bmult_allocated(0), open_allocated(0), bopen_allocated(0), input_file_int(NULL), input_file_fix(NULL), input_file_share(NULL)
{
  reset(program,0);

  public_input.open(get_filename("Programs/Public-Input/",false).c_str());
  private_input.open(private_input_filename.c_str());
  public_output.open(get_filename(PREP_DIR "Public-Output-",true).c_str(), ios_base::out);
  private_output.open(get_filename(PREP_DIR "Private-Output-",true).c_str(), ios_base::out);

  spdz_gfp_ext_context.handle = 0;
  cout << "Processor " << thread_num << " SPDZ GFP extension library initializing." << endl;
#if defined(EXT_NEC_RING)
  if(0 != (*the_ext_lib_z2n.ext_init)(&spdz_gfp_ext_context, P.my_num(), P.num_players(), "Z2n_Ring",0, 0, 0))
#else
  if(0 != (*the_ext_lib_z2n.ext_init)(&spdz_gfp_ext_context, P.my_num(), P.num_players(), "ring32", 100, 100, 100))
#endif
  {
  	cerr << "SPDZ extension library initialization failed." << endl;
  	dlclose(the_ext_lib_z2n.ext_lib_handle);
  	abort();
  }
  cout << "SPDZ GFP extension library initialized." << endl;

  spdz_gf2n_ext_context.handle = 0;
  cout << "Processor" << thread_num << "SPDZ GF2N extension library initializing." << endl;
#if defined(EXT_NEC_RING)
	if(0 != (*the_ext_lib_z2.ext_init)(&spdz_gf2n_ext_context, P.my_num(), P.num_players(), "Z2_Bool", 0, 0, 0))
#else
	if(0 != (*the_ext_lib_z2.ext_init)(&spdz_gf2n_ext_context, P.my_num(), P.num_players(), "gf2n40", 10, 10, 10))
#endif
	{
		cerr << "SPDZ GF2N extension library initialization failed." << endl;
		dlclose(the_ext_lib_z2.ext_lib_handle);
		abort();
	}
	cout << "SPDZ GF2N extension library initialized." << endl;


  zp_word64_size = get_zp_word64_size();
  if(0 != open_input_file())
  {
	  	cerr << "SPDZ extension library input files open failed." << endl;
	  	dlclose(the_ext_lib_z2.ext_lib_handle);
	  	abort();
  }
}


Processor::~Processor()
{
  cerr << "Sent " << sent << " elements in " << rounds << " rounds" << endl;
  mult_clear();
  open_clear();
  close_input_file();
  (*the_ext_lib_z2n.ext_term)(&spdz_gfp_ext_context);
  (*the_ext_lib_z2.ext_term)(&spdz_gf2n_ext_context);
  dlclose(the_ext_lib_z2n.ext_lib_handle);
  dlclose(the_ext_lib_z2.ext_lib_handle);
}

string Processor::get_filename(const char* prefix, bool use_number)
{
  stringstream filename;
  filename << prefix;
  if (!use_number)
    filename << machine.progname;
  if (use_number)
    filename << P.my_num();
  if (thread_num > 0)
    filename << "-" << thread_num;
  cerr << "Opening file " << filename.str() << endl;
  return filename.str();
}


void Processor::reset(const Program& program,int arg)
{
  reg_max2 = program.num_reg(GF2N);
  reg_maxp = program.num_reg(MODP);
  reg_maxi = program.num_reg(INT);
  C2.resize(reg_max2); Cp.resize(reg_maxp);
  S2.resize(reg_max2); Sp.resize(reg_maxp);
  Ci.resize(reg_maxi);
  this->arg = arg;

  #ifdef DEBUG
    rw2.resize(2*reg_max2);
    for (int i=0; i<2*reg_max2; i++) { rw2[i]=0; }
    rwp.resize(2*reg_maxp);
    for (int i=0; i<2*reg_maxp; i++) { rwp[i]=0; }
    rwi.resize(2*reg_maxi);
    for (int i=0; i<2*reg_maxi; i++) { rwi[i]=0; }
  #endif
}

#include "Networking/sockets.h"
#include "Math/Setup.h"

// Write socket (typically SPDZ engine -> external client), for different register types.
// RegType and SecrecyType determines how registers are read and the socket stream is packed.
// If message_type is > 0, send message_type in bytes 0 - 3, to allow an external client to
//  determine the data structure being sent in a message.
// Encryption is enabled if key material (for DH Auth Encryption and/or STS protocol) has been already setup.
void Processor::write_socket(const RegType reg_type, const SecrecyType secrecy_type, const bool send_macs,
                             int socket_id, int message_type, const vector<int>& registers)
{
  if (socket_id >= (int)external_clients.external_client_sockets.size())
  {
    cerr << "No socket connection exists for client id " << socket_id << endl;
    return;  
  }
  int m = registers.size();
  socket_stream.reset_write_head();

  //First 4 bytes is message_type (unless indicate not needed)
  if (message_type != 0) {
    socket_stream.store(message_type);
  }

  for (int i = 0; i < m; i++)
  {
    if (reg_type == MODP && secrecy_type == SECRET) {
      // Send vector of secret shares and optionally macs
      get_S_ref<gfp>(registers[i]).get_share().pack(socket_stream);
      if (send_macs)
        get_S_ref<gfp>(registers[i]).get_mac().pack(socket_stream);
    }
    else if (reg_type == MODP && secrecy_type == CLEAR) {
      // Send vector of clear public field elements
      get_C_ref<gfp>(registers[i]).pack(socket_stream);
    }
    else if (reg_type == INT && secrecy_type == CLEAR) {
      // Send vector of 32-bit clear ints
      socket_stream.store((int&)get_Ci_ref(registers[i]));
    } 
    else {
      stringstream ss;
      ss << "Write socket instruction with unknown reg type " << reg_type << 
        " and secrecy type " << secrecy_type << "." << endl;      
      throw Processor_Error(ss.str());
    }
  }

  // Apply DH Auth encryption if session keys have been created.
  map<int,octet*>::iterator it = external_clients.symmetric_client_keys.find(socket_id);
  if (it != external_clients.symmetric_client_keys.end()) {
    socket_stream.encrypt(it->second);
  }

  // Apply STS commsec encryption if session keys have been created.
  try {
    maybe_encrypt_sequence(socket_id);
    socket_stream.Send(external_clients.external_client_sockets[socket_id]);
  }
    catch (bad_value& e) {
    cerr << "Send error thrown when writing " << m << " values of type " << reg_type << " to socket id " 
      << socket_id << "." << endl;
  }
}


// Receive vector of 32-bit clear ints
void Processor::read_socket_ints(int client_id, const vector<int>& registers)
{
  if (client_id >= (int)external_clients.external_client_sockets.size())
  {
    cerr << "No socket connection exists for client id " << client_id << endl; 
    return; 
  }

  int m = registers.size();
  socket_stream.reset_write_head();
  socket_stream.Receive(external_clients.external_client_sockets[client_id]);
  maybe_decrypt_sequence(client_id);
  for (int i = 0; i < m; i++)
  {
    int val;
    socket_stream.get(val);
    write_Ci(registers[i], (long)val);
  }
}

// Receive vector of public field elements
template <class T>
void Processor::read_socket_vector(int client_id, const vector<int>& registers)
{
  if (client_id >= (int)external_clients.external_client_sockets.size())
  {
    cerr << "No socket connection exists for client id " << client_id << endl;
    return;  
  }

  int m = registers.size();
  socket_stream.reset_write_head();
  socket_stream.Receive(external_clients.external_client_sockets[client_id]);
  maybe_decrypt_sequence(client_id);
  for (int i = 0; i < m; i++)
  {
    get_C_ref<T>(registers[i]).unpack(socket_stream);
  }
}

// Receive vector of field element shares over private channel
template <class T>
void Processor::read_socket_private(int client_id, const vector<int>& registers, bool read_macs)
{
  if (client_id >= (int)external_clients.external_client_sockets.size())
  {
    cerr << "No socket connection exists for client id " << client_id << endl;
    return;  
  }
  int m = registers.size();
  socket_stream.reset_write_head();
  socket_stream.Receive(external_clients.external_client_sockets[client_id]);
  maybe_decrypt_sequence(client_id);

  map<int,octet*>::iterator it = external_clients.symmetric_client_keys.find(client_id);
  if (it != external_clients.symmetric_client_keys.end())
  {
    socket_stream.decrypt(it->second);
  }
  for (int i = 0; i < m; i++)
  {
    temp.ansp.unpack(socket_stream);
    get_Sp_ref(registers[i]).set_share(temp.ansp);
    if (read_macs)
    {
      temp.ansp.unpack(socket_stream);
      get_Sp_ref(registers[i]).set_mac(temp.ansp);
    }
  }
}

// Read socket for client public key as 8 ints, calculate session key for client.
void Processor::read_client_public_key(int client_id, const vector<int>& registers) {

  read_socket_ints(client_id, registers);

  // After read into registers, need to extract values
  vector<int> client_public_key (registers.size(), 0);
  for(unsigned int i = 0; i < registers.size(); i++) {
    client_public_key[i] = (int&)get_Ci_ref(registers[i]);
  }

  external_clients.generate_session_key_for_client(client_id, client_public_key);  
}

void Processor::init_secure_socket_internal(int client_id, const vector<int>& registers) {
  external_clients.symmetric_client_commsec_send_keys.erase(client_id);
  external_clients.symmetric_client_commsec_recv_keys.erase(client_id);
  unsigned char client_public_bytes[crypto_sign_PUBLICKEYBYTES];
  sts_msg1_t m1;
  sts_msg2_t m2;
  sts_msg3_t m3;

  external_clients.load_server_keys_once();
  external_clients.require_ed25519_keys();

  // Validate inputs and state
  if(registers.size() != 8) {
      throw "Invalid call to init_secure_socket.";
  }
  if (client_id >= (int)external_clients.external_client_sockets.size())
  {
    cerr << "No socket connection exists for client id " << client_id << endl;
    throw "No socket connection exists for client";
  }

  // Extract client long term public key into bytes
  vector<int> client_public_key (registers.size(), 0);
  for(unsigned int i = 0; i < registers.size(); i++) {
    client_public_key[i] = (int&)get_Ci_ref(registers[i]);
  }
  external_clients.curve25519_ints_to_bytes(client_public_bytes,  client_public_key);

  // Start Station to Station Protocol
  STS ke(client_public_bytes, external_clients.server_publickey_ed25519, external_clients.server_secretkey_ed25519);
  m1 = ke.send_msg1();
  socket_stream.reset_write_head();
  socket_stream.append(m1.bytes, sizeof m1.bytes);
  socket_stream.Send(external_clients.external_client_sockets[client_id]);
  socket_stream.ReceiveExpected(external_clients.external_client_sockets[client_id],
                                96);
  socket_stream.consume(m2.pubkey, sizeof m2.pubkey);
  socket_stream.consume(m2.sig, sizeof m2.sig);
  m3 = ke.recv_msg2(m2);
  socket_stream.reset_write_head();
  socket_stream.append(m3.bytes, sizeof m3.bytes);
  socket_stream.Send(external_clients.external_client_sockets[client_id]);

  // Use results of STS to generate send and receive keys.
  vector<unsigned char> sendKey = ke.derive_secret(crypto_secretbox_KEYBYTES);
  vector<unsigned char> recvKey = ke.derive_secret(crypto_secretbox_KEYBYTES);
  external_clients.symmetric_client_commsec_send_keys[client_id] = make_pair(sendKey,0);
  external_clients.symmetric_client_commsec_recv_keys[client_id] = make_pair(recvKey,0);
}

void Processor::init_secure_socket(int client_id, const vector<int>& registers) {

  try {
      init_secure_socket_internal(client_id, registers);
  } catch (char const *e) {
      cerr << "STS initiator role failed with: " << e << endl;
      throw Processor_Error("STS initiator failed");
  }
}

void Processor::resp_secure_socket(int client_id, const vector<int>& registers) {
  try {
      resp_secure_socket_internal(client_id, registers);
  } catch (char const *e) {
      cerr << "STS responder role failed with: " << e << endl;
      throw Processor_Error("STS responder failed");
  }
}

void Processor::resp_secure_socket_internal(int client_id, const vector<int>& registers) {
  external_clients.symmetric_client_commsec_send_keys.erase(client_id);
  external_clients.symmetric_client_commsec_recv_keys.erase(client_id);
  unsigned char client_public_bytes[crypto_sign_PUBLICKEYBYTES];
  sts_msg1_t m1;
  sts_msg2_t m2;
  sts_msg3_t m3;

  external_clients.load_server_keys_once();
  external_clients.require_ed25519_keys();

  // Validate inputs and state
  if(registers.size() != 8) {
      throw "Invalid call to init_secure_socket.";
  }
  if (client_id >= (int)external_clients.external_client_sockets.size())
  {
    cerr << "No socket connection exists for client id " << client_id << endl;
    throw "No socket connection exists for client";
  }
  vector<int> client_public_key (registers.size(), 0);
  for(unsigned int i = 0; i < registers.size(); i++) {
    client_public_key[i] = (int&)get_Ci_ref(registers[i]);
  }
  external_clients.curve25519_ints_to_bytes(client_public_bytes,  client_public_key);

  // Start Station to Station Protocol for the responder
  STS ke(client_public_bytes, external_clients.server_publickey_ed25519, external_clients.server_secretkey_ed25519);
  socket_stream.reset_read_head();
  socket_stream.ReceiveExpected(external_clients.external_client_sockets[client_id],
                                32);
  socket_stream.consume(m1.bytes, sizeof m1.bytes);
  m2 = ke.recv_msg1(m1);
  socket_stream.reset_write_head();
  socket_stream.append(m2.pubkey, sizeof m2.pubkey);
  socket_stream.append(m2.sig, sizeof m2.sig);
  socket_stream.Send(external_clients.external_client_sockets[client_id]);

  socket_stream.ReceiveExpected(external_clients.external_client_sockets[client_id],
                                64);
  socket_stream.consume(m3.bytes, sizeof m3.bytes);
  ke.recv_msg3(m3);

  // Use results of STS to generate send and receive keys.
  vector<unsigned char> recvKey = ke.derive_secret(crypto_secretbox_KEYBYTES);
  vector<unsigned char> sendKey = ke.derive_secret(crypto_secretbox_KEYBYTES);
  external_clients.symmetric_client_commsec_recv_keys[client_id] = make_pair(recvKey,0);
  external_clients.symmetric_client_commsec_send_keys[client_id] = make_pair(sendKey,0);
}

// Read share data from a file starting at file_pos until registers filled.
// file_pos_register is written with new file position (-1 is eof).
// Tolerent to no file if no shares yet persisted.
template <class T> 
void Processor::read_shares_from_file(int start_file_posn, int end_file_pos_register, const vector<int>& data_registers) {
  string filename;
  filename = "Persistence/Transactions-P" + to_string(P.my_num()) + ".data";

  unsigned int size = data_registers.size();

  vector< Share<T> > outbuf(size);

  int end_file_posn = start_file_posn;

  try {
    binary_file_io.read_from_file<T>(filename, outbuf, start_file_posn, end_file_posn);

    for (unsigned int i = 0; i < size; i++)
    {
      get_Sp_ref(data_registers[i]).set_share(outbuf[i].get_share());
      get_Sp_ref(data_registers[i]).set_mac(outbuf[i].get_mac());
    }

    write_Ci(end_file_pos_register, (long)end_file_posn);    
  }
  catch (file_missing& e) {
    cerr << "Got file missing error, will return -2. " << e.what() << endl;
    write_Ci(end_file_pos_register, (long)-2);
  }
}

// Append share data in data_registers to end of file. Expects Persistence directory to exist.
template <class T>
void Processor::write_shares_to_file(const vector<int>& data_registers) {
  string filename;
  filename = "Persistence/Transactions-P" + to_string(P.my_num()) + ".data";

  unsigned int size = data_registers.size();

  vector< Share<T> > inpbuf (size);

  for (unsigned int i = 0; i < size; i++)
  {
    inpbuf[i] = get_S_ref<T>(data_registers[i]);
  }
  binary_file_io.write_to_file<T>(filename, inpbuf);
}

template <class T>
void Processor::POpen_Start(const vector<int>& reg,const Player& P,MAC_Check<T>& MC,int size)
{
	int sz=reg.size();

	vector< Share<T> >& Sh_PO = get_Sh_PO<T>();
	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

	prep_shares(reg, Sh_PO, size);

	vector<T>& PO = get_PO<T>();
	PO.resize(sz*size);

	MC.POpen_Begin(PO,Sh_PO,P);
}


template <class T>
void Processor::POpen_Stop(const vector<int>& reg,const Player& P,MAC_Check<T>& MC,int size)
{
	vector< Share<T> >& Sh_PO = get_Sh_PO<T>();
	vector<T>& PO = get_PO<T>();
	vector<T>& C = get_C<T>();
	int sz=reg.size();
	PO.resize(sz*size);
	MC.POpen_End(PO,Sh_PO,P);

	load_clears(reg, PO, C, size);

	sent += reg.size() * size;
	rounds++;
}

template <class T>
void Processor::prep_shares(const vector<int>& reg, vector< Share<T> >& shares, int size)
{
	if (size>1)
	{
		for (typename vector<int>::const_iterator reg_it=reg.begin(); reg_it!=reg.end(); reg_it++)
		{
			typename vector<Share<T> >::iterator begin=get_S<T>().begin()+*reg_it;
			shares.insert(shares.end(),begin,begin+size);
		}
	}
	else
	{
		int sz=reg.size();
		for (int i=0; i<sz; i++)
		{
			shares.push_back(get_S_ref<T>(reg[i]));
		}
	}
}

template <class T>
void Processor::load_shares(const vector<int>& reg, const vector< Share<T> >& shares, int size)
{
	if (size>1)
	{
		size_t share_idx = 0;
		for (typename vector<int>::const_iterator reg_it=reg.begin(); reg_it!=reg.end(); reg_it++)
		{
			vector<Share<gfp> >::iterator insert_point=get_S<gfp>().begin()+*reg_it;
			for(int i = 0; i < size; ++i)
			{
				*(insert_point + i) = shares[share_idx++];
			}
		}
	}
	else
	{
		int sz=reg.size();
		for(int i = 0; i < sz; ++i)
		{
			get_S_ref<gfp>(reg[i]) = shares[i];
		}
	}
}

template <class T>
void Processor::load_bshares(const vector<int>& reg, const vector< Share<T> >& shares, int size)
{
	if (size>1)
	{
		size_t share_idx = 0;
		for (typename vector<int>::const_iterator reg_it=reg.begin(); reg_it!=reg.end(); reg_it++)
		{
			vector<Share<gf2n> >::iterator insert_point=get_S<gf2n>().begin()+*reg_it;
			for(int i = 0; i < size; ++i)
			{
				*(insert_point + i) = shares[share_idx++];
			}
		}
	}
	else
	{
		int sz=reg.size();
		for(int i = 0; i < sz; ++i)
		{
			get_S_ref<gf2n>(reg[i]) = shares[i];
		}
	}
}

template <class T>
void Processor::load_clears(const vector<int>& reg, vector<T>& PO, vector<T>& C, int size)
{
	if (size>1)
	{
		typename vector<T>::iterator PO_it=PO.begin();
		for (typename vector<int>::const_iterator reg_it=reg.begin(); reg_it!=reg.end(); reg_it++)
		{
			for (typename vector<T>::iterator C_it=C.begin()+*reg_it; C_it!=C.begin()+*reg_it+size; C_it++)
			{
			  *C_it=*PO_it;
			  PO_it++;
			}
		}
	}
	else
	{
		for (unsigned int i=0; i<reg.size(); i++)
		{
			get_C_ref<T>(reg[i]) = PO[i];
		}
	}
}

ostream& operator<<(ostream& s,const Processor& P)
{
  s << "Processor State" << endl;
  s << "Char 2 Registers" << endl;
  s << "Val\tClearReg\tSharedReg" << endl;
  for (int i=0; i<P.reg_max2; i++)
    { s << i << "\t";
      P.read_C2(i).output(s,true);
      s << "\t";
      P.read_S2(i).output(s,true);
      s << endl;
    }
  s << "Char p Registers" << endl;
  s << "Val\tClearReg\tSharedReg" << endl;
  for (int i=0; i<P.reg_maxp; i++)
    { s << i << "\t";
      P.read_Cp(i).output(s,true);
      s << "\t";
      P.read_Sp(i).output(s,true);
      s << endl;
    }

  return s;
}

void Processor::maybe_decrypt_sequence(int client_id)
{
  map<int, pair<vector<octet>,uint64_t> >::iterator it_cs = external_clients.symmetric_client_commsec_recv_keys.find(client_id);
  if (it_cs != external_clients.symmetric_client_commsec_recv_keys.end())
  {
    socket_stream.decrypt_sequence(&it_cs->second.first[0], it_cs->second.second);
    it_cs->second.second++;
  }
}

void Processor::maybe_encrypt_sequence(int client_id)
{
  map<int, pair<vector<octet>,uint64_t> >::iterator it_cs = external_clients.symmetric_client_commsec_send_keys.find(client_id);
  if (it_cs != external_clients.symmetric_client_commsec_send_keys.end())
  {
    socket_stream.encrypt_sequence(&it_cs->second.first[0], it_cs->second.second);
    it_cs->second.second++;
  }
}

template void Processor::POpen_Start(const vector<int>& reg,const Player& P,MAC_Check<gf2n>& MC,int size);
template void Processor::POpen_Start(const vector<int>& reg,const Player& P,MAC_Check<gfp>& MC,int size);
template void Processor::POpen_Stop(const vector<int>& reg,const Player& P,MAC_Check<gf2n>& MC,int size);
template void Processor::POpen_Stop(const vector<int>& reg,const Player& P,MAC_Check<gfp>& MC,int size);
template void Processor::read_socket_private<gfp>(int client_id, const vector<int>& registers, bool send_macs);
template void Processor::read_socket_vector<gfp>(int client_id, const vector<int>& registers);
template void Processor::read_shares_from_file<gfp>(int start_file_pos, int end_file_pos_register, const vector<int>& data_registers);
template void Processor::write_shares_to_file<gfp>(const vector<int>& data_registers);

static const int share_port_order = -1;
static const size_t share_port_size = 8;
static const int share_port_endian = 0;
static const size_t share_port_nails = 0;

void Processor::Ext_Skew_Bit_Decomp_R2B(const Share<gfp>& src_reg, const vector<int>& dest_reg, int size)
{
#if defined(EXT_NEC_RING)
	share_t rings_in, bits_out;
	rings_in.size = bits_out.size = 2* zp_word64_size * 8;
	rings_in.count = 1;
	bits_out.count = dest_reg.size();
	rings_in.data = new u_int8_t[rings_in.size * rings_in.count];
	bits_out.data = new u_int8_t[bits_out.size * bits_out.count];
	rings_in.md_ring_size = sizeof(SPDZEXT_VALTYPE) * 8;
	bits_out.md_ring_size = 1;

	SPDZEXT_VALTYPE src_share1 = src_reg.get_share().get_ring();
	SPDZEXT_VALTYPE src_share2 = src_reg.get_mac().get_ring();

	memcpy(rings_in.data,                           &src_share1, sizeof(SPDZEXT_VALTYPE));
	memcpy(rings_in.data + sizeof(SPDZEXT_VALTYPE), &src_share2, sizeof(SPDZEXT_VALTYPE));

	if(0 != (*the_ext_lib_z2n.ext_skew_bit_decomp)(&spdz_gfp_ext_context, &rings_in, &bits_out))
	{
		cerr << "Processor::Ext_Skew_Bit_Decomp_R2B extension library ext_skew_bit_decomp() failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}

	int sz=dest_reg.size();
	vector< Share<gf2n> >& Sh_PO = get_Sh_PO<gf2n>();
	Sh_PO.clear();
	Sh_PO.resize(sz*size);
	import_shares(bits_out, Sh_PO);
	load_bshares(dest_reg, Sh_PO, size);

//	cout << "[Processor::Ext_Skew_Bit_Decomp_R2B] dest_reg.size() = " << dest_reg.size() << endl;
//	for (int i=0; i<sz; i++) {
//		cout << "[Processor::Ext_Skew_Bit_Decomp_R2B] Sh_PO[" << i << "] share 1 = " << Sh_PO[i].get_share().get() << endl;
//		cout << "[Processor::Ext_Skew_Bit_Decomp_R2B] Sh_PO[" << i << "] share 2 = " << Sh_PO[i].get_mac().get() << endl;
//		cout << "[Processor::Ext_Skew_Bit_Decomp_R2B] reg[" << i << "] share 1 = " << get_S_ref<gf2n>(dest_reg[i]).get_share().get() << endl;
//		cout << "[Processor::Ext_Skew_Bit_Decomp_R2B] reg[" << i << "] share 2 = " << get_S_ref<gf2n>(dest_reg[i]).get_mac().get() << endl;
//
//	}

	delete rings_in.data;
	delete bits_out.data;
	rings_in.data = NULL;
	bits_out.data = NULL;

#else
	int sz=src_reg.size();

	vector< Share<gfp> >& Sh_PO = get_Sh_PO<gfp>();
	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

	prep_shares(src_reg, Sh_PO, size);

	share_t rings_in, bits_out;
	rings_in.size = bits_out.size = zp_word64_size * 8;
	rings_in.count = bits_out.count = Sh_PO.size();
	rings_in.data = new u_int8_t[rings_in.size * rings_in.count];
	bits_out.data = new u_int8_t[bits_out.size * bits_out.count];

	export_shares(Sh_PO, rings_in);

	if(0 != (*the_ext_lib_z2n.ext_skew_bit_decomp)(&spdz_gfp_ext_context, &rings_in, &bits_out))
	{
		cerr << "Processor::Ext_Skew_Bit_Decomp extension library ext_skew_bit_decomp() failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}
	import_shares(bits_out, Sh_PO);
	load_shares(dest_reg, Sh_PO, size);
#endif
}

void Processor::Ext_Skew_Bit_Decomp_B2B(const Share<gf2n>& src_reg, const vector<int>& dest_reg, int size)
{
#if defined(EXT_NEC_RING)
	share_t bits_in, bits_out;
	bits_in.size = bits_out.size = 2* zp_word64_size * 8;
	bits_in.count = 1;
	bits_out.count = dest_reg.size();
	bits_in.data = new u_int8_t[bits_in.size * bits_in.count];
	bits_out.data = new u_int8_t[bits_out.size * bits_out.count];
	bits_in.md_ring_size = 1;
	bits_out.md_ring_size = 1;

	SPDZEXT_VALTYPE src_share1 = src_reg.get_share().get();
	SPDZEXT_VALTYPE src_share2 = src_reg.get_mac().get();

	memcpy(bits_in.data,                           &src_share1, sizeof(SPDZEXT_VALTYPE));
	memcpy(bits_in.data + sizeof(SPDZEXT_VALTYPE), &src_share2, sizeof(SPDZEXT_VALTYPE));

	if(0 != (*the_ext_lib_z2.ext_skew_bit_decomp)(&spdz_gf2n_ext_context, &bits_in, &bits_out))
	{
		cerr << "Processor::Ext_Skew_Bit_Decomp_B2B extension library ext_skew_bit_decomp() failed." << endl;
		dlclose(the_ext_lib_z2.ext_lib_handle);
		abort();
	}

	int sz=dest_reg.size();
	vector< Share<gf2n> >& Sh_PO = get_Sh_PO<gf2n>();
	Sh_PO.clear();
	Sh_PO.resize(sz*size);
	import_shares(bits_out, Sh_PO);
	load_bshares(dest_reg, Sh_PO, size);

//	cout << "[Processor::Ext_Skew_Bit_Decomp_B2B] src_reg.share1 = " << src_reg.get_share().get() << endl;
//	cout << "[Processor::Ext_Skew_Bit_Decomp_B2B] src_reg.share2 = " << src_reg.get_mac().get() << endl;
//	cout << "[Processor::Ext_Skew_Bit_Decomp_B2B] dest.x1.share1 = " << get_S_ref<gf2n>(dest_reg[0]).get_share().get() << endl;
//	cout << "[Processor::Ext_Skew_Bit_Decomp_B2B] dest.x1.share2 = " << get_S_ref<gf2n>(dest_reg[0]).get_mac().get() << endl;
//	cout << "[Processor::Ext_Skew_Bit_Decomp_B2B] dest.x2.share1 = " << get_S_ref<gf2n>(dest_reg[1]).get_share().get() << endl;
//	cout << "[Processor::Ext_Skew_Bit_Decomp_B2B] dest.x2.share2 = " << get_S_ref<gf2n>(dest_reg[1]).get_mac().get() << endl;
//	cout << "[Processor::Ext_Skew_Bit_Decomp_B2B] dest.x3.share1 = " << get_S_ref<gf2n>(dest_reg[2]).get_share().get() << endl;
//	cout << "[Processor::Ext_Skew_Bit_Decomp_B2B] dest.x3.share2 = " << get_S_ref<gf2n>(dest_reg[2]).get_mac().get() << endl;
//	cout << endl;

	delete bits_in.data;
	delete bits_out.data;
	bits_in.data = NULL;
	bits_out.data = NULL;

#else
	int sz=src_reg.size();

	vector< Share<gfp> >& Sh_PO = get_Sh_PO<gfp>();
	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

	prep_shares(src_reg, Sh_PO, size);

	share_t bits_in, bits_out;
	bits_in.size = bits_out.size = zp_word64_size * 8;
	bits_in.count = bits_out.count = Sh_PO.size();
	bits_in.data = new u_int8_t[bits_in.size * bits_in.count];
	bits_out.data = new u_int8_t[bits_out.size * bits_out.count];

	export_shares(Sh_PO, bits_in);

	if(0 != (*the_ext_lib_z2n.ext_skew_bit_decomp)(&spdz_gfp_ext_context, &bits_in, &bits_out))
	{
		cerr << "Processor::Ext_Skew_Bit_Decomp extension library ext_skew_bit_decomp() failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}
	import_shares(bits_out, Sh_PO);
	load_shares(dest_reg, Sh_PO, size);
#endif
}

void Processor::Ext_Skew_Bit_Decomp_B2R(const Share<gf2n>& src_reg, const vector<int>& dest_reg, int size)
{
#if defined(EXT_NEC_RING)
	share_t bits_in, rings_out;
	bits_in.size = rings_out.size = 2* zp_word64_size * 8;
	bits_in.count = 1;
	rings_out.count = dest_reg.size();
	bits_in.data = new u_int8_t[bits_in.size * bits_in.count];
	rings_out.data = new u_int8_t[rings_out.size * rings_out.count];
	bits_in.md_ring_size = 1;
	rings_out.md_ring_size = sizeof(SPDZEXT_VALTYPE) * 8;

	SPDZEXT_VALTYPE src_share1 = src_reg.get_share().get();
	SPDZEXT_VALTYPE src_share2 = src_reg.get_mac().get();

	memcpy(bits_in.data,                           &src_share1, sizeof(SPDZEXT_VALTYPE));
	memcpy(bits_in.data + sizeof(SPDZEXT_VALTYPE), &src_share2, sizeof(SPDZEXT_VALTYPE));

	if(0 != (*the_ext_lib_z2.ext_skew_bit_decomp)(&spdz_gf2n_ext_context, &bits_in, &rings_out))
	{
		cerr << "Processor::Ext_Skew_Bit_Decomp_B2R extension library ext_skew_bit_decomp() failed." << endl;
		dlclose(the_ext_lib_z2.ext_lib_handle);
		abort();
	}

	int sz=dest_reg.size();
	vector< Share<gfp> >& Sh_PO = get_Sh_PO<gfp>();
	Sh_PO.clear();
	Sh_PO.resize(sz*size);
	import_shares(rings_out, Sh_PO);
	load_shares(dest_reg, Sh_PO, size);

	delete bits_in.data;
	delete rings_out.data;
	bits_in.data = NULL;
	rings_out.data = NULL;

#else
	int sz=src_reg.size();

	vector< Share<gfp> >& Sh_PO = get_Sh_PO<gfp>();
	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

	prep_shares(src_reg, Sh_PO, size);

	share_t bits_in, rings_out;
	bits_in.size = rings_out.size = zp_word64_size * 8;
	bits_in.count = rings_out.count = Sh_PO.size();
	bits_in.data = new u_int8_t[bits_in.size * bits_in.count];
	rings_out.data = new u_int8_t[rings_out.size * rings_out.count];

	export_shares(Sh_PO, bits_in);

	if(0 != (*the_ext_lib_z2n.ext_skew_bit_decomp)(&spdz_gfp_ext_context, &bits_in, &rings_out))
	{
		cerr << "Processor::Ext_Skew_Bit_Decomp extension library ext_skew_bit_decomp() failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}
	import_shares(rings_out, Sh_PO);
	load_shares(dest_reg, Sh_PO, size);
#endif
}

void Processor::Ext_Skew_Ring_Comp(const int& dest, const vector<int>& reg, int size)
{
#if defined(EXT_NEC_RING)
	int sz=reg.size();

	vector< Share<gf2n> >& Sh_PO = get_Sh_PO<gf2n>();
	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

	prep_shares(reg, Sh_PO, size);

	share_t bits_in, rings_out;
	bits_in.size = rings_out.size = 2* zp_word64_size * 8;
	bits_in.count = Sh_PO.size();
	rings_out.count = 1;
	bits_in.data = new u_int8_t[bits_in.size * bits_in.count];
	rings_out.data = new u_int8_t[rings_out.size * rings_out.count];
	bits_in.md_ring_size = 1;
	rings_out.md_ring_size = sizeof(SPDZEXT_VALTYPE) * 8;

	export_shares(Sh_PO, bits_in);

	if(0 != (*the_ext_lib_z2.ext_skew_ring_comp)(&spdz_gf2n_ext_context, &bits_in, &rings_out))
	{
		cerr << "Processor::Ext_Skew_Ring_Comp extension library ext_skew_ring_comp() failed." << endl;
		dlclose(the_ext_lib_z2.ext_lib_handle);
		abort();
	}
//
//	memcpy(bits_in.data,                           &src_share1, sizeof(SPDZEXT_VALTYPE));
//	memcpy(bits_in.data + sizeof(SPDZEXT_VALTYPE), &src_share2, sizeof(SPDZEXT_VALTYPE));
	SPDZEXT_VALTYPE * ps1 = (SPDZEXT_VALTYPE *)(rings_out.data);
	SPDZEXT_VALTYPE * ps2 = (SPDZEXT_VALTYPE *)(rings_out.data + sizeof(SPDZEXT_VALTYPE));
	gfp s1, s2;
	s1.assign_ring(*ps1);
	s2.assign_ring(*ps2);

	get_S_ref<gfp>(dest).set_share(s1);
	get_S_ref<gfp>(dest).set_mac(s2);

//	SPDZEXT_VALTYPE tmp1, tmp2;
//	tmp1 = get_S_ref<gfp>(dest).get_share().get_ring();
//	tmp2 = get_S_ref<gfp>(dest).get_mac().get_ring();

//	cout << "[Processor::Ext_Skew_Ring_Comp] share 1 = " << tmp1 << endl;
//	cout << "[Processor::Ext_Skew_Ring_Comp] share 2 = " << tmp2 << endl;
//	cout << endl;

#else
	int sz=reg.size();

	vector< Share<gfp> >& Sh_PO = get_Sh_PO<gfp>();
	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

	prep_shares(reg, Sh_PO, size);

	share_t bits_in, rings_out;
	bits_in.size = rings_out.size = zp_word64_size * 8;
	bits_in.count = rings_out.count = Sh_PO.size();
	bits_in.data = new u_int8_t[bits_in.size * bits_in.count];
	rings_out.data = new u_int8_t[rings_out.size * rings_out.count];

	export_shares(Sh_PO, bits_in);

	if(0 != (*the_ext_lib_z2n.ext_skew_ring_comp)(&spdz_gfp_ext_context, &bits_in, &rings_out))
	{
		cerr << "Processor::Ext_Skew_Ring_Comp extension library ext_skew_ring_comp() failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}
	import_shares(rings_out, Sh_PO);
	load_shares(reg, Sh_PO, size);
#endif
}

void Processor::Ext_Input_Share_Int(const vector<int>& reg, int size, const int input_party_id)
{
	size_t required_input_count = reg.size();
	size_t required_input_size = required_input_count * zp_word64_size * 8;

	clear_t clr_int_input;
	clr_int_input.count = required_input_count;
	clr_int_input.size = zp_word64_size * 8;
	clr_int_input.data = new u_int8_t[required_input_size];
	memset(clr_int_input.data, 0, required_input_size);

	share_t sec_int_input;
	sec_int_input.count = required_input_count;
#if defined(EXT_NEC_RING)
	sec_int_input.size = 2* zp_word64_size * 8;
	sec_int_input.data = new u_int8_t[2 * required_input_size];
	memset(sec_int_input.data, 0, 2*required_input_size);
#else
	sec_int_input.size = zp_word64_size * 8;
	sec_int_input.data = new u_int8_t[required_input_size];
	memset(sec_int_input.data, 0, required_input_size);
#endif

	if(P.my_num() == input_party_id)
	{
		std::vector<u_int64_t> int_inputs(required_input_count);
		std::string str_input;
		for(size_t i = 0; i < required_input_count; ++i)
		{
			if(0 != read_input_line(input_file_int, str_input))
			{
				dlclose(the_ext_lib_z2n.ext_lib_handle);
				dlclose(the_ext_lib_z2.ext_lib_handle);
				abort();
			}
			int_inputs[i] = strtol(str_input.c_str(), NULL, 10);
		}

		if(0 != (*the_ext_lib_z2n.ext_make_input_from_integer)(&spdz_gfp_ext_context, &int_inputs[0], required_input_count, &clr_int_input))
		{
			cerr << "Processor::Ext_Input_Share_Int extension library ext_make_input_from_integer() failed." << endl;
			dlclose(the_ext_lib_z2n.ext_lib_handle);
			abort();
		}

	}


	if(0 != (*the_ext_lib_z2n.ext_input_party)(&spdz_gfp_ext_context, input_party_id, &clr_int_input, &sec_int_input))
	{
		cerr << "Processor::Ext_Input_Share_Int extension library ext_input_party() failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}

	delete clr_int_input.data;

	int sz=reg.size();
	vector< Share<gfp> >& Sh_PO = get_Sh_PO<gfp>();
	Sh_PO.clear();
#if defined(EXT_NEC_RING)
	Sh_PO.resize(sz*size);
#else
	Sh_PO.reserve(sz*size);
#endif
	import_shares(sec_int_input, Sh_PO);
	load_shares(reg, Sh_PO, size);

	delete sec_int_input.data;
}

void Processor::Ext_BInput_Share_Int(const vector<int>& reg, int size, const int input_party_id)
{
	size_t required_input_count = reg.size();
	size_t required_input_size = required_input_count * zp_word64_size * 8;

	clear_t clr_bit_input;
	clr_bit_input.count = required_input_count;
	clr_bit_input.size = zp_word64_size * 8;
	clr_bit_input.data = new u_int8_t[required_input_size];
	memset(clr_bit_input.data, 0, required_input_size);

	share_t sec_bit_input;
	sec_bit_input.count = required_input_count;
#if defined(EXT_NEC_RING)
	sec_bit_input.size = 2* zp_word64_size * 8;
	sec_bit_input.data = new u_int8_t[2 * required_input_size];
	memset(sec_bit_input.data, 0, 2*required_input_size);
#else
	sec_int_input.size = zp_word64_size * 8;
	sec_int_input.data = new u_int8_t[required_input_size];
	memset(sec_int_input.data, 0, required_input_size);
#endif

	if(P.my_num() == input_party_id)
	{
		std::vector<u_int64_t> bit_inputs(required_input_count);
		std::string str_input;
		for(size_t i = 0; i < required_input_count; ++i)
		{
			if(0 != read_input_line(input_file_bit, str_input))
			{
				dlclose(the_ext_lib_z2n.ext_lib_handle);
				dlclose(the_ext_lib_z2.ext_lib_handle);
				abort();
			}
			bit_inputs[i] = strtol(str_input.c_str(), NULL, 10);
		}

		if(0 != (*the_ext_lib_z2.ext_make_input_from_integer)(&spdz_gf2n_ext_context, &bit_inputs[0], required_input_count, &clr_bit_input))
		{
			cerr << "Processor::Ext_BInput_Share_Int extension library ext_make_input_from_integer() failed." << endl;
			dlclose(the_ext_lib_z2.ext_lib_handle);
			abort();
		}

	}


	if(0 != (*the_ext_lib_z2.ext_input_party)(&spdz_gf2n_ext_context, input_party_id, &clr_bit_input, &sec_bit_input))
	{
		cerr << "Processor::Ext_BInput_Share_Int extension library ext_input_party() failed." << endl;
		dlclose(the_ext_lib_z2.ext_lib_handle);
		abort();
	}

	delete clr_bit_input.data;

	int sz=reg.size();
	vector< Share<gf2n> >& Sh_PO = get_Sh_PO<gf2n>();
	Sh_PO.clear();
#if defined(EXT_NEC_RING)
	Sh_PO.resize(sz*size);
#else
	Sh_PO.reserve(sz*size);
#endif
	import_shares(sec_bit_input, Sh_PO);
	load_bshares(reg, Sh_PO, size);

	delete sec_bit_input.data;
}

void Processor::Ext_Input_Share_Fix(const vector<int>& reg, int size, const int input_party_id)
{
	size_t required_input_count = reg.size();
	size_t required_input_size = required_input_count * zp_word64_size * 8;

	clear_t clr_fix_input;
	clr_fix_input.count = required_input_count;
	clr_fix_input.size = zp_word64_size * 8;
	clr_fix_input.data = new u_int8_t[required_input_size];
	memset(clr_fix_input.data, 0, required_input_size);

	share_t sec_fix_input;
	sec_fix_input.count = required_input_count;
	sec_fix_input.size = zp_word64_size * 8;
	sec_fix_input.data = new u_int8_t[required_input_size];
	memset(sec_fix_input.data, 0, required_input_size);

	if(P.my_num() == input_party_id)
	{
		std::vector<const char *> fix_inputs(required_input_count);
		std::vector<std::string> str_inputs(required_input_count);
		for(size_t i = 0; i < required_input_count; ++i)
		{
			if(0 != read_input_line(input_file_fix, str_inputs[i]))
			{
				cerr << "Processor::Ext_Input_Share_Fix failed reading fix input value " << i << endl;
				dlclose(the_ext_lib_z2n.ext_lib_handle);
				dlclose(the_ext_lib_z2.ext_lib_handle);
				abort();
			}
			fix_inputs[i] = str_inputs[i].c_str();
		}
		if(0 != (*the_ext_lib_z2n.ext_make_input_from_fixed)(&spdz_gfp_ext_context, &fix_inputs[0], required_input_count, &clr_fix_input))
		{
			cerr << "Processor::Ext_Input_Share_Fix extension library ext_make_input_from_fixed() failed." << endl;
			dlclose(the_ext_lib_z2n.ext_lib_handle);
			dlclose(the_ext_lib_z2.ext_lib_handle);
			abort();
		}
	}

	if(0 != (*the_ext_lib_z2n.ext_input_party)(&spdz_gfp_ext_context, input_party_id, &clr_fix_input, &sec_fix_input))
	{
		cerr << "Processor::Ext_Input_Share_Fix extension library ext_input_party() failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}

	delete clr_fix_input.data;

	int sz=reg.size();
	vector< Share<gfp> >& Sh_PO = get_Sh_PO<gfp>();
	Sh_PO.clear();
	Sh_PO.reserve(sz*size);
	import_shares(sec_fix_input, Sh_PO);
	load_shares(reg, Sh_PO, size);

	delete sec_fix_input.data;
}

void Processor::Ext_Input_Clear_Int(const vector<int>& reg, int size, const int input_party_id)
{
	size_t required_input_count = reg.size();
	size_t required_input_size = required_input_count * zp_word64_size * 8;

	clear_t clr_int_input;
	clr_int_input.count = required_input_count;
	clr_int_input.size = zp_word64_size * 8;
	clr_int_input.data = new u_int8_t[required_input_size];
	memset(clr_int_input.data, 0, required_input_size);

	if(P.my_num() == input_party_id)
	{
		std::vector<u_int64_t> int_inputs(required_input_count);
		std::string str_input;
		for(size_t i = 0; i < required_input_count; ++i)
		{
			if(0 != read_input_line(input_file_int, str_input))
			{
				cerr << "Processor::Ext_Input_Clear_Int failed reading integer input value " << i << endl;
				dlclose(the_ext_lib_z2n.ext_lib_handle);
				dlclose(the_ext_lib_z2.ext_lib_handle);
				abort();
			}
			int_inputs[i] = strtol(str_input.c_str(), NULL, 10);
		}
		if(0 != (*the_ext_lib_z2n.ext_make_input_from_integer)(&spdz_gfp_ext_context, &int_inputs[0], required_input_count, &clr_int_input))
		{
			cerr << "Processor::Ext_Input_Clear_Int extension library ext_make_input_from_integer() failed." << endl;
			dlclose(the_ext_lib_z2n.ext_lib_handle);
			abort();
		}
	}

	vector<gfp>& PO = get_PO<gfp>();
	vector<gfp>& C = get_C<gfp>();
	int sz=reg.size();
	PO.resize(sz*size);
	import_clears(clr_int_input, PO);
	load_clears(reg, PO, C, size);

	delete clr_int_input.data;
}

void Processor::Ext_Input_Clear_Fix(const vector<int>& reg, int size, const int input_party_id)
{
	size_t required_input_count = reg.size();
	size_t required_input_size = required_input_count * zp_word64_size * 8;

	clear_t clr_fix_input;
	clr_fix_input.count = required_input_count;
	clr_fix_input.size = zp_word64_size * 8;
	clr_fix_input.data = new u_int8_t[required_input_size];
	memset(clr_fix_input.data, 0, required_input_size);

	if(P.my_num() == input_party_id)
	{
		std::vector<const char *> fix_inputs(required_input_count);
		std::vector<std::string> str_inputs(required_input_count);
		for(size_t i = 0; i < required_input_count; ++i)
		{
			if(0 != read_input_line(input_file_fix, str_inputs[i]))
			{
				cerr << "Processor::Ext_Input_Clear_Fix failed reading fix input value " << i << endl;
				dlclose(the_ext_lib_z2n.ext_lib_handle);
				abort();
			}
			fix_inputs[i] = str_inputs[i].c_str();
		}
		if(0 != (*the_ext_lib_z2n.ext_make_input_from_fixed)(&spdz_gfp_ext_context, &fix_inputs[0], required_input_count, &clr_fix_input))
		{
			cerr << "Processor::Ext_Input_Clear_Fix extension library ext_make_input_from_fixed() failed." << endl;
			dlclose(the_ext_lib_z2n.ext_lib_handle);
			abort();
		}
	}

	vector<gfp>& PO = get_PO<gfp>();
	vector<gfp>& C = get_C<gfp>();
	int sz=reg.size();
	PO.resize(sz*size);
	import_clears(clr_fix_input, PO);
	load_clears(reg, PO, C, size);

	delete clr_fix_input.data;
}

void Processor::Ext_Suggest_Optional_Verification()
{
	int error = 0;
	if(0 != (*the_ext_lib_z2n.ext_verify_optional_suggest)(&spdz_gfp_ext_context, &error))
	{
		cerr << "Processor::Ext_Suggest_Optional_Verification extension library ext_verify_optional_suggest() failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}
	cout << "Optional verification suggestion returned " << error << endl;
}

void Processor::Ext_Final_Verification()
{
	int error = 0;
	if(0 != (*the_ext_lib_z2n.ext_verify_final)(&spdz_gfp_ext_context, &error))
	{
		cerr << "Processor::Ext_Final_Verification extension library ext_verify_final() failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}
	cout << "Final verification returned " << error << endl;
}

void Processor::Ext_Mult_Start(const vector<int>& reg, int size)
{
	int sz=reg.size();

	vector< Share<gfp> >& Sh_PO = get_Sh_PO<gfp>();
	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

	prep_shares(reg, Sh_PO, size);
	if(Sh_PO.size()%2 != 0)
	{
		cerr << "Processor::Ext_Mult_Start called with an odd number of operands " << Sh_PO.size() << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}

//	vector<gfp>& PO = get_PO<gfp>();
//	PO.resize(sz*size);

//	vector< Share<gfp> > lhs_factors, rhs_factors;
//	vector< Share<gfp> >::const_iterator curr = Sh_PO.begin(), stop = Sh_PO.end();
//	while(curr != stop)
//	{
//		lhs_factors.push_back(*curr++);
//		rhs_factors.push_back(*curr++);
//	}

	if (lhs_factors_ring.size() != (uint32_t)(sz/2)) {
		lhs_factors_ring.resize(sz/2);
		rhs_factors_ring.resize(sz/2);
		mult_allocate(lhs_factors_ring.size());
	}

	for (int i=0; i<sz/2; i++) {
		lhs_factors_ring[i] = Sh_PO[2*i];
		rhs_factors_ring[i] = Sh_PO[2*i+1];
	}

	export_shares(lhs_factors_ring, mult_factor1);
	export_shares(rhs_factors_ring, mult_factor2);

//	memset(mult_product.data, 0, mult_product.size * mult_product.count);

	if(0 != (*the_ext_lib_z2n.ext_start_mult)(&spdz_gfp_ext_context, &mult_factor1, &mult_factor2, &mult_product))
	{
		cerr << "Processor::Ext_Mult_Start extension library start_mult failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}
	else
	{
//		cout << "Processor::Ext_Mult_Start extension library start_mult launched." << endl;
	}
}

#if defined(EXT_NEC_RING)
void Processor::Ext_BMult_Start(const vector<int>& reg, int size)
{
	int sz=reg.size();

	vector< Share<gf2n> >& Sh_PO = get_Sh_PO<gf2n>();

	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

//	if (Sh_PO.size() != (uint32_t)(sz*size)) {
//		Sh_PO.clear();
//		Sh_PO.reserve(sz*size);
//	}

	prep_shares(reg, Sh_PO, size);
	if(Sh_PO.size()%2 != 0)
	{
		cerr << "Processor::Ext_Mult_Start called with an odd number of operands " << Sh_PO.size() << endl;
		dlclose(the_ext_lib_z2.ext_lib_handle);
		abort();
	}

//	vector<gfp>& PO = get_PO<gfp>();
//	PO.resize(sz*size);

//	vector< Share<gf2n> > lhs_factors, rhs_factors;
//	vector< Share<gf2n> >::const_iterator curr = Sh_PO.begin(), stop = Sh_PO.end();

	if (lhs_factors_bit.size() != (uint32_t)(sz/2)) {
		lhs_factors_bit.resize(sz/2);
		rhs_factors_bit.resize(sz/2);
		bmult_allocate(lhs_factors_bit.size());
	}

	for (int i=0; i<sz/2; i++) {
		lhs_factors_bit[i] = Sh_PO[2*i];
		rhs_factors_bit[i] = Sh_PO[2*i+1];
//		cout << "lhs_factors " << i << " = " << lhs_factors[i].get_share().get() << ", " << lhs_factors[i].get_mac().get() << endl;
//		cout << "rhs_factors " << i << " = " << rhs_factors[i].get_share().get() << ", " << rhs_factors[i].get_mac().get() << endl;
	}

//	while(curr != stop)
//	{
//		lhs_factors.push_back(*curr++);
//		rhs_factors.push_back(*curr++);
//	}

	export_shares(lhs_factors_bit, bmult_factor1);
	export_shares(rhs_factors_bit, bmult_factor2);

// ###### start debug ######
//	SPDZEXT_VALTYPE *pb1 = (SPDZEXT_VALTYPE *)bmult_factor1.data;
//	SPDZEXT_VALTYPE *pb2 = (SPDZEXT_VALTYPE *)bmult_factor2.data;
//	for (size_t i=0; i<bmult_factor1.count; i++) {
//		cout << "pb1 = " << pb1[2*i] << ", " << pb1[2*i+1] << endl;
//		cout << "pb2 = " << pb2[2*i] << ", " << pb2[2*i+1] << endl;
//	}
// ###### end debug ######


//	memset(bmult_product.data, 0, bmult_product.size * bmult_product.count);

	if(0 != (*the_ext_lib_z2.ext_start_mult)(&spdz_gf2n_ext_context, &bmult_factor1, &bmult_factor2, &bmult_product))
	{
		cerr << "Processor::Ext_BMult_Start extension library start_mult failed." << endl;
		dlclose(the_ext_lib_z2.ext_lib_handle);
		abort();
	}
	else
	{
//		cout << "Processor::Ext_BMult_Start extension library start_mult launched." << endl;
	}
}
#endif

void Processor::Ext_Mult_Stop(const vector<int>& reg, int size)
{
	if(0 != (*the_ext_lib_z2n.ext_stop_mult)(&spdz_gfp_ext_context))
	{
		cerr << "Processor::Ext_Mult_Stop library stop_mult failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}

#if defined(EXT_NEC_RING)
	vector< Share<gfp> >& Sh_PO = get_Sh_PO<gfp>();
	int sz=reg.size();
	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

	prep_shares(reg, Sh_PO, size);
	import_shares(mult_product, Sh_PO);
	load_shares(reg, Sh_PO, size);
#else
	mult_stop_prep_products(reg, size);
#endif
	sent += reg.size() * size;
	rounds++;
//	cout << "Processor::Ext_Mult_Stop extension library stop_mult launched." << endl;
}

#if defined(EXT_NEC_RING)
void Processor::Ext_BMult_Stop(const vector<int>& reg, int size)
{
	if(0 != (*the_ext_lib_z2.ext_stop_mult)(&spdz_gf2n_ext_context))
	{
		cerr << "Processor::Ext_BMult_Stop library stop_mult failed." << endl;
		dlclose(the_ext_lib_z2.ext_lib_handle);
		abort();
	}

	vector< Share<gf2n> >& Sh_PO = get_Sh_PO<gf2n>();
	int sz=reg.size();

	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

//	if (Sh_PO.size() != (uint32_t)(sz*size)) {
//		Sh_PO.clear();
//		Sh_PO.reserve(sz*size);
//	}

	prep_shares(reg, Sh_PO, size);
	import_shares(bmult_product, Sh_PO);
//	load_shares(reg, Sh_PO, size);
	load_bshares(reg, Sh_PO, size);

	sent += reg.size() * size;
	rounds++;
//	cout << "Processor::Ext_BMult_Stop extension library stop_mult launched." << endl;
}
#endif

void Processor::Ext_Open_Start(const vector<int>& reg, int size)
{
	int sz=reg.size();

	vector< Share<gfp> >& Sh_PO = get_Sh_PO<gfp>();
	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

	prep_shares(reg, Sh_PO, size);

	vector<gfp>& PO = get_PO<gfp>();
	PO.resize(sz*size);

	open_allocate(Sh_PO.size());
	export_shares(Sh_PO, open_shares);

//	cout << "[Processor.cpp::Ext_Open_Start] open_clears  = " << (SPDZEXT_VALTYPE)(*open_clears.data) <<endl;

	if(0 != (*the_ext_lib_z2n.ext_start_open)(&spdz_gfp_ext_context, &open_shares, &open_clears))
	{
		cerr << "Processor::Ext_Open_Start library start_open failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}
	else
	{
		//cout << "Processor::Ext_Open_Start extension library start_open launched." << endl;
	}

//	cout << "[Processor.cpp::Ext_Open_Start] open_clears  = " << (SPDZEXT_VALTYPE)(*open_clears.data) <<endl;
}

void Processor::Ext_BOpen_Start(const vector<int>& reg, int size)
{
	int sz=reg.size();

	vector< Share<gf2n> >& Sh_PO = get_Sh_PO<gf2n>();
	Sh_PO.clear();
	Sh_PO.reserve(sz*size);

	prep_shares(reg, Sh_PO, size);

	vector<gf2n>& PO = get_PO<gf2n>();
	PO.resize(sz*size);

	bopen_allocate(Sh_PO.size());
	export_shares(Sh_PO, bopen_shares);


	if(0 != (*the_ext_lib_z2.ext_start_open)(&spdz_gf2n_ext_context, &bopen_shares, &bopen_clears))
	{
		cerr << "Processor::Ext_BOpen_Start library start_open failed." << endl;
		dlclose(the_ext_lib_z2.ext_lib_handle);
		abort();
	}
	else
	{
//		cout << "Processor::Ext_BOpen_Start extension library start_open launched." << endl;s
	}
}

void Processor::Ext_Open_Stop(const vector<int>& reg, int size)
{
	if(0 != (*the_ext_lib_z2n.ext_stop_open)(&spdz_gfp_ext_context))
	{
		cerr << "Processor::Ext_Open_Stop library start_open failed." << endl;
		dlclose(the_ext_lib_z2n.ext_lib_handle);
		abort();
	}

	vector<gfp>& PO = get_PO<gfp>();
	vector<gfp>& C = get_C<gfp>();
	int sz=reg.size();
	PO.resize(sz*size);
	import_clears(open_clears, PO);
	load_clears(reg, PO, C, size);
}

void Processor::Ext_BOpen_Stop(const vector<int>& reg, int size)
{
	if(0 != (*the_ext_lib_z2.ext_stop_open)(&spdz_gf2n_ext_context))
	{
		cerr << "Processor::Ext_BOpen_Stop library start_open failed." << endl;
		dlclose(the_ext_lib_z2.ext_lib_handle);
		abort();
	}

	vector<gf2n>& PO = get_PO<gf2n>();
	vector<gf2n>& C = get_C<gf2n>();
	int sz=reg.size();
	PO.resize(sz*size);
	import_clears(bopen_clears, PO);
	load_clears(reg, PO, C, size);
}

void Processor::mult_stop_prep_products(const vector<int>& reg, int size)
{
	bigint b;
	gfp mac, value;
	if (size>1)
	{
		size_t product_idx = 0;
		for (typename vector<int>::const_iterator reg_it=reg.begin(); reg_it!=reg.end(); reg_it++)
		{
			vector<Share<gfp> >::iterator insert_point=get_S<gfp>().begin()+*reg_it;
			for(int i = 0; i < size; ++i)
			{
				mpz_import(b.get_mpz_t(), zp_word64_size, share_port_order, share_port_size, share_port_endian,
						   share_port_nails, mult_product.data + (product_idx * mult_product.size));
				to_gfp(value, b);
				mac.mul(MCp.get_alphai(), value);
				(*(insert_point + i)).set_share(value);
				(*(insert_point + i)).set_share(mac);
			}
		}
	}
	else
	{
		int sz=reg.size();
		for(int i = 0; i < sz; ++i)
		{
			mpz_import(b.get_mpz_t(), zp_word64_size, share_port_order, share_port_size, share_port_endian,
					   share_port_nails, mult_product.data + (i * mult_product.size));
			to_gfp(value, b);
			mac.mul(MCp.get_alphai(), value);
			get_S_ref<gfp>(reg[i]).set_share(value);
			get_S_ref<gfp>(reg[i]).set_share(mac);
		}
	}
}

size_t Processor::get_zp_word64_size()
{
	size_t bit_size = gfp::get_ZpD().pr.numBits();
	size_t byte_size = ((bit_size + 7) / 8);
	size_t word64_size = ((byte_size + 7) / 8);

	return word64_size;
}

void Processor::export_shares(const vector< Share<gfp> > & shares_in, share_t & shares_out)
{
	assert(shares_in.size() == shares_out.count);

#if defined(EXT_NEC_RING)
	SPDZEXT_VALTYPE *p = (SPDZEXT_VALTYPE *)shares_out.data;

	for (size_t i=0; i<shares_out.count; ++i) {
		SPDZEXT_VALTYPE x1 = shares_in[i].get_share().get_ring();
		SPDZEXT_VALTYPE x2 = shares_in[i].get_mac().get_ring();
		p[2*i]   = x1;
		p[2*i+1] = x2;
//		memcpy(shares_out.data + (i*shares_out.size), &x1, sizeof(SPDZEXT_VALTYPE) );
//		memcpy(shares_out.data + (i*shares_out.size) + sizeof(SPDZEXT_VALTYPE), &x2, sizeof(SPDZEXT_VALTYPE) );
	}
#else
	bigint b;
	for(size_t i = 0; i < shares_out.count; ++i)
	{
		to_bigint(b, shares_in[i].get_share());
		memset(shares_out.data + (i * shares_out.size), 0, shares_out.size);
		mpz_export(shares_out.data + (i * shares_out.size), NULL, share_port_order, share_port_size, share_port_endian, share_port_nails, b.get_mpz_t());
	}
#endif
}

#if defined(EXT_NEC_RING)
void Processor::export_shares(const vector< Share<gf2n> > & shares_in, share_t & shares_out)
{
	assert(shares_in.size() == shares_out.count);

	SPDZEXT_VALTYPE *p = (SPDZEXT_VALTYPE *)shares_out.data;
	for (size_t i=0; i<shares_out.count; ++i) {
		SPDZEXT_VALTYPE x1 = shares_in[i].get_share().get();
		SPDZEXT_VALTYPE x2 = shares_in[i].get_mac().get();
		p[2*i]   = x1;
		p[2*i+1] = x2;
	}
}
#endif

void Processor::import_shares(const share_t & shares_in, vector< Share<gfp> > & shares_out)
{
	assert(shares_in.count == shares_out.size());

#if defined(EXT_NEC_RING)
	SPDZEXT_VALTYPE *p = (SPDZEXT_VALTYPE *)shares_in.data;

	for (size_t i=0; i<shares_in.count; ++i) {
		SPDZEXT_VALTYPE x1 = p[2*i];
		SPDZEXT_VALTYPE x2 = p[2*i+1];
		gfp g1, g2;
		g1.assign_ring(x1);
		g2.assign_ring(x2);
		shares_out[i].set_share(g1);
		shares_out[i].set_mac(g2);
	}
#else
	bigint b;
	gfp mac, value;
	for(size_t i = 0; i < shares_in.count; ++i)
	{
		mpz_import(b.get_mpz_t(), zp_word64_size, share_port_order, share_port_size, share_port_endian, share_port_nails, shares_in.data + (i * shares_in.size));
		to_gfp(value, b);
		mac.mul(MCp.get_alphai(), value);
		shares_out[i].set_share(value);
		shares_out[i].set_mac(mac);
	}
#endif
}

#if defined(EXT_NEC_RING)
void Processor::import_shares(const share_t & shares_in, vector< Share<gf2n> > & shares_out)
{
	assert(shares_in.count == shares_out.size());

	SPDZEXT_VALTYPE *p = (SPDZEXT_VALTYPE *)shares_in.data;

	for (size_t i=0; i<shares_in.count; ++i) {
		SPDZEXT_VALTYPE x1 = p[2*i];
		SPDZEXT_VALTYPE x2 = p[2*i+1];
		gf2n g1, g2;
		g1.assign(x1);
		g2.assign(x2);
		shares_out[i].set_share(g1);
		shares_out[i].set_mac(g2);
	}
}
#endif

void Processor::import_clears(const clear_t & clear_in, vector< gfp > & clears_out)
{
	assert(clear_in.count == clears_out.size());
#if defined(EXT_NEC_RING)

	for (size_t i=0; i<clear_in.count; i++) {
		SPDZEXT_VALTYPE tmp = 0;
		for (size_t j = 0; j<clear_in.size; j++) {
			tmp += ((SPDZEXT_VALTYPE)(*(clear_in.data + j + (i*clear_in.size) )) << j * 8);
		}
		clears_out[i].assign_ring(tmp);
	}

//	for (size_t i=0; i<clear_in.count; i++) {
//		clears_out[i].assign_ring((SPDZEXT_VALTYPE)(*(clear_in.data + i*clear_in.size)));
//	}

#else
	bigint b;
	for(size_t i = 0; i < clear_in.count; ++i)
	{
		mpz_import(b.get_mpz_t(), zp_word64_size, share_port_order, share_port_size, share_port_endian, share_port_nails, clear_in.data + (i * clear_in.size));
		to_gfp(clears_out[i], b);
	}
#endif
}

#if defined(EXT_NEC_RING)
void Processor::import_clears(const clear_t & clear_in, vector< gf2n > & clears_out)
{
	assert(clear_in.count == clears_out.size());

	for (size_t i=0; i<clear_in.count; i++) {
		SPDZEXT_VALTYPE tmp = 0;
		for (size_t j = 0; j<clear_in.size; j++) {
			tmp += ((SPDZEXT_VALTYPE)(*(clear_in.data + j + (i*clear_in.size) )) << j * 8);
		}
		clears_out[i].assign(tmp);
	}

//	for (size_t i=0; i<clear_in.count; i++) {
//		clears_out[i].assign((SPDZEXT_VALTYPE)(*(clear_in.data + i*clear_in.size)));
//	}
}
#endif

int Processor::open_input_file()
{
	char buffer[256];

	snprintf(buffer, 256, "integers_input_%d.txt", P.my_num());
	input_file_int = fopen(buffer, "r");
	if(NULL == input_file_int)
		return -1;

	snprintf(buffer, 256, "fixes_input_%d.txt", P.my_num());
	input_file_fix = fopen(buffer, "r");
	if(NULL == input_file_fix)
	{
		fclose(input_file_int);
		return -1;
	}

	snprintf(buffer, 256, "bits_input_%d.txt", P.my_num());
	input_file_bit = fopen(buffer, "r");
	if(NULL == input_file_bit)
	{
		fclose(input_file_int);
		fclose(input_file_fix);
		return -1;
	}

	snprintf(buffer, 256, "shares_input_%d.txt", P.my_num());
	input_file_share = fopen(buffer, "r");
	if(NULL == input_file_share)
	{
		fclose(input_file_int);
		fclose(input_file_fix);
		fclose(input_file_bit);
		return -1;
	}

	return 0;
}

int Processor::close_input_file()
{
	if(NULL != input_file_int)
	{
		fclose(input_file_int);
		input_file_int = NULL;
	}
	if(NULL != input_file_fix)
	{
		fclose(input_file_fix);
		input_file_fix = NULL;
	}
	if(NULL != input_file_bit)
	{
		fclose(input_file_bit);
		input_file_bit = NULL;
	}
	if(NULL != input_file_share)
	{
		fclose(input_file_share);
		input_file_share = NULL;
	}
	return 0;
}

int Processor::read_input_line(FILE * input_file, std::string & line)
{
	char buffer[256];
	if(NULL != fgets(buffer, 256, input_file))
	{
		line = buffer;
		return 0;
	}
	else
		return -1;
}

void Processor::mult_allocate(const size_t required_count)
{
	if(required_count > mult_allocated)
	{
		mult_clear();
		mult_allocated = mult_factor1.count = mult_factor2.count = mult_product.count = required_count;
#if defined(EXT_NEC_RING)
		mult_factor1.size = mult_factor2.size = mult_product.size = 2 * zp_word64_size * 8; // 2 * ... replicated
#else
		mult_factor1.size = mult_factor2.size = mult_product.size = zp_word64_size * 8;
#endif
		mult_factor1.data = new u_int8_t[mult_factor1.size * mult_factor1.count];
		mult_factor2.data = new u_int8_t[mult_factor2.size * mult_factor2.count];
		mult_product.data = new u_int8_t[mult_product.size * mult_product.count];
	}
	else
	{
		mult_factor1.count = mult_factor2.count = mult_product.count = required_count;
	}
}

void Processor::mult_clear()
{
	if(0 < mult_allocated)
	{
		delete mult_factor1.data;		mult_factor1.data = NULL;
		delete mult_factor2.data;		mult_factor2.data = NULL;
		delete mult_product.data;		mult_product.data = NULL;
		mult_factor1.size = mult_factor2.size = mult_product.size = 0;
		mult_factor1.count = mult_factor2.count = mult_product.count = mult_allocated = 0;
	}
}

#if defined(EXT_NEC_RING)
void Processor::bmult_allocate(const size_t required_count)
{
	if(required_count > bmult_allocated)
	{
		bmult_clear();
		bmult_allocated = bmult_factor1.count = bmult_factor2.count = bmult_product.count = required_count;

		bmult_factor1.size = bmult_factor2.size = bmult_product.size = 2 * zp_word64_size * 8; // 2 * ... replicated
		bmult_factor1.data = new u_int8_t[bmult_factor1.size * bmult_factor1.count];
		bmult_factor2.data = new u_int8_t[bmult_factor2.size * bmult_factor2.count];
		bmult_product.data = new u_int8_t[bmult_product.size * bmult_product.count];
	}
	else
	{
		bmult_factor1.count = bmult_factor2.count = bmult_product.count = required_count;
	}
}

void Processor::bmult_clear()
{
	if(0 < bmult_allocated)
	{
		delete bmult_factor1.data;		bmult_factor1.data = NULL;
		delete bmult_factor2.data;		bmult_factor2.data = NULL;
		delete bmult_product.data;		bmult_product.data = NULL;
		bmult_factor1.size = bmult_factor2.size = bmult_product.size = 0;
		bmult_factor1.count = bmult_factor2.count = bmult_product.count = bmult_allocated = 0;
	}
}
#endif

/*
size_t open_allocated;
share_t open_shares;
clear_t open_clears;*/
void Processor::open_allocate(const size_t required_count)
{
#if defined(EXT_NEC_RING)
	if(required_count > open_allocated)
	{
		open_clear();
		open_shares.count = open_clears.count = open_allocated = required_count;
		open_clears.size = zp_word64_size * 8;
		open_shares.size = 2 * open_clears.size;
		open_shares.data = new u_int8_t[open_shares.size * open_shares.count];
		open_clears.data = new u_int8_t[open_clears.size * open_clears.count];
	}
#else
	if(required_count > open_allocated)
	{
		open_clear();
		open_shares.count = open_clears.count = open_allocated = required_count;
		open_shares.size = open_clears.size = zp_word64_size * 8;
		open_shares.data = new u_int8_t[open_shares.size * open_shares.count];
		open_clears.data = new u_int8_t[open_clears.size * open_clears.count];
	}
#endif
	else
	{
		open_shares.count = open_clears.count = required_count;
	}
}

void Processor::open_clear()
{
	if(0 < open_allocated)
	{
		delete open_shares.data;		open_shares.data = NULL;
		delete open_clears.data;		open_clears.data = NULL;
		open_shares.size = open_clears.size = 0;
		open_shares.count = open_clears.count = open_allocated = 0;
	}
}



#if defined(EXT_NEC_RING)
/*
size_t bopen_allocated;
share_t bopen_shares;
clear_t bopen_clears;*/
void Processor::bopen_allocate(const size_t required_count)
{
	if(required_count > bopen_allocated)
	{
		bopen_clear();
		bopen_shares.count = bopen_clears.count = bopen_allocated = required_count;
		bopen_clears.size = zp_word64_size * 8;
		bopen_shares.size = 2 * bopen_clears.size;
		bopen_shares.data = new u_int8_t[bopen_shares.size * bopen_shares.count];
		bopen_clears.data = new u_int8_t[bopen_clears.size * bopen_clears.count];
	}
	else
	{
		bopen_shares.count = bopen_clears.count = required_count;
	}
}

void Processor::bopen_clear()
{
	if(0 < bopen_allocated)
	{
		delete bopen_shares.data;		bopen_shares.data = NULL;
		delete bopen_clears.data;		bopen_clears.data = NULL;
		bopen_shares.size = bopen_clears.size = 0;
		bopen_shares.count = bopen_clears.count = bopen_allocated = 0;
	}
}
#endif

//*****************************************************************************************//

#define LOAD_LIB_METHOD(Name,Proc)	\
if(0 != load_extension_method(Name, (void**)(&Proc), ext_lib_handle)) { dlclose(ext_lib_handle); abort(); }

spdz_ext_ifc::spdz_ext_ifc()
{
	ext_lib_handle = NULL;
	*(void**)(&ext_init) = NULL;
	*(void**)(&ext_term) = NULL;
	*(void**)(&ext_skew_bit_decomp) = NULL;
	*(void**)(&ext_skew_ring_comp) = NULL;
	*(void**)(&ext_input_party) = NULL;
	*(void**)(&ext_input_share) = NULL;
	*(void**)(&ext_make_input_from_integer) = NULL;
	*(void**)(&ext_make_input_from_fixed) = NULL;
	*(void**)(&ext_start_open) = NULL;
	*(void**)(&ext_stop_open) = NULL;
	*(void**)(&ext_make_integer_output) = NULL;
	*(void**)(&ext_make_fixed_output) = NULL;
	*(void**)(&ext_verify_optional_suggest) = NULL;
	*(void**)(&ext_verify_final) = NULL;
	*(void**)(&ext_start_mult) = NULL;
	*(void**)(&ext_stop_mult) = NULL;

	//get the SPDZ-2 extension library for env-var
	const char * spdz_ext_lib = getenv("SPDZ_EXT_LIB");
	if(NULL == spdz_ext_lib)
	{
		cerr << "SPDZ extension library not set" << endl;
		abort();
	}
	cout << "set extension library " << spdz_ext_lib << endl;

	//verify the SPDZ-2 extension library exists
	struct stat st;
	if(0 != stat(spdz_ext_lib, &st))
	{
		cerr << "failed to find extension library " << spdz_ext_lib << endl;
		abort();
	}
	cout << "found extension library " << spdz_ext_lib << endl;

	//load the SPDZ-2 extension library
	ext_lib_handle = dlopen(spdz_ext_lib, RTLD_NOW);
	if(NULL == ext_lib_handle)
	{
		const char * dlopen_err_msg = dlerror();
		cerr << "failed to load extension library [" << ((NULL != dlopen_err_msg)? dlopen_err_msg: "") << "]" << endl;
		abort();
	}

	//loading the SPDZ-2 extension library methods
	LOAD_LIB_METHOD("init", ext_init)
	LOAD_LIB_METHOD("term", ext_term)
	LOAD_LIB_METHOD("skew_bit_decomp", ext_skew_bit_decomp)
	LOAD_LIB_METHOD("skew_ring_comp", ext_skew_ring_comp)
	LOAD_LIB_METHOD("input_party", ext_input_party)
	LOAD_LIB_METHOD("input_share", ext_input_share)
	LOAD_LIB_METHOD("make_input_from_integer", ext_make_input_from_integer)
	LOAD_LIB_METHOD("make_input_from_fixed", ext_make_input_from_fixed)
	LOAD_LIB_METHOD("start_open", ext_start_open)
	LOAD_LIB_METHOD("stop_open", ext_stop_open)
	LOAD_LIB_METHOD("make_integer_output", ext_make_integer_output)
	LOAD_LIB_METHOD("make_fixed_output", ext_make_fixed_output)
	LOAD_LIB_METHOD("verify_optional_suggest", ext_verify_optional_suggest)
	LOAD_LIB_METHOD("verify_final", ext_verify_final)
	LOAD_LIB_METHOD("start_mult", ext_start_mult)
	LOAD_LIB_METHOD("stop_mult", ext_stop_mult)
}

spdz_ext_ifc::~spdz_ext_ifc()
{
	dlclose(ext_lib_handle);
}

int spdz_ext_ifc::load_extension_method(const char * method_name, void ** proc_addr, void * libhandle)
{
	*proc_addr = dlsym(libhandle, method_name);
	const char * dlsym_error = dlerror();
	if(NULL != dlsym_error || NULL == *proc_addr)
	{
		cerr << "failed to load " << method_name << " extension [" << ((NULL != dlsym_error)? dlsym_error: "") << "]" << endl;
		return -1;
	}
	return 0;
}

//*****************************************************************************************//

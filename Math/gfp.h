// (C) 2018 University of Bristol. See License.txt

#ifndef _gfp
#define _gfp

#include <iostream>
using namespace std;

#include "Math/gf2n.h"
#include "Math/modp.h"
#include "Math/Zp_Data.h"
#include "Math/field_types.h"
#include "Tools/random.h"

/* This is a wrapper class for the modp data type
 * It is used to be interface compatible with the gfp
 * type, which then allows us to template the Share
 * data type.
 *
 * So gfp is used ONLY for the stuff in the finite fields
 * we are going to be doing MPC over, not the modp stuff
 * for the FHE scheme
 */

class gfp
{
  modp a;
  static Zp_Data ZpD;

#if defined(EXT_NEC_RING)
  SPDZEXT_VALTYPE a_ring;
  uint32_t precision;
#endif

  public:

  typedef gfp value_type;

  static void init_field(const bigint& p,bool mont=true)
    { ZpD.init(p,mont); }
  static bigint pr()   
    { return ZpD.pr; }
  static int t()
    { return ZpD.get_t();  }
  static Zp_Data& get_ZpD()
    { return ZpD; }

  static DataFieldType field_type() { return DATA_MODP; }
  static char type_char() { return 'p'; }
  static string type_string() { return "gfp"; }

  static int size() { return t() * sizeof(mp_limb_t); }

  void assign(const gfp& g) {
	  a=g.a;
#if defined(EXT_NEC_RING)
	  a_ring = g.a_ring;
#endif
  }
  void assign_zero()        {
#if defined(EXT_NEC_RING)
	  a_ring = 0;
#else
	  assignZero(a,ZpD);
#endif
  }
  void assign_one()         { assignOne(a,ZpD); } 
  void assign(word aa)      {
	  bigint b=aa; to_gfp(*this,b);
#if defined(EXT_NEC_RING)
	  a_ring = (SPDZEXT_VALTYPE)aa;
#endif
  }
  void assign(long aa)      {
	  bigint b=aa; to_gfp(*this,b);
#if defined(EXT_NEC_RING)
	  a_ring = (SPDZEXT_VALTYPE)aa;
#endif
  }
  void assign(int aa)       {
	  bigint b=aa; to_gfp(*this,b);
#if defined(EXT_NEC_RING)
	  a_ring = (SPDZEXT_VALTYPE)aa;
#endif
  }
  void assign(const char* buffer) { a.assign(buffer, ZpD.get_t()); }

  modp get() const          { return a; }
#if defined(EXT_NEC_RING)
  void assign_ring(SPDZEXT_VALTYPE aa) { a_ring = aa; }

  SPDZEXT_VALTYPE get_ring() const { return a_ring; }
#endif

  // Assumes prD behind x is equal to ZpD
  void assign(modp& x) { a=x; }
  
  gfp()              { assignZero(a,ZpD); }
  gfp(const gfp& g)  { a=g.a; }
  gfp(const modp& g) { a=g; }
  gfp(const __m128i& x) { *this=x; }
  gfp(const int128& x) { *this=x.a; }
  gfp(const bigint& x) { to_modp(a, x, ZpD); }
  gfp(int x)         { assign(x); }
  ~gfp()             { ; }

  gfp& operator=(const gfp& g)
    { if (&g!=this) {
    	a=g.a;
#if defined(EXT_NEC_RING)
    	a_ring = g.a_ring;
#endif
    }
      return *this;
    }

  gfp& operator=(const __m128i other)
    {
      memcpy(a.x, &other, sizeof(other));
      return *this;
    }

  void to_m128i(__m128i& ans)
    {
      memcpy(&ans, a.x, sizeof(ans));
    }

  __m128i to_m128i()
    {
      return _mm_loadu_si128((__m128i*)a.x);
    }


  bool is_zero() const            { return isZero(a,ZpD); }
  bool is_one()  const            { return isOne(a,ZpD); }
  bool is_bit()  const            { return is_zero() or is_one(); }
  bool equal(const gfp& y) const  { return areEqual(a,y.a,ZpD); }
  bool operator==(const gfp& y) const { return equal(y); }
  bool operator!=(const gfp& y) const { return !equal(y); }

  // x+y
  template <int T>
  void add(const gfp& x,const gfp& y)
    {
	  Add<T>(a,x.a,y.a,ZpD);
#if defined(EXT_NEC_RING)
	  a_ring = x.a_ring + y.a_ring;
#endif
    }
  template <int T>
  void add(const gfp& x)
    {
	  Add<T>(a,a,x.a,ZpD);
#if defined(EXT_NEC_RING)
	  a_ring += x.a_ring;
#endif
    }
  template <int T>
  void add(void* x)
    {
	  ZpD.Add<T>(a.x,a.x,(mp_limb_t*)x);
#if defined(EXT_NEC_RING)
#endif
    }
  template <int T>
  void add(octetStream& os)
    { add<T>(os.consume(size())); }
  void add(const gfp& x,const gfp& y)
    {
	  Add(a,x.a,y.a,ZpD);
#if defined(EXT_NEC_RING)
	  a_ring = x.a_ring + y.a_ring;
#endif
    }
  void add(const gfp& x)
    {
	  Add(a,a,x.a,ZpD);
#if defined(EXT_NEC_RING)
	  a_ring += x.a_ring;
#endif
    }
  void add(void* x)
    {
	  ZpD.Add(a.x,a.x,(mp_limb_t*)x);
#if defined(EXT_NEC_RING)
#endif
    }
  void sub(const gfp& x,const gfp& y)
    {
	  Sub(a,x.a,y.a,ZpD);
#if defined(EXT_NEC_RING)
	  a_ring = x.a_ring - y.a_ring;
#endif
    }
  void sub(const gfp& x)
    {
	  Sub(a,a,x.a,ZpD);
#if defined(EXT_NEC_RING)
	  a_ring -= x.a_ring;
#endif
	  }
  // = x * y
  void mul(const gfp& x,const gfp& y)
    {
	  Mul(a,x.a,y.a,ZpD);
#if defined(EXT_NEC_RING)
	  a_ring = x.a_ring * y.a_ring;
#endif
    }
  void mul(const gfp& x) 
    {
	  Mul(a,a,x.a,ZpD);
#if defined(EXT_NEC_RING)
	  a_ring = a_ring * x.a_ring;
#endif
    }

  gfp operator+(const gfp& x) {
	  gfp res; res.add(*this, x); return res;
#if defined(EXT_NEC_RING)
#endif
  }
  gfp operator-(const gfp& x) { gfp res; res.sub(*this, x); return res; }
  gfp operator*(const gfp& x) { gfp res; res.mul(*this, x); return res; }
  gfp& operator+=(const gfp& x) { add(x); return *this; }
  gfp& operator-=(const gfp& x) { sub(x); return *this; }
  gfp& operator*=(const gfp& x) { mul(x); return *this; }

  gfp operator-() { gfp res = *this; res.negate(); return res; }

  void square(const gfp& aa)
    { Sqr(a,aa.a,ZpD); }
  void square()
    { Sqr(a,a,ZpD); }
  void invert()
    { Inv(a,a,ZpD); }
  void invert(const gfp& aa)
    { Inv(a,aa.a,ZpD); }
  void negate() 
    { Negate(a,a,ZpD); }
  void power(long i)
    { Power(a,a,i,ZpD); }

  // deterministic square root
  gfp sqrRoot();

  void randomize(PRNG& G)
    { a.randomize(G,ZpD); }
  // faster randomization, see implementation for explanation
  void almost_randomize(PRNG& G);

  void output(ostream& s,bool human) const
    {
#if defined(EXT_NEC_RING)
	  // human: true
	  if (human) {
		  s << a_ring;
	  }
#else
	  a.output(s,ZpD,human);
#endif
    }
  void input(istream& s,bool human)
    {
#if defined(EXT_NEC_RING)
	  // human: true
	  if (human) {
		  s >> a_ring;
	  }
#else
	  a.input(s,ZpD,human);
#endif
    }
  friend ostream& operator<<(ostream& s,const gfp& x)
    { x.output(s,true);
      return s;
    }
  friend istream& operator>>(istream& s,gfp& x)
    { x.input(s,true);
      return s;
    }

  /* Bitwise Ops 
   *   - Converts gfp args to bigints and then converts answer back to gfp
   */
  void AND(const gfp& x,const gfp& y);
  void XOR(const gfp& x,const gfp& y);
  void OR(const gfp& x,const gfp& y);
  void AND(const gfp& x,const bigint& y);
  void XOR(const gfp& x,const bigint& y);
  void OR(const gfp& x,const bigint& y);
  void SHL(const gfp& x,int n);
  void SHR(const gfp& x,int n);
  void SHL(const gfp& x,const bigint& n);
  void SHR(const gfp& x,const bigint& n);

  gfp operator&(const gfp& x) { gfp res; res.AND(*this, x); return res; }
  gfp operator^(const gfp& x) { gfp res; res.XOR(*this, x); return res; }
  gfp operator|(const gfp& x) { gfp res; res.OR(*this, x); return res; }
  gfp operator<<(int i) { gfp res; res.SHL(*this, i); return res; }
  gfp operator>>(int i) { gfp res; res.SHR(*this, i); return res; }

  // Pack and unpack in native format
  //   i.e. Dont care about conversion to human readable form
  void pack(octetStream& o) const
    { a.pack(o,ZpD); }
  void unpack(octetStream& o)
    { a.unpack(o,ZpD); }


  // Convert representation to and from a bigint number
  friend void to_bigint(bigint& ans,const gfp& x,bool reduce=true)
    { to_bigint(ans,x.a,x.ZpD,reduce); }
  friend void to_gfp(gfp& ans,const bigint& x)
    { to_modp(ans.a,x,ans.ZpD); }
};


#endif

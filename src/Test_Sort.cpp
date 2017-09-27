/* Copyright (C) 2012,2013 IBM Corp.
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* Test_General.cpp - A general test program that uses a mix of operations over four ciphertexts.
 */
#include <NTL/ZZ.h>
#include <NTL/BasicThreadPool.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>

#include <cassert>
#include <cstdio>

#include <algorithm>

#ifdef DEBUG_PRINTOUT
#define debugCompare(ea,sk,p,c) {\
  NewPlaintextArray pp(ea);\
  ea.decrypt(c, sk, pp);\
  if (!equals(ea, pp, p)) { \
    cerr << "oops:\n"; cerr << p << "\n"; \
    cerr << pp << "\n"; \
    exit(0); \
  }}
#else
#define debugCompare(ea,sk,p,c)
#endif

/**************

1. c1.multiplyBy(c0)
2. c0 += random constant
3. c2 *= random constant
4. tmp = c1
5. ea.shift(tmp, random amount in [-nSlots/2, nSlots/2])
6. c2 += tmp
7. ea.rotate(c2, random amount in [1-nSlots, nSlots-1])
8. c1.negate()
9. c3.multiplyBy(c2) 
10. c0 -= c3

**************/
vector<ZZX> BitsToBytePoly(const EncryptedArray &ea, const vector<NewPlaintextArray> &ptxt, int nset)
{
	vector<ZZX> result(nset, ZZX(0));
	for(int i=0; i<ptxt.size(); i++)
	{
		vector<ZZX> temp;
		decode(ea, temp, ptxt[i]);
		std::transform(temp.begin(), temp.end(), temp.begin(),
                                bind1st(std::multiplies<ZZX>(),pow(2,i)));
		std::transform (result.begin(), result.end(), temp.begin(), result.begin(), std::plus<ZZX>());
	}
	return result;
}

vector<long> BitsToByte(const EncryptedArray &ea, const vector<NewPlaintextArray> &ptxt, int nset)
{
	vector<long> result(nset, 0);
	for(int i=0; i<ptxt.size(); i++)
	{
		vector<long> temp;
		decode(ea, temp, ptxt[i]);
		std::transform(temp.begin(), temp.end(), temp.begin(), 
				bind1st(std::multiplies<long>(),pow(2,i)));
		std::transform (result.begin(), result.end(), temp.begin(), result.begin(), std::plus<long>());
	}

	return result;
}

/*void Complement(Ctxt &out, const EncryptedArray &ea, const Ctxt &in)
{
	NewPlaintextArray mask(ea);
	ea.encode(); //add(ea, p0, const1); // c0 += random constant
     c0.addConstant(const1_poly);
}*/

//z = (x+y)'
void EqualBit(Ctxt &out, const EncryptedArray &ea, const Ctxt &in1, const Ctxt &in2, const NewPlaintextArray &mask)
{
	out = in1;
	out += in2;
	ZZX one(1);
	out.addConstant(one);
//	out.addConstant(mask);
	//out.negate();
}

//z = x'.y
void LessThanBit(Ctxt &out, const EncryptedArray &ea, const Ctxt &in1, const Ctxt &in2, const NewPlaintextArray &mask, const FHEPubKey& publicKey)
{
	out = in1;
	//out.negate();
	//out.addConstant(mask);
	ZZX one(1);
        out.addConstant(one);
	out.multiplyBy(in2);
}

// z = x7'.y7 + (x7+y7)' . [x6'.y6 + (x6+y6)' . [...]]
void LessThanByte(Ctxt &out, const EncryptedArray &ea, vector<Ctxt> in1, vector<Ctxt> in2, const NewPlaintextArray &mask, const FHEPubKey& publicKey)
{
	// (X1 x0 < y1 y0)
	// (x1 < y1) + (x1 = y1) (x0 < y0)
/*	LessThanBit(out, ea, in1[1], in2[1], mask, publicKey);
	Ctxt temp1(publicKey);
	Ctxt temp2(publicKey);
	LessThanBit(temp1, ea, in1[0], in2[0], mask, publicKey);
	EqualBit(temp2, ea, in1[1], in2[1], mask);
	temp1.multiplyBy(temp2);
	out += temp1;
*/

	//Ctxt z(publicKey);
	vector<Ctxt> t(8, Ctxt(publicKey));
	vector<Ctxt> k(8, Ctxt(publicKey));
	vector<Ctxt> d(7, Ctxt(publicKey));
	vector<Ctxt> e(5, Ctxt(publicKey));
	vector<Ctxt> c(4, Ctxt(publicKey));

	for(int i=0; i<8; i++)
	{
		EqualBit(t[i], ea, in1[i], in2[i], mask);
		//t[i] = in1[i];
        	//t[i] += in2[i];
       		//t[i].negate();
	}

	for(int i=0; i<8; i++)
	{
		LessThanBit(k[i], ea, in1[i], in2[i], mask, publicKey);
		//k[i] = in1[i];
		//k[i].negate();
		//k[i].multiplyBy(in2[i]);
	}

	d[0] = t[7];
	d[0].multiplyBy(t[6]);
	d[1] = t[5];
        d[1].multiplyBy(t[4]);
	d[2] = t[3];
        d[2].multiplyBy(t[2]);
	d[3] = t[1];
	d[3].multiplyBy(k[0]);
	d[4] = t[3];
        d[4].multiplyBy(k[2]);
	d[5] = t[5];
        d[5].multiplyBy(k[4]);
	d[6] = t[7];
        d[6].multiplyBy(k[6]);

	e[0] = d[0];
	e[0].multiplyBy(k[5]);
	e[1] = d[5];
	e[1].multiplyBy(d[0]);
	e[2] = d[1];
	e[2].multiplyBy(d[0]);
	e[3] = k[1];
	e[3].multiplyBy(d[2]);
	e[4] = d[3];
	e[4].multiplyBy(d[2]);

	c[0] = k[3];
	c[0].multiplyBy(e[2]);
	c[1] = d[4];
	c[1].multiplyBy(e[2]);
	c[2] = e[3];
	c[2].multiplyBy(e[2]);
	c[3] = e[4];
	c[3].multiplyBy(e[2]);

	out = c[3];
	out += c[2];
	out += c[1];
	out += c[0];
	out += e[1];
	out += e[0];
	out += d[6];
	out += k[7];


	for(int i=0; i<4; i++)
	{
		c[i].cleanUp();
		e[i].cleanUp();
		d[i].cleanUp();
		k[i].cleanUp();
		t[i].cleanUp();
	}
	for(int i=4; i<5; i++)
	{
		e[i].cleanUp();
                d[i].cleanUp();
                k[i].cleanUp();
                t[i].cleanUp();
	}
	for(int i=5; i<7; i++)
        {
                d[i].cleanUp();
                k[i].cleanUp();
                t[i].cleanUp();
        }
	for(int i=7; i<8; i++)
        {
                k[i].cleanUp();
                t[i].cleanUp();
        }


}
/*

	z = (c[3] + c[2] + c[1] + c[0] + e[1] + e[0] + d[6] + k[7]);
*/

	//vector<Ctxt> temp_lt;
	//vector<Ctxt> temp_eq;

	//for(int i=0; i<7; i++)
	//{
	//	Ctxt temp(out);
	//	LessThanBit(temp, ea, in1.back(), in2.back());
	//	temp_lt.push_back(temp);

	//	EqualBit(temp, ea, in1.back(), in2.back());
	//	temp_eq.push_back(temp);

	//	in1.pop_back();
	//	in2.pop_back();
	//}
	//Ctxt temp(out);
	//LessThanBit(temp, ea, in1.back(), in2.back());
	//temp_lt.push_back(temp);


/*
	vector<Ctxt> temp_lt = in1;
	vector<Ctxt> temp_eq = in1;
	for(int i=0; i<8; i++)
	{
		EqualBit(temp_eq[i], ea, in1[i], in2[i]);
		LessThanBit(temp_lt[i], ea, in1[i], in2[i]);
	}
	
	vector<Ctxt> temp_prod;
	for(int i=2; i<8; i+=2)
	{
		Ctxt temp = temp_eq[i];
		temp.multiplyBy(temp_eq[i+1]);
		temp_prod.push_back(temp);
	}
	for(int i=0; i<8; i+=2)
	{
		Ctxt temp = temp_lt[i];
		temp.multiplyBy(temp_eq[i+1]);
		temp_prod.push_back(temp);
	}

*/


void  TestIt(long R, long p, long r, long d, long c, long k, long w, 
               long L, long m, const Vec<long>& gens, const Vec<long>& ords)
{
  char buffer[32];
  cerr << "\n\n******** TestIt" << (isDryRun()? "(dry run):" : ":");
  cerr << " R=" << R 
       << ", p=" << p
       << ", r=" << r
       << ", d=" << d
       << ", c=" << c
       << ", k=" << k
       << ", w=" << w
       << ", L=" << L
       << ", m=" << m
       << ", gens=" << gens
       << ", ords=" << ords
       << endl;

  vector<long> gens1, ords1;
  convert(gens1, gens);
  convert(ords1, ords);

  FHEcontext context(m, p, r, gens1, ords1);
  buildModChain(context, L, c);

#ifdef DEBUG_PRINTOUT
  if (context.lazy)
    cerr << "LAZY REDUCTIONS\n";
  else
    cerr << "NON-LAZY REDUCTIONS\n";
#endif
  context.zMStar.printout();
  cerr << endl;

  cerr << "# ctxt primes = " << context.ctxtPrimes.card() << "\n";
  cerr << "# bits in ctxt primes = " 
       << long(context.logOfProduct(context.ctxtPrimes)/log(2.0) + 0.5) << "\n";
  cerr << "# special primes = " << context.specialPrimes.card() << "\n";
  cerr << "# bits in special primes = " 
       << long(context.logOfProduct(context.specialPrimes)/log(2.0) + 0.5) << "\n";

  FHESecKey secretKey(context);
  const FHEPubKey& publicKey = secretKey;
  secretKey.GenSecKey(w); // A Hamming-weight-w secret key


  ZZX G;

  if (d == 0)
    G = context.alMod.getFactorsOverZZ()[0];
  else
    G = makeIrredPoly(p, d); 

  cerr << "G = " << G << "\n";
  cerr << "generating key-switching matrices... ";
  addSome1DMatrices(secretKey); // compute key-switching matrices that we need
  cerr << "done\n";


  cerr << "computing masks and tables for rotation...";
  EncryptedArray ea(context, G);
  cerr << "done\n";



  long nslots = ea.size();
	cerr << "Number of slots: " << nslots << endl;
	
	// How many numbers to Sort?
	NewPlaintextArray mask(ea);
	int SetSize = 4;
	vector<long> bits(SetSize, 1);
	vector<long> zeros(nslots - SetSize, 0);
	bits.insert(bits.end(), zeros.begin(), zeros.end());
	encode(ea, mask, bits);


	// Bitlength of the numbers to sort =
	// Number of plaintexts =
	// Number of ciphertexts.
	int nbits = 8;
/*
	vector<ZZX> ptxts(nbits);
	for(int i=0; i<nbits; i++)
	{
		ptxts[i].SetLength(nslots);
		for(int j=0; j<SetSize; j++)
		{
			ptxts[i][j] = rand()%2;
			ptxts[i][nslots - j - 1] = ptxts[i][j];
		}
		//cout << ptxts[i] << endl;
	}
*/	cout << endl << endl;


	vector<NewPlaintextArray> Ptext_bits(nbits, NewPlaintextArray(ea));
	vector<Ctxt> Ctext_bits(nbits, Ctxt(publicKey));

	vector<long> temp(nslots);
	for(int i=0; i<nbits; i++)
	{
		random(ea, Ptext_bits[i]);
		//cout << ptxts[i] << endl;
		//encode(ea, Ptext_bits[i], ptxts[i]);
		//cerr << "Ptext" << i << " :" << Ptext_bits[i] << endl;
		mul(ea, Ptext_bits[i], mask);

		decode(ea, temp, Ptext_bits[i]);
		for(int j=0; j<SetSize; j++)
		{
			temp[nslots - SetSize + j] = temp[j];
		}
		encode(ea, Ptext_bits[i], temp);

		ea.encrypt(Ctext_bits[i], publicKey, Ptext_bits[i]);
		//cerr << Ctext_bits[i] << endl;
	}

	vector<long> set = BitsToByte(ea, Ptext_bits, nslots);// SetSize);
	cerr << "Set : { ";
	for(int i=0; i<set.size(); i++)
		cerr << set[i] << " ";
	cerr << "}" << endl << endl;


////////////////////

////////////////////


  resetAllTimers();

  FHE_NTIMER_START(Circuit);

	// LESS THAN Comparisons

	long rotamt = 1;
	vector<Ctxt> Ctext_rot;
	for(int i=0; i<nbits; i++)
	{
		Ctxt Ctext_temp(Ctext_bits[i]);
     		ea.rotate(Ctext_temp, rotamt);
		Ctext_rot.push_back(Ctext_temp);
	}
/*
	set = BitsToByte(ea, Ptext_bits, nslots);//SetSize);
        cerr << "Set : { ";
        for(int i=0; i<set.size(); i++)
                cerr << set[i] << " ";
        cerr << "}" << endl << endl;
*/
	rotamt = 2;
        vector<Ctxt> Ctext_rot2;
        for(int i=0; i<nbits; i++)
        {
                //rotate(ea, Ptext_bits[i], rotamt-1);
                Ctxt Ctext_temp(Ctext_bits[i]);
                ea.rotate(Ctext_temp, rotamt);
                Ctext_rot2.push_back(Ctext_temp);
        }
/*
        set = BitsToByte(ea, Ptext_bits, nslots);//SetSize);
        cerr << "Set : { ";
        for(int i=0; i<set.size(); i++)
                cerr << set[i] << " ";
        cerr << "}" << endl << endl;
*/

	Ctxt lt1(publicKey); Ctxt lt2(publicKey);
	LessThanByte(lt1, ea, Ctext_bits, Ctext_rot, mask, publicKey);
	LessThanByte(lt2, ea, Ctext_bits, Ctext_rot2, mask, publicKey);

	ZZX one(1);
	ZZX x_poly;
	x_poly.SetLength(2);
	x_poly[1] = 1;
	//cerr << x_poly << endl;

	Ctxt res1(publicKey);
	res1 = lt1;
	res1.addConstant(one);
	res1.multByConstant(x_poly);
	res1 += lt1;

	Ctxt comp1(publicKey);
	comp1 = lt1;
	comp1.addConstant(one);
	rotamt = nslots - 1;
	ea.rotate(comp1, rotamt);

	Ctxt res3(publicKey);
	res3 = comp1;
	res3.addConstant(one);
	res3.multByConstant(x_poly);
	res3 += comp1;

	Ctxt res2(publicKey);
	res2 = lt2;
	res2.addConstant(one);
	res2.multByConstant(x_poly);
	res2 += lt2;

	res1.multiplyBy(res2);
	res1.multiplyBy(res3);

/*
	NewPlaintextArray pp(ea);
        ea.decrypt(res1, secretKey, pp);
        cerr << pp << endl;
*/
	//Multiply(vector<Ctxt> &out, const vector<Ctxt> &in1, const Ctxt &in2);
	for(int i=0; i<Ctext_bits.size(); i++)
	{
		Ctext_bits[i].multiplyBy(res1);
		//NewPlaintextArray pp(ea);
//        	ea.decrypt(Ctext_bits[i], secretKey, Ptext_bits[i]);
        	//cerr << pp << endl;
	}
/*
	vector<ZZX> final;
	final = BitsToBytePoly(ea, Ptext_bits, nslots);
        cerr << "Set : { ";
        for(int i=0; i<final.size(); i++)
                cerr << final[i] << " ";
        cerr << "}" << endl << endl;
*/
	lt1.cleanUp();
	lt2.cleanUp();
	comp1.cleanUp();
	res1.cleanUp();
	res2.cleanUp();
	res3.cleanUp();





//	cerr << pp[0] << endl;
//
//	Ctxt c1(publicKey);
//	Ctxt c2(publicKey);
//	Ctxt c3(publicKey);
//	Ctxt c4(publicKey);


	// Shift Amount
     //long shamt = RandomBnd(2*(nslots/2) + 1) - (nslots/2);
                  // random number in [-nslots/2..nslots/2]
	// Rotation Amount
     //long rotamt = RandomBnd(2*nslots - 1) - (nslots - 1);
                  // random number in [-(nslots-1)..nslots-1]

     // two random constants
//     NewPlaintextArray const1(ea);
//     NewPlaintextArray const2(ea);
//     random(ea, const1);
//     random(ea, const2);
//	NewPlaintextArray const3 = const1;
	//cerr << "Random const : " << const1 << endl;
//	ea.encrypt(c1, publicKey, const1);
//	ea.encrypt(c2, publicKey, const2);
//	ea.encrypt(c3, publicKey, const1);
//	ea.encrypt(c4, publicKey, const2);

     //ZZX p1, ;
     //ea.encode(const1_poly, const1);
     //ea.encode(const2_poly, const2);
	//cerr << "Encoded : " << const1_poly << endl;

//     mul(ea, const1, const2);     // c1.multiplyBy(c0)
//     c1.multiplyBy(c2);              
//	CheckCtxt(c1, "c1*=c2");
//     debugCompare(ea,secretKey,p1,c1);

//	mul(ea, const1, const3);
//	c1.multiplyBy(c3);
//	CheckCtxt(c1, "c1*=c3");
//	debugCompare(ea, secretKey, p1, c1);

/*
     add(ea, p0, const1); // c0 += random constant
     c0.addConstant(const1_poly);    CheckCtxt(c0, "c0+=k1");
     debugCompare(ea,secretKey,p0,c0);

     mul(ea, p2, const2); // c2 *= random constant
     c2.multByConstant(const2_poly); CheckCtxt(c2, "c2*=k2");
     debugCompare(ea,secretKey,p2,c2);

     NewPlaintextArray tmp_p(p1); // tmp = c1
     Ctxt tmp(c1);
     sprintf(buffer, "c2>>=%d", (int)shamt);
     shift(ea, tmp_p, shamt); // ea.shift(tmp, random amount in [-nSlots/2,nSlots/2])
     ea.shift(tmp, shamt);           CheckCtxt(tmp, buffer);
     debugCompare(ea,secretKey,tmp_p,tmp);

     add(ea, p2, tmp_p);  // c2 += tmp
     c2 += tmp;                      CheckCtxt(c2, "c2+=tmp");
     debugCompare(ea,secretKey,p2,c2);

     sprintf(buffer, "c2>>>=%d", (int)rotamt);
     rotate(ea, p2, rotamt); // ea.rotate(c2, random amount in [1-nSlots, nSlots-1])
     ea.rotate(c2, rotamt);          CheckCtxt(c2, buffer);
     debugCompare(ea,secretKey,p2,c2);

     ::negate(ea, p1); // c1.negate()
     c1.negate();                    CheckCtxt(c1, "c1=-c1");
     debugCompare(ea,secretKey,p1,c1);

     mul(ea, p3, p2); // c3.multiplyBy(c2) 
     c3.multiplyBy(c2);              CheckCtxt(c3, "c3*=c2");
     debugCompare(ea,secretKey,p3,c3);

     sub(ea, p0, p3); // c0 -= c3
     c0 -= c3;                       CheckCtxt(c0, "c0=-c3");
     debugCompare(ea,secretKey,p0,c0);
*/
//	c1.cleanUp();
//	c2.cleanUp();
//	c3.cleanUp();
//	c4.cleanUp();
FHE_NTIMER_STOP(Circuit);

	for(int i=0; i<Ctext_bits.size(); i++)
	{
		Ctext_bits[i].cleanUp();
		//Ctext_rot[i].cleanUp();
	}
FHE_NTIMER_START(Check);
//  FHE_NTIMER_STOP(Circuit);
   
  cerr << endl;
  printAllTimers();
  cerr << endl;
  
 
  resetAllTimers();
  //FHE_NTIMER_START(Check);
   
  //NewPlaintextArray pp0(ea);
  //NewPlaintextArray pp1(ea);
  //NewPlaintextArray pp2(ea);
  //NewPlaintextArray pp3(ea);
   
  //ea.decrypt(Ctext_bits[0], secretKey, pp0);
  //ea.decrypt(c1, secretKey, pp1);
  //ea.decrypt(c2, secretKey, pp2);
  //ea.decrypt(c3, secretKey, pp3);

	//cerr << "Decrypted ptext :" << pp0 << endl;
	//cerr << "Plaintext :" << pp1 << endl;

   
  //if (!equals(ea, pp0, p0))  cerr << "oops 0\n";
  //if (!equals(ea, pp1, p1))  cerr << "oops 1\n";
  //if (!equals(ea, pp2, p2))  cerr << "oops 2\n";
  //if (!equals(ea, pp3, p3))  cerr << "oops 3\n";
   
  //FHE_NTIMER_STOP(Check);
   
  //cerr << endl;
  //printAllTimers();
  //cerr << endl;
   

#if 0

  vector<Ctxt> vc(L,c0);            // A vector of L ciphertexts
  vector<NewPlaintextArray> vp(L, p0); // A vector of L plaintexts
  for (long i=0; i<L; i++) {
    vp[i].random();                     // choose a random plaintext 
    ea.encrypt(vc[i], publicKey, vp[i]); // encrypt it
    if (i>0) vp[i].mul(vp[i-1]); // keep a running product of plaintexts
  }
  incrementalProduct(vc); // Compute the same running product homomorphically

  // Check that the products match
  bool fail = false;
  for (long i=0; i<L; i++) {
    ea.decrypt(vc[i], secretKey, p0); // decrypt it
    if (!p0.equals(vp[i])) {
      fail = true;
      cerr << "incrementalProduct oops "<<i<< endl;
    }
  }
  if (!fail) cerr << "incrementalProduct works\n";
#endif

}


/* A general test program that uses a mix of operations over four ciphertexts.
 * Usage: Test_General_x [ name=value ]...
 *   R       number of rounds  [ default=1 ]
 *   p       plaintext base  [ default=2 ]
 *   r       lifting  [ default=1 ]
 *   d       degree of the field extension  [ default=1 ]
 *              d == 0 => factors[0] defines extension
 *   c       number of columns in the key-switching matrices  [ default=2 ]
 *   k       security parameter  [ default=80 ]
 *   L       # of levels in the modulus chain  [ default=heuristic ]
 *   s       minimum number of slots  [ default=0 ]
 *   repeat  number of times to repeat the test  [ default=1 ]
 *   m       use specified value as modulus
 *   mvec    use product of the integers as  modulus
 *              e.g., mvec='[5 3 187]' (this overwrite the m argument)
 *   gens    use specified vector of generators
 *              e.g., gens='[562 1871 751]'
 *   ords    use specified vector of orders
 *              e.g., ords='[4 2 -4]', negative means 'bad'
 */
int main(int argc, char **argv) 
{
  setTimersOn();

  ArgMapping amap;

  bool dry=false;
  amap.arg("dry", dry, "dry=1 for a dry-run");

  long R=1;
  amap.arg("R", R, "number of rounds");

  long p=2;
  amap.arg("p", p, "plaintext base");

  long r=1;
  amap.arg("r", r,  "lifting");

  long d=1;
  amap.arg("d", d, "degree of the field extension");
  amap.note("d == 0 => factors[0] defines extension");

  long c=2;
  amap.arg("c", c, "number of columns in the key-switching matrices");

  
  long k=80;
  amap.arg("k", k, "security parameter");

  long L=10;
  amap.arg("L", L, "# of levels in the modulus chain",  "heuristic");

  long s=60;
  amap.arg("s", s, "minimum number of slots");

  long repeat=1;
  amap.arg("repeat", repeat,  "number of times to repeat the test");

  long chosen_m=0;
  amap.arg("m", chosen_m, "use specified value as modulus", NULL);

  Vec<long> mvec;
  amap.arg("mvec", mvec, "use product of the integers as  modulus", NULL);
  amap.note("e.g., mvec='[5 3 187]' (this overwrite the m argument)");

  Vec<long> gens;
  amap.arg("gens", gens, "use specified vector of generators", NULL);
  amap.note("e.g., gens='[562 1871 751]'");

  Vec<long> ords;
  amap.arg("ords", ords, "use specified vector of orders", NULL);
  amap.note("e.g., ords='[4 2 -4]', negative means 'bad'");

  long seed=0;
  amap.arg("seed", seed, "PRG seed");

  long nt=1;
  amap.arg("nt", nt, "num threads");

  amap.parse(argc, argv);

  SetSeed(ZZ(seed));
  SetNumThreads(nt);
  
  if (L==0) { // determine L based on R,r
    L = 3*R+3;
    if (p>2 || r>1) { // add some more primes for each round
      long addPerRound = 2*ceil(log((double)p)*r*3)/(log(2.0)*FHE_p2Size) +1;
      L += R * addPerRound;
    }
  }

  long w = 64; // Hamming weight of secret key
  //  long L = z*R; // number of levels

  if (mvec.length()>0)
    chosen_m = computeProd(mvec);
  long m = FindM(k, L, c, p, d, s, chosen_m, true);

  setDryRun(dry);
  for (long repeat_cnt = 0; repeat_cnt < repeat; repeat_cnt++) {
    TestIt(R, p, r, d, c, k, w, L, m, gens, ords);
  }
}

// call to get our running test case:
// Test_General_x p=23 m=20485 L=10 R=5
//
// another call to get an example where phi(m) is very
// close to m:
// Test_General_x m=18631 L=10 R=5

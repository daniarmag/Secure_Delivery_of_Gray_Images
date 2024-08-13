/*
subject: Elliptic curve digital signature algorithm,
         toy version for small modulus N.
*/

#include "ECDSA.h"

// dlong for holding intermediate results,
// long variables in exgcd() for efficiency,
// maximum parameter size 2 * p.y (line 129)
// limits the modulus size to 30 bits.

// maximum modulus
const long mxN = 1073741789;
// max order G = mxN + 65536
const long mxr = 1073807325;
// symbolic infinity
const long inf = -2147483647;

//private key da
long privateDa=0;
int flagPrivate = 0;

//curve parameter
const long eparm[6] = {2, 3, 97, 3, 6, 5};

// single global curve
curve e;
// point at infinity zerO
epnt zerO;
// impossible inverse mod N
int inverr;

// return mod(v^-1, u)
long exgcd (long v, long u)
{
register long q, t;
long r = 0, s = 1;
if (v < 0) v += u;

   while (v) {
      q = u / v;
      t = u - q * v;
      u = v; v = t;
      t = r - q * s;
      r = s; s = t;
   }
   if (u != 1) {
      printf (" impossible inverse mod N, gcd = %d\n", u);
      inverr = 1;
   }
return r;
}

// return mod(a, N)
static inline dlong modn (dlong a)
{
   a %= e.N;
   if (a < 0) a += e.N;
return a;
}

// return mod(a, r)
dlong modr (dlong a)
{
   a %= e.r;
   if (a < 0) a += e.r;
return a;
}

// return the discriminant of E
long disc (void)
{
   dlong c, a = e.a, b = e.b;
   c = 4 * modn(a * modn(a * a));
   return modn(-16 * (c + 27 * modn(b * b)));
}

// return 1 if P = zerO
int isO (epnt p)
{
   return (p.x == inf) && (p.y == 0);
}

// return 1 if P is on curve E
int ison (epnt p)
{
   long r, s;
   if (! isO (p)) {
      r = modn(e.b + p.x * modn(e.a + p.x * p.x));
      s = modn(p.y * p.y);
   }
   return (r == s);
}


// full ec point addition
void padd (epnt *r, epnt p, epnt q)
{
   dlong la, t;

   if (isO(p)) {*r = q; return;}
   if (isO(q)) {*r = p; return;}

   if (p.x != q.x) {                    // R:= P + Q
      t = p.y - q.y;
      la = modn(t * exgcd(p.x - q.x, e.N));
   }
   else                                 // P = Q, R := 2P
      if ((p.y == q.y) && (p.y != 0)) {
         t = modn(3 * modn(p.x * p.x) + e.a);
         la = modn(t * exgcd (2 * p.y, e.N));
      }
      else
         {*r = zerO; return;}           // P = -Q, R := O

   t = modn(la * la - p.x - q.x);
   r->y = modn(la * (p.x - t) - p.y);
   r->x = t; if (inverr) *r = zerO;
}

// R:= multiple kP
void pmul (epnt *r, epnt p, long k)
{
   epnt s = zerO, q = p;

   for (; k; k >>= 1) {
      if (k & 1) padd(&s, s, q);
      if (inverr) {s = zerO; break;}
      padd(&q, q, q);
   }
   *r = s;
}

// print point P with prefix f
void pprint (char *f, epnt p)
{
   dlong y = p.y;

   if (isO (p))
      printf ("%s (0)\n", f);

   else {
      if (y > e.N - y) y -= e.N;
      printf ("%s (%lld, %lld)\n", f, p.x, y);
   }
}

// initialize elliptic curve
int ellinit()
{
   //eparm values
   const long i[6] = {2, 3, 97, 3, 6, 5};
   zerO.x = inf; zerO.y = 0;
   long a = i[0], b = i[1];
      e.N = i[2]; inverr = 0;

   if ((e.N < 5) || (e.N > mxN)) return 0;

      e.a = modn(a);
      e.b = modn(b);
      e.G.x = modn(i[3]);
      e.G.y = modn(i[4]);
      e.r = i[5];

   if ((e.r < 5) || (e.r > mxr)) return 0;

   // printf ("\nE: y^2 = x^3 + %dx + %d", a, b);
   // printf (" (mod %lld)\n", e.N);
   // pprint ("base point G", e.G);
   // printf ("order(G, E) = %lld\n", e.r);

   return 1;
}

// pseudorandom number [0..1)
double rnd(void)
{
   return rand() / ((double)RAND_MAX + 1);
}

// signature primitive
pair signature (dlong private, long message)
{
   long r, s, k, kInv;
   pair sg;
   epnt V;

   printf ("Signning...\n");
   do {
      do {
         k = 1 + (long)(rnd() * (e.r - 1));
         pmul (&V, e.G, k);
         r = modr(V.x);
      }
      while (r == 0);

      kInv = exgcd (k, e.r);
      s = modr(kInv * (message + modr(private * r)));
   }
   while (s == 0);
   //printf ("one-time k = %d\n", k);
   //pprint ("(x1,y1) = kG", V);

   sg.a = r; sg.b = s;
   return sg;
}

// verification primitive
int verifySign (epnt public, long message, pair signature)
{
   long r = signature.a, s = signature.b;
   long t, x1, u1, u2;
   dlong sInv;
   epnt V, V2;

   // domain check
   t = (r > 0) && (r < e.r);
   t &= (s > 0) && (s < e.r);
   if (! t) return 0;

   printf ("Verifying...\n");
   sInv = exgcd (s, e.r);
   u1 = modr(message * sInv);
   u2 = modr(r * sInv);
   // printf ("u1,u2 = %d, %d\n", u1,u2);
   pmul (&V, e.G, u1);
   pmul (&V2, public, u2);
   // pprint ("u1G", V);
   // pprint ("u2Qa", V2);
   padd (&V, V, V2);
   // pprint ("+ =", V);
   if (isO (V)) return 0;
   x1 = modr(V.x);
   // printf ("x1 = %d\n", x1);

   return (x1 == r);
}

//private key init one time only
void privateInit()
{
   if(flagPrivate == 0){
      privateDa = 1 + (long)(rnd() * (e.r - 1));
      flagPrivate = 1;
   }
}

// digital signature on hashed message
keyAndSign sign (long message)
{
   long i, t;
   pair sg;
   epnt helper;
   epnt public;
   keyAndSign res;
   //printf("sign function\n");
   // parameter check validation
   t = (disc() == 0);
   t |= isO (e.G);
   pmul (&helper, e.G, e.r);
   t |= ! isO (helper);
   t |= ! ison (e.G);
   if (t) goto errmsgsign;

   //private key generation
   privateInit();
   //printf ("private key = %d\n", privateDa);
   
   //public key (point) generation
   pmul (&public, e.G, privateDa);
   //pprint ("public key  = ", public);

   //z creation (Ln leftmost bit of hashed message)
   // next highest power of 2 - 1
   t = e.r;
   for (i = 1; i < 32; i <<= 1)
      t |= t >> i;
   //printf("t = %d",t);
   while (message > t) message >>= 1;
   //printf ("\naligned hash %x\n", message);

   sg =  signature (privateDa, message);
   if (inverr) goto errmsgsign;
   //printf ("signature r,s = %d, %d\n", sg.a, sg.b);
   res.sign = sg;
   res.publicKey = public;
   return res;

   errmsgsign:
   printf ("invalid parameter set\n");
   printf ("_____________________\n");
}

// digital signature verification
int verify (epnt public, long message, pair signature)
{
   long i, t;
   epnt helper;

   // parameter check validation
   t = (disc() == 0);
   t |= isO (e.G);
   pmul (&helper, e.G, e.r);
   t |= ! isO (helper);
   t |= ! ison (e.G);
   if (t) goto errmsgverify;

   //z creation (Ln leftmost bit of hashed message)
   // next highest power of 2 - 1
   t = e.r;
   for (i = 1; i < 32; i <<= 1)
      t |= t >> i;
   while (message > t) message >>= 1;
   // printf ("\naligned hash %x\n", message);

   t = verifySign (public, message, signature);
   if (inverr) goto errmsgverify;

   if (t) {
      // printf ("Valid\n_____\n");
      return 1;
   }
   else {
      // printf ("invalid\n_______\n");
      return 0;
   }

   errmsgverify:
   printf ("invalid parameter set\n");
   printf ("_____________________\n");
   return 0;
}

package util;

// javac DH.java && java DH
// "Just use libsodium if you can," also applies for every other language below

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Random;


public class DH {

  private static int bitLength = 512;
  private static int certainty = 20;// probabilistic prime generator 1-2^-certainty => practically
                                    // 'almost
  // sure'

  private static final SecureRandom rnd = new SecureRandom();

  public static void main(String[] args) throws Exception {
    System.err.println(getDHParameters().get("secretA"));
    System.err.println(getDHParameters().get("secretA"));
  }

  public DH() throws Exception {
    Random randomGenerator = new Random();
    BigInteger generatorValue, primeValue, publicA, publicB, secretA, secretB, sharedKeyA, sharedKeyB;

    primeValue = findPrime();// BigInteger.valueOf((long)g);
    System.out.println("the prime is " + primeValue);
    generatorValue = findPrimeRoot(primeValue);// BigInteger.valueOf((long)p);
    System.out.println("the generator of the prime is " + generatorValue);

    // on machine 1
    secretA = new BigInteger(bitLength - 2, randomGenerator);
    // on machine 2
    secretB = new BigInteger(bitLength - 2, randomGenerator);

    // to be published:
    publicA = generatorValue.modPow(secretA, primeValue);
    publicB = generatorValue.modPow(secretB, primeValue);
    sharedKeyA = publicB.modPow(secretA, primeValue);// should always be same as:
    sharedKeyB = publicA.modPow(secretB, primeValue);

    System.out.println("the public key of A is " + publicA);
    System.out.println("the public key of B is " + publicB);
    System.out.println("the shared key for A is " + sharedKeyA);
    System.out.println("the shared key for B is " + sharedKeyB);
    System.out.println("The secret key for A is " + secretA);
    System.out.println("The secret key for B is " + secretB);
  }


  public static HashMap<String, BigInteger> getDHParameters(BigInteger generatorValue, // for client
      BigInteger primeValue) {

    SecureRandom randomGenerator = new SecureRandom();
    BigInteger _public, _secret;

    // on machine 1
    _secret = new BigInteger(bitLength - 2, randomGenerator);

    // to be published:
    _public = generatorValue.modPow(_secret, primeValue);

    HashMap<String, BigInteger> map = new HashMap<String, BigInteger>();
    map.put("secret", _secret);
    map.put("public", _public);
    map.put("generatorValue", generatorValue);
    map.put("primeValue", primeValue);
    return map;
  }

  public static BigInteger getSharedKey(BigInteger _public, BigInteger _secret, BigInteger primeValue) {
    return _public.modPow(_secret, primeValue);// should always be same as:
  }



  public static HashMap<String, BigInteger> getDHParameters() { // random version for server

    BigInteger primeValue = findPrime();// BigInteger.valueOf((long)g);
    BigInteger generatorValue = findPrimeRoot(primeValue);// BigInteger.valueOf((long)p);
    return getDHParameters(generatorValue, primeValue);
  }



  private static BigInteger findPrimeRoot(BigInteger p) {
    int start = 2001;// first best probably precalculated by NSA?
    // preferably 3, 17 and 65537

    for (int i = start; i < 100000000; i++)
      if (isPrimeRoot(BigInteger.valueOf(i), p))
        return BigInteger.valueOf(i);
    // if(isPrimeRoot(i,p))return BigInteger.valueOf(i);
    return BigInteger.valueOf(0);
  }


  private static BigInteger findPrime() {
    Random rnd = new Random();
    BigInteger p = BigInteger.ZERO;
    // while(!isPrime(p))
    p = new BigInteger(bitLength, certainty, rnd);// sufficiently NSA SAFE?!!
    return p;

    // BigInteger r;
    // BigInteger r2= BN_generate_prime(r,512);
    // System.out.println("isPrime(i)? "+r+" "+r2);
    // return r;
  }

  private static boolean isPrimeRoot(BigInteger g, BigInteger p) {
    BigInteger totient = p.subtract(BigInteger.ONE); // p-1 for primes;// factor.phi(p);
    List<BigInteger> factors = primeFactors(totient);
    int i = 0;
    int j = factors.size();
    for (; i < j; i++) {
      BigInteger factor = factors.get(i);// elementAt
      BigInteger t = totient.divide(factor);
      if (g.modPow(t, p).equals(BigInteger.ONE))
        return false;
    }
    return true;
  }

  private static List<BigInteger> primeFactors(BigInteger number) {
    BigInteger n = number;
    BigInteger i = BigInteger.valueOf(2);
    BigInteger limit = BigInteger.valueOf(10000);// speed hack! -> consequences ???
    List<BigInteger> factors = new ArrayList<BigInteger>();
    while (!n.equals(BigInteger.ONE)) {
      while (n.mod(i).equals(BigInteger.ZERO)) {
        factors.add(i);
        n = n.divide(i);
        // System.out.println(i);
        // System.out.println(n);
        if (isPrime(n)) {
          factors.add(n);// yes?
          return factors;
        }
      }
      i = i.add(BigInteger.ONE);
      if (i.equals(limit))
        return factors;// hack! -> consequences ???
      // System.out.print(i+"    \r");
    }
    System.out.println(factors);
    return factors;
  }



  private static boolean miller_rabin_pass(BigInteger a, BigInteger n) {
    BigInteger n_minus_one = n.subtract(BigInteger.ONE);
    BigInteger d = n_minus_one;
    int s = d.getLowestSetBit();
    d = d.shiftRight(s);
    BigInteger a_to_power = a.modPow(d, n);
    if (a_to_power.equals(BigInteger.ONE))
      return true;
    for (int i = 0; i < s - 1; i++) {
      if (a_to_power.equals(n_minus_one))
        return true;
      a_to_power = a_to_power.multiply(a_to_power).mod(n);
    }
    if (a_to_power.equals(n_minus_one))
      return true;
    return false;
  }

  private static boolean miller_rabin(BigInteger n) {
    for (int repeat = 0; repeat < 20; repeat++) {
      BigInteger a;
      do {
        a = new BigInteger(n.bitLength(), rnd);
      } while (a.equals(BigInteger.ZERO));
      if (!miller_rabin_pass(a, n)) {
        return false;
      }
    }
    return true;
  }

  private static boolean isPrime(BigInteger r) {
    return miller_rabin(r);
    // return BN_is_prime_fasttest_ex(r,bitLength)==1;
  }


}

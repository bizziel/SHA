/**
 * SHA-256 implementation based on FIPS PUB 180-1.
 * Highly understandable.
 * <p>
 * (http://www.itl.nist.gov/fipspubs/fip180-1.htm)
 * 
 * @author Steven Reynolds
 * @version 1.0 2014.08.11
 */
class SHA256
{


/*

type - byte - bit

     -    1 -  8
byte -    1 -  8
int  -    4 - 32
long -    8 - 64

*/
  public final String run(String message){
    // Initialize hash values:
    // (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
    int H0 = 0x6a09e667;
    int H1 = 0xbb67ae85;
    int H2 = 0x3c6ef372;
    int H3 = 0xa54ff53a;
    int H4 = 0x510e527f;
    int H5 = 0x9b05688c;
    int H6 = 0x1f83d9ab;
    int H7 = 0x5be0cd19;

    // Initialize array of round constants:
    // (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):
    int[] K =
  {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    
    byte[] msg = message.getBytes();

    //Pre-processing:
    /*
  message     =  "asdasd"
  msg         =  [97,115,100,97,115,100] 
  msg[0]      =  0b 0110 0001
    */
    int original_byte_len = msg.length;
    long original_bit_len = original_byte_len * 8;

    // add 1 bit to message
    //msg += 0x80;
    msg = add(msg, (byte)0x80);


    // append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    // is equal to 448 (mod 512)
    int times = (((56 - (original_byte_len + 1) % 64) + 64) % 64);

    for (int i =0; i < times ; i++) {
      msg = add(msg, (byte)0x00);
    }

    // append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    msg = add(msg, original_bit_len);

    System.out.println("msg: " + msg.length);
    System.out.println(toHexString(msg));

    // Process the message in successive 512-bit chunks:
    for (int i = 0; i < msg.length; i = i + 64 ) {
      int[] w = new int[64];
      /*
        w[0]        =  msg[0] + msg[1] + msg[2] + msg[3]
        w[1]        =  msg[4] + msg[5] + msg[6] + msg[7]
        ...
        w[15]       =  msg[60] + msg[61] + msg[62] + msg[63]
      */
      // break chunk into sixteen 32-bit big-endian words w[i], 0 <= i <= 15
      for (int j=0; j < 16; j++) {
        w[j] = (msg[i + (j * 4) + 0] << 24) + 
               (msg[i + (j * 4) + 1] << 16) + 
               (msg[i + (j * 4) + 2] <<  8) + 
               (msg[i + (j * 4) + 3] & 0xff);
      }

      /*
      w[16]       = (w[13] xor w[8] xor w[2] xor w[0]) leftrotate 1
      w[17]       = (w[14] xor w[9] xor w[3] xor w[1]) leftrotate 1
      ...
      w[79]       = (w[76] xor w[71] xor w[65] xor w[63]) leftrotate 1
      */
      //  Extend the first 16 words into the remaining
      //  48 words w[16..63] of the message schedule array:
      for (int t = 16; t < 64; t++){
        int s0 = rightrotate(w[t-15], 7) ^ rightrotate(w[t-15], 18) ^ (w[t-15] >>> 3);
        int s1 = rightrotate(w[t-2], 17) ^ rightrotate(w[t-2], 19) ^ (w[t-2] >>> 10);
        w[t] = w[t-16] + s0 + w[t-7] + s1;
      }
      System.out.println(toHexString(w));
      // Initialize working variables to current hash value:
      int A = H0;
      int B = H1;
      int C = H2;
      int D = H3;
      int E = H4;
      int F = H5;
      int G = H6;
      int H = H7;

      /*
      * Mainloop
      */
      for(int t = 0; t < 64; t++){

          
        int s1 = rightrotate(E, 6) ^ rightrotate(E, 11) ^ rightrotate(E, 25);
        int ch = (E & F) ^ ((~E) & G);
        int temp1 = H + s1 + ch + K[t] + w[t];

        int s0 = rightrotate(A, 2) ^ rightrotate(A, 13) ^ rightrotate(A, 22);
        int maj = (A & B) ^ (A & C) ^ (B & C);
        int temp2 = s0 + maj;

        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;

        System.out.println( "t = " + t + " : " + toHexString(A) + " " +
                toHexString(B) + " " + toHexString(C) + " " +
                toHexString(D) + " " + toHexString(E) + " " + 
                toHexString(F) + " " + toHexString(G)+ " " + toHexString(H));
      }
      H0 = H0 + A;
      H1 = H1 + B;
      H2 = H2 + C;
      H3 = H3 + D;
      H4 = H4 + E;
      H5 = H5 + F;
      H6 = H6 + G;
      H7 = H7 + H;
    }
    
    //160 bit number:
    //magic
    String res = "" + toHexString(H0) + toHexString(H1) + toHexString(H2) +
                      toHexString(H3) + toHexString(H4) + toHexString(H5) +
                      toHexString(H6) + toHexString(H7);
    return res;
  }

  /**
  *     byte[] one = [xxxxxxxx, xxxxxxxx, ...]
  *     int    two =  yyyyyyyy * 4  (16 bit)
  *     byte[] res = [xxxxxxxx, xxxxxxxx, ..., yyyyyyyy, ..., yyyyyyyy]
  */
  public final byte[] add(byte[] one, int two){
    byte[] temp = new byte[4];
    temp[0] = (byte) (two >> 24);
    temp[1] = (byte) (two >> 16);
    temp[2] = (byte) (two >> 8);
    temp[3] = (byte) (two);
    return add(one,temp);
  }


  /**
  *     byte[] one = [xxxxxxxx, xxxxxxxx, ...]
  *     byte   two =  yyyyyyyy   (8 bit)
  *     byte[] res = [xxxxxxxx, xxxxxxxx, ..., yyyyyyyy]
  */
  public final byte[] add(byte[] one, byte two){
    byte[] temp = new byte[1];
    temp[0] = two;
    return add(one,temp);
  }

  /**
  *     byte[] one = [xxxxxxxx, xxxxxxxx, ...]
  *     long   two =  yyyyyyyy * 8  (64 bit)
  *     byte[] res = [xxxxxxxx, xxxxxxxx, ..., yyyyyyyy*8]
  */
  public final byte[] add(byte[] one, long two){
    byte[] temp = new byte[8];
    temp[0] = (byte) (two >> 56);
    temp[1] = (byte) (two >> 48);
    temp[2] = (byte) (two >> 40);
    temp[3] = (byte) (two >> 32);
    temp[4] = (byte) (two >> 24);
    temp[5] = (byte) (two >> 16);
    temp[6] = (byte) (two >> 8);
    temp[7] = (byte) (two);
    return add(one,temp);
  }

  /**
  *     byte[] one = [xxxxxxxx, xxxxxxxx, ...]
  *     byte[]  two = [yyyyyyyy, yyyyyyyy, ...]
  *     byte[] res = [xxxxxxxx, xxxxxxxx, ..., yyyyyyyy, yyyyyyyy, ...]
  */
  public final byte[] add(byte[] one, byte[] two){
    byte[] combined = new byte[one.length + two.length];

    System.arraycopy(one,0,combined,0         ,one.length);
    System.arraycopy(two,0,combined,one.length,two.length);

    return combined;
  }

  private final int rightrotate(int x, int count){
    return (((x >>> count)) | (x << (32 - count)));
  }

  private String toHexString(int[] two) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < two.length; i++) {
      sb.append(toHexString(two[i]));
    }
    return sb.toString();
  }
  
  private String toHexString(int two) {
    byte[] temp = new byte[4];
    temp[0] = (byte) (two >>> 24);
    temp[1] = (byte) (two >>> 16);
    temp[2] = (byte) (two >>> 8);
    temp[3] = (byte) (two);
    return toHexString(temp);
  }

  
  private static String toHexString(byte[] b)
  {
    final String hexChar = "0123456789ABCDEF";
    //final String hexChar = "0123456789abcdef";

    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < b.length; i++)
    {
      sb.append(hexChar.charAt((b[i] >> 4) & 0x0f));
      sb.append(hexChar.charAt(b[i] & 0x0f));
    }
    return sb.toString();
  }

  public static void main(String[] args)
  {
  
    SHA256 sha = new SHA256();
    String dig1_res = sha.run("abc");
    String dig2_res = sha.run("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    String dig3_res = sha.run("");

    String dig1_ref = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
    String dig2_ref = "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1";
    String dig3_ref = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
    System.out.println("\n");
    System.out.println("SHA256 hash of \"abc\":");
    System.out.println("result:    " +dig1_res);
    System.out.println("reference: " +dig1_ref);
    System.out.println("is equal? " + dig1_ref.equals(dig1_res));

    System.out.println("\nSHA256 hash of "
      +"\"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq\":");
    System.out.println("result:    " +dig2_res);
    System.out.println("reference: " +dig2_ref);
    System.out.println("is equal? " + dig2_ref.equals(dig2_res));

    System.out.println("\nSHA256 hash of \"\":");
    System.out.println("result:    " +dig3_res);
    System.out.println("reference: " +dig3_ref);
    System.out.println("is equal? " + dig3_ref.equals(dig3_res));
  }
}

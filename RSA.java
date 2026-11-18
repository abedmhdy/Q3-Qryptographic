import java.math.BigInteger;

public class RSA {
    public int checkPublicKey(int p, int q, int e) {
        int phi = (p - 1) * (q - 1);
        if (e <= 1 || e >= phi) {
            return 0;
        }
        return gcd(e, phi) == 1 ? 1 : 0;
    }
    private int gcd(int a, int b) {
        while (b != 0) {
            int remainder = a % b;
            a = b;
            b = remainder;
        }
        return a;
    }
    public int calculatePrivateKey(int p, int q, int e) {
        int phi = (p - 1) * (q - 1);
        return BigInteger.valueOf(e).modInverse(BigInteger.valueOf(phi)).intValueExact();
    }
    private int powerMod(int value, int k, int n) {
        BigInteger base = BigInteger.valueOf(value);
        return base.modPow(BigInteger.valueOf(k), BigInteger.valueOf(n)).intValueExact();
    }
    public int encryptMessage(int m, int k, int n) {
        return powerMod(m, k, n);
    }
    public int decryptMessage(int c, int k, int n) {
        return powerMod(c, k, n);
    }
    public int createSignature(int m, int k, int n, int s) {
        int hash = m % s;
        return powerMod(hash, k, n);
    }
    public int validateSignature(int signature, int m, int k, int n, int s) {
        int hash = m % s;
        return powerMod(signature, k, n) == hash ? 1 : 0;
    }
}

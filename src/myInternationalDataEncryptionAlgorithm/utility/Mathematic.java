package myInternationalDataEncryptionAlgorithm.utility;

// for 16 bit subblocks
public class Mathematic {
    public static final int deg2 = 0x10000;        // 2^16

    public static int xor(int a, int b) {
        return a ^ b;
    }
    public static int add(int a, int b) {
        return (a + b) & 0xFFFF;
    }
    public static int mult(int a, int b) {
        if(a == 0) {
            a = deg2;
        }
        if(b == 0) {
            b = deg2;
        }

        long lmult = ((long) a * b) % (deg2 + 1);
        return (int)lmult & 0xFFFF;
    }

    public static int addInv(int a) {
        return (deg2 - a) & 0xFFFF;
    }

    // based on extended Euclid algorithm
    public static int multInv(int a) {
        if(a <= 1) {
            return a;
        }

        int m = deg2 + 1;
        int     x1 = 0, x2 = 1,
                b = m;

        while(b > 0) {
            int x = x2 - (a / b)*x1;

            int tmp = a;
            a = b;
            b = tmp % b;

            x2 = x1;
            x1 = x;
        }

        return ((x2 % m + m) % m) & 0xFFFF;
    }
}

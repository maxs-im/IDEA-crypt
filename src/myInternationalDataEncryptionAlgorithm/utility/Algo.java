package myInternationalDataEncryptionAlgorithm.utility;

public class Algo {
    private static KeyGen storage;
    public static void setStorage(KeyGen storage) {
        Algo.storage = storage;
    }


    /* block of 8 bytes == 64 bits */

    public static byte[] encryptBlock(byte[] block) {
        return crypt(block, false);
    }
    public static byte[] decryptBlock(byte[] block) {
        return crypt(block, true);
    }

    private static byte[] crypt(byte[] data, boolean isInvert) {
        int d[] = new int[4];
        for(int i = 0; i < 4; ++i) {
            d[i] = ((data[2*i] & 0xFF) << 8) | (data[2*i+1] & 0xFF);
        }

        for(int i = 0; i < storage.getRounds(); ++i) {
            int     A = Mathematic.mult( d[0], storage.getSub(i, 0, isInvert) ),
                    B = Mathematic.add( d[1], storage.getSub(i, 1, isInvert) ),
                    C = Mathematic.add( d[2], storage.getSub(i, 2, isInvert) ),
                    D = Mathematic.mult( d[3], storage.getSub(i, 3, isInvert) );

            int     E = Mathematic.xor(A, C),
                    F = Mathematic.xor(B, D);

            int G = Mathematic.mult( storage.getSub(i, 5, isInvert),
                        Mathematic.add( F,
                            Mathematic.mult( E, storage.getSub(i, 4, isInvert) ) ) );

            d[0] = Mathematic.xor(A, G);
            d[1] = Mathematic.xor(C, G);

            int H = Mathematic.add( G,
                        Mathematic.mult(E, storage.getSub(i, 4, isInvert) ) );

            d[2] = Mathematic.xor(B, H);
            d[3] = Mathematic.xor(D, H);
        }

        int last[] = new int [4];
        last[0] = Mathematic.mult( d[0], storage.getSub(8, 0, isInvert) );
        last[1] = Mathematic.add( d[2], storage.getSub(8, 1, isInvert) );
        last[2] = Mathematic.add( d[1], storage.getSub(8, 2, isInvert) );
        last[3] = Mathematic.mult( d[3], storage.getSub(8, 3, isInvert) );

        for(int i = 0; i < 4; ++i) {
            data[2*i] = (byte)(last[i] >> 8);
            data[2*i + 1] = (byte)last[i];
        }
        return data;
    }
}

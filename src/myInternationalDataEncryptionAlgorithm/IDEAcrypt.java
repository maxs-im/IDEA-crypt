package myInternationalDataEncryptionAlgorithm;

import myInternationalDataEncryptionAlgorithm.utility.Algo;
import myInternationalDataEncryptionAlgorithm.utility.KeyGen;

public class IDEAcrypt {
    private byte[] key;
    private byte[] fill;           // default block (64 bit)

    public IDEAcrypt() {
        this(8, KeyGen.randomizeKey());
    }
    public IDEAcrypt(int round) {
        this(round, KeyGen.randomizeKey());
    }
    public IDEAcrypt(byte[] keyIn) {
        this(8, keyIn);
    }
    public IDEAcrypt(int round, byte[] keyIn) {
        key = new byte[16];
        for(int i = 0; i < key.length; ++i) {
            if(i < keyIn.length) {
                key[i] = keyIn[i];
            } else {
                key[i] = 0;
            }
        }

        Algo.setStorage(new KeyGen(key, round));
        fill = new byte[8];
    }

    public byte[] getFill() {
        return fill;
    }
    public void setFill(byte[] fillIn) {
        for(int i = 0; i < 4 && i < fillIn.length; ++i) {
            fill[i] = fillIn[i];
        }
    }
    public byte[] getKey() {
        return key;
    }

    public byte[] encrypt(byte[] text) {
        int numblocks = text.length >> 3;
        if(text.length % 8 != 0) {
            ++numblocks;
        }

        byte[] cryptText = new byte[numblocks << 3];

        for(int i = 0; i < numblocks; ++i) {
            byte[] block = new byte[8];

            for(int j = 0; j < block.length; ++j) {
                if(((i << 3) + j) < text.length) {
                    block[j] = text[(i << 3) + j];
                } else {
                    block[j] = fill[j];
                }
            }

            block = Algo.encryptBlock(block);

            for(int j = 0; j < 8; ++j) {
                cryptText[(i << 3) + j] = block[j];
            }
        }

        return cryptText;
    }

    public byte[] decrypt(byte[] text) throws Exception {
        // if not divide on blocks (64 bit)
        if(text.length % 8 != 0) {
            throw new Exception("It is not encrypt by IDEA");
        }

        int numblocks = text.length >> 3;

        byte[] cryptText = new byte[numblocks << 3];

        for(int i = 0; i < numblocks; ++i) {
            byte[] block = new byte[8];

            for(int j = 0; j < block.length; ++j) {
                block[j] = text[(i << 3) + j];
            }

            block = Algo.decryptBlock(block);

            for(int j = 0; j < 8; ++j) {
                cryptText[(i << 3) + j] = block[j];
            }
        }

        return cryptText;
    }
}

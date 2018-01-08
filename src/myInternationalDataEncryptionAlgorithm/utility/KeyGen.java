package myInternationalDataEncryptionAlgorithm.utility;

import java.security.SecureRandom;

public class KeyGen {
    private int rounds;

    private int[] key = new int[8];           // 8 parts of 16 significant bits

    private int[] subkeys;
    private int[] subinverskeys;

    public KeyGen(byte[] keyin, int round) {
        for(int i = 0; i < keyin.length/2; ++i) {
            key[i] = ((keyin[2*i] & 0xFF) << 8) | (keyin[2*i + 1] & 0xFF);
        }

        rounds = round;
        setSubKeys();
        setInversSubKeys();
    }

    public int getRounds() {
        return rounds;
    }
    // return needed subKey from number (0 - 5) after round (0 - rounds) and number in queue
    public int getSub(int round, int num, boolean isinvers) {
        int index = round * 6 + num;
        index %= subkeys.length;

        if(isinvers) {
            return subinverskeys[index];
        }

        return subkeys[index];
    }

    private void setSubKeys() {
        subkeys = new int [rounds * 6 + 4];

        int curr = 0;
        for(int shf = 0; shf < subkeys.length / 8; ++shf) {
            for (int i = 0; i < 8; ++i, ++curr) {
                subkeys[curr] = key[i];
                key = shiftBits(key);
            }
        }

        for(int i = 0; i < subkeys.length % 8; ++i, ++curr) {
            subkeys[curr] = key[i];
        }
    }
    private void setInversSubKeys(){
        subinverskeys = new int[subkeys.length];

        for(int r = 0; r <= rounds; ++r) {

            // swap for first and last round
            int chng = 0;
            if(r == 0 || r == rounds) {
                chng = 1;
            }

            int startindex = r*6;

            subinverskeys[startindex + 0] = Mathematic.multInv( getSub(rounds - r, 0, false) );
            subinverskeys[startindex + 1] = Mathematic.addInv( getSub(rounds - r, 2 - chng, false) );
            subinverskeys[startindex + 2] = Mathematic.addInv( getSub(rounds - r, 1 + chng, false) );
            subinverskeys[startindex + 3] = Mathematic.multInv( getSub(rounds - r, 3, false) );

            if(r == rounds) {
                break;
            }
            subinverskeys[startindex + 4] = getSub(rounds - (r + 1), 4, false);
            subinverskeys[startindex + 5] = getSub(rounds - (r + 1), 5, false);
        }
    }

    //  this function shifts left current keys @currkey on 25 bits.
    private int[] shiftBits(int[] currkey) {

        // shift on 16 position
        int first = currkey[0];
        for(int i = 0; i < currkey.length - 1; ++i) {
            currkey[i] = currkey[i + 1];
        }
        currkey[currkey.length - 1] = first;

        //shift on 9 position
        first = currkey[0] >> 7;
        for(int i = 0; i < currkey.length - 1; ++i) {
            currkey[i] = (currkey[i] << 9) & 0xFFFF;
            int add = currkey[i+1] >> 7;
            currkey[i] += add;
        }
        currkey[currkey.length - 1] = (currkey[currkey.length - 1] << 9) & 0xFFFF;
        currkey[currkey.length - 1] += first;

        return currkey;
    }
    public static byte[] randomizeKey(){
        SecureRandom rnd = new SecureRandom();
        byte[] keyout = new byte[16];
        rnd.nextBytes(keyout);
        return keyout;
    }
}

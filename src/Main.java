import myInternationalDataEncryptionAlgorithm.IDEAcrypt;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class Main {
    public static void main(String argv[]) {
        test();
    }

    private static void test() {
        IDEAcrypt obj = new IDEAcrypt();

        try(FileInputStream fin = new FileInputStream("text.txt");
            FileOutputStream fout = new FileOutputStream("encrypt.txt"))
        {
            byte[] buffer = new byte[fin.available()];
            fin.read(buffer);

            fout.write(obj.encrypt(buffer));

        } catch(IOException ex) {
            System.out.println("File Error\n");
        }

        try(FileInputStream fin = new FileInputStream("encrypt.txt");
            FileOutputStream fout = new FileOutputStream("decrypt.txt"))
        {
            byte[] buffer = new byte[fin.available()];
            fin.read(buffer);

            fout.write(obj.decrypt(buffer));

        } catch(IOException ex) {
            System.out.println("File Error\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

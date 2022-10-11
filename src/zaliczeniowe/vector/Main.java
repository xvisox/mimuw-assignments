package zaliczeniowe.vector;

import java.util.Random;

public class Main {
    private static final int HOW_MANY = 1000;

    private static void fillArray(int[] arr, Random r) {
        for (int i = 0; i < HOW_MANY; i++) {
            arr[i] = r.nextInt(100);
        }
    }

    public static void main(String[] args) {
        Random r = new Random();
        int[] randomValues1 = new int[HOW_MANY];
        int[] randomValues2 = new int[HOW_MANY];
        fillArray(randomValues1, r);
        fillArray(randomValues2, r);
        Vector v1 = new Vector(randomValues1);
        Vector v2 = new Vector(randomValues2);

        Vector vSum = v1.sum(v2);
        Vector vDot = v1.dot(v2);
        Vector vSumSeq = v1.sumSeq(v2);
        Vector vDotSeq = v1.dotSeq(v2);

        for (int i = 0; i < HOW_MANY; i++) {
            assert (vSumSeq.getValues()[i] == vSum.getValues()[i]);
            assert (vDotSeq.getValues()[i] == vDot.getValues()[i]);
        }
        System.out.println("Test passed!");
    }
}

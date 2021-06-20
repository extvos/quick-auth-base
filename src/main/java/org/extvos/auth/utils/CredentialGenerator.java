package org.extvos.auth.utils;

import java.util.Random;

/**
 * @author Mingcai SHEN
 */
public class CredentialGenerator {

    private static final String[] DECIMAL_DIGITS = "0,1,2,3,4,5,6,7,8,9".split(",");
    private static final String[] HEX_DIGITS = "0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f".split(",");
    private static final String[] ALPHABETS = "a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z".split(",");
    private static final String[] MIX_LETTERS = "a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z".split(",");

    public static String makeRandomString(String[] source, int length) {
        assert source != null && source.length > 0;
        assert length > 0;
        Random rand = new Random();
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < length; ++i) {
            text.append(source[rand.nextInt(source.length)]);
        }
        return text.toString();
    }

    public static String getDecimalDigits(int length) {
        return makeRandomString(DECIMAL_DIGITS, length);
    }

    public static String getHexDigits(int length) {
        return makeRandomString(HEX_DIGITS, length);
    }

    public static String getAlphabets(int length) {
        return makeRandomString(ALPHABETS, length);
    }

    public static String getRandom(int length) {
        return makeRandomString(MIX_LETTERS, length);
    }
}

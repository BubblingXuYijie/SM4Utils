package icu.xuyijie.sm4utils.util;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author 徐一杰
 * @date 2022/10/11
 * <p>
 * ECB 加密模式
 * 不使用自定义 secretKey，一般用于后端自行加解密,如果是前端加密后端解密，则需要自定义secretKey，前后端一致才能正确解密
 * 经过ECB加密的密文为：SM4Utils.encryptData_ECB("123456");
 * 经过ECB解密的密文为：SM4Utils.decryptData_ECB("UQZqWWcVSu7MIrMzWRD/wA==");
 * 使用自定义 secretKey，传入的 secretKey 必须为16位，可包含字母、数字、标点
 * 经过ECB加密的密文为：SM4Utils.encryptData_ECB("123456");
 * 经过ECB解密的密文为：SM4Utils.decryptData_ECB("UQZqWWcVSu7MIrMzWRD/wA==");
 * <p>
 * CBC 加密模式（更加安全），需要两个密钥
 * 经过CBC加密的密文为：SM4Utils.encryptData_CBC("123456");
 * 经过CBC解密的密文为：SM4Utils.decryptData_CBC("hbMK6/IeJ3UTzaTgLb3f3A==");
 * 同样可以自定义 secretKey 和 iv，需要两个密钥前后端都一致
 * 经过CBC加密的密文为：SM4Utils.encryptData_CBC("123456","asdfghjklzxcvb!_","1234567890123456");
 * 经过CBC解密的密文为：SM4Utils.decryptData_CBC("sTyCl3G6TF311kIENzsKNg==","asdfghjklzxcvb!_","1234567890123456");
 */
public class SM4Utils {
    private SM4Utils() {

    }

    private static final Logger logger = LoggerFactory.getLogger(SM4Utils.class);

    /**
     * 默认 SECRET_KEY
     * 当时用ECB模式的时候，和前端key一致
     * secretKey 必须为16位，可包含字母、数字、标点
     */
    private static final String SECRET_KEY = "GJwsXX_BzW=gJWJW";

    /**
     * 默认 IV
     * 当时用CBC模式的时候，SECRET_KEY和IV都需要传值，解密要和加密的SECRET_KEY和IV一致，更加安全
     * iv 必须为 16 位，可包含字母、数字、标点
     */
    private static final String IV = "ZkR_SiNoSOFT=568";

    static final String ECB = "ECB";

    static final String CBC = "CBC";

    private static final boolean HEX_STRING = false;

    private static final Pattern P = Pattern.compile("\\s*|\t|\r|\n");

    private static String encryptData(String type, String plainText, String secretKey, String iv) {
        try {
            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_ENCRYPT;

            byte[] keyBytes = secretKey == null ? SECRET_KEY.getBytes() : secretKey.getBytes();
            SM4 sm4 = new SM4();
            sm4.sm4SetKeyEnc(ctx, keyBytes);

            String cipherText;
            if (ECB.equals(type)) {
                byte[] encrypted = sm4.sm4CryptEcb(ctx, plainText.getBytes(StandardCharsets.UTF_8));
                cipherText = Base64.encodeBase64String(encrypted);
                if (cipherText != null && cipherText.trim().length() > 0) {
                    Matcher m = P.matcher(cipherText);
                    cipherText = m.replaceAll("");
                }
            } else {
                byte[] ivBytes = iv == null ? IV.getBytes() : iv.getBytes();
                byte[] encrypted = sm4.sm4CryptCbc(ctx, ivBytes, plainText.getBytes(StandardCharsets.UTF_8));
                cipherText = Base64.encodeBase64String(encrypted);
                if (cipherText != null && cipherText.trim().length() > 0) {
                    Matcher m = P.matcher(cipherText);
                    cipherText = m.replaceAll("");
                }
            }
            return cipherText;
        } catch (Exception e) {
            logger.error("加密失败！", e);
            return null;
        }
    }

    private static String decryptData(String type, String cipherText, String secretKey, String iv) {
        try {
            SM4_Context ctx = new SM4_Context();
            ctx.isPadding = true;
            ctx.mode = SM4.SM4_DECRYPT;

            SM4 sm4 = new SM4();
            if (ECB.equals(type)) {
                byte[] keyBytes = secretKey == null ? SECRET_KEY.getBytes() : secretKey.getBytes();
                sm4.sm4SetKeyDec(ctx, keyBytes);
                byte[] decrypted = sm4.sm4CryptEcb(ctx, Base64.decodeBase64(cipherText));
                return new String(decrypted, StandardCharsets.UTF_8);
            } else {
                byte[] keyBytes;
                byte[] ivBytes;
                if (HEX_STRING) {
                    keyBytes = Util.hexStringToBytes(secretKey);
                    ivBytes = Util.hexStringToBytes(iv);
                } else {
                    keyBytes = secretKey == null ? SECRET_KEY.getBytes() : secretKey.getBytes();
                    ivBytes = iv == null ? IV.getBytes() : iv.getBytes();
                }
                sm4.sm4SetKeyDec(ctx, keyBytes);
                byte[] decrypted = sm4.sm4CryptCbc(ctx, ivBytes, Base64.decodeBase64(cipherText));
                return new String(decrypted, StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            logger.error("解密失败！请检查密钥和密文是否对应", e);
            return null;
        }
    }


    /**
     * ECB模式加密，自定义密钥，加解密密钥需一致
     *
     * @param plainText 要加密的数据
     * @param secretKey 密钥，必须为 16 位，可包含字母、数字、标点
     * @return 加密后的字符串
     */
    public static String encryptData_ECB(String plainText, String secretKey) {
        return encryptData(ECB, plainText, secretKey, null);
    }

    /**
     * ECB模式加密，默认密钥
     *
     * @param plainText 要加密的数据
     * @return 加密后的字符串
     */
    public static String encryptData_ECB(String plainText) {
        return encryptData(ECB, plainText, null, null);
    }

    /**
     * ECB模式解密，自定义密钥，加解密密钥需一致
     *
     * @param cipherText 要解密的数据
     * @param secretKey 密钥，必须为 16 位，可包含字母、数字、标点
     * @return 解密后的字符串
     */
    public static String decryptData_ECB(String cipherText, String secretKey) {
        return decryptData(ECB, cipherText, secretKey, null);
    }

    /**
     * ECB模式解密，默认密钥
     *
     * @param cipherText 要解密的数据
     * @return 解密后的字符串
     */
    public static String decryptData_ECB(String cipherText) {
        return decryptData(ECB, cipherText, null, null);
    }

    /**
     * CBC模式加密，SECRET_KEY和IV都需要传值，解密要和加密的SECRET_KEY和IV一致，更加安全
     *
     * @param plainText 要加密的数据
     * @param secretKey 密钥一，必须为 16 位，可包含字母、数字、标点
     * @param iv 密钥二，必须为 16 位，可包含字母、数字、标点
     * @return 加密后的字符串
     */
    public static String encryptData_CBC(String plainText, String secretKey, String iv) {
        return encryptData(CBC, plainText, secretKey, iv);
    }

    /**
     * CBC模式加密，SECRET_KEY和IV都需要传值，解密要和加密的SECRET_KEY和IV一致，更加安全
     *
     * @param plainText 要加密的数据
     * @return 加密后的字符串
     */
    public static String encryptData_CBC(String plainText) {
        return encryptData(CBC, plainText, null, null);
    }

    /**
     * CBC模式解密，SECRET_KEY和IV都需要传值，解密要和加密的SECRET_KEY和IV一致，更加安全
     *
     * @param cipherText 要解密的数据
     * @param secretKey 密钥一，必须为 16 位，可包含字母、数字、标点
     * @param iv 密钥二，必须为 16 位，可包含字母、数字、标点
     * @return 解密后的字符串
     */
    public static String decryptData_CBC(String cipherText, String secretKey, String iv) {
        return decryptData(CBC, cipherText, secretKey, iv);
    }

    /**
     * CBC模式解密，SECRET_KEY和IV都需要传值，解密要和加密的SECRET_KEY和IV一致，更加安全
     *
     * @param cipherText 要解密的数据
     * @return 解密后的字符串
     */
    public static String decryptData_CBC(String cipherText) {
        return decryptData(CBC, cipherText, null, null);
    }

//    public static void main(String[] args) {
//        System.out.println("经过ECB加密的密文为：" + SM4Utils.encryptData_ECB("41150320000416041X"));
//        System.out.println("经过ECB解密的密文为：" + SM4Utils.decryptData_ECB("ZaCySfpl8DLflqpnM67eqBuFHqHevz6NvJY7i77t4zk="));
//        System.out.println("经过CBC加密的密文为：" + SM4Utils.encryptData_CBC("411503200004161234"));
//        System.out.println("经过CBC解密的密文为：" + SM4Utils.decryptData_CBC("+jrRkCWcUHUQhU8KD+oI8QmV8caxJph1FJlL/gMmXaw="));
//        System.out.println("经过CBC自定义密钥加密的密文为：" + SM4Utils.encryptData_CBC("123456", "1sdfghjklzxcvbnm", ".234567890@$^-_*"));
//        System.out.println("经过CBC自定义密钥解密的密文为：" + SM4Utils.decryptData_CBC("nDYTqPakB7kMcxwJSfq05Q==", "1sdfghjklzxcvbnm", ".234567890@$^-_*"));
//    }
}

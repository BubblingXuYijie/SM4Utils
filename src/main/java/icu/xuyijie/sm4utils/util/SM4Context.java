package icu.xuyijie.sm4utils.util;

/**
 * @author 徐一杰
 * @date 2022/10/11
 */
class SM4Context {
    int mode;

    int[] sk;

    boolean isPadding;

    public SM4Context() {
        this.mode = 1;
        this.isPadding = true;
        this.sk = new int[32];
    }
}

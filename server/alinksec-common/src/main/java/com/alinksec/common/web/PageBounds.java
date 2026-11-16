package com.alinksec.common.web;

/** Reject invalid pagination before calculating an offset or issuing SQL. */
public final class PageBounds {
    private PageBounds() {}
    public static int offset(int page,int size) {
        if(page<1 || size<1 || size>1000)throw new IllegalArgumentException("分页参数超出范围");
        long offset=((long)page-1)*size;
        if(offset>Integer.MAX_VALUE)throw new IllegalArgumentException("分页偏移超出范围");
        return (int)offset;
    }
}

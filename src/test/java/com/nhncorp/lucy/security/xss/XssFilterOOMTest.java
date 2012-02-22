/*
 * @(#) XssFilterTest.java 2010. 8. 11
 *
 * Copyright 2010 NHN Corp. All rights Reserved.
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss;


import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.Writer;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * 대용량 파일 처리 시 {@link XssFilter} OOM 분석을 위한 테스트 코드.
 * 메일웹 개발팀 문의 사항.
 * @author Web Platform Development Team
 */
public class XssFilterOOMTest extends XssFilterTestCase {
	private static final String BIG_HTML_FILES_6M = "본문이 큰 html 메일_6M.html";
	private static final String BIG_HTML_FILES_62M = "본문이 큰 html 메일_62M.html";
	private static final String BIG_EML_FILES_8M = "본문이_큰_html_메일.eml";
	private static final String BIG_HTML_FILES_6M_REMOVE_IEHACK = "본문이 큰 html 메일_IEHack제거_6M.html";
	private static final String BIG_HTML_FILES_6M_REMOVE_HTML_BODY_TAG = "본문이 큰 html 메일_6M_remove_html_body_tag.html";
	private static final String BIG_HTML_FILES_3M = "본문이 큰 html 메일_용량줄임.html";

	@Ignore
	@Test
	public void testHtmlFiltering() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_EML_FILES_8M);
		String clean = filter.doFilter(target);
		
	}
	
	@Test
	public void testOnlyOneElementCase() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = "<h1>Hello</h1>";
		String clean = filter.doFilter(target);
		long total = Runtime.getRuntime().totalMemory();
		long free = Runtime.getRuntime().freeMemory();
		long used = total - free;
		System.out.println("Used memory: " + used);
		System.out.println("clean : " + clean);
	}
	
	@Ignore
	@Test
	public void test6MFileSizeCase() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES_6M);
		String result = filter.doFilter(target);
		Assert.assertTrue(target.equals(result));
	}
	
	@Ignore
	@Test
	public void test3MFileSize() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES_3M);
		//String result = filter.doFilter(target);
		//Assert.assertTrue(target.equals(result));
		Writer writer;
		writer = new BufferedWriter(new FileWriter("d:/test3MFileSizeForEachTokenWayOldRule.html"));
		//writer = new BufferedWriter(new FileWriter("d:/test3MFileSizeForAllTokenWay2.html"));
		filter.doFilter(target, writer);
	}
	
	@Ignore
	@Test
	public void test6MFileSizeRemoveIEHackCase() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES_6M_REMOVE_IEHACK);
		String result = filter.doFilter(target);
		Assert.assertTrue(target.equals(result));
	}
	
	@Ignore
	@Test
	public void test6MFileSizeRemoveHtmlBodyTagCase() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES_6M_REMOVE_HTML_BODY_TAG);
		String result = filter.doFilter(target);
		Assert.assertTrue(target.equals(result));
	}
	
	@Ignore
	@Test
	public void test62MFileSizeCase() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES_62M);
		filter.doFilter(target);
	}
}
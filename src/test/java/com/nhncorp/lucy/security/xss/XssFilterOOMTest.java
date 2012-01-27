/*
 * @(#) XssFilterTest.java 2010. 8. 11
 *
 * Copyright 2010 NHN Corp. All rights Reserved.
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss;

import org.junit.Test;

/**
 * 대용량 파일 처리 시 {@link XssFilter} OOM 분석을 위한 테스트 코드.
 * 메일웹 개발팀 문의 사항.
 * @author Web Platform Development Team
 */
public class XssFilterOOMTest extends XssFilterTestCase {
	private static final String BIG_HTML_FILES = "본문이_큰_html_메일.eml";

	@Test
	public void testHtmlFiltering() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES);
		String clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		clean = filter.doFilter(target);
		//Assert.assertTrue("\n" + target + "\n" + clean, target.equals(clean));
	}
	
	@Test
	public void testHtmlFilteringOtherFiles() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES);
		String clean = filter.doFilter(target);
		target = readString("html_본문이지만_태그가_없는_경우.eml");
		clean = filter.doFilter(target);
		//Assert.assertTrue("\n" + target + "\n" + clean, target.equals(clean));
	}
}
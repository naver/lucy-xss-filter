/*
 * @(#) XssFilterPerformance.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss;

/**
 * {@link XssFilter} 성능 테스트.
 * 
 * 파일의 크기와 반복횟수를 조절해서 성능을 점검한다.
 * 
 * @author Web Platform Development Team
 */
public class XssFilterPerformance extends XssFilterTestCase {

//	private static final String DEFAULT_SMALL_FILES[] = { "xss-size27k.html",
//			"xss-size60k.html" };
//	private static final String DEFAULT_BIG_FILES[] = { "xss-size4m.html" };
	
	private static final String DEFAULT_SMALL_FILES[] = { "xss-size27k.html"};

	public void product(int loopCount, String... filePaths) throws Exception {
		XssFilter filter = XssFilter.getInstance();
		for (String text : readString(filePaths)) {
			printPerformance(filter, text, loopCount);
		}
	}

	public static void main(String[] args) throws Exception {
		XssFilterPerformance main = new XssFilterPerformance();
		if (0 != args.length) {
			main.product(0, args);
			return;
		}

		main.product(1000, DEFAULT_SMALL_FILES);
//		main.product(1, DEFAULT_BIG_FILES);
	}
}
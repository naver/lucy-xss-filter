/*
 * @(#) XssFilterTest.java 2010. 8. 11
 *
 * Copyright 2010 NHN Corp. All rights Reserved.
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss;

import java.util.Collection;

import org.junit.Test;

import com.nhncorp.lucy.security.xss.markup.Content;
import com.nhncorp.lucy.security.xss.markup.MarkupParser;

/**
 * 대용량 파일 처리 시 {@link XssFilter} 와 HtmlCleaner 의 메모리 사용량 비교 테스트
 * 메일웹 개발팀 문의 사항.
 * @author Web Platform Development Team
 */
public class XssFilterCompareToHtmlCleanerTest extends XssFilterTestCase {
	private static final String BIG_HTML_FILES = "본문이_큰_html_메일.eml";

	@Test
	public void testHtmlFiltering() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES);
		String clean = filter.doFilter(target);
		//Assert.assertTrue("\n" + target + "\n" + clean, target.equals(clean));
	}
	
	@Test
	public void testXSSFilteringParsingResultMemory() throws Exception {
		XssFilter filter = XssFilter.getInstance();
		String target = readString(BIG_HTML_FILES);
		Collection<Content> contents = MarkupParser.parse(target);
		System.out.println("contents.size()" + contents.size());
		
	}
	
//	@Test
//	public void testHtmlCleanerParsingResultMemory() throws Exception {
//		// 메일팀 HtmlCleaner 설정 그대로 적요.
//		CleanerProperties cleanerProperties = new CleanerProperties();
//		cleanerProperties.setAdvancedXmlEscape(true);
//		cleanerProperties.setOmitDoctypeDeclaration(true);
//		cleanerProperties.setOmitXmlDeclaration(true);
//		cleanerProperties.setOmitHtmlEnvelope(false);
//		cleanerProperties.setOmitComments(false);
//		cleanerProperties.setUseCdataForScriptAndStyle(false);
//		cleanerProperties.setAllowMultiWordAttributes(true);
//		cleanerProperties.setAllowHtmlInsideAttributes(true);
//		cleanerProperties.setTranslateSpecialEntities(false);
//		HtmlCleaner htmlCleaner = new HtmlCleaner(cleanerProperties);
//		
//		String orgContents = readString(BIG_HTML_FILES);
//		TagNode tagNode = htmlCleaner.clean(orgContents);
//		System.out.println("a" + 1);
//	}
}
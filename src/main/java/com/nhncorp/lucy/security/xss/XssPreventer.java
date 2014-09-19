/*
 * @(#) XssPreventer.java 2014. 7. 22
 *
 * Copyright 2014 Naver Corp. All rights Reserved.
 * Naver PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss;

import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


/**
 * 이 클래스는 {@code Cross Site Scripting} 코드가 삽입된 {@code String} 데이터를 
 * Apache Common Lang3을 사용해 신뢰할 수 있는 코드로 변환 시키는 기능을 제공한다. <br/><br/> 
 * 기존의 XssFilter, XssSaxFilter와 주요 차이점은 모든 태그를 무력화시키는 점이다.  
 * 이 클래스를 사용하는 방법은 다음과 같다.
 *
 * <pre>
 * ...
 *
 * String clean = XssPreventer.htmlEscaper(dirty);
 * String dirty = XssPreventer.htmlUnEscaper(clean);
 *
 * ...
 * </pre>
 *
 * @author Web Platform Development Lab
 *
 */
public class XssPreventer {
	
	private static final Log LOG = LogFactory.getLog(XssFilter.class);
		
	/**
	 * 이 메소드는 XSS({@code Cross Site Scripting})가 포함된 위험한 코드에 대하여 
	 * 신뢰할 수 있는 코드로 변환하는 기능을 제공한다.
	 *  기존의 XssFilter, XssSaxFilter와 주요 차이점은 모든 태그를 무력화시키는 점이다.  
	 * 
	 * @param dirty
	 *            XSS({@code Cross Site Scripting})이 포함된 위험한 코드.            
	 * @return 신뢰할 수 있는 코드.
	 */
	public static String escape(String dirty) {
		
		String clean = StringEscapeUtils.escapeHtml4(dirty);
		
		if (clean == null) {
			return null;
		}
		
		return clean.replaceAll("'", "&#39");
	}
	
	/**
	 * 이 메소드는 XssPreventer를 수행하기 전의 코드로 원복하는 기능을 제공한다. <br/>   
	 * 
	 * @param clean
	 *            XssPreventer를 수행 후 문자열.            
	 * @return XssPreventer를 수행 전의 문자열.
	 */
	public static String unescape(String clean) {
		
		String str = StringEscapeUtils.unescapeHtml4(clean);
		
		if (str == null) {
			return null;
		}
		
		return str.replaceAll("&#39", "'");
	}
}

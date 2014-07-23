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
	
	public enum PreventionRule {
		//보안팀 필수 룰, 아래로 내려갈수록 보안 룰이 엄격해짐
		//보안팀 권고 룰
		//OWASP 권고 룰
	}
		
	/**
	 * 이 메소드는 XSS({@code Cross Site Scripting})가 포함된 위험한 코드에 대하여 
	 * 신뢰할 수 있는 코드로 변환하는 기능을 제공한다.
	 *  기존의 XssFilter, XssSaxFilter와 주요 차이점은 모든 태그를 무력화시키는 점이다.  
	 * 
	 * @param dirty
	 *            XSS({@code Cross Site Scripting})이 포함된 위험한 코드.            
	 * @return 신뢰할 수 있는 코드.
	 */
	public static String htmlEscaper(String dirty) {
		return StringEscapeUtils.escapeHtml4(dirty);
	}
	
	/**
	 * 이 메소드는 htmlEscaper를 수행하기 전의 코드로 원복하는 기능을 제공한다. <br/>   
	 * 
	 * @param clean
	 *            htmlEscaper를 수행 후 코드.            
	 * @return htmlEscaper를 수행 전의 코드.
	 */
	public static String htmlUnEscaper(String clean) {
		return StringEscapeUtils.unescapeHtml4(clean);
	}
}

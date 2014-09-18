/*
 * @(#) ObjectListener.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.listener;

import java.util.regex.Pattern;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * 이 클래스는 Object 태그에 대한 보안 필터링을 수행한다.
 * 
 * @author Naver Labs
 * 
 */
public class ParamListener implements ElementListener {
	private static final Pattern INVOKEURLS = Pattern.compile("['\"]?\\s*(?i:invokeURLs)\\s*['\"]?");
	private static final Pattern AUTOSTART = Pattern.compile("['\"]?\\s*(?i:autostart)\\s*['\"]?");
	private static final Pattern ALLOWSCRIPTACCESS = Pattern.compile("['\"]?\\s*(?i:allowScriptAccess)\\s*['\"]?");
	private static final Pattern AUTOPLAY = Pattern.compile("['\"]?\\s*(?i:autoplay)\\s*['\"]?");
	private static final Pattern ENABLEHREF = Pattern.compile("['\"]?\\s*(?i:enablehref)\\s*['\"]?");
	private static final Pattern ENABLEJAVASCRIPT = Pattern.compile("['\"]?\\s*(?i:enablejavascript)\\s*['\"]?");
	private static final Pattern NOJAVA = Pattern.compile("['\"]?\\s*(?i:nojava)\\s*['\"]?");
	private static final Pattern ALLOWHTMLPOPUPWINDOW = Pattern.compile("['\"]?\\s*(?i:AllowHtmlPopupwindow)\\s*['\"]?");
	private static final Pattern ENABLEHTMLACCESS = Pattern.compile("['\"]?\\s*(?i:enableHtmlAccess)\\s*['\"]?");

	public void handleElement(Element element) {
		String name = element.getAttributeValue("name");

		if (INVOKEURLS.matcher(name).matches()) {
			element.putAttribute("value", "\"false\"");
		} else if (AUTOSTART.matcher(name).matches()) {
			element.putAttribute("value", "\"false\"");
		} else if (ALLOWSCRIPTACCESS.matcher(name).matches()) {
			element.putAttribute("value", "\"never\"");
		} else if (AUTOPLAY.matcher(name).matches()) {
			element.putAttribute("value", "\"false\"");
		} else if (ENABLEHREF.matcher(name).matches()) {
			element.putAttribute("value", "\"false\"");
		} else if (ENABLEJAVASCRIPT.matcher(name).matches()) {
			element.putAttribute("value", "\"false\"");
		} else if (NOJAVA.matcher(name).matches()) {
			element.putAttribute("value", "\"true\"");
		} else if (ALLOWHTMLPOPUPWINDOW.matcher(name).matches()) {
			element.putAttribute("value", "\"false\"");
		} else if (ENABLEHTMLACCESS.matcher(name).matches()) {
			element.putAttribute("value", "\"false\"");
		}
	}
}
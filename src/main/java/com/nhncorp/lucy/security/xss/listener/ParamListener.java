/*
 *	Copyright 2014 Naver Corp.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *		http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
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
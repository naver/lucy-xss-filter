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

import java.util.List;
import java.util.regex.Pattern;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Attribute;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * 이 클래스는 Object 태그에 대한 보안 필터링을 수행한다.
 * 
 * @author Naver Labs
 * 
 */
public class ObjectListener implements ElementListener {
	private static final Pattern INVOKEURLS = Pattern.compile("['\"]?\\s*(?i:invokeURLs)\\s*['\"]?");
	private static final Pattern AUTOSTART = Pattern.compile("['\"]?\\s*(?i:autostart)\\s*['\"]?");
	private static final Pattern ALLOWSCRIPTACCESS = Pattern.compile("['\"]?\\s*(?i:allowScriptAccess)\\s*['\"]?");
	private static final Pattern ALLOWNETWORKING = Pattern.compile("['\"]?\\s*(?i:allowNetworking)\\s*['\"]?");
	private static final Pattern AUTOPLAY = Pattern.compile("['\"]?\\s*(?i:autoplay)\\s*['\"]?");
	private static final Pattern ENABLEHREF = Pattern.compile("['\"]?\\s*(?i:enablehref)\\s*['\"]?");
	private static final Pattern ENABLEJAVASCRIPT = Pattern.compile("['\"]?\\s*(?i:enablejavascript)\\s*['\"]?");
	private static final Pattern NOJAVA = Pattern.compile("['\"]?\\s*(?i:nojava)\\s*['\"]?");
	private static final Pattern ALLOWHTMLPOPUPWINDOW = Pattern.compile("['\"]?\\s*(?i:AllowHtmlPopupwindow)\\s*['\"]?");
	private static final Pattern ENABLEHTMLACCESS = Pattern.compile("['\"]?\\s*(?i:enableHtmlAccess)\\s*['\"]?");

	private static final Pattern[] URLNAMES = {Pattern.compile("['\"]?\\s*(?i:url)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:href)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:src)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:movie)\\s*['\"]?")};

	private static boolean containsURLName(String name) {
		for (Pattern pattern : URLNAMES) {
			if (pattern.matcher(name).matches()) {
				return true;
			}
		}
		return false;
	}

	public void handleElement(Element element) {
		boolean invokeURLsExisted = false;
		boolean autostartExisted = false;
		boolean allowScriptAccessExisted = false;
		boolean allowNetworkingExisted = false;
		boolean autoplayExisted = false;
		boolean enablehrefExisted = false;
		boolean enablejavascriptExisted = false;
		boolean nojavaExisted = false;
		boolean allowHtmlPopupwindowExisted = false;
		boolean enableHtmlAccessExisted = false;

		String allowNetworkingValue = "\"internal\"";
		boolean isWhiteUrl = false;
		boolean isSrcWhiteUrl = true;

		if (element.isDisabled()) {
			return;
		}

		Attribute dataUrl = element.getAttribute("data");

		if (dataUrl != null) { // data 속성이 존재하면 체크
			String dataUrlStr = dataUrl.getValue();
			boolean isDataUrlWhite = this.isWhiteUrl(dataUrlStr);

			// URL MIME 체크
			boolean isVulnerable = SecurityUtils.checkVulnerable(element, dataUrlStr, isDataUrlWhite);

			if (isVulnerable) {
				element.setEnabled(false);
				return;
			}

			if (isDataUrlWhite) {
				allowNetworkingValue = "\"all\"";
			}
		}

		List<Element> elements = element.getElements();

		if (elements != null) {
			for (Element param : elements) {
				if ("param".equalsIgnoreCase(param.getName()) && containsURLName(param.getAttributeValue("name"))) {

					String srcUrl = param.getAttributeValue("value");

					if (!this.isWhiteUrl(srcUrl)) {
						isWhiteUrl = false;
						isSrcWhiteUrl = false;
					} else {
						isWhiteUrl = true;
					}

					// URL MIME 체크
					boolean isVulnerable = SecurityUtils.checkVulnerable(element, srcUrl, isWhiteUrl);

					if (isVulnerable) {
						element.setEnabled(false);
						return;
					}
				}
			}

			if (isWhiteUrl && isSrcWhiteUrl) {
				allowNetworkingValue = "\"all\"";
			}

			for (Element param : elements) {
				if (!"param".equalsIgnoreCase(param.getName())) {
					continue;
				}

				String name = param.getAttributeValue("name");
				if (INVOKEURLS.matcher(name).matches()) {
					param.putAttribute("value", "\"false\"");
					invokeURLsExisted = true;
				} else if (AUTOSTART.matcher(name).matches()) {
					param.putAttribute("value", "\"false\"");
					autostartExisted = true;
				} else if (ALLOWSCRIPTACCESS.matcher(name).matches()) {
					param.putAttribute("value", "\"never\"");
					allowScriptAccessExisted = true;
				} else if (ALLOWNETWORKING.matcher(name).matches()) {
					param.putAttribute("value", allowNetworkingValue);
					allowNetworkingExisted = true;
				} else if (AUTOPLAY.matcher(name).matches()) {
					param.putAttribute("value", "\"false\"");
					autoplayExisted = true;
				} else if (ENABLEHREF.matcher(name).matches()) {
					param.putAttribute("value", "\"false\"");
					enablehrefExisted = true;
				} else if (ENABLEJAVASCRIPT.matcher(name).matches()) {
					param.putAttribute("value", "\"false\"");
					enablejavascriptExisted = true;
				} else if (NOJAVA.matcher(name).matches()) {
					param.putAttribute("value", "\"true\"");
					nojavaExisted = true;
				} else if (ALLOWHTMLPOPUPWINDOW.matcher(name).matches()) {
					param.putAttribute("value", "\"false\"");
					allowHtmlPopupwindowExisted = true;
				} else if (ENABLEHTMLACCESS.matcher(name).matches()) {
					param.putAttribute("value", "\"false\"");
					enableHtmlAccessExisted = true;
				}
			}
		}

		// <param name="invokeURLs" value="false" />
		if (!invokeURLsExisted) {
			Element invokeURLs = new Element("param");
			invokeURLs.putAttribute("name", "\"invokeURLs\"");
			invokeURLs.putAttribute("value", "\"false\"");
			element.addContent(invokeURLs);
		}

		// <param name="autostart" value="false" />
		if (!autostartExisted) {
			Element autostart = new Element("param");
			autostart.putAttribute("name", "\"autostart\"");
			autostart.putAttribute("value", "\"false\"");
			element.addContent(autostart);
		}

		// <param name="allowScriptAccess" value="never" />
		if (!allowScriptAccessExisted) {
			Element allowScriptAccess = new Element("param");
			allowScriptAccess.putAttribute("name", "\"allowScriptAccess\"");
			allowScriptAccess.putAttribute("value", "\"never\"");
			element.addContent(allowScriptAccess);
		}

		// <param name="allowNetworking" value="all|internal" />

		if (!allowNetworkingExisted) {
			Element allowNetworking = new Element("param");
			allowNetworking.putAttribute("name", "\"allowNetworking\"");
			allowNetworking.putAttribute("value", allowNetworkingValue);
			element.addContent(allowNetworking);
		}

		// <param name="autoplay" value="false" />
		if (!autoplayExisted) {
			Element autoplay = new Element("param");
			autoplay.putAttribute("name", "\"autoplay\"");
			autoplay.putAttribute("value", "\"false\"");
			element.addContent(autoplay);
		}

		// <param name="enablehref" value="flase" />
		if (!enablehrefExisted) {
			Element enablehref = new Element("param");
			enablehref.putAttribute("name", "\"enablehref\"");
			enablehref.putAttribute("value", "\"false\"");
			element.addContent(enablehref);
		}

		// <param name="enablejavascript" value="flase" />
		if (!enablejavascriptExisted) {
			Element enablejavascript = new Element("param");
			enablejavascript.putAttribute("name", "\"enablejavascript\"");
			enablejavascript.putAttribute("value", "\"false\"");
			element.addContent(enablejavascript);
		}

		// <param name="nojava" value="true" />
		if (!nojavaExisted) {
			Element nojava = new Element("param");
			nojava.putAttribute("name", "\"nojava\"");
			nojava.putAttribute("value", "\"true\"");
			element.addContent(nojava);
		}

		// <param name="AllowHtmlPopupwindow" value="false" />
		if (!allowHtmlPopupwindowExisted) {
			Element allowHtmlPopupwindow = new Element("param");
			allowHtmlPopupwindow.putAttribute("name", "\"AllowHtmlPopupwindow\"");
			allowHtmlPopupwindow.putAttribute("value", "\"false\"");
			element.addContent(allowHtmlPopupwindow);
		}

		// <param name="enableHtmlAccess" value="false" />
		if (!enableHtmlAccessExisted) {
			Element enableHtmlAccess = new Element("param");
			enableHtmlAccess.putAttribute("name", "\"enableHtmlAccess\"");
			enableHtmlAccess.putAttribute("value", "\"false\"");
			element.addContent(enableHtmlAccess);
		}
	}

	private boolean isWhiteUrl(String url) {
		WhiteUrlList list = WhiteUrlList.getInstance();
		if (list != null && list.contains(url)) {
			return true;
		}

		return false;
	}

}
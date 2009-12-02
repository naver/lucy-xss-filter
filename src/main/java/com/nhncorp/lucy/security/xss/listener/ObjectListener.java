package com.nhncorp.lucy.security.xss.listener;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * 이 클래스는 Object 태그에 대한 보안 필터링을 수행한다.
 * 
 * @author Web Platform Development Team
 * @version $Rev: 22162 $, $Date: 2009-08-25 19:03:29 +0900 (화, 25 8 2009) $
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
	private static final Pattern[] URLNAMES = {Pattern.compile("['\"]?\\s*(?i:url)\\s*['\"]?"),
		Pattern.compile("['\"]?\\s*(?i:href)\\s*['\"]?"), Pattern.compile("['\"]?\\s*(?i:src)\\s*['\"]?"),
		Pattern.compile("['\"]?\\s*(?i:movie)\\s*['\"]?")};
 
	/**
	 * Contains url name.
	 * 
	 * @param name the name
	 * 
	 * @return true, if successful
	 */
	private static boolean containsURLName(String name) {
		for (Pattern pattern : URLNAMES) {
			if (pattern.matcher(name).matches()) {
				return true;
			}
		}
		
		return false;
	}

	/**
	 * @param element Element
	 */
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

		String allowNetworkingValue = "\"all\"";
		
		if (element != null && element.getElements() != null) {

			List<Element> tempElements = element.getElements();

			Element param = null;
			
			for (int i = 0; tempElements != null && i < tempElements.size(); i++) {
				
				param = tempElements.get(i);
				
				//for (Element param : e.getElements()) {
				
				if ("param".equalsIgnoreCase(param.getName()) && containsURLName(param.getAttributeValue("name"))
					&& !this.isWhiteUrl(param.getAttributeValue("value"))) {
					allowNetworkingValue = "\"internal\"";
					break;
				}
			}

			param = null;
			
			for (int i = 0; tempElements != null && i < tempElements.size(); i++) {
				
				param = tempElements.get(i);
				
				//for (Element param : e.getElements()) {
				
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

		Map<String, Boolean> handleElementMap = new HashMap<String, Boolean>();
		handleElementMap.put("invokeURLsExisted", invokeURLsExisted);
		handleElementMap.put("autostartExisted", autostartExisted);
		handleElementMap.put("allowScriptAccessExisted", allowScriptAccessExisted);
		handleElementMap.put("allowNetworkingExisted", allowNetworkingExisted);
		handleElementMap.put("autoplayExisted", autoplayExisted);
		handleElementMap.put("enablehrefExisted", enablehrefExisted);
		handleElementMap.put("enablejavascriptExisted", enablejavascriptExisted);
		handleElementMap.put("nojavaExisted", nojavaExisted);
		handleElementMap.put("allowHtmlPopupwindowExisted", allowHtmlPopupwindowExisted);
		handleElementMap.put("enableHtmlAccessExisted", enableHtmlAccessExisted);
		
		List<Element> list = getElements(handleElementMap, allowNetworkingValue);

		for (int i = 0; i < list.size(); i++) {
			if (element != null) {
				element.addContent(list.get(i));
			}
		}
	}

	/**
	 * Gets the elements.
	 * 
	 * @param handleElementMap Map
	 * handleElementMap key
	 * @invokeURLsExisted the invoke ur ls existed
	 * @autostartExisted the autostart existed
	 * @allowScriptAccessExisted the allow script access existed
	 * @allowNetworkingExisted the allow networking existed
	 * @autoplayExisted the autoplay existed
	 * @enablehrefExisted the enablehref existed
	 * @enablejavascriptExisted the enablejavascript existed
	 * @nojavaExisted the nojava existed
	 * @allowHtmlPopupwindowExisted the allow html popupwindow existed
	 * @enableHtmlAccessExisted the enable html access existed
	 * 
	 * @param allowNetworkingValue the allow networking value
	 * 
	 * @return the elements
	 */
	private List<Element> getElements(Map<String, Boolean> handleElementMap, String allowNetworkingValue) {

		List<Element> list = new ArrayList<Element>();

		// <param name="invokeURLs" value="false" />
		if (!handleElementMap.get("invokeURLsExisted")) {
			Element invokeURLs = new Element("param");
			invokeURLs.putAttribute("name", "\"invokeURLs\"");
			invokeURLs.putAttribute("value", "\"false\"");
			list.add(invokeURLs);
		}

		// <param name="autostart" value="false" />
		if (!handleElementMap.get("autostartExisted")) {
			Element autostart = new Element("param");
			autostart.putAttribute("name", "\"autostart\"");
			autostart.putAttribute("value", "\"false\"");
			list.add(autostart);
		}

		// <param name="allowScriptAccess" value="never" />
		if (!handleElementMap.get("allowScriptAccessExisted")) {
			Element allowScriptAccess = new Element("param");
			allowScriptAccess.putAttribute("name", "\"allowScriptAccess\"");
			allowScriptAccess.putAttribute("value", "\"never\"");
			list.add(allowScriptAccess);
		}

		// <param name="allowNetworking" value="all|internal" />

		if (!handleElementMap.get("allowNetworkingExisted")) {
			Element allowNetworking = new Element("param");
			allowNetworking.putAttribute("name", "\"allowNetworking\"");
			allowNetworking.putAttribute("value", allowNetworkingValue);
			list.add(allowNetworking);
		}

		// <param name="autoplay" value="false" />
		if (!handleElementMap.get("autoplayExisted")) {
			Element autoplay = new Element("param");
			autoplay.putAttribute("name", "\"autoplay\"");
			autoplay.putAttribute("value", "\"false\"");
			list.add(autoplay);
		}

		// <param name="enablehref" value="flase" />
		if (!handleElementMap.get("enablehrefExisted")) {
			Element enablehref = new Element("param");
			enablehref.putAttribute("name", "\"enablehref\"");
			enablehref.putAttribute("value", "\"false\"");
			list.add(enablehref);
		}

		// <param name="enablejavascript" value="flase" />
		if (!handleElementMap.get("enablejavascriptExisted")) {
			Element enablejavascript = new Element("param");
			enablejavascript.putAttribute("name", "\"enablejavascript\"");
			enablejavascript.putAttribute("value", "\"false\"");
			list.add(enablejavascript);
		}

		// <param name="nojava" value="true" />
		if (!handleElementMap.get("nojavaExisted")) {
			Element nojava = new Element("param");
			nojava.putAttribute("name", "\"nojava\"");
			nojava.putAttribute("value", "\"true\"");
			list.add(nojava);
		}

		// <param name="AllowHtmlPopupwindow" value="false" />
		if (!handleElementMap.get("allowHtmlPopupwindowExisted")) {
			Element allowHtmlPopupwindow = new Element("param");
			allowHtmlPopupwindow.putAttribute("name", "\"AllowHtmlPopupwindow\"");
			allowHtmlPopupwindow.putAttribute("value", "\"false\"");
			list.add(allowHtmlPopupwindow);
		}

		// <param name="enableHtmlAccess" value="false" />
		if (!handleElementMap.get("enableHtmlAccessExisted")) {
			
			Element enableHtmlAccess = new Element("param");
			enableHtmlAccess.putAttribute("name", "\"enableHtmlAccess\"");
			enableHtmlAccess.putAttribute("value", "\"false\"");
			list.add(enableHtmlAccess);
		}
		
		return list;
	}

	/**
	 * Checks if is white url.
	 * 
	 * @param url the url
	 * 
	 * @return true, if is white url
	 */
	private boolean isWhiteUrl(String url) {
		try {
			
			WhiteUrlList list = WhiteUrlList.getInstance();

			if (list != null && list.contains(url)) {
				return true;
			}
		} catch (Exception e) {
			
			// ignore
			e.getMessage();
		}

		return false;
	}
}
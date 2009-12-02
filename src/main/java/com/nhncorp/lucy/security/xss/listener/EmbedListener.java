package com.nhncorp.lucy.security.xss.listener;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * 이 클래스는 Embed 태그에 대한 보안 필터링을 수행한다.
 *
 * @author Web Platform Development Team
 * @version $Rev: 22103 $, $Date: 2009-08-21 17:55:46 +0900 (금, 21 8 2009) $
 */
public class EmbedListener implements ElementListener {
	/**
	 * @param element {@link Element}
	 */
	public void handleElement(Element element) {
		element.putAttribute("invokeURLs", "\"false\"");
		element.putAttribute("autostart", "\"false\"");
		element.putAttribute("allowScriptAccess", "\"never\"");

		if (this.isWhiteUrl(element.getAttributeValue("src"))) {
			element.putAttribute("allowNetworking", "\"all\"");
		} else {
			element.putAttribute("allowNetworking", "\"internal\"");
		}

	}

	/**
	 * 
	 * @param url {@link String}
	 * @return boolean
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

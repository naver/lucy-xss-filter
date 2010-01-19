package com.nhncorp.lucy.security.xss.listener;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * 이 클래스는 Embed 태그에 대한 보안 필터링을 수행한다.
 *
 * @author Web Platform Development Team
 * @version $Rev: 20085 $, $Date: 2009-02-05 18:19:28 +0900 (목, 05 2 2009) $
 */
public class EmbedListener implements ElementListener {

	public void handleElement(Element e) {
		e.putAttribute("invokeURLs", "\"false\"");
		e.putAttribute("autostart", "\"false\"");
		e.putAttribute("allowScriptAccess", "\"never\"");
		
		if (this.isWhiteUrl(e.getAttributeValue("src"))) {
			e.putAttribute("allowNetworking", "\"all\"");
		} else {
			e.putAttribute("allowNetworking", "\"internal\"");
		}
		
	}
	
	private boolean isWhiteUrl(String url) {
		try {
			WhiteUrlList list = WhiteUrlList.getInstance();
			if (list.contains(url)) {
				return true;
			}
		} catch (Exception e) {
			// ignore
		}
		return false;
	}

}

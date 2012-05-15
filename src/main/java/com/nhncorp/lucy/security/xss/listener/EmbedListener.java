/*
 * @(#) EmbedListener.java 2010. 8. 11 
 *
 * Copyright 2010 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.listener;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * 이 클래스는 Embed 태그에 대한 보안 필터링을 수행한다.
 *
 * @author Web Platform Development Team
 * 
 */
public class EmbedListener implements ElementListener {
	public void handleElement(Element e) {
		if (e.isDisabled()) {
			return;
		}
		
		String srcUrl = e.getAttributeValue("src");
		boolean isWhiteUrl = this.isWhiteUrl(srcUrl);

		// URL MIME 체크
		boolean isVulnerable = SecurityUtils.checkVulnerable(e, srcUrl, isWhiteUrl);

		if (isVulnerable) {
			e.setEnabled(false);
			return;
		}

		e.putAttribute("invokeURLs", "\"false\"");
		e.putAttribute("autostart", "\"false\"");
		e.putAttribute("allowScriptAccess", "\"never\"");

		if (isWhiteUrl) {
			e.putAttribute("allowNetworking", "\"all\"");
		} else {
			e.putAttribute("allowNetworking", "\"internal\"");
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

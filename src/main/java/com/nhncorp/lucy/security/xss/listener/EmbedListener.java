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

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * 이 클래스는 Embed 태그에 대한 보안 필터링을 수행한다.
 *
 * @author Naver Labs
 * 
 */
public class EmbedListener implements ElementListener {
	public void handleElement(Element element) {
		if (element.isDisabled()) {
			return;
		}
		
		String srcUrl = element.getAttributeValue("src");
		boolean isWhiteUrl = this.isWhiteUrl(srcUrl);

		// URL MIME 체크
		boolean isVulnerable = SecurityUtils.checkVulnerable(element, srcUrl, isWhiteUrl);

		if (isVulnerable) {
			element.setEnabled(false);
			return;
		}

		element.putAttribute("invokeURLs", "\"false\"");
		element.putAttribute("autostart", "\"false\"");
		element.putAttribute("allowScriptAccess", "\"never\"");

		if (isWhiteUrl) {
			element.putAttribute("allowNetworking", "\"all\"");
		} else {
			element.putAttribute("allowNetworking", "\"internal\"");
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

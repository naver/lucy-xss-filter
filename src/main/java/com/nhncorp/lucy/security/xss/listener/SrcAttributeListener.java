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

import com.nhncorp.lucy.security.xss.event.AttributeListener;
import com.nhncorp.lucy.security.xss.markup.Attribute;

/**
 * 이 클래스는 src attribute를 기준으로 태그에 대한 보안 필터링을 수행한다.
 *
 * @author Naver Labs
 *
 */
public class SrcAttributeListener implements AttributeListener {
	public void handleAttribute(Attribute attr) {
		if (this.isWhiteUrl(attr.getValue())) {
		} else {
			attr.setValue("\"\""); // 허락되지 않은 url 이면 empty string 처리. setValue()메소드는 자동으로 인용부호를 할당 하지 않으므로 ""를 할당한다.
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

/*
 * @(#) EmbedListener.java 2010. 8. 11
 *
 * Copyright 2010 NHN Corp. All rights Reserved.
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.listener;

import com.nhncorp.lucy.security.xss.event.AttributeListener;
import com.nhncorp.lucy.security.xss.markup.Attribute;

/**
 * 이 클래스는 src attribute를 기준으로 태그에 대한 보안 필터링을 수행한다.
 *
 * @author Web Platform Development Team
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

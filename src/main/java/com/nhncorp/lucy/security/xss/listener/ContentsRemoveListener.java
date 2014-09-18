/*
 * @(#)ContentsRemoveListener.java $version 2012. 5. 4.
 *
 * Copyright 2007 NHN Corp. All rights Reserved. 
 * NHN PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 */
package com.nhncorp.lucy.security.xss.listener;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

/**
 * @author Naver Labs
 */
public class ContentsRemoveListener implements ElementListener {
	public void handleElement(Element element) {
		element.removeAllContents();
	}
}

package com.nhncorp.lucy.security.xss.listener;

import com.nhncorp.lucy.security.xss.event.ElementListener;
import com.nhncorp.lucy.security.xss.markup.Element;

public class ContentsRemoveListener implements ElementListener {

	public void handleElement(Element e) {
		e.removeAllContents();
	}
}
